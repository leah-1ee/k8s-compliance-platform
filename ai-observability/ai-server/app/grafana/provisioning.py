from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx

from app import storage


logger = logging.getLogger("ai-server.grafana.provisioning")
GRAFANA_URL = os.getenv("GRAFANA_URL_INTERNAL", "http://grafana.monitoring.svc.cluster.local:3000").rstrip("/")
CLIENT_GRAFANA_URL = os.getenv("GRAFANA_CLIENT_URL_INTERNAL", GRAFANA_URL).rstrip("/")
ADMIN_GRAFANA_URL = os.getenv("GRAFANA_ADMIN_URL_INTERNAL", GRAFANA_URL).rstrip("/")
AI_SERVER_PROXY_BASE_URL = os.getenv(
    "AI_SERVER_PROXY_BASE_URL",
    "http://ai-server.compliance-system.svc.cluster.local:8000",
).rstrip("/")
DASHBOARD_TEMPLATE_PATH = Path(__file__).resolve().parent / "dashboard_template.json"
BUNDLED_DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboards"
BUNDLED_DASHBOARD_PATHS = (
    BUNDLED_DASHBOARD_DIR / "compliance-overview.json",
    BUNDLED_DASHBOARD_DIR / "runtime-dashboard.json",
)


class ProvisioningError(RuntimeError):
    pass


def provision_user(user_id: str, cluster_id: str, email: str) -> dict[str, Any]:
    normalized_user_id = str(user_id or "").strip()
    normalized_cluster_id = str(cluster_id or "").strip()
    normalized_email = str(email or "").strip().lower()
    if not normalized_user_id or not normalized_cluster_id or not normalized_email:
        raise ProvisioningError("user_id, cluster_id, and email are required")

    client_auth = _grafana_auth("CLIENT")
    admin_auth = _grafana_auth("ADMIN")
    org_name = f"org-{normalized_user_id}"
    org_id: int | None = None
    created_org = False

    try:
        with httpx.Client(base_url=CLIENT_GRAFANA_URL, auth=client_auth, timeout=10) as client:
            org = _get_org(client, org_name)
            if org is None:
                response = client.post("/api/orgs", json={"name": org_name})
                if response.status_code not in {200, 201}:
                    raise ProvisioningError(f"Grafana org create failed: {response.status_code} {response.text}")
                org_id = int(response.json()["orgId"])
                created_org = True
            else:
                org_id = int(org["id"])

            _switch_org(client, org_id)
            datasource_uid = _datasource_uid(normalized_cluster_id)
            datasource = _ensure_datasource(client, org_id, normalized_user_id, normalized_cluster_id, datasource_uid)
            dashboard_urls = _import_dashboards(client, org_id, datasource_uid, admin_auth)

            user_response = client.post(
                f"/api/orgs/{org_id}/users",
                json={"loginOrEmail": normalized_email, "role": "Viewer"},
            )
            if user_response.status_code not in {200, 201, 409}:
                if user_response.status_code == 404:
                    _ensure_user(client, normalized_email)
                    user_response = client.post(
                        f"/api/orgs/{org_id}/users",
                        json={"loginOrEmail": normalized_email, "role": "Viewer"},
                    )
                if user_response.status_code not in {200, 201, 409}:
                    raise ProvisioningError(
                        f"Grafana org user add failed: {user_response.status_code} {user_response.text}"
                    )

            mapping = storage.save_grafana_provisioning(
                user_id=normalized_user_id,
                cluster_id=normalized_cluster_id,
                org_id=org_id,
                org_name=org_name,
                datasource_uid=datasource.get("uid", datasource_uid),
                dashboard_url=dashboard_urls[0] if dashboard_urls else "",
            )
            mapping["dashboard_urls"] = dashboard_urls
            return mapping
    except Exception as error:
        if created_org and org_id is not None:
            _rollback_org(org_id, client_auth)
        if isinstance(error, ProvisioningError):
            raise
        raise ProvisioningError(str(error)) from error


def _grafana_auth(scope: str = "") -> tuple[str, str]:
    prefix = f"GRAFANA_{scope.strip().upper()}_ADMIN" if scope else "GRAFANA_ADMIN"
    user = (
        os.getenv(f"{prefix}_USER")
        or os.getenv("GRAFANA_ADMIN_USER")
        or os.getenv("GF_SECURITY_ADMIN_USER", "admin")
    )
    password = (
        os.getenv(f"{prefix}_PASSWORD")
        or os.getenv("GRAFANA_ADMIN_PASSWORD")
        or os.getenv("GF_SECURITY_ADMIN_PASSWORD", "")
    )
    if not password:
        raise ProvisioningError("Grafana admin password is required")
    return user, password


def _get_org(client: httpx.Client, org_name: str) -> dict[str, Any] | None:
    response = client.get(f"/api/orgs/name/{org_name}")
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise ProvisioningError(f"Grafana org lookup failed: {response.status_code} {response.text}")
    return response.json()


def _switch_org(client: httpx.Client, org_id: int) -> None:
    response = client.post(f"/api/user/using/{org_id}")
    if response.status_code != 200:
        raise ProvisioningError(f"Grafana org switch failed: {response.status_code} {response.text}")


def _ensure_datasource(
    client: httpx.Client,
    org_id: int,
    user_id: str,
    cluster_id: str,
    datasource_uid: str,
) -> dict[str, Any]:
    name = f"kubeowl-prometheus-{cluster_id}"
    headers = {"X-Grafana-Org-Id": str(org_id)}
    existing = client.get(f"/api/datasources/name/{name}", headers=headers)
    payload = {
        "name": name,
        "uid": datasource_uid,
        "type": "prometheus",
        "access": "proxy",
        "url": f"{AI_SERVER_PROXY_BASE_URL}/grafana/prometheus/{cluster_id}",
        "isDefault": True,
        "jsonData": {
            "httpMethod": "POST",
            "httpHeaderName1": "Authorization",
        },
        "secureJsonData": {
            "httpHeaderValue1": f"Bearer {_proxy_jwt(user_id, cluster_id)}",
        },
    }
    if existing.status_code == 200:
        datasource = existing.json()
        existing_uid = datasource.get("uid") or datasource_uid
        response = client.put(f"/api/datasources/uid/{existing_uid}", headers=headers, json=payload)
    elif existing.status_code == 404:
        response = client.post("/api/datasources", headers=headers, json=payload)
    else:
        raise ProvisioningError(f"Grafana datasource lookup failed: {existing.status_code} {existing.text}")
    if response.status_code not in {200, 201}:
        raise ProvisioningError(f"Grafana datasource provision failed: {response.status_code} {response.text}")
    return response.json().get("datasource") or response.json()


def _ensure_user(client: httpx.Client, email: str) -> None:
    password = os.getenv("GRAFANA_DEFAULT_VIEWER_PASSWORD", "").strip() or hashlib.sha256(
        f"{email}:{time.time()}".encode("utf-8")
    ).hexdigest()
    response = client.post(
        "/api/admin/users",
        json={
            "name": email,
            "email": email,
            "login": email,
            "password": password,
        },
    )
    if response.status_code not in {200, 201, 409}:
        raise ProvisioningError(f"Grafana user create failed: {response.status_code} {response.text}")


def _import_dashboards(
    client: httpx.Client,
    org_id: int,
    datasource_uid: str,
    admin_auth: tuple[str, str] | None = None,
) -> list[str]:
    dashboard_urls: list[str] = []
    for dashboard in _dashboard_payloads(client, datasource_uid, admin_auth=admin_auth):
        dash_response = client.post(
            "/api/dashboards/db",
            headers={"X-Grafana-Org-Id": str(org_id)},
            json={"dashboard": dashboard, "overwrite": True},
        )
        if dash_response.status_code not in {200, 201}:
            raise ProvisioningError(
                f"Grafana dashboard import failed: {dash_response.status_code} {dash_response.text}"
            )
        dashboard_url = str(dash_response.json().get("url", "")).strip()
        if dashboard_url:
            dashboard_urls.append(dashboard_url)
    return dashboard_urls


def _dashboard_payloads(
    client: httpx.Client,
    datasource_uid: str,
    *,
    master_client: httpx.Client | None = None,
    admin_auth: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    dashboards = _load_master_dashboards(master_client, admin_auth)
    if _include_bundled_dashboards():
        _append_missing_dashboards(dashboards, _load_bundled_dashboards())
    local_dashboard = _load_local_dashboard_template()
    if _include_local_dashboard() and not any(
        dashboard.get("uid") == local_dashboard.get("uid") for dashboard in dashboards
    ):
        dashboards.append(local_dashboard)
    if not dashboards:
        dashboards = [local_dashboard]
    return [
        _replace_datasource_uid(_sanitize_dashboard_for_import(dashboard), datasource_uid)
        for dashboard in dashboards
    ]


def _append_missing_dashboards(dashboards: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> None:
    seen = {str(dashboard.get("uid") or "").strip() for dashboard in dashboards}
    for dashboard in candidates:
        uid = str(dashboard.get("uid") or "").strip()
        if uid and uid in seen:
            continue
        dashboards.append(dashboard)
        if uid:
            seen.add(uid)


def _load_bundled_dashboards() -> list[dict[str, Any]]:
    dashboards: list[dict[str, Any]] = []
    for path in BUNDLED_DASHBOARD_PATHS:
        if not path.exists():
            logger.warning("Skipping missing bundled Grafana dashboard %s", path)
            continue
        try:
            dashboard = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            logger.warning("Skipping invalid bundled Grafana dashboard %s: %s", path, error)
            continue
        if isinstance(dashboard, dict):
            dashboards.append(dashboard)
    return dashboards


def _load_master_dashboards(
    master_client: httpx.Client | None = None,
    admin_auth: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    master_uids = _master_dashboard_uids()
    if not master_uids:
        return []
    master_org_id = os.getenv("GRAFANA_MASTER_ORG_ID", "1").strip() or "1"
    dashboards: list[dict[str, Any]] = []

    def fetch_dashboards(admin_client: httpx.Client) -> None:
        for master_uid in master_uids:
            response = admin_client.get(
                f"/api/dashboards/uid/{master_uid}",
                headers={"X-Grafana-Org-Id": master_org_id},
            )
            if response.status_code != 200:
                if not _require_master_dashboards():
                    logger.warning(
                        "Skipping Grafana master dashboard %s fetch after %s: %s",
                        master_uid,
                        response.status_code,
                        response.text[:300],
                    )
                    continue
                raise ProvisioningError(
                    f"Grafana master dashboard fetch failed for {master_uid}: {response.status_code} {response.text}"
                )
            dashboard = response.json().get("dashboard")
            if not isinstance(dashboard, dict):
                raise ProvisioningError(f"Grafana master dashboard response missing dashboard for {master_uid}")
            dashboards.append(dashboard)

    if master_client is not None:
        fetch_dashboards(master_client)
    else:
        with httpx.Client(
            base_url=ADMIN_GRAFANA_URL,
            auth=admin_auth or _grafana_auth("ADMIN"),
            timeout=10,
        ) as admin_client:
            fetch_dashboards(admin_client)
    return dashboards


def _require_master_dashboards() -> bool:
    return os.getenv("GRAFANA_REQUIRE_MASTER_DASHBOARDS", "").strip().lower() in {"true", "1", "yes"}


def _master_dashboard_uids() -> list[str]:
    raw = os.getenv("GRAFANA_MASTER_DASHBOARD_UIDS", "").strip()
    if not raw:
        raw = os.getenv("GRAFANA_MASTER_DASHBOARD_UID", "").strip()
    seen: set[str] = set()
    uids: list[str] = []
    for item in raw.split(","):
        uid = item.strip()
        if uid and uid not in seen:
            seen.add(uid)
            uids.append(uid)
    return uids


def _load_local_dashboard_template() -> dict[str, Any]:
    if DASHBOARD_TEMPLATE_PATH.exists():
        return json.loads(DASHBOARD_TEMPLATE_PATH.read_text(encoding="utf-8"))
    return {
        "uid": "kubeowl-observability",
        "title": "KubeOwl Observability",
        "schemaVersion": 39,
        "version": 1,
        "panels": [],
    }


def _include_local_dashboard() -> bool:
    return os.getenv("GRAFANA_INCLUDE_LOCAL_DASHBOARD", "true").strip().lower() not in {"false", "0", "no"}


def _include_bundled_dashboards() -> bool:
    return os.getenv("GRAFANA_INCLUDE_BUNDLED_DASHBOARDS", "true").strip().lower() not in {"false", "0", "no"}


def _sanitize_dashboard_for_import(dashboard: dict[str, Any]) -> dict[str, Any]:
    clean = json.loads(json.dumps(dashboard))
    clean["id"] = None
    clean["version"] = 0
    if not clean.get("uid"):
        clean["uid"] = "kubeowl-observability"
    return clean


def _replace_datasource_uid(value: Any, datasource_uid: str) -> Any:
    if isinstance(value, dict):
        replaced = {}
        for key, item in value.items():
            if key == "uid" and value.get("type") == "prometheus":
                replaced[key] = datasource_uid
            else:
                replaced[key] = _replace_datasource_uid(item, datasource_uid)
        return replaced
    if isinstance(value, list):
        return [_replace_datasource_uid(item, datasource_uid) for item in value]
    return value


def _datasource_uid(cluster_id: str) -> str:
    suffix = hashlib.sha256(cluster_id.encode("utf-8")).hexdigest()[:16]
    return f"kubeowl-prom-{suffix}"


def _proxy_jwt(user_id: str, cluster_id: str) -> str:
    secret = os.getenv("JWT_SECRET", "").strip()
    if not secret:
        raise ProvisioningError("JWT_SECRET is required for Grafana proxy datasource auth")
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "user_id": user_id,
        "cluster_id": cluster_id,
        "iat": now,
        "exp": now + _grafana_proxy_jwt_ttl_seconds(),
    }
    signing_input = f"{_b64json(header)}.{_b64json(payload)}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def _grafana_proxy_jwt_ttl_seconds() -> int:
    raw = os.getenv("GRAFANA_PROXY_JWT_TTL_SECONDS", "").strip()
    if raw:
        try:
            return max(3600, int(raw))
        except ValueError:
            pass
    return 60 * 60 * 24 * 30


def _b64json(value: dict[str, Any]) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _rollback_org(org_id: int, auth: tuple[str, str]) -> None:
    try:
        with httpx.Client(base_url=GRAFANA_URL, auth=auth, timeout=5) as client:
            client.delete(f"/api/orgs/{org_id}")
    except httpx.HTTPError:
        pass
