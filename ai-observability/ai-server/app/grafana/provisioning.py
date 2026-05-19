from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from app import storage


GRAFANA_URL = os.getenv("GRAFANA_URL_INTERNAL", "http://grafana.monitoring.svc.cluster.local:3000").rstrip("/")
AI_SERVER_PROXY_BASE_URL = os.getenv(
    "AI_SERVER_PROXY_BASE_URL",
    "http://ai-server.compliance-system.svc.cluster.local:8000",
).rstrip("/")
DASHBOARD_TEMPLATE_PATH = Path(__file__).resolve().parent / "dashboard_template.json"


class ProvisioningError(RuntimeError):
    pass


def provision_user(user_id: str, cluster_id: str, email: str) -> dict[str, Any]:
    normalized_user_id = str(user_id or "").strip()
    normalized_cluster_id = str(cluster_id or "").strip()
    normalized_email = str(email or "").strip().lower()
    if not normalized_user_id or not normalized_cluster_id or not normalized_email:
        raise ProvisioningError("user_id, cluster_id, and email are required")
    existing = storage.get_grafana_provisioning(normalized_user_id, normalized_cluster_id)
    if existing:
        return existing

    auth = _grafana_auth()
    org_name = f"org-{normalized_user_id}"
    org_id: int | None = None
    created_org = False

    try:
        with httpx.Client(base_url=GRAFANA_URL, auth=auth, timeout=10) as client:
            org = _get_org(client, org_name)
            if org is None:
                response = client.post("/api/orgs", json={"name": org_name})
                if response.status_code not in {200, 201}:
                    raise ProvisioningError(f"Grafana org create failed: {response.status_code} {response.text}")
                org_id = int(response.json()["orgId"])
                created_org = True
            else:
                org_id = int(org["id"])

            datasource_uid = _datasource_uid(normalized_cluster_id)
            datasource = _ensure_datasource(client, org_id, normalized_user_id, normalized_cluster_id, datasource_uid)
            dashboard = _dashboard_payload(client, datasource_uid)
            dash_response = client.post(
                "/api/dashboards/db",
                headers={"X-Grafana-Org-Id": str(org_id)},
                json={"dashboard": dashboard, "overwrite": True},
            )
            if dash_response.status_code not in {200, 201}:
                raise ProvisioningError(f"Grafana dashboard import failed: {dash_response.status_code} {dash_response.text}")

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

            dashboard_body = dash_response.json()
            return storage.save_grafana_provisioning(
                user_id=normalized_user_id,
                cluster_id=normalized_cluster_id,
                org_id=org_id,
                org_name=org_name,
                datasource_uid=datasource.get("uid", datasource_uid),
                dashboard_url=str(dashboard_body.get("url", "")),
            )
    except Exception as error:
        if created_org and org_id is not None:
            _rollback_org(org_id, auth)
        if isinstance(error, ProvisioningError):
            raise
        raise ProvisioningError(str(error)) from error


def _grafana_auth() -> tuple[str, str]:
    user = os.getenv("GRAFANA_ADMIN_USER") or os.getenv("GF_SECURITY_ADMIN_USER", "admin")
    password = os.getenv("GRAFANA_ADMIN_PASSWORD") or os.getenv("GF_SECURITY_ADMIN_PASSWORD", "")
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
        response = client.put(f"/api/datasources/{datasource['id']}", headers=headers, json=payload)
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


def _dashboard_payload(client: httpx.Client, datasource_uid: str) -> dict[str, Any]:
    dashboard = _load_master_dashboard(client) or _load_local_dashboard_template()
    dashboard = _sanitize_dashboard_for_import(dashboard)
    return _replace_datasource_uid(dashboard, datasource_uid)


def _load_master_dashboard(client: httpx.Client) -> dict[str, Any] | None:
    master_uid = os.getenv("GRAFANA_MASTER_DASHBOARD_UID", "").strip()
    if not master_uid:
        return None
    master_org_id = os.getenv("GRAFANA_MASTER_ORG_ID", "1").strip() or "1"
    response = client.get(
        f"/api/dashboards/uid/{master_uid}",
        headers={"X-Grafana-Org-Id": master_org_id},
    )
    if response.status_code != 200:
        raise ProvisioningError(
            f"Grafana master dashboard fetch failed: {response.status_code} {response.text}"
        )
    dashboard = response.json().get("dashboard")
    if not isinstance(dashboard, dict):
        raise ProvisioningError("Grafana master dashboard response missing dashboard")
    return dashboard


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
        "exp": now + 60 * 60 * 24,
    }
    signing_input = f"{_b64json(header)}.{_b64json(payload)}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


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
