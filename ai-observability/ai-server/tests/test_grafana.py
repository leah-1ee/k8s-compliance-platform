import base64
import hashlib
import hmac
import json
import time

import httpx
from fastapi.testclient import TestClient

from app import storage
from app.grafana import proxy
from app.grafana import provisioning
from app.grafana import ui_proxy
from app.grafana.promql_inject import PromQLInjectionError, inject_cluster_label
from app.main import app
import app.main as main_module


client = TestClient(app)


def _jwt(secret: str, user_id: str, cluster_id: str, exp: int | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "user_id": user_id,
        "cluster_id": cluster_id,
        "exp": exp or int(time.time()) + 300,
    }
    signing_input = f"{_b64json(header)}.{_b64json(payload)}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def _b64json(value: dict) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def test_promql_injects_cluster_label_for_supported_shapes():
    assert inject_cluster_label("up", "abc") == 'up{cluster_id="abc"}'
    assert (
        inject_cluster_label('http_requests_total{method="GET"}', "abc")
        == 'http_requests_total{method="GET",cluster_id="abc"}'
    )
    assert inject_cluster_label('up{cluster_id="evil"}', "abc") == 'up{cluster_id="abc"}'
    assert inject_cluster_label("up + http_requests_total", "abc") == (
        'up{cluster_id="abc"} + http_requests_total{cluster_id="abc"}'
    )
    assert inject_cluster_label("rate(http_requests_total[5m])", "abc") == (
        'rate(http_requests_total{cluster_id="abc"}[5m])'
    )
    assert inject_cluster_label("sum by (pod)(metric)", "abc") == 'sum by (pod)(metric{cluster_id="abc"})'


def test_promql_empty_query_raises():
    try:
        inject_cluster_label("", "abc")
    except PromQLInjectionError:
        return
    raise AssertionError("empty query must raise PromQLInjectionError")


def test_prometheus_proxy_rewrites_query_and_writes_audit(monkeypatch, tmp_path):
    secret = "test-secret"
    audit_path = tmp_path / "audit.log"
    captured = {}

    async def fake_forward(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        return httpx.Response(200, json={"status": "success"})

    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.setattr(proxy, "AUDIT_LOG_PATH", audit_path)
    monkeypatch.setattr(proxy, "_forward_request", fake_forward)
    token = _jwt(secret, "user-1", "cluster-1")

    response = client.get(
        "/grafana/prometheus/cluster-1/api/v1/query",
        params={"query": 'up{cluster_id="evil"}'},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert captured["url"] == "http://prometheus.monitoring.svc.cluster.local:9090/api/v1/query"
    assert captured["params"] == [("query", 'up{cluster_id="cluster-1"}')]

    audit = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert audit["user_id"] == "user-1"
    assert audit["cluster_id"] == "cluster-1"
    assert audit["original_query"] == 'up{cluster_id="evil"}'
    assert audit["injected_query"] == 'up{cluster_id="cluster-1"}'
    assert audit["status_code"] == 200


def test_prometheus_proxy_rejects_cluster_mismatch(monkeypatch, tmp_path):
    secret = "test-secret"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.setattr(proxy, "AUDIT_LOG_PATH", tmp_path / "audit.log")
    token = _jwt(secret, "user-1", "cluster-owned")

    response = client.get(
        "/grafana/prometheus/cluster-other/api/v1/query",
        params={"query": "up"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "cluster_id mismatch"


def test_cluster_grafana_provision_endpoint_calls_provisioner(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-provision@example.test",
        email="grafana-provision@example.test",
    )
    session = storage.create_session(user["id"])
    cluster = storage.create_cluster("grafana-provision-cluster", user_id=user["id"])
    captured = {}

    def fake_provision_user(user_id, cluster_id, email):
        captured["user_id"] = user_id
        captured["cluster_id"] = cluster_id
        captured["email"] = email
        return {
            "cluster_id": cluster_id,
            "user_id": user_id,
            "org_id": 42,
            "org_name": f"org-{user_id}",
            "datasource_uid": "kubeowl-prom-test",
            "dashboard_url": "/d/kubeowl-observability/kubeowl-observability",
        }

    monkeypatch.setenv("GRAFANA_PUBLIC_URL", "http://grafana.example.test")
    monkeypatch.setattr(main_module, "provision_user", fake_provision_user)

    response = client.post(
        f"/api/clusters/{cluster['id']}/grafana/provision",
        cookies={"compliance_ai_session": session},
    )
    body = response.json()

    assert response.status_code == 200
    assert captured == {
        "user_id": user["id"],
        "cluster_id": cluster["id"],
        "email": "grafana-provision@example.test",
    }
    assert body["status"] == "provisioned"
    assert body["grafana"]["org_id"] == 42
    assert body["grafana"]["url"].startswith("/grafana-ui/org/switch/42")


def test_cluster_grafana_provision_requires_cluster_ownership(monkeypatch):
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-owner@example.test",
        email="grafana-owner@example.test",
    )
    other = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-other@example.test",
        email="grafana-other@example.test",
    )
    session = storage.create_session(other["id"])
    cluster = storage.create_cluster("grafana-owned-cluster", user_id=owner["id"])

    def fail_if_called(*args, **kwargs):
        raise AssertionError("provision_user should not run for unowned cluster")

    monkeypatch.setattr(main_module, "provision_user", fail_if_called)

    response = client.post(
        f"/api/clusters/{cluster['id']}/grafana/provision",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 404
    assert response.json()["error"] == "cluster not found"


def test_grafana_ui_proxy_requires_login():
    response = client.get("/grafana-ui/")

    assert response.status_code == 401
    assert response.json()["error"] == "login required"


def test_grafana_ui_proxy_injects_auth_proxy_headers(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-proxy@example.test",
        email="grafana-ui-proxy@example.test",
        name="Grafana Viewer",
    )
    session = storage.create_session(user["id"])
    captured = {}

    async def fake_forward(request, upstream_path, user):
        headers = ui_proxy._request_headers(request, user)
        captured["upstream_path"] = upstream_path
        captured["headers"] = headers
        return httpx.Response(
            200,
            text="grafana ok",
            headers={"content-type": "text/plain"},
        )

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    response = client.get(
        "/grafana-ui/d/kubeowl-observability/kubeowl-observability",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 200
    assert response.text == "grafana ok"
    assert captured["upstream_path"] == "/grafana-ui/d/kubeowl-observability/kubeowl-observability"
    assert captured["headers"]["X-WEBAUTH-USER"] == "grafana-ui-proxy@example.test"
    assert captured["headers"]["X-WEBAUTH-EMAIL"] == "grafana-ui-proxy@example.test"
    assert captured["headers"]["X-WEBAUTH-NAME"] == "Grafana Viewer"


def test_dashboard_payload_fetches_master_dashboard_and_rewrites_datasource(monkeypatch):
    requested = {}

    class FakeClient:
        def get(self, path, headers=None):
            requested["path"] = path
            requested["headers"] = headers
            return httpx.Response(
                200,
                json={
                    "dashboard": {
                        "id": 7,
                        "uid": "admin-master",
                        "title": "Admin Master",
                        "version": 15,
                        "panels": [
                            {
                                "datasource": {
                                    "type": "prometheus",
                                    "uid": "admin-datasource",
                                },
                                "targets": [
                                    {
                                        "datasource": {
                                            "type": "prometheus",
                                            "uid": "admin-datasource",
                                        },
                                        "expr": "up",
                                    }
                                ],
                            }
                        ],
                    }
                },
            )

    monkeypatch.setenv("GRAFANA_MASTER_DASHBOARD_UID", "admin-master")
    monkeypatch.setenv("GRAFANA_MASTER_ORG_ID", "1")

    dashboard = provisioning._dashboard_payload(FakeClient(), "user-datasource")

    assert requested["path"] == "/api/dashboards/uid/admin-master"
    assert requested["headers"] == {"X-Grafana-Org-Id": "1"}
    assert dashboard["id"] is None
    assert dashboard["version"] == 0
    assert dashboard["panels"][0]["datasource"]["uid"] == "user-datasource"
    assert dashboard["panels"][0]["targets"][0]["datasource"]["uid"] == "user-datasource"
