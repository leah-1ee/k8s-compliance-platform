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
    assert body["grafana"]["url"] == "/grafana-ui/d/kubeowl-observability/kubeowl-observability?orgId=42"


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
    assert captured["upstream_path"] == "/d/kubeowl-observability/kubeowl-observability"
    assert captured["headers"]["X-WEBAUTH-USER"] == "grafana-ui-proxy@example.test"
    assert captured["headers"]["X-WEBAUTH-EMAIL"] == "grafana-ui-proxy@example.test"
    assert captured["headers"]["X-WEBAUTH-NAME"] == "Grafana Viewer"


def test_grafana_ui_proxy_strips_subpath_for_static_assets(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-asset@example.test",
        email="grafana-ui-asset@example.test",
    )
    session = storage.create_session(user["id"])
    captured = {}

    async def fake_forward(request, upstream_path, user):
        captured["upstream_path"] = upstream_path
        return httpx.Response(
            200,
            text="console.log('stat panel')",
            headers={"content-type": "text/javascript"},
        )

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    response = client.get(
        "/grafana-ui/public/build/statPanel.3fd0656497f2451671cd.js",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 200
    assert captured["upstream_path"] == "/public/build/statPanel.3fd0656497f2451671cd.js"


def test_grafana_ui_proxy_rewrites_html_asset_paths(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-html@example.test",
        email="grafana-ui-html@example.test",
    )
    session = storage.create_session(user["id"])

    async def fake_forward(request, upstream_path, user):
        return httpx.Response(
            200,
            text=(
                '<html><head><base href="/">'
                '<script src="public/build/runtime.js"></script>'
                '<link href="/public/build/grafana.dark.css" rel="stylesheet">'
                '<script>window.grafanaBootData={"settings":{"appSubUrl":""}}</script>'
                "</head></html>"
            ),
            headers={"content-type": "text/html; charset=utf-8"},
        )

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    response = client.get(
        "/grafana-ui/",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 200
    assert '<base href="/grafana-ui/">' in response.text
    assert 'src="/grafana-ui/public/build/runtime.js"' in response.text
    assert 'href="/grafana-ui/public/build/grafana.dark.css"' in response.text
    assert '"appSubUrl":"/grafana-ui"' in response.text


def test_grafana_ui_proxy_rewrites_javascript_chunk_paths(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-js@example.test",
        email="grafana-ui-js@example.test",
    )
    session = storage.create_session(user["id"])

    async def fake_forward(request, upstream_path, user):
        return httpx.Response(
            200,
            text='__webpack_require__.p="/public/build/";import("/public/build/7651.js")',
            headers={"content-type": "text/javascript; charset=utf-8"},
        )

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    response = client.get(
        "/grafana-ui/public/build/runtime.js",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 200
    assert '"/grafana-ui/public/build/"' in response.text
    assert '"/grafana-ui/public/build/7651.js"' in response.text
    assert '"/public/build/' not in response.text


def test_grafana_ui_proxy_serves_root_public_lazy_chunks(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-root-public@example.test",
        email="grafana-ui-root-public@example.test",
    )
    session = storage.create_session(user["id"])
    captured = {}

    async def fake_forward(request, upstream_path, user):
        captured["upstream_path"] = upstream_path
        return httpx.Response(
            200,
            text="chunk ok",
            headers={"content-type": "text/javascript; charset=utf-8"},
        )

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    response = client.get(
        "/public/build/7651.06c4a6f267dfa91784a2.js",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 200
    assert response.text == "chunk ok"
    assert captured["upstream_path"] == "/public/build/7651.06c4a6f267dfa91784a2.js"


def test_grafana_ui_proxy_serves_root_grafana_api_paths(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-root-api@example.test",
        email="grafana-ui-root-api@example.test",
    )
    session = storage.create_session(user["id"])
    captured = []

    async def fake_forward(request, upstream_path, user):
        captured.append(upstream_path)
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    for path in (
        "/api/login/ping",
        "/api/plugins/grafana-lokiexplore-app/settings",
        "/api/user/orgs",
        "/api/ds/query?ds_type=prometheus",
        "/api/prometheus/grafana/api/v1/rules?dashboard_uid=compliance-overview",
        "/apis/dashboard.grafana.app/v1beta1/namespaces/default/dashboards",
        "/avatar/78d07744450b61186736ffc6f97b1082",
    ):
        response = client.get(path, cookies={"compliance_ai_session": session})
        assert response.status_code == 200

    metrics_response = client.post("/api/frontend-metrics", cookies={"compliance_ai_session": session})
    assert metrics_response.status_code == 200

    assert captured == [
        "/api/login/ping",
        "/api/plugins/grafana-lokiexplore-app/settings",
        "/api/user/orgs",
        "/api/ds/query?ds_type=prometheus",
        "/api/prometheus/grafana/api/v1/rules?dashboard_uid=compliance-overview",
        "/apis/dashboard.grafana.app/v1beta1/namespaces/default/dashboards",
        "/avatar/78d07744450b61186736ffc6f97b1082",
        "/api/frontend-metrics",
    ]


def test_grafana_ui_proxy_rewrites_root_relative_redirects():
    assert ui_proxy._rewrite_location("/login?redirectTo=%2F") == "/grafana-ui/login?redirectTo=%2F"
    assert ui_proxy._rewrite_location(f"{ui_proxy.GRAFANA_URL}/login") == "/grafana-ui/login"


def test_grafana_ui_proxy_headers_are_ascii_safe_for_non_ascii_names(monkeypatch):
    user = storage.upsert_user(
        provider="dev",
        provider_subject="grafana-ui-korean@example.test",
        email="grafana-ui-korean@example.test",
        name="홍길동",
    )
    session = storage.create_session(user["id"])
    captured = {}

    async def fake_forward(request, upstream_path, user):
        headers = ui_proxy._request_headers(request, user)
        captured["headers"] = headers
        return httpx.Response(200, text="grafana ok")

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    response = client.get(
        "/grafana-ui/d/kubeowl-observability/kubeowl-observability",
        cookies={"compliance_ai_session": session},
    )

    assert response.status_code == 200
    assert captured["headers"]["X-WEBAUTH-USER"] == "grafana-ui-korean@example.test"
    assert captured["headers"]["X-WEBAUTH-NAME"] == "grafana-ui-korean@example.test"
    for value in captured["headers"].values():
        value.encode("ascii")


def test_admin_grafana_url_sets_admin_proxy_cookie(monkeypatch):
    unauthorized = client.get("/admin/api/grafana/url")
    assert unauthorized.status_code == 401

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    url_response = client.get(
        "/admin/api/grafana/url",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    url_body = url_response.json()
    admin_cookie = url_response.cookies.get("kubeowl_admin_grafana")

    assert url_response.status_code == 200
    assert url_body["grafana"]["url"] == "/grafana-ui/dashboards?orgId=1"
    assert url_body["grafana"]["mode"] == "admin"
    assert admin_cookie

    captured = {}

    async def fake_forward(request, upstream_path, user):
        headers = ui_proxy._request_headers(request, user)
        captured["upstream_path"] = upstream_path
        captured["headers"] = headers
        return httpx.Response(200, text="admin grafana ok")

    monkeypatch.setattr(ui_proxy, "_forward_grafana_request", fake_forward)

    grafana_response = client.get(
        "/grafana-ui/dashboards?orgId=1",
        cookies={"kubeowl_admin_grafana": admin_cookie},
    )

    assert grafana_response.status_code == 200
    assert grafana_response.text == "admin grafana ok"
    assert captured["upstream_path"] == "/dashboards?orgId=1"
    assert captured["headers"]["X-WEBAUTH-USER"] == "kubeowl-admin@local"
    assert captured["headers"]["X-WEBAUTH-EMAIL"] == "kubeowl-admin@local"
    assert captured["headers"]["X-WEBAUTH-NAME"] == "KubeOwl Admin"


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

    dashboards = provisioning._dashboard_payloads(FakeClient(), "user-datasource")
    dashboard = dashboards[0]

    assert requested["path"] == "/api/dashboards/uid/admin-master"
    assert requested["headers"] == {"X-Grafana-Org-Id": "1"}
    assert dashboard["id"] is None
    assert dashboard["version"] == 0
    assert dashboard["panels"][0]["datasource"]["uid"] == "user-datasource"
    assert dashboard["panels"][0]["targets"][0]["datasource"]["uid"] == "user-datasource"


def test_dashboard_payloads_support_multiple_master_uids(monkeypatch):
    requested = []

    class FakeClient:
        def get(self, path, headers=None):
            requested.append((path, headers))
            uid = path.rsplit("/", 1)[-1]
            return httpx.Response(
                200,
                json={
                    "dashboard": {
                        "id": 7,
                        "uid": uid,
                        "title": uid,
                        "version": 15,
                        "panels": [
                            {
                                "datasource": {
                                    "type": "prometheus",
                                    "uid": "admin-datasource",
                                }
                            }
                        ],
                    }
                },
            )

    monkeypatch.setenv(
        "GRAFANA_MASTER_DASHBOARD_UIDS",
        "compliance-overview,runtime-detection,grafana-overview",
    )
    monkeypatch.setenv("GRAFANA_MASTER_ORG_ID", "1")

    dashboards = provisioning._dashboard_payloads(FakeClient(), "user-datasource")

    assert [dashboard["uid"] for dashboard in dashboards] == [
        "compliance-overview",
        "runtime-detection",
        "grafana-overview",
    ]
    assert [item[0] for item in requested] == [
        "/api/dashboards/uid/compliance-overview",
        "/api/dashboards/uid/runtime-detection",
        "/api/dashboards/uid/grafana-overview",
    ]
    assert all(dashboard["panels"][0]["datasource"]["uid"] == "user-datasource" for dashboard in dashboards)
