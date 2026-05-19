import base64
import hashlib
import hmac
import json
import time

import httpx
from fastapi.testclient import TestClient

from app.grafana import proxy
from app.grafana.promql_inject import PromQLInjectionError, inject_cluster_label
from app.main import app


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
