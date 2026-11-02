import base64
import hashlib
import hmac
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.grafana import proxy
from app.main import app


@pytest.fixture
def proxy_client(monkeypatch, tmp_path):
    monkeypatch.setenv("JWT_SECRET", "proxy-test-secret")
    monkeypatch.setattr(proxy, "AUDIT_LOG_PATH", tmp_path / "audit.log")
    return TestClient(app)


@pytest.fixture
def mock_prometheus(monkeypatch):
    calls = []

    async def fake_forward(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        return httpx.Response(200, json={"status": "success", "data": {"result": []}})

    monkeypatch.setattr(proxy, "_forward_request", fake_forward)
    return calls


def test_valid_jwt_and_matching_cluster_id_returns_200(proxy_client, mock_prometheus):
    token = _jwt("proxy-test-secret", "proxy-user-valid", "cluster-valid")

    response = proxy_client.get(
        "/grafana/prometheus/cluster-valid/api/v1/query",
        params={"query": "up"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert mock_prometheus[0]["params"] == [("query", 'up{cluster_id="cluster-valid"}')]


def test_valid_jwt_and_mismatched_cluster_id_returns_403(proxy_client, mock_prometheus):
    token = _jwt("proxy-test-secret", "proxy-user-mismatch", "cluster-owned")

    response = proxy_client.get(
        "/grafana/prometheus/cluster-other/api/v1/query",
        params={"query": "up"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "cluster_id mismatch"
    assert mock_prometheus == []


def test_missing_jwt_returns_401(proxy_client, mock_prometheus):
    response = proxy_client.get(
        "/grafana/prometheus/cluster-missing/api/v1/query",
        params={"query": "up"},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "missing bearer token"
    assert mock_prometheus == []


def test_rate_limit_exceeded_returns_429(proxy_client, mock_prometheus):
    token = _jwt("proxy-test-secret", "proxy-user-rate-limit", "cluster-rate")
    headers = {"Authorization": f"Bearer {token}"}
    url = "/grafana/prometheus/cluster-rate/api/v1/query"

    responses = [
        proxy_client.get(url, params={"query": "up"}, headers=headers)
        for _ in range(601)
    ]

    assert all(response.status_code == 200 for response in responses[:600])
    assert responses[600].status_code == 429


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
