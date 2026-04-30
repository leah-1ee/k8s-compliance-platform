from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_healthz():
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_classify_contract():
    response = client.post(
        "/classify",
        json={
            "rule": "Compliance - Shell Spawned in Container",
            "priority": "Warning",
            "output": "Shell spawned in container",
            "output_fields": {
                "proc.name": "bash",
                "user.name": "root",
                "user.uid": 0,
                "container.id": "abc123",
                "k8s.ns.name": "default",
            },
            "tags": ["shell", "runtime"],
            "time": "2026-04-30T10:00:00Z",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["severity"] in {"low", "medium", "high"}
    assert isinstance(body["reason"], str)
    assert 0.0 <= body["confidence"] <= 1.0
