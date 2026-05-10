from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_healthz():
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_config_contract():
    response = client.get("/config")

    assert response.status_code == 200
    assert response.json()["grafana_url"] == "https://compliance-grafana.shares.zrok.io"


def test_ui_is_served():
    response = client.get("/ui")

    assert response.status_code == 200
    assert "Compliance AI Console" in response.text


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


def test_generate_policy_contract():
    response = client.post(
        "/generate-policy",
        json={
            "prompt": "latest 태그를 사용하는 컨테이너 이미지를 금지해줘",
            "constraint_name": "disallow-latest-tag",
            "enforcement_action": "deny",
            "excluded_namespaces": ["kube-system", "gatekeeper-system"],
            "use_llm": True,
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["policy_kind"] == "latest-tag"
    assert "ConstraintTemplate" in body["constraint_template"]
    assert "K8sDisallowLatestTag" in body["constraint"]
    assert "endswith(container.image, \":latest\")" in body["rego"]
    assert body["llm_used"] is False
    assert body["llm_review"] == ""


def test_generate_policy_default_exclusions():
    response = client.post(
        "/generate-policy",
        json={
            "prompt": "non-root 정책을 만들어줘",
            "constraint_name": "require-non-root",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert '- "kube-flannel"' in body["constraint"]
    assert '- "monitoring"' in body["constraint"]


def test_generate_mutation_policy_contract():
    response = client.post(
        "/generate-policy",
        json={
            "prompt": "resource limits를 자동 주입하는 mutation 정책을 만들어줘",
            "policy_kind": "resource-limits-mutation",
            "constraint_name": "assign-resource-limits",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["policy_kind"] == "resource-limits-mutation"
    assert body["constraint_template"] == ""
    assert body["rego"] == ""
    assert "kind: Assign" in body["constraint"]
    assert "resources.limits.cpu" in body["constraint"]


def test_analyze_violation_contract():
    response = client.post(
        "/analyze-violation",
        json={
            "cluster": "school-cloud",
            "rule": "Compliance - Shell Spawned in Container",
            "priority": "Warning",
            "output": "Shell spawned in container by root user",
            "output_fields": {
                "proc.name": "sh",
                "user.name": "root",
                "user.uid": 0,
                "container.id": "abc123",
                "k8s.ns.name": "default",
                "k8s.pod.name": "test-pod",
            },
            "tags": ["shell", "runtime"],
            "time": "2026-05-09T00:00:00Z",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["severity"] in {"low", "medium", "high"}
    assert "school-cloud" in body["summary"]
    assert body["recommended_actions"]
