from fastapi.testclient import TestClient

from app.llm_client import LLMClient
from app.main import app


client = TestClient(app)


def _analysis_payload() -> dict:
    return {
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
    }


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
    assert "Kubernetes Policy-as-Code 자동 생성 및 위반 분석 도구" in response.text
    assert "OpenAI (GPT)" in response.text
    assert "Anthropic (Claude)" in response.text
    assert "Google (Gemini)" in response.text
    assert "xAI (Grok)" in response.text
    assert "Use my own API key" in response.text
    assert "Your API key is used only for requests in this session" in response.text
    assert "policyLoadingText" in response.text
    assert "정책을 생성하면 여기에 결과가 표시됩니다" in response.text
    assert 'data-copy-target="templateOutput"' in response.text
    assert 'aria-label="ConstraintTemplate 복사"' in response.text


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
    assert "LLM API key" in body["llm_error"]


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
    response = client.post("/analyze-violation", json=_analysis_payload())

    body = response.json()

    assert response.status_code == 200
    assert body["severity"] in {"low", "medium", "high"}
    assert "school-cloud" in body["summary"]
    assert body["recommended_actions"]


def test_default_key_rate_limit_returns_json_error():
    limited_client = TestClient(app, client=("203.0.113.10", 50000))
    response = None
    for _ in range(6):
        response = limited_client.post("/analyze-violation", json=_analysis_payload())

    assert response is not None
    assert response.status_code == 429
    assert response.json() == {
        "error": "Rate limit exceeded. Add your own API key above to continue."
    }


def test_user_api_key_bypasses_rate_limit():
    keyed_client = TestClient(app, client=("203.0.113.11", 50000))
    response = None
    for _ in range(6):
        response = keyed_client.post(
            "/analyze-violation",
            headers={
                "X-LLM-Provider": "openai",
                "X-LLM-API-Key": "test-user-key",
            },
            json=_analysis_payload(),
        )

    assert response is not None
    assert response.status_code == 200


def test_llm_review_normalization_removes_markdown():
    client = LLMClient(provider="google", api_key="test-api-key")
    review = client._normalize_review(
        """## Kubernetes Gatekeeper 정책 검토 노트

* **정책 의도**: `latest` 태그 사용을 금지합니다.
* **적용 범위**: Pod containers를 검사합니다.
```yaml
apiVersion: templates.gatekeeper.sh/v1
```
* **주의할 점**: 예외 네임스페이스 확인이 필요합니다.
* **운영 권장사항**: warn 후 deny 전환을 권장합니다.
* **추가 내용**: 이 줄은 잘립니다.
"""
    )

    assert "**" not in review
    assert "`" not in review
    assert "apiVersion" not in review
    assert len(review.splitlines()) == 4
