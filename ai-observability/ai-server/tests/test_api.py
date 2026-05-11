from fastapi.testclient import TestClient
import httpx

from app.llm_client import LLMClient
from app.main import app
from app.analyzer import _parse_llm_incident_json
from app.policy_generator import _complete_review, _format_llm_http_error


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
    assert "Policy Generation Request" in response.text
    assert '<label id="policyPromptField" hidden>' in response.text
    assert "생성 결과 LLM 검토" in response.text
    assert "policyLoadingText" in response.text
    assert "analysisLoadingText" in response.text
    assert "정책을 생성하면 여기에 결과가 표시됩니다" in response.text
    assert "LLM 검토를 선택하면 여기에 결과가 표시됩니다" in response.text
    assert "Violation Detail" in response.text
    assert "Resource Manifest" in response.text
    assert "LLM으로 원인/수정 YAML 생성" in response.text
    assert "최근 위반 새로고침" in response.text
    assert "AI Report" in response.text
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


def test_generate_network_policy_from_ingress_prompt():
    response = client.post(
        "/generate-policy",
        json={
            "prompt": "ingress 네트워크 정책 만들어줘",
            "constraint_name": "default-deny-ingress",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["policy_kind"] == "network-policy"
    assert body["constraint_template"] == ""
    assert body["rego"] == ""
    assert "kind: NetworkPolicy" in body["constraint"]
    assert "policyTypes:\n    - Ingress" in body["constraint"]
    assert "ingress: []" in body["constraint"]
    assert "latest" not in body["constraint"]


def test_generate_policy_rejects_unsupported_prompt_with_examples():
    response = client.post(
        "/generate-policy",
        json={
            "prompt": "서비스 메시 mTLS 정책 만들어줘",
            "constraint_name": "mesh-mtls",
        },
    )

    body = response.json()

    assert response.status_code == 400
    assert "지원하지 않는 정책 요청" in body["error"]
    assert "latest 태그를 사용하는 컨테이너 이미지를 금지해줘" in body["examples"]


def test_llm_partial_review_is_completed(monkeypatch):
    def fake_review_policy(self, prompt: str) -> str:
        return "정책 의도: 기본 ingress 트래픽을 제한합니다."

    monkeypatch.setattr(LLMClient, "review_policy", fake_review_policy)
    response = client.post(
        "/generate-policy",
        headers={
            "X-LLM-Provider": "google",
            "X-LLM-API-Key": "test-user-key",
        },
        json={
            "prompt": "ingress 네트워크 정책 만들어줘",
            "constraint_name": "default-deny-ingress",
            "use_llm": True,
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["llm_used"] is True
    assert body["llm_review"].splitlines() == [
        "정책 의도: 기본 ingress 트래픽을 제한합니다.",
        "적용 범위: 생성된 NetworkPolicy의 namespace와 podSelector 대상 Pod에 적용됩니다.",
        "주의할 점: podSelector가 비어 있으면 namespace 내 모든 Pod에 적용될 수 있습니다.",
        "운영 권장사항: 테스트 네임스페이스에서 통신 영향도를 먼저 확인하세요.",
    ]


def test_llm_truncated_review_line_is_replaced():
    review = _complete_review(
        "정책 의도: 이 정책은 컨테이너 이미지에 latest 태그 사용을 금지하고, 태",
        "latest-tag",
        "deny",
        ["kube-system", "gatekeeper-system", "monitoring"],
    )

    assert review.splitlines()[0] == "정책 의도: 컨테이너 이미지의 latest 태그와 태그 누락을 차단합니다."
    assert "태\n" not in review


def test_llm_http_error_includes_provider_detail():
    request = httpx.Request("POST", "https://example.test")
    response = httpx.Response(
        503,
        request=request,
        json={
            "error": {
                "status": "UNAVAILABLE",
                "message": "The model is overloaded. Please try again later.",
            }
        },
    )
    error = httpx.HTTPStatusError("server unavailable", request=request, response=response)

    message = _format_llm_http_error(error)

    assert "HTTP 503 (UNAVAILABLE)" in message
    assert "일시적으로 응답하지 않는 상태" in message
    assert "The model is overloaded" in message


def test_analyze_violation_contract():
    payload = _analysis_payload()
    payload["resource_manifest"] = """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
"""
    response = client.post("/analyze-violation", json=payload)

    body = response.json()

    assert response.status_code == 200
    assert body["severity"] in {"low", "medium", "high"}
    assert "school-cloud" in body["summary"]
    assert body["recommended_actions"]
    assert body["root_cause"]
    assert body["remediation"]
    assert body["yaml_snippet"]
    assert body["llm_used"] is False


def test_analyze_violation_uses_llm_when_enabled(monkeypatch):
    def fake_complete_text(self, prompt: str, system_prompt: str, max_tokens: int = 1200) -> str:
        return """{
  "root_cause": "컨테이너에서 허용되지 않은 shell 실행이 감지되었습니다.",
  "remediation": "불필요한 shell 진입점을 제거하고 non-root 보안 컨텍스트를 적용하세요.",
  "yaml_snippet": "securityContext:\\n  runAsNonRoot: true"
}"""

    monkeypatch.setattr(LLMClient, "complete_text", fake_complete_text)
    payload = _analysis_payload()
    payload["resource_manifest"] = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\n"
    payload["use_llm"] = True

    response = client.post(
        "/analyze-violation",
        headers={
            "X-LLM-Provider": "google",
            "X-LLM-API-Key": "test-user-key",
        },
        json=payload,
    )
    body = response.json()

    assert response.status_code == 200
    assert body["llm_used"] is True
    assert "허용되지 않은 shell" in body["root_cause"]
    assert "runAsNonRoot" in body["yaml_snippet"]


def test_gatekeeper_event_is_collected_and_reported():
    response = client.post(
        "/gatekeeper-events",
        json={
            "constraint": "k8sdisallowlatesttag",
            "message": "container <app> uses latest image tag",
            "namespace": "default",
            "pod_name": "bad-pod",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["status"] == "recorded"
    event_id = body["event"]["id"]

    list_response = client.get("/runtime-events?limit=5")
    list_body = list_response.json()

    assert list_response.status_code == 200
    assert any(event["id"] == event_id for event in list_body["events"])

    detail_response = client.get(f"/runtime-events/{event_id}")
    detail_body = detail_response.json()

    assert detail_response.status_code == 200
    assert detail_body["source"] == "gatekeeper"
    assert detail_body["action_taken"] == "deny"

    report_response = client.get("/compliance-report")
    report_body = report_response.json()

    assert report_response.status_code == 200
    assert report_body["summary"]["total_events"] >= 1
    assert report_body["recommendations"]


def test_ingested_falco_event_is_listed_with_manifest_snapshot():
    response = client.post(
        "/ingest/falco-events",
        json={
            "cluster": "customer-a",
            "resource_manifest": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: suspicious-pod",
            "event": {
                "time": "2026-05-11T12:34:56Z",
                "rule": "Compliance - Shell Spawned in Container",
                "priority": "Warning",
                "output": "shell spawned",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "suspicious-pod",
                    "container.name": "app",
                    "container.image.repository": "docker.io/library/busybox",
                    "container.image.tag": "1.36.1",
                    "user.name": "root",
                    "proc.cmdline": "sh",
                },
            },
        },
    )
    body = response.json()

    assert response.status_code == 200
    assert body["status"] == "recorded"
    event_id = body["event"]["id"]

    list_response = client.get("/runtime-events?limit=5")
    list_body = list_response.json()

    assert list_response.status_code == 200
    assert any(event["id"] == event_id for event in list_body["events"])

    detail_response = client.get(f"/runtime-events/{event_id}")
    detail_body = detail_response.json()

    assert detail_response.status_code == 200
    assert detail_body["source"] == "falco-agent"
    assert detail_body["cluster"] == "customer-a"
    assert detail_body["namespace"] == "prod"
    assert detail_body["resource_manifest"].startswith("apiVersion: v1")


def test_resource_manifest_without_kube_env_is_clear(monkeypatch):
    monkeypatch.setattr("app.runtime_client.KUBE_API_URL", "")

    response = client.get("/resource-manifest?namespace=default&pod=test-pod")
    body = response.json()

    assert response.status_code == 200
    assert body["manifest"] == ""
    assert "Kubernetes API 환경 변수" in body["error"]


def test_parse_llm_incident_json_accepts_code_fence():
    parsed = _parse_llm_incident_json(
        """```json
{"root_cause":"원인","remediation":"수정","yaml_snippet":"kind: Pod"}
```"""
    )

    assert parsed == {
        "root_cause": "원인",
        "remediation": "수정",
        "yaml_snippet": "kind: Pod",
    }


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


def test_llm_review_normalization_does_not_cut_mid_sentence():
    client = LLMClient(provider="google", api_key="test-api-key")
    review = client._normalize_review(
        "정책 의도: latest 태그 사용을 금지합니다. "
        "적용 범위: Pod 컨테이너 이미지에 적용됩니다. "
        "주의할 점: 예외 네임스페이스를 확인해야 합니다. "
        "운영 권장사항: warn으로 검증 후 deny 전환을 권장합니다."
    )

    assert review.splitlines() == [
        "정책 의도: latest 태그 사용을 금지합니다.",
        "적용 범위: Pod 컨테이너 이미지에 적용됩니다.",
        "주의할 점: 예외 네임스페이스를 확인해야 합니다.",
        "운영 권장사항: warn으로 검증 후 deny 전환을 권장합니다.",
    ]
