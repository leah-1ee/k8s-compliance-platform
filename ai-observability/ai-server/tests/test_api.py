import json

from fastapi.testclient import TestClient
import httpx

from app.llm_client import LLMClient
from app.main import app
from app.analyzer import _parse_llm_incident_json
from app.policy_generator import _complete_review, _format_llm_http_error
from app import storage


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


def _session_for(email: str) -> str:
    user = storage.upsert_user(
        provider="dev",
        provider_subject=email,
        email=email,
    )
    return storage.create_session(user["id"])


def test_healthz():
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_config_contract():
    response = client.get("/config")

    assert response.status_code == 200
    assert response.json()["grafana_url"] == "https://compliance-grafana.shares.zrok.io"
    assert response.json()["auth_provider"] == ""


def test_ui_is_served():
    response = client.get("/ui")

    assert response.status_code == 200
    assert "KubeOwl Console" in response.text
    assert "Kubernetes Policy-as-Code 자동 생성 및 위반 분석 도구" in response.text
    assert "OpenAI (GPT)" in response.text
    assert "Anthropic (Claude)" in response.text
    assert "Google (Gemini)" in response.text
    assert "xAI (Grok)" in response.text
    assert "Use my own API key" in response.text
    assert "Google 로그인" in response.text
    assert "PDF 다운로드" in response.text
    assert "개발 로그인" in response.text
    assert "Your API key is used only for requests in this session" in response.text
    assert "Cluster Setup" in response.text
    assert "로그인 후 런타임 위반을 확인할 수 있습니다." in response.text
    assert "로그인 후 AI 리포트를 생성할 수 있습니다." in response.text
    assert "Falco Sidekick 설치 명령" in response.text
    assert "내 클러스터" in response.text
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
    assert "클러스터 구분" in response.text
    assert "레거시 response-server 이벤트 포함" in response.text
    assert "AI Report" in response.text
    assert 'data-copy-target="templateOutput"' in response.text
    assert 'aria-label="ConstraintTemplate 복사"' in response.text


def test_admin_is_served():
    response = client.get("/admin")

    assert response.status_code == 200
    assert "Compliance Admin" in response.text
    assert "클러스터 등록" in response.text
    assert "운영 요약" in response.text
    assert "사용자 목록" in response.text


def test_me_reports_anonymous_user():
    response = client.get("/me")
    body = response.json()

    assert response.status_code == 200
    assert body["authenticated"] is False
    assert body["user"] is None
    assert body["auth"]["google_configured"] is False
    assert body["auth"]["dev_enabled"] is False


def test_me_reports_authenticated_session():
    user = storage.upsert_user(
        provider="google",
        provider_subject="google-subject-1",
        email="user@example.com",
        name="Example User",
    )
    token = storage.create_session(user["id"])

    response = client.get("/me", cookies={"compliance_ai_session": token})
    body = response.json()

    assert response.status_code == 200
    assert body["authenticated"] is True
    assert body["user"]["email"] == "user@example.com"
    assert body["user"]["provider"] == "google"


def test_google_login_requires_oauth_configuration():
    response = client.get("/auth/google/login", follow_redirects=False)

    assert response.status_code == 503
    assert response.json()["error"] == "Google OAuth is not configured"


def test_dev_login_requires_explicit_enable():
    response = client.get("/auth/dev-login", follow_redirects=False)

    assert response.status_code == 503
    assert response.json()["error"] == "dev auth is disabled"


def test_dev_login_creates_session(monkeypatch):
    monkeypatch.setenv("DEV_AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_AUTH_EMAIL", "dev-user@example.test")
    monkeypatch.setenv("DEV_AUTH_NAME", "Dev User")

    login_response = client.get("/auth/dev-login", follow_redirects=False)

    assert login_response.status_code == 302
    assert login_response.headers["location"] == "/ui"
    session_cookie = login_response.cookies.get("compliance_ai_session")
    assert session_cookie

    me_response = client.get("/me", cookies={"compliance_ai_session": session_cookie})
    body = me_response.json()

    assert me_response.status_code == 200
    assert body["authenticated"] is True
    assert body["user"]["email"] == "dev-user@example.test"
    assert body["user"]["provider"] == "dev"
    client.cookies.clear()


def test_user_cluster_registration_requires_login():
    response = client.post("/api/clusters", json={"name": "login-required-cluster"})

    assert response.status_code == 401
    assert response.json()["error"] == "login required"


def test_user_cluster_registration_returns_install_command():
    user = storage.upsert_user(
        provider="dev",
        provider_subject="cluster-owner@example.test",
        email="cluster-owner@example.test",
        name="Cluster Owner",
    )
    token = storage.create_session(user["id"])

    create_response = client.post(
        "/api/clusters",
        cookies={"compliance_ai_session": token},
        json={"name": "owned-cluster-a"},
    )
    create_body = create_response.json()

    assert create_response.status_code == 200
    assert create_body["cluster"]["name"] == "owned-cluster-a"
    assert create_body["cluster"]["user_id"] == user["id"]
    assert create_body["cluster"]["kind"] == "customer"
    assert create_body["cluster"]["token"]
    assert "falcosidekick.enabled=true" in create_body["cluster"]["install_command"]

    list_response = client.get("/api/clusters", cookies={"compliance_ai_session": token})
    list_body = list_response.json()

    assert list_response.status_code == 200
    assert any(cluster["id"] == create_body["cluster"]["id"] for cluster in list_body["clusters"])
    assert all("token" not in cluster for cluster in list_body["clusters"])

    rotate_response = client.post(
        f"/api/clusters/{create_body['cluster']['id']}/rotate-token",
        cookies={"compliance_ai_session": token},
    )
    rotate_body = rotate_response.json()

    assert rotate_response.status_code == 200
    assert rotate_body["cluster"]["token"] != create_body["cluster"]["token"]
    assert "https://console.example.test/ingest/falco-events" in rotate_body["cluster"]["install_command"]


def test_cluster_names_are_scoped_per_user():
    owner_a = storage.upsert_user(
        provider="dev",
        provider_subject="same-name-a@example.test",
        email="same-name-a@example.test",
    )
    owner_b = storage.upsert_user(
        provider="dev",
        provider_subject="same-name-b@example.test",
        email="same-name-b@example.test",
    )
    session_a = storage.create_session(owner_a["id"])
    session_b = storage.create_session(owner_b["id"])

    first = client.post(
        "/api/clusters",
        cookies={"compliance_ai_session": session_a},
        json={"name": "shared-prod-name"},
    )
    second = client.post(
        "/api/clusters",
        cookies={"compliance_ai_session": session_b},
        json={"name": "shared-prod-name"},
    )
    duplicate = client.post(
        "/api/clusters",
        cookies={"compliance_ai_session": session_a},
        json={"name": "shared-prod-name"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["cluster"]["user_id"] == owner_a["id"]
    assert second.json()["cluster"]["user_id"] == owner_b["id"]
    assert duplicate.status_code == 409


def test_user_cluster_trash_and_restore():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="trash-owner@example.test",
        email="trash-owner@example.test",
    )
    other = storage.upsert_user(
        provider="dev",
        provider_subject="trash-other@example.test",
        email="trash-other@example.test",
    )
    session = storage.create_session(owner["id"])
    other_session = storage.create_session(other["id"])
    cluster = storage.create_cluster("trashable-cluster", user_id=owner["id"])

    forbidden = client.delete(
        f"/api/clusters/{cluster['id']}",
        cookies={"compliance_ai_session": other_session},
    )
    trash_response = client.delete(
        f"/api/clusters/{cluster['id']}",
        cookies={"compliance_ai_session": session},
    )
    hidden_list = client.get("/api/clusters", cookies={"compliance_ai_session": session}).json()
    trash_list = client.get(
        "/api/clusters?include_deleted=true",
        cookies={"compliance_ai_session": session},
    ).json()
    restore_response = client.post(
        f"/api/clusters/{cluster['id']}/restore",
        cookies={"compliance_ai_session": session},
    )

    assert forbidden.status_code == 404
    assert trash_response.status_code == 200
    assert trash_response.json()["cluster"]["status"] == "deleted"
    assert trash_response.json()["cluster"]["deleted_at"]
    assert all(item["id"] != cluster["id"] for item in hidden_list["clusters"])
    assert any(item["id"] == cluster["id"] for item in trash_list["clusters"])
    assert restore_response.status_code == 200
    assert restore_response.json()["cluster"]["status"] == "disabled"


def test_slack_settings_require_login():
    assert client.get("/api/slack-settings").status_code == 401
    assert client.post("/api/slack-settings", json={"webhook_url": ""}).status_code == 401
    assert client.post("/api/slack-settings/test").status_code == 401


def test_slack_settings_and_cluster_toggle(monkeypatch):
    calls = []

    class FakeSlackResponse:
        def raise_for_status(self):
            return None

    def fake_post(url, json, timeout):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeSlackResponse()

    monkeypatch.setattr("app.main.httpx.post", fake_post)
    session = _session_for("slack-settings-owner@example.test")
    cluster = client.post(
        "/api/clusters",
        cookies={"compliance_ai_session": session},
        json={"name": "slack-settings-cluster"},
    ).json()["cluster"]

    invalid = client.post(
        "/api/slack-settings",
        cookies={"compliance_ai_session": session},
        json={"webhook_url": "https://example.test/services/not-slack"},
    )
    assert invalid.status_code == 400

    save_response = client.post(
        "/api/slack-settings",
        cookies={"compliance_ai_session": session},
        json={"webhook_url": "https://hooks.slack.com/services/T000/B000/XXX"},
    )
    save_body = save_response.json()

    assert save_response.status_code == 200
    assert save_body["settings"]["configured"] is True
    assert save_body["settings"]["webhook_url"].startswith("https://hooks.slack.com/services/")

    test_response = client.post(
        "/api/slack-settings/test",
        cookies={"compliance_ai_session": session},
    )
    assert test_response.status_code == 200
    assert test_response.json()["status"] == "sent"
    assert calls[0]["timeout"] == 5
    assert "Slack 알림 테스트" in calls[0]["json"]["blocks"][0]["text"]["text"]

    toggle_response = client.post(
        f"/api/clusters/{cluster['id']}/slack",
        cookies={"compliance_ai_session": session},
        json={"enabled": False},
    )
    assert toggle_response.status_code == 200
    assert toggle_response.json()["cluster"]["slack_enabled"] is False

    list_response = client.get("/api/clusters", cookies={"compliance_ai_session": session})
    listed_cluster = next(item for item in list_response.json()["clusters"] if item["id"] == cluster["id"])
    assert listed_cluster["slack_enabled"] is False


def test_slack_notification_only_for_enabled_high_or_critical_events(monkeypatch):
    calls = []

    class FakeSlackResponse:
        def raise_for_status(self):
            return None

    def fake_post(url, json, timeout):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeSlackResponse()

    monkeypatch.setattr("app.main.httpx.post", fake_post)
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="slack-notify-owner@example.test",
        email="slack-notify-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("slack-notify-cluster", user_id=owner["id"])
    client.post(
        "/api/slack-settings",
        cookies={"compliance_ai_session": session},
        json={"webhook_url": "https://hooks.slack.com/services/T111/B222/YYY"},
    )

    warning_response = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={"event": {"time": "2026-05-14T00:00:00Z", "rule": "Warning Event", "priority": "Warning"}},
    )
    assert warning_response.status_code == 200
    assert calls == []

    critical_response = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-14T00:01:00Z",
                "rule": "Critical Event",
                "priority": "Critical",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "critical-pod",
                    "container.name": "app",
                },
            }
        },
    )
    assert critical_response.status_code == 200
    assert len(calls) == 1
    assert calls[0]["url"] == "https://hooks.slack.com/services/T111/B222/YYY"
    assert "Critical Event" in calls[0]["json"]["text"]
    assert "slack-notify-cluster/prod/critical-pod" in calls[0]["json"]["text"]

    disable_response = client.post(
        f"/api/clusters/{cluster['id']}/slack",
        cookies={"compliance_ai_session": session},
        json={"enabled": False},
    )
    assert disable_response.status_code == 200

    disabled_response = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={"event": {"time": "2026-05-14T00:02:00Z", "rule": "Disabled Event", "priority": "Critical"}},
    )
    assert disabled_response.status_code == 200
    assert len(calls) == 1


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
    assert body["severity_explanation"]
    assert body["recommended_actions"]
    assert body["root_cause"]
    assert "Compliance - Shell Spawned in Container" in body["root_cause"]
    assert body["recommended_fix"]
    assert body["remediation"]
    assert body["yaml_snippet"]
    assert body["llm_used"] is False


def test_analyze_violation_falls_back_without_llm_key():
    payload = _analysis_payload()
    payload["use_llm"] = True

    response = client.post("/analyze-violation", json=payload)
    body = response.json()

    assert response.status_code == 200
    assert body["llm_used"] is False
    assert "LLM API key" in body["llm_error"]
    assert "Falco priority" in body["severity_explanation"]
    assert "기본 분석" in body["llm_error"]
    assert body["recommended_fix"]
    assert body["yaml_snippet"]


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
    assert "불필요한 shell" in body["recommended_fix"]
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
    assert event_id.startswith("gk-")
    assert body["event"]["source"] == "gatekeeper"
    assert body["event"]["action_taken"] == "deny"


def test_ingested_falco_event_is_listed_with_manifest_snapshot():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="customer-a-owner@example.test",
        email="customer-a-owner@example.test",
    )
    other_owner = storage.upsert_user(
        provider="dev",
        provider_subject="customer-a-other@example.test",
        email="customer-a-other@example.test",
    )
    session = storage.create_session(owner["id"])
    other_session = storage.create_session(other_owner["id"])
    cluster = storage.create_cluster("customer-a", user_id=owner["id"])

    response = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
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

    list_response = client.get("/runtime-events?limit=5", cookies={"compliance_ai_session": session})
    list_body = list_response.json()

    assert list_response.status_code == 200
    assert any(event["id"] == event_id for event in list_body["events"])

    customer_list_response = client.get(
        "/runtime-events?limit=20&cluster_kind=customer",
        cookies={"compliance_ai_session": session},
    )
    customer_list_body = customer_list_response.json()
    assert customer_list_response.status_code == 200
    assert any(event["id"] == event_id for event in customer_list_body["events"])

    demo_list_response = client.get(
        "/runtime-events?limit=20&cluster_kind=demo",
        cookies={"compliance_ai_session": session},
    )
    demo_list_body = demo_list_response.json()
    assert demo_list_response.status_code == 200
    assert all(event["id"] != event_id for event in demo_list_body["events"])

    detail_response = client.get(
        f"/runtime-events/{event_id}",
        cookies={"compliance_ai_session": session},
    )
    detail_body = detail_response.json()

    assert detail_response.status_code == 200
    assert detail_body["source"] == "sidekick"
    assert detail_body["cluster_id"] == cluster["id"]
    assert detail_body["cluster"] == "customer-a"
    assert detail_body["cluster_kind"] == "customer"
    assert detail_body["namespace"] == "prod"
    assert detail_body["resource_manifest"].startswith("apiVersion: v1")

    hidden_detail = client.get(
        f"/runtime-events/{event_id}",
        cookies={"compliance_ai_session": other_session},
    )
    assert hidden_detail.status_code == 404


def test_ingested_manifest_snapshot_accepts_structured_payload():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="structured-manifest-owner@example.test",
        email="structured-manifest-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("structured-manifest-cluster", user_id=owner["id"])

    response = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-12T02:00:00Z",
                "rule": "Structured Manifest Event",
                "priority": "Warning",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "structured-pod",
                },
                "resource_manifest": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "structured-pod", "namespace": "prod"},
                },
            },
        },
    )
    event = response.json()["event"]

    assert response.status_code == 200
    stored = client.get(
        f"/runtime-events/{event['id']}",
        cookies={"compliance_ai_session": session},
    ).json()

    manifest = json.loads(stored["resource_manifest"])
    assert manifest["apiVersion"] == "v1"
    assert manifest["kind"] == "Pod"
    assert manifest["metadata"]["name"] == "structured-pod"


def test_runtime_events_exclude_infra_before_limit():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="runtime-filter-owner@example.test",
        email="runtime-filter-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("runtime-filter-cluster", user_id=owner["id"])

    client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-18T10:00:00Z",
                "rule": "Newest Infra Event",
                "priority": "Warning",
                "output_fields": {
                    "k8s.ns.name": "kube-system",
                    "k8s.pod.name": "infra-pod",
                },
            },
        },
    )
    client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-18T09:00:00Z",
                "rule": "Older Workload Event",
                "priority": "Warning",
                "output_fields": {
                    "k8s.ns.name": "default",
                    "k8s.pod.name": "workload-pod",
                },
            },
        },
    )

    unfiltered = client.get(
        "/runtime-events?limit=1",
        cookies={"compliance_ai_session": session},
    ).json()
    filtered_response = client.get(
        "/runtime-events?limit=1&exclude_infra=true",
        cookies={"compliance_ai_session": session},
    )
    filtered = filtered_response.json()

    assert unfiltered["events"][0]["rule"] == "Newest Infra Event"
    assert filtered_response.status_code == 200
    assert len(filtered["events"]) == 1
    assert filtered["events"][0]["rule"] == "Older Workload Event"
    assert filtered["events"][0]["namespace"] == "default"


def test_runtime_analysis_uses_stored_manifest_snapshot():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="analysis-manifest-owner@example.test",
        email="analysis-manifest-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("analysis-manifest-cluster", user_id=owner["id"])

    event = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "resource_manifest": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: analysis-pod\n  namespace: prod\n",
            "event": {
                "time": "2026-05-12T02:05:00Z",
                "rule": "Analysis Manifest Event",
                "priority": "Warning",
                "output": "shell spawned",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "analysis-pod",
                    "container.name": "app",
                },
            },
        },
    ).json()["event"]

    response = client.post(
        f"/analyze-runtime-event/{event['id']}",
        cookies={"compliance_ai_session": session},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["llm_used"] is False
    assert body["llm_error"] == ""
    assert body["yaml_snippet"]


def test_malformed_and_oversized_manifest_payloads_are_ignored_safely():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="bad-manifest-owner@example.test",
        email="bad-manifest-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("bad-manifest-cluster", user_id=owner["id"])

    malformed_event = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "resource_manifest": 12345,
            "event": {
                "time": "2026-05-12T02:10:00Z",
                "rule": "Malformed Manifest Event",
                "priority": "Warning",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "malformed-pod",
                },
            },
        },
    ).json()["event"]
    oversized_event = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "resource_manifest": "x" * 210_000,
            "event": {
                "time": "2026-05-12T02:11:00Z",
                "rule": "Oversized Manifest Event",
                "priority": "Warning",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "oversized-pod",
                },
            },
        },
    ).json()["event"]

    malformed_detail = client.get(
        f"/runtime-events/{malformed_event['id']}",
        cookies={"compliance_ai_session": session},
    ).json()
    oversized_detail = client.get(
        f"/runtime-events/{oversized_event['id']}",
        cookies={"compliance_ai_session": session},
    ).json()
    guidance = client.get(
        f"/resource-manifest?event_id={oversized_event['id']}",
        cookies={"compliance_ai_session": session},
    ).json()

    assert malformed_detail["resource_manifest"] == ""
    assert oversized_detail["resource_manifest"] == ""
    assert guidance["manifest"] == ""
    assert guidance["kubectl_command"] == "kubectl get pod oversized-pod -n prod -o yaml"


def test_ingested_demo_cluster_event_is_tagged_and_filterable(monkeypatch):
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="demo-cluster-owner@example.test",
        email="demo-cluster-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("task-demo-cluster", user_id=owner["id"])
    monkeypatch.setenv("DEMO_CLUSTER_NAMES", "task-demo-cluster")

    response = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-12T00:01:00Z",
                "rule": "Demo Cluster Event",
                "priority": "Critical",
            },
        },
    )
    body = response.json()

    assert response.status_code == 200
    assert body["event"]["cluster_id"] == cluster["id"]
    assert body["event"]["cluster"] == "task-demo-cluster"
    assert body["event"]["cluster_kind"] == "demo"
    assert storage.get_cluster(cluster["id"])["kind"] == "demo"

    demo_response = client.get(
        "/runtime-events?limit=20&cluster_kind=demo",
        cookies={"compliance_ai_session": session},
    )
    customer_response = client.get(
        "/runtime-events?limit=20&cluster_kind=customer",
        cookies={"compliance_ai_session": session},
    )
    cluster_response = client.get(
        "/runtime-events?limit=20&cluster=task-demo-cluster&source=sidekick",
        cookies={"compliance_ai_session": session},
    )
    wrong_source_response = client.get(
        "/runtime-events?limit=20&cluster=task-demo-cluster&source=gatekeeper",
        cookies={"compliance_ai_session": session},
    )

    assert demo_response.status_code == 200
    assert customer_response.status_code == 200
    assert cluster_response.status_code == 200
    assert wrong_source_response.status_code == 200
    event_id = body["event"]["id"]
    assert event_id in {event["id"] for event in demo_response.json()["events"]}
    assert event_id not in {event["id"] for event in customer_response.json()["events"]}
    assert event_id in {event["id"] for event in cluster_response.json()["events"]}
    assert event_id not in {event["id"] for event in wrong_source_response.json()["events"]}


def test_runtime_events_are_scoped_to_logged_in_users():
    owner_a = storage.upsert_user(
        provider="dev",
        provider_subject="runtime-owner-a@example.test",
        email="runtime-owner-a@example.test",
    )
    owner_b = storage.upsert_user(
        provider="dev",
        provider_subject="runtime-owner-b@example.test",
        email="runtime-owner-b@example.test",
    )
    session_a = storage.create_session(owner_a["id"])
    session_b = storage.create_session(owner_b["id"])
    cluster_a = storage.create_cluster("runtime-owned-a", user_id=owner_a["id"])
    cluster_b = storage.create_cluster("runtime-owned-b", user_id=owner_b["id"])

    event_a = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster_a['token']}"},
        json={
            "event": {
                "time": "2026-05-12T00:00:00Z",
                "rule": "Owner A Event",
                "priority": "Warning",
            },
        },
    ).json()["event"]
    event_b = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster_b['token']}"},
        json={
            "event": {
                "time": "2026-05-12T00:00:01Z",
                "rule": "Owner B Event",
                "priority": "Warning",
            },
        },
    ).json()["event"]

    list_a = client.get("/runtime-events?limit=20", cookies={"compliance_ai_session": session_a}).json()
    list_b = client.get("/runtime-events?limit=20", cookies={"compliance_ai_session": session_b}).json()

    ids_a = {event["id"] for event in list_a["events"]}
    ids_b = {event["id"] for event in list_b["events"]}
    assert event_a["id"] in ids_a
    assert event_b["id"] not in ids_a
    assert event_b["id"] in ids_b
    assert event_a["id"] not in ids_b

    hidden_detail = client.get(
        f"/runtime-events/{event_b['id']}",
        cookies={"compliance_ai_session": session_a},
    )
    assert hidden_detail.status_code == 404


def test_resource_manifest_guidance_is_scoped_to_event_owner():
    owner_a = storage.upsert_user(
        provider="dev",
        provider_subject="manifest-owner-a@example.test",
        email="manifest-owner-a@example.test",
    )
    owner_b = storage.upsert_user(
        provider="dev",
        provider_subject="manifest-owner-b@example.test",
        email="manifest-owner-b@example.test",
    )
    session_a = storage.create_session(owner_a["id"])
    session_b = storage.create_session(owner_b["id"])
    cluster_a = storage.create_cluster("manifest-owned-a", user_id=owner_a["id"])

    event = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster_a['token']}"},
        json={
            "event": {
                "time": "2026-05-12T01:00:00Z",
                "rule": "Manifest Guidance Event",
                "priority": "Warning",
                "output_fields": {
                    "k8s.ns.name": "prod",
                    "k8s.pod.name": "suspicious-pod",
                    "container.name": "app",
                },
            },
        },
    ).json()["event"]

    response = client.get(
        f"/resource-manifest?event_id={event['id']}",
        cookies={"compliance_ai_session": session_a},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["manifest"] == ""
    assert body["kubectl_command"] == "kubectl get pod suspicious-pod -n prod -o yaml"
    assert "사용자 클러스터" in body["manifest_guidance"]
    assert body["resource_context"] == {
        "cluster": "manifest-owned-a",
        "namespace": "prod",
        "pod": "suspicious-pod",
        "container": "app",
    }

    hidden_response = client.get(
        f"/resource-manifest?event_id={event['id']}",
        cookies={"compliance_ai_session": session_b},
    )
    assert hidden_response.status_code == 404


def test_resource_manifest_guidance_degrades_when_fields_are_missing():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="manifest-missing-fields@example.test",
        email="manifest-missing-fields@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("manifest-missing-fields", user_id=owner["id"])

    event = client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-12T01:05:00Z",
                "rule": "Manifest Missing Fields Event",
                "priority": "Warning",
            },
        },
    ).json()["event"]

    response = client.get(
        f"/resource-manifest?event_id={event['id']}",
        cookies={"compliance_ai_session": session},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["manifest"] == ""
    assert body["kubectl_command"] == ""
    assert "namespace와 pod 이름" in body["error"]
    assert body["resource_context"]["cluster"] == "manifest-missing-fields"


def test_runtime_events_skip_legacy_response_server_by_default(monkeypatch):
    calls = []

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("legacy response-server should be opt-in")

    monkeypatch.setattr("app.runtime_client.httpx.get", fake_get)

    response = client.get(
        "/runtime-events?limit=1",
        cookies={"compliance_ai_session": _session_for("legacy-skip@example.test")},
    )
    body = response.json()

    assert response.status_code == 200
    assert calls == []
    assert body["source_status"]["response_server"] == "skipped"


def test_runtime_features_require_login():
    assert client.get("/runtime-events?limit=1").status_code == 401
    assert client.get("/runtime-events/missing-event").status_code == 401
    assert client.get("/resource-manifest?namespace=default&pod=test-pod").status_code == 401
    assert client.post("/analyze-runtime-event/missing-event").status_code == 401
    assert client.get("/dashboard-summary").status_code == 401
    assert client.get("/compliance-report").status_code == 401
    assert client.post("/api/clusters/missing-cluster/policy-applies", json={"manifest": "kind: Pod"}).status_code == 401


def test_dashboard_summary_uses_live_counts(monkeypatch):
    monkeypatch.setattr(
        "app.runtime_client._count_gatekeeper_constraints",
        lambda: {"count": 7, "source": "kubernetes", "error": ""},
    )
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="dashboard-summary-owner@example.test",
        email="dashboard-summary-owner@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("dashboard-summary-cluster", user_id=owner["id"])
    storage.mark_cluster_seen(cluster["id"], "2026-05-18T10:00:00Z")
    client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-18T09:30:00Z",
                "rule": "Dashboard Summary Event",
                "priority": "Warning",
            },
        },
    )

    response = client.get("/dashboard-summary", cookies={"compliance_ai_session": session})
    body = response.json()

    assert response.status_code == 200
    assert body["active_policies"] == 7
    assert body["active_policies_source"] == "kubernetes"
    assert body["runtime_events"] >= 1
    assert body["recent_violations"] >= 1
    assert body["last_sync"] == "2026-05-18T10:00:00Z"


def test_policy_apply_rejects_cluster_owned_by_other_user():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="policy-apply-owner@example.test",
        email="policy-apply-owner@example.test",
    )
    other = storage.upsert_user(
        provider="dev",
        provider_subject="policy-apply-other@example.test",
        email="policy-apply-other@example.test",
    )
    other_session = storage.create_session(other["id"])
    cluster = storage.create_cluster("policy-apply-owned", user_id=owner["id"])

    response = client.post(
        f"/api/clusters/{cluster['id']}/policy-applies",
        cookies={"compliance_ai_session": other_session},
        json={"manifest": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: blocked\n"},
    )

    assert response.status_code == 404
    assert response.json()["error"] == "cluster not found"


def test_policy_apply_rejects_disabled_and_deleted_clusters():
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="policy-apply-status@example.test",
        email="policy-apply-status@example.test",
    )
    session = storage.create_session(owner["id"])
    disabled = storage.create_cluster("policy-apply-disabled", user_id=owner["id"])
    deleted = storage.create_cluster("policy-apply-deleted", user_id=owner["id"])
    storage.disable_cluster(disabled["id"])
    storage.trash_cluster(deleted["id"], owner["id"])

    disabled_response = client.post(
        f"/api/clusters/{disabled['id']}/policy-applies",
        cookies={"compliance_ai_session": session},
        json={"manifest": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: disabled\n"},
    )
    deleted_response = client.post(
        f"/api/clusters/{deleted['id']}/policy-applies",
        cookies={"compliance_ai_session": session},
        json={"manifest": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: deleted\n"},
    )

    assert disabled_response.status_code == 409
    assert deleted_response.status_code == 409


def test_policy_apply_orders_multi_document_yaml_with_fallback(monkeypatch):
    monkeypatch.delenv("POLICY_APPLY_ENABLED", raising=False)
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="policy-apply-order@example.test",
        email="policy-apply-order@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("policy-apply-order", user_id=owner["id"])
    manifest = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: default
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-owner
---
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
"""

    response = client.post(
        f"/api/clusters/{cluster['id']}/policy-applies",
        cookies={"compliance_ai_session": session},
        json={"manifest": manifest},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["status"] == "not_configured"
    assert [item["kind"] for item in body["resources"]] == [
        "ConstraintTemplate",
        "K8sRequiredLabels",
        "NetworkPolicy",
    ]
    assert "kubectl apply --dry-run=server" in body["fallback"]["combined_command"]
    assert body["history"]["status"] == "not_configured"


def test_policy_apply_dry_run_failure_prevents_apply_and_records_history(monkeypatch):
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="policy-apply-dryrun@example.test",
        email="policy-apply-dryrun@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("policy-apply-dryrun", user_id=owner["id"])

    def fake_apply(manifest, cluster):
        return {
            "status": "dry_run_failed",
            "error": "dry-run 검증 실패로 실제 apply를 실행하지 않았습니다.",
            "policy_type": "gatekeeper_constraint",
            "policy_name": "require-owner",
            "resources": [
                {
                    "order": 1,
                    "api_version": "constraints.gatekeeper.sh/v1beta1",
                    "kind": "K8sRequiredLabels",
                    "name": "require-owner",
                    "namespace": "",
                    "dry_run_status": "failed",
                    "apply_status": "skipped",
                    "error": "spec.match is required",
                }
            ],
            "fallback": {},
        }

    monkeypatch.setattr("app.main.apply_policy_manifest", fake_apply)

    response = client.post(
        f"/api/clusters/{cluster['id']}/policy-applies",
        cookies={"compliance_ai_session": session},
        json={"manifest": "apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sRequiredLabels\nmetadata:\n  name: require-owner\n"},
    )
    body = response.json()
    history = storage.list_policy_apply_history(user_id=owner["id"], cluster_id=cluster["id"], limit=1)[0]

    assert response.status_code == 200
    assert body["resources"][0]["apply_status"] == "skipped"
    assert body["history"]["status"] == "dry_run_failed"
    assert history["status"] == "dry_run_failed"
    assert history["policy_name"] == "require-owner"


def test_successful_gatekeeper_policy_apply_is_recorded(monkeypatch):
    owner = storage.upsert_user(
        provider="dev",
        provider_subject="policy-apply-success@example.test",
        email="policy-apply-success@example.test",
    )
    session = storage.create_session(owner["id"])
    cluster = storage.create_cluster("policy-apply-success", user_id=owner["id"])

    def fake_apply(manifest, cluster):
        return {
            "status": "applied",
            "error": "",
            "policy_type": "gatekeeper_constraint",
            "policy_name": "require-owner",
            "resources": [
                {
                    "order": 1,
                    "api_version": "templates.gatekeeper.sh/v1beta1",
                    "kind": "ConstraintTemplate",
                    "name": "k8srequiredlabels",
                    "namespace": "",
                    "dry_run_status": "success",
                    "apply_status": "success",
                    "error": "",
                },
                {
                    "order": 2,
                    "api_version": "constraints.gatekeeper.sh/v1beta1",
                    "kind": "K8sRequiredLabels",
                    "name": "require-owner",
                    "namespace": "",
                    "dry_run_status": "success",
                    "apply_status": "success",
                    "error": "",
                },
            ],
            "fallback": {},
        }

    monkeypatch.setattr("app.main.apply_policy_manifest", fake_apply)

    response = client.post(
        f"/api/clusters/{cluster['id']}/policy-applies",
        cookies={"compliance_ai_session": session},
        json={"manifest": "apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sRequiredLabels\nmetadata:\n  name: require-owner\n"},
    )
    body = response.json()
    history = storage.list_policy_apply_history(user_id=owner["id"], cluster_id=cluster["id"], limit=1)[0]

    assert response.status_code == 200
    assert body["status"] == "applied"
    assert body["history"]["status"] == "applied"
    assert history["policy_type"] == "gatekeeper_constraint"
    assert history["policy_name"] == "require-owner"
    assert history["result"]["resources"][1]["apply_status"] == "success"


def test_compliance_report_uses_llm_when_configured(monkeypatch):
    calls = []

    def fake_complete_text(self, prompt, system_prompt, max_tokens=1200):
        calls.append(
            {
                "provider": self.provider,
                "prompt": prompt,
                "system_prompt": system_prompt,
                "max_tokens": max_tokens,
            }
        )
        return "High 이벤트를 우선 확인하고 namespace별 반복 위반을 줄이세요."

    monkeypatch.setattr(LLMClient, "complete_text", fake_complete_text)
    session = _session_for("report-llm@example.test")

    response = client.get(
        "/compliance-report",
        cookies={"compliance_ai_session": session},
        headers={"X-LLM-Provider": "google", "X-LLM-API-Key": "session-key-123"},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["llm_used"] is True
    assert "High 이벤트" in body["llm_summary"]
    assert body["llm_error"] == ""
    assert calls[0]["provider"] == "google"
    assert "컴플라이언스 리포트" in calls[0]["prompt"]
    assert calls[0]["max_tokens"] == 900


def test_ingest_rejects_missing_cluster_token():
    response = client.post(
        "/ingest/falco-events",
        json={
            "rule": "Compliance - Shell Spawned in Container",
            "priority": "Warning",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"] == "valid cluster token required"


def test_admin_cluster_lifecycle():
    unauthorized = client.get("/admin/api/clusters")
    assert unauthorized.status_code == 401

    create_response = client.post(
        "/admin/api/clusters",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "lifecycle-cluster"},
    )
    create_body = create_response.json()

    assert create_response.status_code == 200
    assert create_body["cluster"]["name"] == "lifecycle-cluster"
    assert create_body["cluster"]["kind"] == "customer"
    assert create_body["cluster"]["token"]
    assert "falcosidekick.enabled=true" in create_body["cluster"]["install_command"]
    assert "https://console.example.test/ingest/falco-events" in create_body["cluster"]["install_command"]

    cluster_id = create_body["cluster"]["id"]
    old_token = create_body["cluster"]["token"]

    list_response = client.get(
        "/admin/api/clusters",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    list_body = list_response.json()

    assert list_response.status_code == 200
    assert any(cluster["id"] == cluster_id for cluster in list_body["clusters"])
    assert all("token" not in cluster for cluster in list_body["clusters"])

    rotate_response = client.post(
        f"/admin/api/clusters/{cluster_id}/rotate-token",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    rotate_body = rotate_response.json()

    assert rotate_response.status_code == 200
    assert rotate_body["cluster"]["token"] != old_token

    mark_demo_response = client.post(
        f"/admin/api/clusters/{cluster_id}/mark-demo",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert mark_demo_response.status_code == 200
    assert mark_demo_response.json()["cluster"]["kind"] == "demo"

    mark_customer_response = client.post(
        f"/admin/api/clusters/{cluster_id}/mark-customer",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert mark_customer_response.status_code == 200
    assert mark_customer_response.json()["cluster"]["kind"] == "customer"

    disable_response = client.post(
        f"/admin/api/clusters/{cluster_id}/disable",
        headers={"X-Admin-Token": "test-admin-token"},
    )

    assert disable_response.status_code == 200
    assert disable_response.json()["cluster"]["status"] == "disabled"


def test_admin_dashboard_lists_users_and_event_counts():
    user = storage.upsert_user(
        provider="dev",
        provider_subject="admin-dashboard-user@example.test",
        email="admin-dashboard-user@example.test",
        name="Admin Dashboard User",
    )
    cluster = storage.create_cluster("admin-dashboard-cluster", user_id=user["id"])
    client.post(
        "/ingest/falco-events",
        headers={"Authorization": f"Bearer {cluster['token']}"},
        json={
            "event": {
                "time": "2026-05-13T00:00:00Z",
                "rule": "Admin Dashboard Event",
                "priority": "Warning",
            },
        },
    )

    unauthorized = client.get("/admin/api/users")
    assert unauthorized.status_code == 401

    users_response = client.get(
        "/admin/api/users",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    users_body = users_response.json()

    assert users_response.status_code == 200
    listed_user = next(item for item in users_body["users"] if item["id"] == user["id"])
    assert listed_user["email"] == "admin-dashboard-user@example.test"
    assert listed_user["cluster_count"] == 1
    assert listed_user["active_cluster_count"] == 1
    assert listed_user["event_count"] == 1
    assert listed_user["last_seen_at"] == "2026-05-13T00:00:00Z"

    clusters_response = client.get(
        "/admin/api/clusters",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    clusters_body = clusters_response.json()

    assert clusters_response.status_code == 200
    listed_cluster = next(item for item in clusters_body["clusters"] if item["id"] == cluster["id"])
    assert listed_cluster["user_email"] == "admin-dashboard-user@example.test"
    assert listed_cluster["event_count"] == 1

    user_clusters_response = client.get(
        f"/admin/api/users/{user['id']}/clusters",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    user_clusters_body = user_clusters_response.json()

    assert user_clusters_response.status_code == 200
    assert user_clusters_body["user"]["email"] == "admin-dashboard-user@example.test"
    assert [item["id"] for item in user_clusters_body["clusters"]] == [cluster["id"]]


def test_resource_manifest_direct_params_return_kubectl_guidance():
    response = client.get(
        "/resource-manifest?namespace=default&pod=test-pod",
        cookies={"compliance_ai_session": _session_for("manifest-user@example.test")},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["manifest"] == ""
    assert body["kubectl_command"] == "kubectl get pod test-pod -n default -o yaml"
    assert body["error"] == ""


def test_parse_llm_incident_json_accepts_code_fence():
    parsed = _parse_llm_incident_json(
        """```json
{"root_cause":"원인","remediation":"수정","yaml_snippet":"kind: Pod"}
```"""
    )

    assert parsed == {
        "severity_explanation": "",
        "root_cause": "원인",
        "recommended_fix": "수정",
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
