import json
import re

import httpx

from app.classifier import classify_event
from app.llm_client import LLMClient
from app.schemas import ViolationAnalysisRequest, ViolationAnalysisResponse
from app.policy_generator import _format_llm_http_error


ACTION_BY_SEVERITY = {
    "high": [
        "해당 Pod 격리 또는 삭제 검토",
        "서비스 계정 권한과 최근 배포 이력 확인",
        "동일 네임스페이스 반복 이벤트 확인",
    ],
    "medium": [
        "Pod 실행 사용자와 컨테이너 명령 확인",
        "정책 예외 필요 여부 검토",
        "동일 rule 반복 발생 여부 확인",
    ],
    "low": [
        "이벤트 맥락 확인",
        "오탐 가능성 검토",
        "필요 시 정책 임계값 조정",
    ],
}
SENSITIVE_KEY_RE = re.compile(
    r"(secret|token|password|passwd|api[_-]?key|authorization|cookie|credential|webhook)",
    re.IGNORECASE,
)
PRIVATE_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b"
)
REGISTRY_HOST_RE = re.compile(r"\b((?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?)/", re.IGNORECASE)
PUBLIC_REGISTRY_HOSTS = {
    "docker.io",
    "gcr.io",
    "ghcr.io",
    "quay.io",
    "registry.k8s.io",
}


def analyze_violation(
    payload: ViolationAnalysisRequest,
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> ViolationAnalysisResponse:
    # 위반 이벤트 분석
    classification = classify_event(payload)
    manifest_context = _manifest_context(payload.resource_manifest)
    namespace = payload.output_fields.get("k8s.ns.name") or manifest_context.get("namespace", "unknown")
    pod = payload.output_fields.get("k8s.pod.name") or manifest_context.get("name", "unknown")
    proc = payload.output_fields.get("proc.name") or payload.output_fields.get(
        "proc.cmdline",
        "unknown",
    )
    user = payload.output_fields.get("user.name", "unknown")
    cluster = payload.cluster or "current-cluster"
    summary = (
        f"{cluster} 클러스터의 {namespace}/{pod} 대상 이벤트가 "
        f"{classification.severity} 심각도로 분류되었습니다."
    )
    severity_explanation = _severity_explanation(
        classification.severity,
        classification.reason,
        payload.priority,
    )
    root_cause = _root_cause(payload, namespace, pod, proc, user)
    remediation = _remediation(classification.severity, namespace, pod)
    recommended_fix = _recommended_fix(classification.severity, namespace, pod)
    yaml_snippet = _yaml_snippet(classification.severity, namespace, pod, manifest_context.get("app_label", ""))
    llm_used = False
    llm_error = ""
    if payload.use_llm:
        llm_result, llm_error = _safe_llm_incident_analysis(
            payload,
            classification.severity,
            classification.reason,
            llm_provider,
            llm_api_key,
        )
        if llm_result:
            severity_explanation = (
                llm_result.get("severity_explanation") or severity_explanation
            )
            root_cause = llm_result.get("root_cause") or root_cause
            recommended_fix = llm_result.get("recommended_fix") or recommended_fix
            remediation = llm_result.get("remediation") or recommended_fix or remediation
            yaml_snippet = llm_result.get("yaml_snippet") or yaml_snippet
            llm_used = True
    return ViolationAnalysisResponse(
        severity=classification.severity,
        reason=classification.reason,
        confidence=classification.confidence,
        summary=summary,
        severity_explanation=severity_explanation,
        recommended_actions=ACTION_BY_SEVERITY[classification.severity],
        root_cause=root_cause,
        recommended_fix=recommended_fix,
        remediation=remediation,
        yaml_snippet=yaml_snippet,
        llm_used=llm_used,
        llm_error=llm_error,
    )


def _safe_llm_incident_analysis(
    payload: ViolationAnalysisRequest,
    severity: str,
    reason: str,
    llm_provider: str | None,
    llm_api_key: str | None,
) -> tuple[dict[str, str], str]:
    client = LLMClient(provider=llm_provider, api_key=llm_api_key)
    if not client.configured:
        return {}, "LLM API key가 설정되어 있지 않아 기본 분석을 표시합니다."
    try:
        text = client.complete_text(
            _build_incident_prompt(payload, severity, reason),
            (
                "You are a Kubernetes runtime security analyst. "
                "Analyze Falco or Gatekeeper violations using the event log and manifest. "
                "Return only valid compact JSON with keys severity_explanation, root_cause, "
                "recommended_fix, remediation, yaml_snippet. "
                "yaml_snippet must be a Kubernetes YAML string."
            ),
            max_tokens=1200,
        )
        parsed = _parse_llm_incident_json(text)
        if parsed:
            return parsed, ""
        return {}, "LLM 응답 형식이 올바르지 않아 기본 분석을 표시합니다."
    except httpx.HTTPStatusError as error:
        return {}, f"{_format_llm_http_error(error)} 기본 분석을 표시합니다."
    except httpx.TimeoutException:
        return {}, "LLM 연결 시간 초과로 기본 분석을 표시합니다."
    except httpx.RequestError:
        return {}, "LLM 연결 실패로 기본 분석을 표시합니다."
    except Exception:
        return {}, "LLM 처리 실패로 기본 분석을 표시합니다."


def _build_incident_prompt(payload: ViolationAnalysisRequest, severity: str, reason: str) -> str:
    event = {
        "cluster": payload.cluster,
        "rule": payload.rule,
        "priority": payload.priority,
        "output": payload.output,
        "output_fields": payload.output_fields,
        "tags": payload.tags,
        "time": payload.time,
        "severity": severity,
        "classification_reason": reason,
    }
    redacted_event = _redact_for_llm(event)
    redacted_manifest = _redact_manifest_for_llm(payload.resource_manifest)
    return (
        "다음 Kubernetes 보안 위반 이벤트를 분석하세요.\n"
        "1. 심각도 판단 근거를 한국어로 작성하세요.\n"
        "2. 자연어 원인 설명을 한국어로 작성하세요.\n"
        "3. 운영자가 수행할 수정 방법을 한국어로 작성하세요.\n"
        "4. 적용 가능한 수정 YAML 스니펫을 작성하세요.\n\n"
        f"위반 이벤트 JSON:\n{json.dumps(redacted_event, ensure_ascii=False, indent=2)}\n\n"
        f"관련 리소스 매니페스트:\n{redacted_manifest or '(not provided)'}"
    )


def _redact_for_llm(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if key_lower in {"by_namespace", "namespaces"} and isinstance(item, dict):
                redacted[key] = {"[REDACTED_NAMESPACE]": sum(int(count or 0) for count in item.values())}
            elif SENSITIVE_KEY_RE.search(key_text):
                redacted[key] = "[REDACTED_SECRET]"
            elif key_lower in {"k8s.ns.name", "namespace"} or key_lower.endswith(".namespace"):
                redacted[key] = "[REDACTED_NAMESPACE]"
            else:
                redacted[key] = _redact_for_llm(item)
        return redacted
    if isinstance(value, list):
        return [_redact_for_llm(item) for item in value]
    if isinstance(value, str):
        return _redact_string_for_llm(value)
    return value


def _redact_string_for_llm(value: str) -> str:
    redacted = PRIVATE_IP_RE.sub("[REDACTED_PRIVATE_IP]", value)
    redacted = re.sub(
        r"(?i)\b(token|password|passwd|secret|api[_-]?key|authorization|cookie|webhook)\s*[:= ]\s*[^,\s;]+",
        lambda match: f"{match.group(1)} [REDACTED_SECRET]",
        redacted,
    )

    def replace_registry(match: re.Match[str]) -> str:
        host = match.group(1)
        normalized_host = host.split(":", 1)[0].lower()
        if normalized_host in PUBLIC_REGISTRY_HOSTS:
            return match.group(0)
        return "[REDACTED_REGISTRY]/"

    return REGISTRY_HOST_RE.sub(replace_registry, redacted)


def _redact_manifest_for_llm(value: str) -> str:
    if not value:
        return ""
    redacted = _redact_string_for_llm(value)
    redacted = re.sub(r"(?im)^(\s*namespace:\s*).+$", r"\1[REDACTED_NAMESPACE]", redacted)
    redacted = re.sub(
        r"(?ims)^(\s*env:\s*\n(?:\s*-\s*name:\s*[^\n]+\n\s*value:\s*).+?)(?=\n\s*-\s*name:|\n\S|\Z)",
        lambda match: re.sub(r"(?im)^(\s*value:\s*).+$", r"\1[REDACTED_ENV_VALUE]", match.group(0)),
        redacted,
    )
    redacted = re.sub(
        r"(?im)^(\s*(?:token|password|secret|api[_-]?key|authorization|cookie|webhook)[\w.-]*:\s*).+$",
        r"\1[REDACTED_SECRET]",
        redacted,
    )
    return redacted


def _parse_llm_incident_json(value: str) -> dict[str, str]:
    cleaned = value.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    remediation = str(data.get("remediation", "")).strip()
    recommended_fix = str(data.get("recommended_fix", "")).strip() or remediation
    parsed = {
        "severity_explanation": str(data.get("severity_explanation", "")).strip(),
        "root_cause": str(data.get("root_cause", "")).strip(),
        "recommended_fix": recommended_fix,
        "remediation": remediation or recommended_fix,
        "yaml_snippet": str(data.get("yaml_snippet", "")).strip(),
    }
    if not any(parsed.values()):
        return {}
    return parsed


def _severity_explanation(severity: str, reason: str, priority: str) -> str:
    if severity == "high":
        impact = (
            "권한 상승, 민감 리소스 접근, 워크로드 격리가 깨질 가능성이 있어 즉시 확인이 필요합니다."
        )
    elif severity == "medium":
        impact = "즉각적인 침해 징후로 단정할 수는 없지만 반복되면 운영 리스크가 커집니다."
    else:
        impact = "현재 단일 이벤트만으로는 영향도가 낮아 보이며 맥락과 반복 여부 확인이 우선입니다."
    return (
        f"Falco priority '{priority or 'unknown'}'와 이벤트 맥락을 기준으로 {severity}로 판단했습니다. "
        f"{impact} 분류 근거: {reason}"
    )


def _root_cause(
    payload: ViolationAnalysisRequest,
    namespace: str,
    pod: str,
    proc: str,
    user: str,
) -> str:
    container = payload.output_fields.get("container.name", "unknown")
    image = payload.output_fields.get("container.image.repository", "")
    image_tag = payload.output_fields.get("container.image.tag", "")
    image_ref = ":".join(item for item in [image, image_tag] if item) or "unknown"
    manifest_note = (
        "입력된 리소스 매니페스트와 함께 확인해야 합니다."
        if payload.resource_manifest
        else "리소스 매니페스트가 없어 실행 컨텍스트 기반으로만 판단했습니다."
    )
    return (
        f"Falco rule '{payload.rule}'가 {namespace}/{pod}에서 감지되었습니다. "
        f"컨테이너 '{container}' 이미지 '{image_ref}' 안에서 프로세스 '{proc}'가 "
        f"사용자 '{user}' 권한으로 실행된 정황이 있으며, "
        f"출력 로그는 '{payload.output[:180]}'입니다. {manifest_note}"
    )


def _recommended_fix(severity: str, namespace: str, pod: str) -> str:
    if severity == "high":
        return (
            f"{namespace}/{pod} Pod의 네트워크 접근을 먼저 차단한 뒤, 이미지와 서비스 계정 권한을 "
            "검증하고 보안 컨텍스트를 강화한 새 워크로드로 교체하세요."
        )
    if severity == "medium":
        return (
            "컨테이너 시작 명령, 디버그 쉘 사용 여부, 실행 사용자를 확인하고 배포 매니페스트에 "
            "non-root와 권한 상승 차단 설정을 추가하세요."
        )
    return (
        "동일 rule의 반복 여부를 모니터링하고, 업무상 정상 동작이 아니라면 보안 컨텍스트 기본값을 "
        "강화하세요."
    )


def _remediation(severity: str, namespace: str, pod: str) -> str:
    if severity == "high":
        return (
            f"{namespace}/{pod} Pod를 우선 격리하고 서비스 계정 권한, 최근 이미지 변경, "
            "컨테이너 command/args를 확인하세요. 재배포 전 runAsNonRoot, readOnlyRootFilesystem, "
            "capabilities drop 설정을 적용하는 것이 좋습니다."
        )
    if severity == "medium":
        return (
            "해당 컨테이너의 정상 운영 명령인지 확인하고, 불필요한 shell/디버그 도구를 제거하세요. "
            "반복 발생 시 Gatekeeper 정책 또는 Falco rule 예외 범위를 재검토하세요."
        )
    return (
        "오탐 여부와 반복 발생 여부를 확인하세요. 운영 영향이 낮으면 모니터링을 유지하고, "
        "동일 Pod에서 반복되면 정책 예외보다 워크로드 설정 수정을 우선 검토하세요."
    )


def _yaml_snippet(severity: str, namespace: str, pod: str, app_label: str = "") -> str:
    safe_pod_name = _safe_k8s_name(pod, "target-pod")
    safe_namespace = _safe_k8s_name(namespace, "default")
    safe_app_label = _safe_k8s_name(app_label, safe_pod_name)
    if severity == "high":
        return "\n".join(
            [
                "apiVersion: networking.k8s.io/v1",
                "kind: NetworkPolicy",
                "metadata:",
                f"  name: isolate-{safe_pod_name}",
                f"  namespace: {safe_namespace}",
                "spec:",
                "  podSelector:",
                "    matchLabels:",
                f"      app: {safe_app_label}",
                "  policyTypes:",
                "    - Ingress",
                "    - Egress",
                "  ingress: []",
                "  egress: []",
            ]
        )
    return "\n".join(
        [
            "securityContext:",
            "  runAsNonRoot: true",
            "  readOnlyRootFilesystem: true",
            "  allowPrivilegeEscalation: false",
            "  capabilities:",
            "    drop:",
            "      - ALL",
        ]
    )


def _manifest_context(manifest: str) -> dict[str, str]:
    if not manifest:
        return {}
    context: dict[str, str] = {}
    in_metadata = False
    in_labels = False
    for raw_line in manifest.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if not stripped or stripped.startswith("#"):
            continue
        if indent == 0:
            in_metadata = stripped == "metadata:"
            in_labels = False
            continue
        if in_metadata and indent == 2 and stripped == "labels:":
            in_labels = True
            continue
        if in_metadata and indent == 2 and ":" in stripped:
            key, value = stripped.split(":", 1)
            if key in {"name", "namespace"}:
                context[key] = value.strip().strip('"\'')
            in_labels = False
            continue
        if in_metadata and in_labels and indent >= 4 and stripped.startswith("app:"):
            context["app_label"] = stripped.split(":", 1)[1].strip().strip('"\'')
    return context


def _safe_k8s_name(value: str, fallback: str) -> str:
    name = re.sub(r"[^a-z0-9.-]+", "-", (value or "").strip().lower()).strip(".-")
    return name[:63] or fallback
