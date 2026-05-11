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


def analyze_violation(
    payload: ViolationAnalysisRequest,
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> ViolationAnalysisResponse:
    # 위반 이벤트 분석
    classification = classify_event(payload)
    namespace = payload.output_fields.get("k8s.ns.name", "unknown")
    pod = payload.output_fields.get("k8s.pod.name", "unknown")
    proc = payload.output_fields.get("proc.name", "unknown")
    user = payload.output_fields.get("user.name", "unknown")
    cluster = payload.cluster or "current-cluster"
    summary = (
        f"{cluster} 클러스터의 {namespace}/{pod} 대상 이벤트가 "
        f"{classification.severity} 심각도로 분류되었습니다."
    )
    root_cause = _root_cause(payload, namespace, pod, proc, user)
    remediation = _remediation(classification.severity, namespace, pod)
    yaml_snippet = _yaml_snippet(classification.severity, namespace, pod)
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
            root_cause = llm_result.get("root_cause") or root_cause
            remediation = llm_result.get("remediation") or remediation
            yaml_snippet = llm_result.get("yaml_snippet") or yaml_snippet
            llm_used = True
    return ViolationAnalysisResponse(
        severity=classification.severity,
        reason=classification.reason,
        confidence=classification.confidence,
        summary=summary,
        recommended_actions=ACTION_BY_SEVERITY[classification.severity],
        root_cause=root_cause,
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
                "Return only valid compact JSON with keys root_cause, remediation, yaml_snippet. "
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
    return (
        "다음 Kubernetes 보안 위반 이벤트를 분석하세요.\n"
        "1. 자연어 원인 설명을 한국어로 작성하세요.\n"
        "2. 운영자가 수행할 수정 방법을 한국어로 작성하세요.\n"
        "3. 적용 가능한 수정 YAML 스니펫을 작성하세요.\n\n"
        f"위반 이벤트 JSON:\n{json.dumps(event, ensure_ascii=False, indent=2)}\n\n"
        f"관련 리소스 매니페스트:\n{payload.resource_manifest or '(not provided)'}"
    )


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
    return {
        "root_cause": str(data.get("root_cause", "")).strip(),
        "remediation": str(data.get("remediation", "")).strip(),
        "yaml_snippet": str(data.get("yaml_snippet", "")).strip(),
    }


def _root_cause(
    payload: ViolationAnalysisRequest,
    namespace: str,
    pod: str,
    proc: str,
    user: str,
) -> str:
    manifest_note = (
        "입력된 리소스 매니페스트와 함께 확인해야 합니다."
        if payload.resource_manifest
        else "리소스 매니페스트가 없어 실행 컨텍스트 기반으로만 판단했습니다."
    )
    return (
        f"Falco rule '{payload.rule}'가 {namespace}/{pod}에서 감지되었습니다. "
        f"프로세스 '{proc}'가 사용자 '{user}' 권한으로 실행된 정황이 있으며, "
        f"출력 로그는 '{payload.output[:180]}'입니다. {manifest_note}"
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


def _yaml_snippet(severity: str, namespace: str, pod: str) -> str:
    if severity == "high":
        return "\n".join(
            [
                "apiVersion: networking.k8s.io/v1",
                "kind: NetworkPolicy",
                "metadata:",
                f"  name: isolate-{pod or 'pod'}",
                f"  namespace: {namespace or 'default'}",
                "spec:",
                "  podSelector:",
                "    matchLabels:",
                f"      app: {pod or 'target-app'}",
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
