from app.classifier import classify_event
from app.schemas import ViolationAnalysisRequest, ViolationAnalysisResponse


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


def analyze_violation(payload: ViolationAnalysisRequest) -> ViolationAnalysisResponse:
    # 위반 이벤트 분석
    classification = classify_event(payload)
    namespace = payload.output_fields.get("k8s.ns.name", "unknown")
    pod = payload.output_fields.get("k8s.pod.name", "unknown")
    cluster = payload.cluster or "current-cluster"
    summary = (
        f"{cluster} 클러스터의 {namespace}/{pod} 대상 이벤트가 "
        f"{classification.severity} 심각도로 분류되었습니다."
    )
    return ViolationAnalysisResponse(
        severity=classification.severity,
        reason=classification.reason,
        confidence=classification.confidence,
        summary=summary,
        recommended_actions=ACTION_BY_SEVERITY[classification.severity],
    )
