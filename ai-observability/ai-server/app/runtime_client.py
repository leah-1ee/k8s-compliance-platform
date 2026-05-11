import os
from datetime import datetime, timezone
from typing import Any

import httpx


RESPONSE_SERVER_URL = os.getenv("RESPONSE_SERVER_URL", "http://response-server:8080").rstrip("/")
KUBE_API_URL = os.getenv("KUBERNETES_SERVICE_HOST", "")
KUBE_API_PORT = os.getenv("KUBERNETES_SERVICE_PORT", "443")
SERVICEACCOUNT_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

_gatekeeper_events: list[dict[str, Any]] = []


def list_runtime_events(limit: int = 50) -> dict[str, Any]:
    # Falco response-server 이벤트와 AI 서버가 수집한 Gatekeeper 이벤트를 통합
    events: list[dict[str, Any]] = []
    source_status = {"response_server": "unavailable", "gatekeeper_buffer": "ok"}
    try:
        response = httpx.get(
            f"{RESPONSE_SERVER_URL}/api/v1/events",
            params={"limit": limit},
            timeout=3,
        )
        response.raise_for_status()
        body = response.json()
        events.extend(_normalize_event(item, source="falco") for item in body.get("events", []))
        source_status["response_server"] = "ok"
    except httpx.HTTPError as error:
        source_status["response_server_error"] = str(error)

    events.extend(reversed(_gatekeeper_events[-limit:]))
    events = sorted(events, key=lambda item: item.get("timestamp", ""), reverse=True)[:limit]
    return {"count": len(events), "events": events, "source_status": source_status}


def get_runtime_event(event_id: str) -> dict[str, Any] | None:
    for event in _gatekeeper_events:
        if event.get("id") == event_id:
            return event

    try:
        response = httpx.get(f"{RESPONSE_SERVER_URL}/api/v1/events/{event_id}", timeout=3)
        response.raise_for_status()
        return _normalize_event(response.json(), source="falco")
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            return None
        raise


def get_runtime_summary() -> dict[str, Any]:
    try:
        response = httpx.get(f"{RESPONSE_SERVER_URL}/api/v1/events/summary", timeout=3)
        response.raise_for_status()
        summary = response.json()
    except httpx.HTTPError as error:
        summary = {
            "total_events": 0,
            "by_severity": {},
            "by_rule": {},
            "by_namespace": {},
            "by_action": {},
            "recent_high": [],
            "source_error": str(error),
        }

    gatekeeper_count = len(_gatekeeper_events)
    if gatekeeper_count:
        summary["total_events"] = int(summary.get("total_events", 0)) + gatekeeper_count
        by_rule = summary.setdefault("by_rule", {})
        by_severity = summary.setdefault("by_severity", {})
        for event in _gatekeeper_events:
            by_rule[event.get("rule", "Gatekeeper deny")] = by_rule.get(event.get("rule", "Gatekeeper deny"), 0) + 1
            by_severity[event.get("severity", "medium")] = by_severity.get(event.get("severity", "medium"), 0) + 1
    return summary


def record_gatekeeper_event(payload: dict[str, Any]) -> dict[str, Any]:
    # Gatekeeper deny/audit 이벤트를 UI 위반 목록과 같은 형태로 정규화
    now = datetime.now(timezone.utc).isoformat()
    review = payload.get("review", {}) if isinstance(payload.get("review"), dict) else {}
    obj = review.get("object", {}) if isinstance(review.get("object"), dict) else {}
    metadata = obj.get("metadata", {}) if isinstance(obj.get("metadata"), dict) else {}
    namespace = payload.get("namespace") or metadata.get("namespace", "")
    name = payload.get("pod_name") or metadata.get("name", "")
    event = {
        "id": f"gk-{len(_gatekeeper_events) + 1:06d}",
        "timestamp": payload.get("timestamp") or now,
        "source": "gatekeeper",
        "rule": payload.get("constraint") or payload.get("rule") or "Gatekeeper deny",
        "priority": "Warning",
        "severity": payload.get("severity") or "medium",
        "classification_source": "gatekeeper",
        "classification_reason": payload.get("message") or payload.get("reason") or "Gatekeeper admission denied the request.",
        "confidence": 0.82,
        "namespace": namespace,
        "pod_name": name,
        "container_name": payload.get("container_name", ""),
        "image": payload.get("image", ""),
        "user": payload.get("user", ""),
        "command": payload.get("command", ""),
        "action_taken": "deny",
        "raw_event": payload,
    }
    _gatekeeper_events.append(event)
    del _gatekeeper_events[:-200]
    return event


def fetch_resource_manifest(namespace: str, pod_name: str) -> dict[str, str]:
    # Pod manifest를 Kubernetes API에서 best-effort 조회
    if not namespace or not pod_name:
        return {"manifest": "", "error": "namespace와 pod 이름이 필요합니다."}
    if not KUBE_API_URL:
        return {"manifest": "", "error": "Kubernetes API 환경 변수가 없어 매니페스트를 자동 조회할 수 없습니다."}

    token_path = f"{SERVICEACCOUNT_DIR}/token"
    ca_path = f"{SERVICEACCOUNT_DIR}/ca.crt"
    try:
        with open(token_path, encoding="utf-8") as token_file:
            token = token_file.read().strip()
    except OSError:
        return {"manifest": "", "error": "ServiceAccount token을 읽을 수 없어 매니페스트를 조회할 수 없습니다."}

    url = f"https://{KUBE_API_URL}:{KUBE_API_PORT}/api/v1/namespaces/{namespace}/pods/{pod_name}"
    try:
        response = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            verify=ca_path,
            timeout=5,
        )
        response.raise_for_status()
        pod = response.json()
        return {"manifest": _pod_to_yaml(pod), "error": ""}
    except httpx.HTTPError as error:
        return {"manifest": "", "error": f"Kubernetes API 조회 실패: {error}"}


def build_report() -> dict[str, Any]:
    summary = get_runtime_summary()
    events = list_runtime_events(limit=100)["events"]
    top_rules = sorted(summary.get("by_rule", {}).items(), key=lambda item: item[1], reverse=True)[:5]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "top_rules": [{"rule": rule, "count": count} for rule, count in top_rules],
        "recommendations": _report_recommendations(summary, events),
        "events": events[:20],
    }


def _report_recommendations(summary: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    recommendations = []
    by_severity = summary.get("by_severity", {})
    if by_severity.get("high", 0):
        recommendations.append("High 이벤트가 있어 자동 격리 결과와 영향을 받은 namespace를 우선 확인하세요.")
    if by_severity.get("medium", 0):
        recommendations.append("Medium 이벤트는 반복 rule과 예외 필요 여부를 검토하세요.")
    if any(event.get("source") == "gatekeeper" for event in events):
        recommendations.append("Gatekeeper deny 이벤트는 리소스 매니페스트 수정 후 재배포 검증이 필요합니다.")
    if not recommendations:
        recommendations.append("최근 수집된 위반 이벤트가 없거나 모두 낮은 위험으로 분류되었습니다.")
    return recommendations


def _normalize_event(item: dict[str, Any], source: str) -> dict[str, Any]:
    normalized = dict(item)
    normalized.setdefault("source", source)
    normalized.setdefault("timestamp", item.get("time", ""))
    normalized.setdefault("rule", item.get("rule", ""))
    normalized.setdefault("namespace", item.get("namespace", item.get("k8s.ns.name", "")))
    normalized.setdefault("pod_name", item.get("pod_name", item.get("k8s.pod.name", "")))
    normalized.setdefault("severity", item.get("severity", "medium"))
    normalized.setdefault("raw_event", item)
    return normalized


def _pod_to_yaml(pod: dict[str, Any]) -> str:
    # 데모용으로 핵심 필드만 안정적으로 출력
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    labels = metadata.get("labels", {})
    lines = [
        "apiVersion: v1",
        "kind: Pod",
        "metadata:",
        f"  name: {metadata.get('name', '')}",
        f"  namespace: {metadata.get('namespace', '')}",
    ]
    if labels:
        lines.append("  labels:")
        for key, value in labels.items():
            lines.append(f"    {key}: {value}")
    lines.append("spec:")
    lines.append("  containers:")
    for container in spec.get("containers", []):
        lines.append(f"    - name: {container.get('name', '')}")
        lines.append(f"      image: {container.get('image', '')}")
        if container.get("command"):
            lines.append("      command:")
            for command in container.get("command", []):
                lines.append(f"        - {command}")
        if container.get("securityContext"):
            lines.append("      securityContext:")
            for key, value in container.get("securityContext", {}).items():
                rendered = str(value).lower() if isinstance(value, bool) else value
                lines.append(f"        {key}: {rendered}")
    return "\n".join(lines)
