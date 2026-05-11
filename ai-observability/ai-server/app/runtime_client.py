import os
from datetime import datetime, timezone
from typing import Any

import httpx

from app import storage


RESPONSE_SERVER_URL = os.getenv("RESPONSE_SERVER_URL", "http://response-server:8080").rstrip("/")
KUBE_API_URL = os.getenv("KUBERNETES_SERVICE_HOST", "")
KUBE_API_PORT = os.getenv("KUBERNETES_SERVICE_PORT", "443")
SERVICEACCOUNT_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


def list_runtime_events(limit: int = 50, cluster: str = "") -> dict[str, Any]:
    # SQLite 저장 이벤트와 레거시 response-server 이벤트를 통합
    events: list[dict[str, Any]] = storage.list_events(limit=limit, cluster=cluster)
    source_status = {
        "response_server": "unavailable",
        "sqlite": "ok",
    }

    if not cluster:
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

    events = sorted(events, key=lambda item: item.get("timestamp", ""), reverse=True)[:limit]
    return {"count": len(events), "events": events, "source_status": source_status}


def get_runtime_event(event_id: str) -> dict[str, Any] | None:
    stored = storage.get_event(event_id)
    if stored is not None:
        return stored

    try:
        response = httpx.get(f"{RESPONSE_SERVER_URL}/api/v1/events/{event_id}", timeout=3)
        response.raise_for_status()
        return _normalize_event(response.json(), source="falco")
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            return None
        raise


def get_runtime_summary() -> dict[str, Any]:
    summary = storage.event_summary()
    try:
        response = httpx.get(f"{RESPONSE_SERVER_URL}/api/v1/events/summary", timeout=3)
        response.raise_for_status()
        _merge_summary(summary, response.json())
    except httpx.HTTPError as error:
        summary["source_error"] = str(error)
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
    return storage.save_event(event)


def record_falco_event(
    payload: dict[str, Any],
    cluster_name: str = "",
    source: str = "sidekick",
) -> dict[str, Any]:
    # Falco Sidekick/agent가 전송한 이벤트를 저장
    now = datetime.now(timezone.utc).isoformat()
    raw_event = payload.get("event", payload)
    if not isinstance(raw_event, dict):
        raw_event = {}
    output_fields = raw_event.get("output_fields", {})
    if not isinstance(output_fields, dict):
        output_fields = {}

    namespace = (
        payload.get("namespace")
        or output_fields.get("k8s.ns.name")
        or output_fields.get("k8s.ns")
        or ""
    )
    pod_name = (
        payload.get("pod_name")
        or output_fields.get("k8s.pod.name")
        or output_fields.get("k8s.pod")
        or ""
    )
    repository = output_fields.get("container.image.repository", "")
    image_tag = output_fields.get("container.image.tag", "")
    image = payload.get("image") or repository
    if repository and image_tag:
        image = f"{repository}:{image_tag}"

    event = {
        "timestamp": payload.get("timestamp") or raw_event.get("time") or now,
        "source": source,
        "cluster": cluster_name or payload.get("cluster") or raw_event.get("cluster") or "unknown-cluster",
        "rule": raw_event.get("rule", "Falco runtime event"),
        "priority": raw_event.get("priority", ""),
        "severity": payload.get("severity") or _priority_to_severity(raw_event.get("priority", "")),
        "classification_source": "agent",
        "classification_reason": raw_event.get("output", "") or raw_event.get("message", ""),
        "confidence": 0.75,
        "namespace": namespace,
        "pod_name": pod_name,
        "container_name": payload.get("container_name") or output_fields.get("container.name", ""),
        "image": image,
        "user": payload.get("user") or output_fields.get("user.name", ""),
        "command": payload.get("command") or output_fields.get("proc.cmdline", ""),
        "action_taken": "alert_and_monitor",
        "resource_manifest": payload.get("resource_manifest", ""),
        "raw_event": raw_event,
    }
    return storage.save_event(event)


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


def _merge_summary(target: dict[str, Any], source: dict[str, Any]) -> None:
    target["total_events"] = int(target.get("total_events", 0)) + int(source.get("total_events", 0) or 0)
    for key in ("by_severity", "by_rule", "by_namespace", "by_action"):
        bucket = target.setdefault(key, {})
        for item_key, count in source.get(key, {}).items():
            bucket[item_key] = int(bucket.get(item_key, 0)) + int(count or 0)
    target.setdefault("recent_high", []).extend(source.get("recent_high", []))


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


def _priority_to_severity(priority: str) -> str:
    normalized = str(priority or "").lower()
    if normalized in {"emergency", "alert", "critical", "error"}:
        return "high"
    if normalized in {"warning", "notice"}:
        return "medium"
    return "low"
