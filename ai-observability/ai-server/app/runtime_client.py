import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
import yaml

from app import storage
from app.llm_client import LLMClient
from app.policy_generator import _format_llm_http_error


RESPONSE_SERVER_URL = os.getenv("RESPONSE_SERVER_URL", "http://response-server:8080").rstrip("/")
DEMO_CLUSTER_NAME = os.getenv("DEMO_CLUSTER_NAME", os.getenv("CLUSTER_NAME", "demo-cluster")).strip()
KUBE_API_URL = os.getenv("KUBERNETES_SERVICE_HOST", "")
KUBE_API_PORT = os.getenv("KUBERNETES_SERVICE_PORT", "443")
SERVICEACCOUNT_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
MAX_RESOURCE_MANIFEST_BYTES = 200_000
INFRA_NAMESPACES = {
    "kube-system",
    "monitoring",
    "gatekeeper-system",
    "falco",
    "local-path-storage",
    "calico-system",
    "cilium",
    "cilium-system",
    "kube-flannel",
    "tigera-operator",
}
POLICY_APPLY_FIELD_MANAGER = "kubeowl-policy-apply"


def apply_policy_manifest(manifest: str, cluster: dict[str, Any]) -> dict[str, Any]:
    resources = _parse_policy_manifest(manifest)
    if not resources:
        return {
            "status": "invalid_manifest",
            "error": "적용할 Kubernetes 리소스가 없습니다.",
            "resources": [],
            "fallback": _policy_apply_fallback(manifest),
        }
    ordered = _order_policy_resources(resources)
    resource_results = [_resource_result(resource, order=index + 1) for index, resource in enumerate(ordered)]
    policy_type, policy_name = _policy_identity(resource_results)

    if not _policy_apply_enabled():
        return {
            "status": "not_configured",
            "error": (
                "AI 서버에 사용자 클러스터 Kubernetes API 적용 권한이 설정되어 있지 않습니다. "
                "아래 kubectl dry-run/apply 명령을 해당 클러스터 context에서 실행하세요."
            ),
            "cluster_id": cluster.get("id", ""),
            "cluster_name": cluster.get("name", ""),
            "policy_type": policy_type,
            "policy_name": policy_name,
            "resources": resource_results,
            "fallback": _policy_apply_fallback(manifest),
        }

    if not _kube_apply_configured():
        for result in resource_results:
            result["dry_run_status"] = "skipped"
            result["apply_status"] = "skipped"
            result["error"] = "Kubernetes ServiceAccount is not available"
        return {
            "status": "not_configured",
            "error": "Kubernetes API 또는 ServiceAccount token을 사용할 수 없습니다.",
            "cluster_id": cluster.get("id", ""),
            "cluster_name": cluster.get("name", ""),
            "policy_type": policy_type,
            "policy_name": policy_name,
            "resources": resource_results,
            "fallback": _policy_apply_fallback(manifest),
        }

    dry_run_failed = False
    for resource, result in zip(ordered, resource_results, strict=True):
        error = _server_side_apply(resource, dry_run=True)
        if error:
            result["dry_run_status"] = "failed"
            result["apply_status"] = "skipped"
            result["error"] = error
            dry_run_failed = True
        else:
            result["dry_run_status"] = "success"
            result["apply_status"] = "pending"
    if dry_run_failed:
        for result in resource_results:
            if result["apply_status"] == "pending":
                result["apply_status"] = "skipped"
        return {
            "status": "dry_run_failed",
            "error": "dry-run 검증 실패로 실제 apply를 실행하지 않았습니다.",
            "cluster_id": cluster.get("id", ""),
            "cluster_name": cluster.get("name", ""),
            "policy_type": policy_type,
            "policy_name": policy_name,
            "resources": resource_results,
            "fallback": _policy_apply_fallback(manifest),
        }

    apply_failed = False
    for resource, result in zip(ordered, resource_results, strict=True):
        error = _server_side_apply(resource, dry_run=False)
        if error:
            result["apply_status"] = "failed"
            result["error"] = error
            apply_failed = True
        else:
            result["apply_status"] = "success"
    return {
        "status": "apply_failed" if apply_failed else "applied",
        "error": "일부 리소스 apply가 실패했습니다." if apply_failed else "",
        "cluster_id": cluster.get("id", ""),
        "cluster_name": cluster.get("name", ""),
        "policy_type": policy_type,
        "policy_name": policy_name,
        "resources": resource_results,
        "fallback": _policy_apply_fallback(manifest) if apply_failed else {},
    }


def _parse_policy_manifest(manifest: str) -> list[dict[str, Any]]:
    try:
        docs = yaml.safe_load_all(str(manifest or ""))
        return [doc for doc in docs if isinstance(doc, dict) and doc.get("kind") and doc.get("apiVersion")]
    except yaml.YAMLError as error:
        raise ValueError(f"YAML parsing failed: {error}") from error


def _order_policy_resources(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def priority(resource: dict[str, Any]) -> tuple[int, str]:
        api_version = str(resource.get("apiVersion", ""))
        kind = str(resource.get("kind", ""))
        if kind == "ConstraintTemplate":
            return (0, kind)
        if api_version.startswith("constraints.gatekeeper.sh/"):
            return (1, kind)
        if api_version.startswith("mutations.gatekeeper.sh/") or kind == "NetworkPolicy":
            return (2, kind)
        return (3, kind)

    return sorted(resources, key=priority)


def _resource_result(resource: dict[str, Any], order: int) -> dict[str, Any]:
    metadata = resource.get("metadata", {}) if isinstance(resource.get("metadata"), dict) else {}
    return {
        "order": order,
        "api_version": str(resource.get("apiVersion", "")),
        "kind": str(resource.get("kind", "")),
        "name": str(metadata.get("name", "")),
        "namespace": str(metadata.get("namespace", "")),
        "dry_run_status": "skipped",
        "apply_status": "skipped",
        "error": "",
    }


def _policy_identity(resource_results: list[dict[str, Any]]) -> tuple[str, str]:
    for result in resource_results:
        if result["api_version"].startswith("constraints.gatekeeper.sh/"):
            return "gatekeeper_constraint", result.get("name") or result.get("kind") or "unknown"
    for result in resource_results:
        if result["kind"] == "NetworkPolicy":
            return "network_policy", result.get("name") or "unknown"
        if result["api_version"].startswith("mutations.gatekeeper.sh/"):
            return "gatekeeper_mutation", result.get("name") or result.get("kind") or "unknown"
    first = resource_results[0] if resource_results else {}
    return first.get("kind", "unknown"), first.get("name", "unknown")


def _policy_apply_enabled() -> bool:
    return os.getenv("POLICY_APPLY_ENABLED", "").strip().lower() in {"true", "1", "yes"}


def _kube_apply_configured() -> bool:
    host = os.getenv("KUBERNETES_SERVICE_HOST", KUBE_API_URL).strip()
    token_path = f"{SERVICEACCOUNT_DIR}/token"
    return bool(host and os.path.exists(token_path))


def _server_side_apply(resource: dict[str, Any], dry_run: bool) -> str:
    path = _resource_apply_path(resource)
    if not path:
        return f"지원하지 않는 리소스입니다: {resource.get('apiVersion', '')} {resource.get('kind', '')}"
    query = {
        "fieldManager": POLICY_APPLY_FIELD_MANAGER,
        "force": "true",
    }
    if dry_run:
        query["dryRun"] = "All"
    suffix = f"?{urlencode(query)}"
    body = yaml.safe_dump(resource, sort_keys=False)
    response = _kube_patch(f"{path}{suffix}", body)
    return response.get("error", "")


def _resource_apply_path(resource: dict[str, Any]) -> str:
    api_version = str(resource.get("apiVersion", ""))
    kind = str(resource.get("kind", ""))
    metadata = resource.get("metadata", {}) if isinstance(resource.get("metadata"), dict) else {}
    name = str(metadata.get("name", "")).strip()
    namespace = str(metadata.get("namespace", "")).strip()
    if not name:
        return ""
    api_resource = _lookup_api_resource(api_version, kind)
    resource_name = api_resource.get("name", "")
    namespaced = bool(api_resource.get("namespaced", False))
    if not resource_name:
        fallback = _fallback_api_resource(api_version, kind)
        resource_name = fallback.get("name", "")
        namespaced = bool(fallback.get("namespaced", False))
    if not resource_name:
        return ""
    if "/" in api_version:
        group, version = api_version.split("/", 1)
        base = f"/apis/{group}/{version}"
    else:
        base = f"/api/{api_version}"
    if namespaced:
        namespace = namespace or "default"
        return f"{base}/namespaces/{namespace}/{resource_name}/{name}"
    return f"{base}/{resource_name}/{name}"


def _lookup_api_resource(api_version: str, kind: str) -> dict[str, Any]:
    if not _kube_apply_configured():
        return {}
    if "/" in api_version:
        group, version = api_version.split("/", 1)
        discovery_path = f"/apis/{group}/{version}"
    else:
        discovery_path = f"/api/{api_version}"
    discovery = _kube_get(discovery_path)
    if discovery.get("error"):
        return {}
    for resource in discovery.get("body", {}).get("resources", []):
        if not isinstance(resource, dict) or "/" in str(resource.get("name", "")):
            continue
        if resource.get("kind") == kind and "patch" in resource.get("verbs", []):
            return resource
    return {}


def _fallback_api_resource(api_version: str, kind: str) -> dict[str, Any]:
    if api_version == "templates.gatekeeper.sh/v1beta1" and kind == "ConstraintTemplate":
        return {"name": "constrainttemplates", "namespaced": False}
    if api_version.startswith("constraints.gatekeeper.sh/"):
        return {"name": kind.lower(), "namespaced": False}
    if api_version.startswith("mutations.gatekeeper.sh/") and kind == "Assign":
        return {"name": "assign", "namespaced": False}
    if api_version == "networking.k8s.io/v1" and kind == "NetworkPolicy":
        return {"name": "networkpolicies", "namespaced": True}
    return {}


def _kube_patch(path: str, yaml_body: str, timeout: float = 10) -> dict[str, Any]:
    token_path = f"{SERVICEACCOUNT_DIR}/token"
    ca_path = f"{SERVICEACCOUNT_DIR}/ca.crt"
    host = os.getenv("KUBERNETES_SERVICE_HOST", KUBE_API_URL).strip()
    port = os.getenv("KUBERNETES_SERVICE_PORT", KUBE_API_PORT).strip() or "443"
    try:
        with open(token_path, encoding="utf-8") as token_file:
            token = token_file.read().strip()
    except OSError as error:
        return {"body": {}, "error": f"ServiceAccount token read failed: {error}"}
    url = f"https://{host}:{port}{path}"
    try:
        response = httpx.patch(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/apply-patch+yaml",
            },
            content=yaml_body.encode("utf-8"),
            verify=ca_path,
            timeout=timeout,
        )
        response.raise_for_status()
        return {"body": response.json(), "error": ""}
    except httpx.HTTPStatusError as error:
        detail = error.response.text[:1000]
        return {"body": {}, "error": f"{error.response.status_code}: {detail}"}
    except httpx.HTTPError as error:
        return {"body": {}, "error": str(error)}


def _policy_apply_fallback(manifest: str) -> dict[str, str]:
    clean_manifest = str(manifest or "").strip()
    dry_run = _fallback_commands(clean_manifest, dry_run=True)
    apply = _fallback_commands(clean_manifest, dry_run=False)
    permission_check = _policy_permission_check_command(clean_manifest)
    admin_rbac = _policy_admin_rbac_command(clean_manifest)
    return {
        "permission_check_command": permission_check,
        "admin_rbac_command": admin_rbac,
        "dry_run_command": dry_run,
        "apply_command": apply,
        "combined_command": "\n\n".join(
            [
                "# 1) 현재 kubeconfig 계정 권한 확인",
                permission_check,
                "# 2) 권한이 부족하면 클러스터 관리자가 먼저 실행",
                admin_rbac,
                "# 3) dry-run 검증",
                dry_run,
                "# 4) 실제 적용",
                apply,
            ]
        ),
    }


def _policy_permission_check_command(manifest: str) -> str:
    namespaces = _manifest_namespaces(manifest)
    namespace = sorted(namespaces)[0] if namespaces else "default"
    commands = [
        "kubectl auth can-i get constrainttemplates.templates.gatekeeper.sh",
        "kubectl auth can-i create constrainttemplates.templates.gatekeeper.sh",
        "kubectl auth can-i patch constrainttemplates.templates.gatekeeper.sh",
        "kubectl auth can-i create '*' --api-group=constraints.gatekeeper.sh",
        "kubectl auth can-i patch '*' --api-group=constraints.gatekeeper.sh",
    ]
    if _manifest_has_kind(manifest, "NetworkPolicy"):
        commands.extend(
            [
                f"kubectl auth can-i create networkpolicies.networking.k8s.io -n {namespace}",
                f"kubectl auth can-i patch networkpolicies.networking.k8s.io -n {namespace}",
            ]
        )
    return "\n".join(commands)


def _policy_admin_rbac_command(manifest: str) -> str:
    include_network_policy = _manifest_has_kind(manifest, "NetworkPolicy")
    network_rule = ""
    if include_network_policy:
        network_rule = """
  - apiGroups:
      - networking.k8s.io
    resources:
      - networkpolicies
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch"""
    return f"""kubectl apply -f - <<'KUBEOWL_RBAC_EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubeowl-policy-applier
rules:
  - apiGroups:
      - templates.gatekeeper.sh
    resources:
      - constrainttemplates
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
  - apiGroups:
      - constraints.gatekeeper.sh
    resources:
      - "*"
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch{network_rule}
KUBEOWL_RBAC_EOF

# 예시: 현재 kubeconfig 사용자가 alice@example.com 이라면
kubectl create clusterrolebinding kubeowl-policy-applier-alice --clusterrole=kubeowl-policy-applier --user=alice@example.com

# 예시: ServiceAccount로 적용한다면
kubectl create serviceaccount kubeowl-policy-applier -n default
kubectl create clusterrolebinding kubeowl-policy-applier-sa --clusterrole=kubeowl-policy-applier --serviceaccount=default:kubeowl-policy-applier"""


def _manifest_has_kind(manifest: str, kind: str) -> bool:
    try:
        return any(resource.get("kind") == kind for resource in _parse_policy_manifest(manifest))
    except ValueError:
        return False


def _manifest_namespaces(manifest: str) -> set[str]:
    namespaces = set()
    try:
        resources = _parse_policy_manifest(manifest)
    except ValueError:
        return namespaces
    for resource in resources:
        metadata = resource.get("metadata", {}) if isinstance(resource.get("metadata"), dict) else {}
        namespace = str(metadata.get("namespace", "")).strip()
        if namespace:
            namespaces.add(namespace)
    return namespaces


def _fallback_commands(manifest: str, dry_run: bool) -> str:
    verb = "kubectl apply --dry-run=server -f -" if dry_run else "kubectl apply -f -"
    try:
        ordered = _order_policy_resources(_parse_policy_manifest(manifest))
    except ValueError:
        ordered = []
    if not ordered:
        return _heredoc_command(verb, manifest, "KUBEOWL_POLICY_EOF")

    templates = [resource for resource in ordered if resource.get("kind") == "ConstraintTemplate"]
    others = [resource for resource in ordered if resource.get("kind") != "ConstraintTemplate"]
    if not templates or not others:
        return _heredoc_command(
            verb,
            _dump_manifest_docs(ordered),
            "KUBEOWL_POLICY_EOF",
        )

    commands = [
        _heredoc_command(verb, _dump_manifest_docs(templates), "KUBEOWL_TEMPLATE_EOF"),
        "kubectl wait --for=condition=Established crd -l gatekeeper.sh/constraint=true --timeout=60s",
        _heredoc_command(verb, _dump_manifest_docs(others), "KUBEOWL_CONSTRAINT_EOF"),
    ]
    return "\n\n".join(commands)


def _dump_manifest_docs(resources: list[dict[str, Any]]) -> str:
    return "\n---\n".join(yaml.safe_dump(resource, sort_keys=False).strip() for resource in resources)


def _heredoc_command(verb: str, manifest: str, marker: str) -> str:
    safe_marker = marker
    if safe_marker in str(manifest or ""):
        safe_marker = f"{marker}_2"
    return f"{verb} <<'{safe_marker}'\n{str(manifest or '').strip()}\n{safe_marker}"


def list_runtime_events(
    limit: int = 50,
    cluster: str = "",
    cluster_kind: str = "",
    source: str = "",
    include_legacy: bool = False,
    user_id: str = "",
    exclude_infra: bool = False,
) -> dict[str, Any]:
    # SQLite 저장 이벤트와 레거시 response-server 이벤트를 통합
    events: list[dict[str, Any]] = storage.list_events(
        limit=limit,
        cluster=cluster,
        cluster_kind=cluster_kind,
        source=source,
        user_id=user_id,
        exclude_namespaces=INFRA_NAMESPACES if exclude_infra else None,
    )
    source_status = {
        "response_server": "skipped",
        "sqlite": "ok",
    }

    if not user_id and include_legacy and not cluster and not source and cluster_kind in {"", "demo"}:
        source_status["response_server"] = "unavailable"
        try:
            request_limit = min(max(limit * 3 if exclude_infra else limit, limit), 500)
            response = httpx.get(
                f"{RESPONSE_SERVER_URL}/api/v1/events",
                params={"limit": request_limit},
                timeout=3,
            )
            response.raise_for_status()
            body = response.json()
            legacy_events = [
                _normalize_event(
                    item,
                    source="falco",
                    cluster_name=DEMO_CLUSTER_NAME,
                    cluster_kind="demo",
                )
                for item in body.get("events", [])
            ]
            if exclude_infra:
                legacy_events = [
                    event for event in legacy_events if event.get("namespace") not in INFRA_NAMESPACES
                ]
            events.extend(legacy_events)
            source_status["response_server"] = "ok"
        except httpx.HTTPError as error:
            source_status["response_server_error"] = str(error)

    events = sorted(events, key=lambda item: item.get("timestamp", ""), reverse=True)[:limit]
    return {"count": len(events), "events": events, "source_status": source_status}


def get_runtime_event(event_id: str, user_id: str = "") -> dict[str, Any] | None:
    stored = storage.get_event(event_id, user_id=user_id)
    if stored is not None:
        return stored
    if user_id:
        return None

    try:
        response = httpx.get(f"{RESPONSE_SERVER_URL}/api/v1/events/{event_id}", timeout=3)
        response.raise_for_status()
        return _normalize_event(response.json(), source="falco")
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            return None
        raise


def get_runtime_summary(user_id: str = "") -> dict[str, Any]:
    summary = storage.event_summary(user_id=user_id)
    if user_id:
        return summary
    try:
        response = httpx.get(f"{RESPONSE_SERVER_URL}/api/v1/events/summary", timeout=3)
        response.raise_for_status()
        _merge_summary(summary, response.json())
    except httpx.HTTPError as error:
        summary["source_error"] = str(error)
    return summary


def build_dashboard_summary(user_id: str = "") -> dict[str, Any]:
    summary = get_runtime_summary(user_id=user_id)
    last_sync = summary.get("last_seen_at") or summary.get("latest_event_at") or ""
    active_policies = _count_gatekeeper_constraints()
    return {
        "active_policies": active_policies.get("count"),
        "active_policies_source": active_policies.get("source", "unknown"),
        "active_policies_error": active_policies.get("error", ""),
        "recent_violations": int(summary.get("recent_24h", 0) or 0),
        "runtime_events": int(summary.get("total_events", 0) or 0),
        "last_sync": last_sync,
    }


def _count_gatekeeper_constraints() -> dict[str, Any]:
    if not KUBE_API_URL:
        return {"count": None, "source": "unavailable", "error": "Kubernetes API unavailable"}
    discovery = _kube_get("/apis/constraints.gatekeeper.sh/v1beta1")
    if discovery.get("error"):
        return {"count": None, "source": "unavailable", "error": discovery["error"]}
    count = 0
    errors = []
    for resource in discovery.get("body", {}).get("resources", []):
        if not isinstance(resource, dict) or "/" in str(resource.get("name", "")):
            continue
        if not resource.get("namespaced", False) and "list" in resource.get("verbs", []):
            body = _kube_get(f"/apis/constraints.gatekeeper.sh/v1beta1/{resource['name']}")
            if not body.get("error"):
                count += len(body.get("body", {}).get("items", []))
            else:
                errors.append(f"{resource['name']}: {body['error']}")
    return {
        "count": count,
        "source": "kubernetes",
        "error": "; ".join(errors[:3]),
    }


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
        "cluster": payload.get("cluster") or DEMO_CLUSTER_NAME,
        "cluster_kind": payload.get("cluster_kind") or "demo",
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
    cluster_id: str = "",
    cluster_name: str = "",
    cluster_kind: str = "customer",
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
        "cluster_id": cluster_id,
        "cluster": cluster_name or payload.get("cluster") or raw_event.get("cluster") or "unknown-cluster",
        "cluster_kind": cluster_kind,
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
        "resource_manifest": _normalize_resource_manifest(
            payload.get("resource_manifest", raw_event.get("resource_manifest", ""))
        ),
        "raw_event": raw_event,
    }
    return storage.save_event(event)


def _normalize_resource_manifest(value: Any) -> str:
    if isinstance(value, str):
        manifest = value.strip()
    elif isinstance(value, dict):
        manifest = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    else:
        return ""
    if len(manifest.encode("utf-8")) > MAX_RESOURCE_MANIFEST_BYTES:
        return ""
    return manifest


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


def _kube_get(path: str, timeout: float = 5) -> dict[str, Any]:
    token_path = f"{SERVICEACCOUNT_DIR}/token"
    ca_path = f"{SERVICEACCOUNT_DIR}/ca.crt"
    host = os.getenv("KUBERNETES_SERVICE_HOST", KUBE_API_URL).strip()
    port = os.getenv("KUBERNETES_SERVICE_PORT", KUBE_API_PORT).strip() or "443"
    if not host:
        return {"body": {}, "error": "Kubernetes API unavailable"}
    try:
        with open(token_path, encoding="utf-8") as token_file:
            token = token_file.read().strip()
    except OSError as error:
        return {"body": {}, "error": f"ServiceAccount token read failed: {error}"}
    url = f"https://{host}:{port}{path}"
    try:
        response = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            verify=ca_path,
            timeout=timeout,
        )
        response.raise_for_status()
        return {"body": response.json(), "error": ""}
    except httpx.HTTPError as error:
        return {"body": {}, "error": str(error)}


def build_report(
    cluster_kind: str = "",
    include_legacy: bool = False,
    user_id: str = "",
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> dict[str, Any]:
    summary = get_runtime_summary(user_id=user_id)
    events = list_runtime_events(
        limit=100,
        cluster_kind=cluster_kind,
        include_legacy=include_legacy,
        user_id=user_id,
    )["events"]
    top_rules = sorted(summary.get("by_rule", {}).items(), key=lambda item: item[1], reverse=True)[:5]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "top_rules": [{"rule": rule, "count": count} for rule, count in top_rules],
        "recommendations": _report_recommendations(summary, events),
        "events": events[:20],
        "llm_used": False,
        "llm_summary": "",
        "llm_error": "",
    }
    llm_summary, llm_error = _safe_llm_report_summary(report, llm_provider, llm_api_key)
    report["llm_summary"] = llm_summary
    report["llm_error"] = llm_error
    report["llm_used"] = bool(llm_summary)
    return report


def _safe_llm_report_summary(
    report: dict[str, Any],
    llm_provider: str | None,
    llm_api_key: str | None,
) -> tuple[str, str]:
    client = LLMClient(provider=llm_provider, api_key=llm_api_key)
    if not client.configured:
        return "", "LLM API key가 설정되어 있지 않아 규칙 기반 리포트만 표시합니다."
    try:
        return (
            client.complete_text(
                _build_report_prompt(report),
                (
                    "You are a Kubernetes compliance analyst. "
                    "Write a concise Korean executive summary for operators. "
                    "Mention risk level, top causes, and the next actions. "
                    "Do not invent events that are not in the JSON."
                ),
                max_tokens=900,
            ).strip(),
            "",
        )
    except httpx.HTTPStatusError as error:
        return "", f"{_format_llm_http_error(error)} 규칙 기반 리포트만 표시합니다."
    except httpx.TimeoutException:
        return "", "LLM 연결 시간 초과로 규칙 기반 리포트만 표시합니다."
    except httpx.RequestError:
        return "", "LLM 연결 실패로 규칙 기반 리포트만 표시합니다."
    except Exception:
        return "", "LLM 처리 실패로 규칙 기반 리포트만 표시합니다."


def _build_report_prompt(report: dict[str, Any]) -> str:
    compact_report = {
        "summary": report.get("summary", {}),
        "top_rules": report.get("top_rules", []),
        "recommendations": report.get("recommendations", []),
        "events": report.get("events", [])[:10],
    }
    return (
        "다음 Kubernetes 컴플라이언스 리포트 JSON을 운영자용으로 요약하세요.\n"
        "출력은 한국어 4~6문장으로 작성하고, 조치 우선순위를 포함하세요.\n\n"
        f"{json.dumps(compact_report, ensure_ascii=False)}"
    )


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


def _normalize_event(
    item: dict[str, Any],
    source: str,
    cluster_name: str = "",
    cluster_kind: str = "customer",
) -> dict[str, Any]:
    normalized = dict(item)
    normalized.setdefault("source", source)
    normalized.setdefault("cluster", cluster_name)
    normalized.setdefault("cluster_kind", cluster_kind)
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
