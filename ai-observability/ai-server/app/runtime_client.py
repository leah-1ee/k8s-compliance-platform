import json
import os
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
import yaml

from app import storage
from app.analyzer import _redact_for_llm
from app.llm_client import LLMClient


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
SYSTEM_NAMESPACE_GUARD = {
    "kube-system",
    "gatekeeper-system",
    "monitoring",
}
HIGH_BLAST_RADIUS_POLICY_MARKERS = (
    "nonroot",
    "non-root",
    "privileged",
    "host",
    "capabilities",
    "hostpath",
    "runas",
    "lowport",
    "port",
)
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

    if _has_gatekeeper_resources(ordered):
        gatekeeper_error = _gatekeeper_installation_error()
        if gatekeeper_error:
            for result in resource_results:
                if _is_gatekeeper_result(result):
                    result["dry_run_status"] = "skipped"
                    result["apply_status"] = "skipped"
                    result["error"] = gatekeeper_error
            return {
                "status": "not_configured",
                "error": gatekeeper_error,
                "cluster_id": cluster.get("id", ""),
                "cluster_name": cluster.get("name", ""),
                "policy_type": policy_type,
                "policy_name": policy_name,
                "resources": resource_results,
                "fallback": _policy_apply_fallback(manifest),
            }

    gatekeeper_constraints = [resource for resource in ordered if _is_gatekeeper_constraint(resource)]
    constraint_template_indexes = [
        index
        for index, resource in enumerate(ordered)
        if _is_constraint_template(resource)
    ]
    preflight_template_indexes: set[int] = set()
    if constraint_template_indexes and gatekeeper_constraints:
        dry_run_failed = False
        for index in constraint_template_indexes:
            resource = ordered[index]
            result = resource_results[index]
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

        template_apply_failed = False
        for index in constraint_template_indexes:
            resource = ordered[index]
            result = resource_results[index]
            error = _server_side_apply(resource, dry_run=False)
            if error:
                result["apply_status"] = "failed"
                result["error"] = error
                template_apply_failed = True
            else:
                result["apply_status"] = "success"
                preflight_template_indexes.add(index)
        if template_apply_failed:
            for index, result in enumerate(resource_results):
                if index not in preflight_template_indexes and result["apply_status"] == "skipped":
                    result["error"] = (
                        "ConstraintTemplate 적용 실패로 Constraint 검증을 진행하지 않았습니다."
                    )
            return {
                "status": "apply_failed",
                "error": "ConstraintTemplate 적용 실패로 Constraint 검증을 진행하지 않았습니다.",
                "cluster_id": cluster.get("id", ""),
                "cluster_name": cluster.get("name", ""),
                "policy_type": policy_type,
                "policy_name": policy_name,
                "resources": resource_results,
                "fallback": _policy_apply_fallback(manifest),
            }

        wait_error = _wait_for_gatekeeper_constraint_discovery(gatekeeper_constraints)
        if wait_error:
            for index, resource in enumerate(ordered):
                if _is_gatekeeper_constraint(resource):
                    resource_results[index]["dry_run_status"] = "failed"
                    resource_results[index]["apply_status"] = "skipped"
                    resource_results[index]["error"] = wait_error
            return {
                "status": "dry_run_failed",
                "error": wait_error,
                "cluster_id": cluster.get("id", ""),
                "cluster_name": cluster.get("name", ""),
                "policy_type": policy_type,
                "policy_name": policy_name,
                "resources": resource_results,
                "fallback": _policy_apply_fallback(manifest),
            }

    dry_run_failed = False
    for index, (resource, result) in enumerate(zip(ordered, resource_results, strict=True)):
        if index in preflight_template_indexes:
            continue
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
    for index, (resource, result) in enumerate(zip(ordered, resource_results, strict=True)):
        if index in preflight_template_indexes:
            continue
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


def policy_blast_radius_warnings(manifest: str) -> list[str]:
    warnings: list[str] = []
    for resource in _parse_policy_manifest(manifest):
        kind = str(resource.get("kind") or "")
        api_version = str(resource.get("apiVersion") or "")
        metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
        spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
        name = str(metadata.get("name") or "")
        namespace = str(metadata.get("namespace") or "")
        if api_version.startswith("constraints.gatekeeper.sh/"):
            action = str(spec.get("enforcementAction") or "deny").lower()
            identity = f"{kind} {name}".lower()
            high_blast_radius = any(marker in identity for marker in HIGH_BLAST_RADIUS_POLICY_MARKERS)
            match = spec.get("match") if isinstance(spec.get("match"), dict) else {}
            excluded = {str(item) for item in match.get("excludedNamespaces", []) if item}
            missing = sorted(SYSTEM_NAMESPACE_GUARD - excluded)
            if action == "deny" and high_blast_radius and missing:
                warnings.append(
                    f"{kind}/{name or 'unnamed'} deny 정책이 시스템 네임스페이스 제외를 누락했습니다: "
                    f"{', '.join(missing)}"
                )
        if kind == "NetworkPolicy" and namespace in SYSTEM_NAMESPACE_GUARD:
            warnings.append(
                f"NetworkPolicy/{name or 'unnamed'}가 시스템 네임스페이스 {namespace}에 적용됩니다."
            )
    return warnings


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


def _is_constraint_template(resource: dict[str, Any]) -> bool:
    return str(resource.get("kind", "")) == "ConstraintTemplate" and str(
        resource.get("apiVersion", "")
    ).startswith("templates.gatekeeper.sh/")


def _is_gatekeeper_constraint(resource: dict[str, Any]) -> bool:
    return str(resource.get("apiVersion", "")).startswith("constraints.gatekeeper.sh/")


def _is_gatekeeper_mutation(resource: dict[str, Any]) -> bool:
    return str(resource.get("apiVersion", "")).startswith("mutations.gatekeeper.sh/")


def _has_gatekeeper_resources(resources: list[dict[str, Any]]) -> bool:
    return any(
        _is_constraint_template(resource)
        or _is_gatekeeper_constraint(resource)
        or _is_gatekeeper_mutation(resource)
        for resource in resources
    )


def _is_gatekeeper_result(result: dict[str, Any]) -> bool:
    api_version = str(result.get("api_version", ""))
    return (
        str(result.get("kind", "")) == "ConstraintTemplate"
        or api_version.startswith("constraints.gatekeeper.sh/")
        or api_version.startswith("mutations.gatekeeper.sh/")
    )


def _gatekeeper_installation_error() -> str:
    for version in ("v1", "v1beta1"):
        discovery = _kube_get(f"/apis/templates.gatekeeper.sh/{version}")
        if not discovery.get("error"):
            return ""
    return (
        "Gatekeeper가 설치되어 있지 않거나 templates.gatekeeper.sh API를 찾을 수 없습니다. "
        "클러스터 관리자가 Gatekeeper를 먼저 설치한 뒤 다시 실행하세요."
    )


def _wait_for_gatekeeper_constraint_discovery(
    resources: list[dict[str, Any]],
    timeout: float = 30,
    interval: float = 1,
) -> str:
    pending = {str(resource.get("kind", "")).strip() for resource in resources if resource.get("kind")}
    if not pending:
        return ""
    deadline = time.monotonic() + timeout
    while pending:
        discovery = _kube_get("/apis/constraints.gatekeeper.sh/v1beta1")
        if not discovery.get("error"):
            for api_resource in discovery.get("body", {}).get("resources", []):
                if not isinstance(api_resource, dict) or "/" in str(api_resource.get("name", "")):
                    continue
                if "patch" in api_resource.get("verbs", []):
                    pending.discard(str(api_resource.get("kind", "")))
        if not pending:
            return ""
        if time.monotonic() >= deadline:
            missing = ", ".join(sorted(pending))
            return f"Gatekeeper Constraint CRD 등록 대기 시간이 초과되었습니다: {missing}"
        time.sleep(interval)
    return ""


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
    if api_version.startswith("templates.gatekeeper.sh/") and kind == "ConstraintTemplate":
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
    gatekeeper_check = _gatekeeper_install_check_command(clean_manifest)
    dry_run = _fallback_commands(clean_manifest, dry_run=True)
    apply = _fallback_commands(clean_manifest, dry_run=False)
    permission_check = _policy_permission_check_command(clean_manifest)
    admin_rbac = _policy_admin_rbac_command(clean_manifest)
    return {
        "gatekeeper_check_command": gatekeeper_check,
        "permission_check_command": permission_check,
        "admin_rbac_command": admin_rbac,
        "dry_run_command": dry_run,
        "apply_command": apply,
        "combined_command": "\n\n".join(
            [
                "# 1) Gatekeeper 설치 확인",
                gatekeeper_check,
                "# 2) 현재 kubeconfig 계정 권한 확인",
                permission_check,
                "# 3) 권한이 부족하면 클러스터 관리자가 먼저 실행",
                admin_rbac,
                "# 4) dry-run 검증",
                dry_run,
                "# 5) 실제 적용",
                apply,
            ]
        ),
    }


def _gatekeeper_install_check_command(manifest: str) -> str:
    if not _manifest_has_gatekeeper_resource(manifest):
        return "echo 'Gatekeeper 리소스가 없어 설치 확인을 건너뜁니다.'"
    return "\n".join(
        [
            "kubectl get crd constrainttemplates.templates.gatekeeper.sh",
            "kubectl api-resources --api-group=templates.gatekeeper.sh",
            "kubectl get pods -n gatekeeper-system",
            (
                "# 위 명령이 실패하면 클러스터 관리자가 Gatekeeper를 먼저 설치한 뒤 "
                "정책 적용을 다시 실행하세요."
            ),
        ]
    )


def _policy_permission_check_command(manifest: str) -> str:
    namespaces = _manifest_namespaces(manifest)
    namespace = sorted(namespaces)[0] if namespaces else "default"
    commands = [
        "kubectl auth can-i get constrainttemplates.templates.gatekeeper.sh",
        "kubectl auth can-i create constrainttemplates.templates.gatekeeper.sh",
        "kubectl auth can-i patch constrainttemplates.templates.gatekeeper.sh",
        "kubectl auth can-i create '*.constraints.gatekeeper.sh'",
        "kubectl auth can-i patch '*.constraints.gatekeeper.sh'",
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

CURRENT_KUBE_USER="$(kubectl config view --minify -o jsonpath='{{.contexts[0].context.user}}')"
if [ -n "${{CURRENT_KUBE_USER}}" ]; then
  kubectl create clusterrolebinding kubeowl-policy-applier-current-user \\
    --clusterrole=kubeowl-policy-applier \\
    --user="${{CURRENT_KUBE_USER}}" \\
    --dry-run=client -o yaml | kubectl apply -f -
else
  echo "현재 kubeconfig user를 찾지 못해 사용자 ClusterRoleBinding을 건너뜁니다."
fi

kubectl create serviceaccount kubeowl-policy-applier -n default \\
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create clusterrolebinding kubeowl-policy-applier-sa \\
  --clusterrole=kubeowl-policy-applier \\
  --serviceaccount=default:kubeowl-policy-applier \\
  --dry-run=client -o yaml | kubectl apply -f -"""


def _manifest_has_kind(manifest: str, kind: str) -> bool:
    try:
        return any(resource.get("kind") == kind for resource in _parse_policy_manifest(manifest))
    except ValueError:
        return False


def _manifest_has_gatekeeper_resource(manifest: str) -> bool:
    try:
        return _has_gatekeeper_resources(_parse_policy_manifest(manifest))
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

    template_manifest = _dump_manifest_docs(templates)
    other_manifest = _dump_manifest_docs(others)
    if dry_run:
        commands = [
            (
                "# ConstraintTemplate dry-run은 Constraint CRD를 실제 등록하지 않으므로 "
                "템플릿을 먼저 검증합니다."
            ),
            _heredoc_command("kubectl apply --dry-run=server -f -", template_manifest, "KUBEOWL_TEMPLATE_DRY_RUN_EOF"),
            "# Constraint kind 검증을 위해 ConstraintTemplate은 실제 적용합니다.",
            _heredoc_command("kubectl apply -f -", template_manifest, "KUBEOWL_TEMPLATE_EOF"),
            "kubectl wait --for=condition=Established crd -l gatekeeper.sh/constraint=true --timeout=60s",
            _heredoc_command("kubectl apply --dry-run=server -f -", other_manifest, "KUBEOWL_CONSTRAINT_DRY_RUN_EOF"),
        ]
        return "\n\n".join(commands)

    commands = [
        _heredoc_command(verb, template_manifest, "KUBEOWL_TEMPLATE_EOF"),
        "kubectl wait --for=condition=Established crd -l gatekeeper.sh/constraint=true --timeout=60s",
        _heredoc_command(verb, other_manifest, "KUBEOWL_CONSTRAINT_EOF"),
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


def get_runtime_summary(user_id: str = "", cluster: str = "") -> dict[str, Any]:
    summary = storage.event_summary(user_id=user_id, cluster=cluster)
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
    if user_id:
        applied_policy_count = storage.count_policy_apply_history(user_id=user_id, statuses={"applied"})
        guided_policy_count = storage.count_policy_apply_history(user_id=user_id, statuses={"not_configured"})
        active_policies = {
            "count": applied_policy_count + guided_policy_count,
            "source": "user_policy_apply_history",
            "error": "",
            "applied": applied_policy_count,
            "generated_guides": guided_policy_count,
        }
    else:
        active_policies = _count_gatekeeper_constraints()
    return {
        "active_policies": active_policies.get("count"),
        "active_policies_source": active_policies.get("source", "unknown"),
        "active_policies_error": active_policies.get("error", ""),
        "active_policies_applied": active_policies.get("applied"),
        "active_policies_generated_guides": active_policies.get("generated_guides"),
        "recent_violations": int(summary.get("recent_24h", 0) or 0),
        "runtime_events": int(summary.get("total_events", 0) or 0),
        "last_sync": last_sync,
    }


def build_user_observability_summary(user_id: str) -> dict[str, Any]:
    summary = get_runtime_summary(user_id=user_id)
    clusters = storage.list_clusters(user_id=user_id, include_deleted=False)
    recent_events = storage.list_events(limit=5, user_id=user_id)
    active_clusters = [cluster for cluster in clusters if cluster.get("status") == "active"]
    disabled_clusters = [cluster for cluster in clusters if cluster.get("status") == "disabled"]
    return {
        "scope": "user_owned_clusters",
        "clusters": [
            {
                "id": cluster.get("id", ""),
                "name": cluster.get("name", ""),
                "kind": cluster.get("kind", "customer"),
                "status": cluster.get("status", "active"),
                "last_seen_at": cluster.get("last_seen_at", ""),
                "event_count": int(cluster.get("event_count", 0) or 0),
                "slack_enabled": bool(cluster.get("slack_enabled", True)),
            }
            for cluster in clusters
        ],
        "cluster_counts": {
            "total": len(clusters),
            "active": len(active_clusters),
            "disabled": len(disabled_clusters),
        },
        "event_counts": {
            "total": int(summary.get("total_events", 0) or 0),
            "recent_24h": int(summary.get("recent_24h", 0) or 0),
        },
        "breakdowns": {
            "severity": _top_items(summary.get("by_severity", {}), limit=6),
            "rule": _top_items(summary.get("by_rule", {}), limit=6),
            "namespace": _top_items(summary.get("by_namespace", {}), limit=6),
            "action": _top_items(summary.get("by_action", {}), limit=6),
        },
        "recent_events": [
            {
                "id": event.get("id", ""),
                "cluster": event.get("cluster", ""),
                "cluster_id": event.get("cluster_id", ""),
                "rule": event.get("rule", ""),
                "severity": event.get("severity", ""),
                "namespace": event.get("namespace", ""),
                "pod_name": event.get("pod_name", ""),
                "timestamp": event.get("timestamp", "") or event.get("created_at", ""),
            }
            for event in recent_events
        ],
        "policy_counts": {
            "applied": storage.count_policy_apply_history(user_id=user_id, statuses={"applied"}),
            "generated_guides": storage.count_policy_apply_history(user_id=user_id, statuses={"not_configured"}),
        },
        "last_sync": summary.get("last_seen_at") or summary.get("latest_event_at") or "",
    }


def _top_items(values: dict[str, int], limit: int = 5) -> list[dict[str, Any]]:
    return [
        {"label": str(label), "count": int(count or 0)}
        for label, count in sorted(values.items(), key=lambda item: item[1], reverse=True)[:limit]
    ]


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


def record_gatekeeper_event(
    payload: dict[str, Any],
    cluster_id: str = "",
    cluster_name: str = "",
    cluster_kind: str = "customer",
) -> dict[str, Any]:
    # Gatekeeper deny/audit 이벤트를 UI 위반 목록과 같은 형태로 정규화
    now = datetime.now(timezone.utc).isoformat()
    raw_event = payload.get("event", payload)
    if not isinstance(raw_event, dict):
        raw_event = {}
    review = raw_event.get("review", {}) if isinstance(raw_event.get("review"), dict) else {}
    obj = review.get("object", {}) if isinstance(review.get("object"), dict) else {}
    metadata = obj.get("metadata", {}) if isinstance(obj.get("metadata"), dict) else {}
    involved = raw_event.get("involvedObject", {}) if isinstance(raw_event.get("involvedObject"), dict) else {}
    namespace = raw_event.get("namespace") or metadata.get("namespace", "") or involved.get("namespace", "")
    name = raw_event.get("pod_name") or metadata.get("name", "") or involved.get("name", "")
    message = (
        raw_event.get("message")
        or raw_event.get("reason")
        or raw_event.get("note")
        or "Gatekeeper admission denied the request."
    )
    event = {
        "timestamp": (
            raw_event.get("timestamp")
            or raw_event.get("eventTime")
            or raw_event.get("lastTimestamp")
            or metadata.get("creationTimestamp")
            or now
        ),
        "source": "gatekeeper",
        "cluster_id": cluster_id or raw_event.get("cluster_id", ""),
        "cluster": cluster_name or raw_event.get("cluster") or DEMO_CLUSTER_NAME,
        "cluster_kind": cluster_kind or raw_event.get("cluster_kind") or "demo",
        "rule": raw_event.get("constraint") or raw_event.get("rule") or "Gatekeeper deny",
        "priority": "Warning",
        "severity": raw_event.get("severity") or "medium",
        "classification_source": "gatekeeper",
        "classification_reason": message,
        "confidence": 0.82,
        "namespace": namespace,
        "pod_name": name,
        "container_name": raw_event.get("container_name", ""),
        "image": raw_event.get("image", ""),
        "user": raw_event.get("user", ""),
        "command": raw_event.get("command", ""),
        "action_taken": "deny",
        "raw_event": raw_event,
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
    cluster: str = "",
    cluster_kind: str = "",
    include_legacy: bool = False,
    user_id: str = "",
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> dict[str, Any]:
    normalized_cluster = str(cluster or "").strip()
    summary = get_runtime_summary(user_id=user_id, cluster=normalized_cluster)
    events = list_runtime_events(
        limit=100,
        cluster=normalized_cluster,
        cluster_kind=cluster_kind,
        include_legacy=include_legacy,
        user_id=user_id,
    )["events"]
    report = _build_structured_report(summary, events, cluster=normalized_cluster)
    llm_report = _safe_llm_structured_report(report, llm_provider, llm_api_key)
    return llm_report or report


def _build_structured_report(
    summary: dict[str, Any],
    events: list[dict[str, Any]],
    cluster: str = "",
) -> dict[str, Any]:
    normalized_cluster = str(cluster or "").strip()
    total_violations = int(summary.get("total_events", 0) or len(events))
    affected_clusters = {event.get("cluster") for event in events if event.get("cluster")}
    affected_namespaces = {event.get("namespace") for event in events if event.get("namespace")}
    affected_pods = {event.get("pod_name") for event in events if event.get("pod_name")}
    top_rules = sorted(summary.get("by_rule", {}).items(), key=lambda item: item[1], reverse=True)[:5]
    overall_severity = _report_overall_severity(summary, events)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "type": "cluster" if normalized_cluster else "all_clusters",
            "label": normalized_cluster or "전체 클러스터",
            "cluster": normalized_cluster,
        },
        "summary": {
            "total_violations": total_violations,
            "severity": overall_severity,
            "affected_clusters": len(affected_clusters),
            "affected_namespaces": len(affected_namespaces),
            "affected_pods": len(affected_pods),
            "description": _report_description(total_violations, overall_severity, top_rules, affected_namespaces),
        },
        "top_rules": [
            {
                "rule": rule,
                "count": int(count or 0),
                "severity": _rule_report_severity(rule, events),
            }
            for rule, count in top_rules
        ],
        "blast_radius": _report_blast_radius(events),
        "timeline": _report_timeline(events),
        "recommendations": _report_recommendations(summary, events),
        "next_actions": _report_next_actions(total_violations),
    }
    return report


def _safe_llm_structured_report(
    report: dict[str, Any],
    llm_provider: str | None,
    llm_api_key: str | None,
) -> dict[str, Any] | None:
    client = LLMClient(provider=llm_provider, api_key=llm_api_key)
    if not client.configured:
        return None
    try:
        raw_text = client.complete_text(
            _build_report_prompt(report),
            (
                "You are a Kubernetes compliance analyst. "
                "Return only a valid JSON object matching the requested schema. "
                "Do not invent clusters, namespaces, pods, rules, times, or counts."
            ),
            max_tokens=1800,
        )
        parsed = _parse_llm_report_json(raw_text)
        return _normalize_report_payload(parsed, fallback=report)
    except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.RequestError):
        return None
    except Exception:
        return None


def _build_report_prompt(report: dict[str, Any]) -> str:
    redacted_report = _redact_for_llm(report)
    return (
        "Given Falco/Gatekeeper events and metrics, return ONLY a JSON object. "
        "No markdown, no explanation, no preamble.\n\n"
        "The JSON must follow this exact structure:\n\n"
        "{\n"
        '  "generated_at": "<ISO8601 timestamp>",\n'
        '  "summary": {\n'
        '    "total_violations": <number>,\n'
        '    "severity": "<Critical|High|Medium|Low>",\n'
        '    "affected_clusters": <number>,\n'
        '    "affected_namespaces": <number>,\n'
        '    "affected_pods": <number>,\n'
        '    "description": "<2-3 sentence plain Korean summary of what happened and why it matters>"\n'
        "  },\n"
        '  "top_rules": [\n'
        '    {"rule": "<rule name>", "count": <number>, "severity": "<Critical|High|Medium|Low>"}\n'
        "  ],\n"
        '  "blast_radius": [\n'
        '    {"cluster": "<cluster name>", "namespace": "<namespace>", "pod": "<pod name>", "rule": "<rule name>", "time": "<ISO8601 timestamp>"}\n'
        "  ],\n"
        '  "timeline": [\n'
        '    {"hour": "<HH:00>", "count": <number>}\n'
        "  ],\n"
        '  "recommendations": ["<actionable Korean sentence>"],\n'
        '  "next_actions": [\n'
        '    {"label": "<button label; use Policy Generator for policy_generator>", "target": "<violation_detail|policy_generator|grafana>"}\n'
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- All Korean text must be natural, concise, and operator-friendly.\n"
        "- Do not include any field outside this schema.\n"
        "- Do not wrap the output in markdown code blocks.\n"
        "- If a field has no data, use null or empty array, never omit the key.\n\n"
        "Use the following already-computed report values. Preserve counts, times, rule names, and targets exactly unless you are only improving Korean wording:\n\n"
        f"{json.dumps(redacted_report, ensure_ascii=False)}"
    )


def _parse_llm_report_json(text: str) -> dict[str, Any]:
    cleaned = str(text or "").strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("LLM report must be a JSON object")
    return parsed


def _normalize_report_payload(payload: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    fallback_summary = fallback["summary"]
    fallback_scope = fallback.get("scope") if isinstance(fallback.get("scope"), dict) else {}
    normalized = {
        "generated_at": str(payload.get("generated_at") or fallback.get("generated_at") or datetime.now(timezone.utc).isoformat()),
        "scope": {
            "type": str(fallback_scope.get("type") or "all_clusters"),
            "label": str(fallback_scope.get("label") or "전체 클러스터"),
            "cluster": str(fallback_scope.get("cluster") or ""),
        },
        "summary": {
            "total_violations": _int_or_default(summary.get("total_violations"), fallback_summary["total_violations"]),
            "severity": _report_severity_label(summary.get("severity") or fallback_summary["severity"]),
            "affected_clusters": _int_or_default(summary.get("affected_clusters"), fallback_summary["affected_clusters"]),
            "affected_namespaces": _int_or_default(summary.get("affected_namespaces"), fallback_summary["affected_namespaces"]),
            "affected_pods": _int_or_default(summary.get("affected_pods"), fallback_summary["affected_pods"]),
            "description": str(summary.get("description") or fallback_summary["description"]),
        },
        "top_rules": _normalize_report_list(payload.get("top_rules"), fallback["top_rules"], _normalize_top_rule),
        "blast_radius": _normalize_report_list(payload.get("blast_radius"), fallback["blast_radius"], _normalize_blast_radius_item),
        "timeline": _normalize_report_list(payload.get("timeline"), fallback["timeline"], _normalize_timeline_item),
        "recommendations": _normalize_string_list(payload.get("recommendations"), fallback["recommendations"]),
        "next_actions": _normalize_report_list(payload.get("next_actions"), fallback["next_actions"], _normalize_next_action),
    }
    return normalized


def _normalize_report_list(value: Any, fallback: list[dict[str, Any]], normalizer) -> list[dict[str, Any]]:
    items = value if isinstance(value, list) else fallback
    normalized = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(normalizer(item))
    return normalized


def _normalize_string_list(value: Any, fallback: list[str]) -> list[str]:
    items = value if isinstance(value, list) else fallback
    return [str(item) for item in items if str(item or "").strip()]


def _normalize_top_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule": _nullable_text(item.get("rule")),
        "count": _int_or_default(item.get("count"), 0),
        "severity": _report_severity_label(item.get("severity")),
    }


def _normalize_blast_radius_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cluster": _nullable_text(item.get("cluster")),
        "namespace": _nullable_text(item.get("namespace")),
        "pod": _nullable_text(item.get("pod")),
        "rule": _nullable_text(item.get("rule")),
        "time": _nullable_text(item.get("time")),
    }


def _normalize_timeline_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "hour": _nullable_text(item.get("hour")),
        "count": _int_or_default(item.get("count"), 0),
    }


def _normalize_next_action(item: dict[str, Any]) -> dict[str, Any]:
    target = str(item.get("target") or "").strip()
    if target not in {"violation_detail", "policy_generator", "grafana"}:
        target = "violation_detail"
    if target == "policy_generator":
        return {
            "label": "Policy Generator",
            "target": target,
        }
    return {
        "label": _nullable_text(item.get("label")) or "위반 상세에서 확인",
        "target": target,
    }


def _report_overall_severity(summary: dict[str, Any], events: list[dict[str, Any]]) -> str:
    by_severity = {str(key).lower(): int(value or 0) for key, value in summary.get("by_severity", {}).items()}
    if by_severity.get("critical", 0):
        return "Critical"
    if by_severity.get("high", 0):
        return "High"
    if by_severity.get("medium", 0):
        return "Medium"
    if by_severity.get("low", 0) or events:
        return "Low"
    return "Low"


def _report_description(
    total_violations: int,
    severity: str,
    top_rules: list[tuple[str, Any]],
    affected_namespaces: set[str],
) -> str:
    if total_violations <= 0:
        return "최근 수집된 Falco/Gatekeeper 위반은 없습니다. 수집 파이프라인과 Grafana 지표가 정상인지 주기적으로 확인하세요."
    top_rule = top_rules[0][0] if top_rules else "알 수 없는 rule"
    namespace_text = f"{len(affected_namespaces)}개 네임스페이스" if affected_namespaces else "확인 가능한 네임스페이스 없음"
    return (
        f"최근 수집된 위반은 총 {total_violations}건이며 최고 심각도는 {severity}입니다. "
        f"가장 많이 발생한 rule은 {top_rule}이고, 영향 범위는 {namespace_text}로 집계되었습니다."
    )


def _rule_report_severity(rule: str, events: list[dict[str, Any]]) -> str:
    severities = [
        _report_severity_label(event.get("severity"))
        for event in events
        if event.get("rule") == rule
    ]
    return _highest_report_severity(severities)


def _report_blast_radius(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "cluster": _nullable_text(event.get("cluster")),
            "namespace": _nullable_text(event.get("namespace")),
            "pod": _nullable_text(event.get("pod_name")),
            "rule": _nullable_text(event.get("rule")),
            "time": _nullable_text(event.get("timestamp") or event.get("created_at")),
        }
        for event in events[:25]
    ]


def _report_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, int] = {}
    for event in events:
        timestamp = _parse_event_time(event.get("timestamp") or event.get("created_at"))
        if timestamp is None:
            continue
        hour = f"{timestamp.hour:02d}:00"
        buckets[hour] = buckets.get(hour, 0) + 1
    return [{"hour": hour, "count": buckets[hour]} for hour in sorted(buckets)]


def _report_next_actions(total_violations: int) -> list[dict[str, str]]:
    actions = []
    if total_violations > 0:
        actions.append({"label": "Violation Detail에서 확인", "target": "violation_detail"})
    actions.extend(
        [
            {"label": "Policy Generator", "target": "policy_generator"},
            {"label": "Grafana에서 추이 보기", "target": "grafana"},
        ]
    )
    return actions


def _parse_event_time(value: Any) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _highest_report_severity(values: list[str]) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    if not values:
        return "Low"
    return max(values, key=lambda item: order.get(item, 0))


def _report_severity_label(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "crit"}:
        return "Critical"
    if normalized in {"high", "error", "alert", "emergency"}:
        return "High"
    if normalized in {"medium", "warning", "notice"}:
        return "Medium"
    return "Low"


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _nullable_text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _report_recommendations(summary: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    recommendations = []
    by_severity = summary.get("by_severity", {})
    if by_severity.get("high", 0):
        recommendations.append(
            "High 이벤트는 Violation Detail에서 영향 cluster, namespace, pod를 먼저 확인하세요."
        )
    if by_severity.get("medium", 0):
        recommendations.append(
            "Medium 이벤트는 같은 rule과 namespace에서 반복되는지 확인한 뒤 정책 예외 여부를 검토하세요."
        )
    if any(event.get("source") == "gatekeeper" for event in events):
        recommendations.append(
            "Gatekeeper deny 이벤트는 실패한 매니페스트를 수정하고 server-side dry-run으로 재검증하세요."
        )
    if any(event.get("source") == "sidekick" for event in events):
        recommendations.append(
            "Falco Sidekick 이벤트는 실행 중 프로세스, 사용자, 이미지, 서비스 계정 권한을 함께 확인하세요."
        )
    if not recommendations:
        recommendations.append(
            "최근 수집된 위반이 없거나 낮은 위험입니다. Sidekick ingest, Gatekeeper audit, Grafana scrape 상태를 주기적으로 확인하세요."
        )
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
