import re
from textwrap import dedent

import httpx

from app.llm_client import LLMClient
from app.prompts import build_policy_prompt
from app.schemas import PolicyGenerationRequest, PolicyGenerationResponse, PolicyKind


DEFAULT_EXCLUDED_NAMESPACES = [
    "kube-system",
    "gatekeeper-system",
    "kube-flannel",
    "monitoring",
]
DEFAULT_ALLOWED_REGISTRIES = [
    "docker.io/library/",
    "gcr.io/",
    "ghcr.io/",
    "registry.k8s.io/",
]
SUPPORTED_POLICY_EXAMPLES = [
    "latest 태그를 사용하는 컨테이너 이미지를 금지해줘",
    "non-root 실행을 강제하는 정책을 만들어줘",
    "허용된 이미지 레지스트리만 사용하게 해줘",
    "host namespace 사용을 금지해줘",
    "securityContext를 자동 주입해줘",
    "resource limits를 자동 주입해줘",
    "ingress 네트워크 정책 만들어줘",
]


class UnsupportedPolicyError(ValueError):
    """Raised when a natural-language policy request is outside the template set."""

    def __init__(self, prompt: str) -> None:
        self.prompt = prompt
        super().__init__(
            "지원하지 않는 정책 요청입니다. 현재는 latest 태그 금지, non-root 강제, "
            "레지스트리 제한, host namespace 금지, securityContext/resource limits 자동 주입, "
            "NetworkPolicy 생성만 지원합니다."
        )


def generate_policy(
    request: PolicyGenerationRequest,
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> PolicyGenerationResponse:
    # 정책 유형 판별
    policy_kind = request.policy_kind or _detect_policy_kind(request.prompt)
    if policy_kind is None:
        raise UnsupportedPolicyError(request.prompt)
    constraint_name = _safe_name(request.constraint_name)
    excluded_namespaces = request.excluded_namespaces or DEFAULT_EXCLUDED_NAMESPACES
    allowed_registries = request.allowed_registries or DEFAULT_ALLOWED_REGISTRIES

    if policy_kind == "latest-tag":
        rego, template, constraint = _latest_tag_policy(
            constraint_name,
            request.enforcement_action,
            excluded_namespaces,
        )
    elif policy_kind == "non-root":
        rego, template, constraint = _non_root_policy(
            constraint_name,
            request.enforcement_action,
            excluded_namespaces,
        )
    elif policy_kind == "allowed-registries":
        rego, template, constraint = _allowed_registries_policy(
            constraint_name,
            request.enforcement_action,
            excluded_namespaces,
            allowed_registries,
        )
    elif policy_kind == "host-namespace":
        rego, template, constraint = _host_namespace_policy(
            constraint_name,
            request.enforcement_action,
            excluded_namespaces,
        )
    elif policy_kind == "security-context-mutation":
        rego, template, constraint = _security_context_mutation_policy(excluded_namespaces)
    elif policy_kind == "resource-limits-mutation":
        rego, template, constraint = _resource_limits_mutation_policy(excluded_namespaces)
    else:
        rego, template, constraint = _network_policy(constraint_name, request.prompt)

    prompt = build_policy_prompt(
        request,
        policy_kind,
        {
            "ConstraintTemplate": template,
            "Constraint or Manifest": constraint,
            "Rego": rego,
        },
    )
    llm_review = ""
    llm_error = ""
    llm_used = False
    if request.use_llm:
        llm_review, llm_error = _safe_llm_review(prompt, llm_provider, llm_api_key)
        llm_review = _complete_review(
            llm_review,
            policy_kind,
            request.enforcement_action,
            excluded_namespaces,
        )
        llm_used = bool(llm_review)

    return PolicyGenerationResponse(
        policy_kind=policy_kind,
        constraint_template=template,
        constraint=constraint,
        rego=rego,
        review_notes=[
            "생성 정책 적용 전 테스트 네임스페이스 검증 필요",
            "운영 적용 전 enforcementAction 단계적 전환 권장",
            "예외 네임스페이스와 이미지 레지스트리 범위 검토 필요",
        ],
        prompt=prompt,
        llm_used=llm_used,
        llm_review=llm_review,
        llm_error=llm_error,
    )


def _safe_llm_review(
    prompt: str,
    llm_provider: str | None,
    llm_api_key: str | None,
) -> tuple[str, str]:
    # LLM 장애 격리
    client = LLMClient(provider=llm_provider, api_key=llm_api_key)
    if not client.configured:
        return (
            "",
            "LLM API key가 설정되어 있지 않습니다. 서버 GOOGLE_API_KEY 또는 세션 API key를 확인하세요.",
        )
    try:
        review = client.review_policy(prompt)
        if not review:
            return "", "LLM 응답이 비어 있습니다. API key, provider, model 설정을 확인하세요."
        return review, ""
    except httpx.HTTPStatusError as error:
        return "", _format_llm_http_error(error)
    except httpx.TimeoutException:
        return "", "LLM 연결 시간 초과: VM의 외부 HTTPS 연결 또는 provider endpoint 설정을 확인하세요."
    except httpx.RequestError:
        return (
            "",
            "LLM 연결 실패: VM에서 generativelanguage.googleapis.com 접속 가능 여부와 provider endpoint 설정을 확인하세요.",
        )
    except Exception:
        return "", "LLM 처리 실패: provider와 model 설정을 확인하세요."


def _format_llm_http_error(error: httpx.HTTPStatusError) -> str:
    # Provider 오류 본문 요약
    status_code = error.response.status_code
    provider_message = ""
    provider_status = ""
    try:
        body = error.response.json()
        if isinstance(body, dict):
            detail = body.get("error", body)
            if isinstance(detail, dict):
                provider_message = str(detail.get("message", ""))
                provider_status = str(detail.get("status", ""))
            elif isinstance(detail, str):
                provider_message = detail
    except ValueError:
        provider_message = error.response.text.strip()

    provider_message = re.sub(r"\s+", " ", provider_message)[:220]
    if status_code in {401, 403}:
        reason = "API key 권한 또는 결제/프로젝트 접근 권한 문제일 가능성이 큽니다."
    elif status_code == 404:
        reason = "provider 또는 model 이름이 현재 계정/엔드포인트에서 유효하지 않을 수 있습니다."
    elif status_code == 429:
        reason = "요청 한도 또는 quota 초과입니다."
    elif status_code in {500, 502, 503, 504}:
        reason = "LLM 제공자 서버나 선택한 모델이 일시적으로 응답하지 않는 상태입니다."
    else:
        reason = "provider, model, API key, 요청 형식을 확인하세요."

    status_suffix = f" ({provider_status})" if provider_status else ""
    message_suffix = f" Provider 메시지: {provider_message}" if provider_message else ""
    return f"LLM 요청 실패: HTTP {status_code}{status_suffix}. {reason}{message_suffix}"


def _detect_policy_kind(prompt: str) -> PolicyKind | None:
    # 키워드 기반 분류
    normalized = prompt.lower()
    if (
        "networkpolicy" in normalized
        or "network policy" in normalized
        or "network-policy" in normalized
        or "네트워크 정책" in normalized
        or "네트워크정책" in normalized
        or "ingress" in normalized
        or "인그레스" in normalized
    ):
        return "network-policy"
    if "latest" in normalized or "태그" in normalized:
        return "latest-tag"
    if "resource" in normalized or "limit" in normalized or "리소스" in normalized:
        return "resource-limits-mutation"
    if "mutation" in normalized or "주입" in normalized or "자동" in normalized:
        return "security-context-mutation"
    if "non-root" in normalized or "non root" in normalized or "root" in normalized:
        return "non-root"
    if "registry" in normalized or "레지스트리" in normalized or "image repo" in normalized:
        return "allowed-registries"
    if "host" in normalized or "namespace" in normalized or "네임스페이스" in normalized:
        return "host-namespace"
    return None


def _complete_review(
    review: str,
    policy_kind: PolicyKind,
    enforcement_action: str,
    excluded_namespaces: list[str],
) -> str:
    # LLM이 일부 항목만 반환해도 UI에는 일관된 4줄 검토를 표시
    if not review:
        return ""
    defaults = _default_review_lines(policy_kind, enforcement_action, excluded_namespaces)
    lines_by_label: dict[str, str] = {}
    ordered_labels = ["정책 의도", "적용 범위", "주의할 점", "운영 권장사항"]
    for line in review.splitlines():
        normalized = line.strip()
        for label in ordered_labels:
            if normalized.startswith(f"{label}:"):
                lines_by_label[label] = normalized
                break
    for line in review.splitlines():
        if len(lines_by_label) >= 4:
            break
        normalized = line.strip()
        if normalized and not any(normalized.startswith(f"{label}:") for label in ordered_labels):
            missing = next(label for label in ordered_labels if label not in lines_by_label)
            lines_by_label[missing] = f"{missing}: {normalized}"

    return "\n".join(lines_by_label.get(label, defaults[label]) for label in ordered_labels)


def _default_review_lines(
    policy_kind: PolicyKind,
    enforcement_action: str,
    excluded_namespaces: list[str],
) -> dict[str, str]:
    excluded = ", ".join(excluded_namespaces)
    intent_by_kind = {
        "latest-tag": "컨테이너 이미지의 latest 태그와 태그 누락을 차단합니다.",
        "non-root": "Pod 컨테이너가 root 권한으로 실행되지 않도록 강제합니다.",
        "allowed-registries": "허용된 이미지 레지스트리 외의 이미지를 차단합니다.",
        "host-namespace": "hostPID, hostIPC, hostNetwork 사용을 차단합니다.",
        "security-context-mutation": "누락된 securityContext 기본값을 Pod 컨테이너에 자동 주입합니다.",
        "resource-limits-mutation": "누락된 CPU와 메모리 limit 값을 Pod 컨테이너에 자동 주입합니다.",
        "network-policy": "선택한 방향의 기본 네트워크 트래픽을 NetworkPolicy로 제한합니다.",
    }
    scope = (
        "적용 범위: 생성된 NetworkPolicy의 namespace와 podSelector 대상 Pod에 적용됩니다."
        if policy_kind == "network-policy"
        else f"적용 범위: Pod 리소스에 적용되며 {excluded} 네임스페이스는 제외됩니다."
    )
    caution = (
        "주의할 점: podSelector가 비어 있으면 namespace 내 모든 Pod에 적용될 수 있습니다."
        if policy_kind == "network-policy"
        else "주의할 점: 기존 워크로드가 정책 조건을 만족하지 않으면 배포가 거부될 수 있습니다."
    )
    recommendation = (
        "운영 권장사항: 테스트 네임스페이스에서 통신 영향도를 먼저 확인하세요."
        if policy_kind == "network-policy"
        else f"운영 권장사항: {enforcement_action} 적용 전 테스트 네임스페이스에서 검증하세요."
    )
    return {
        "정책 의도": f"정책 의도: {intent_by_kind[policy_kind]}",
        "적용 범위": scope,
        "주의할 점": caution,
        "운영 권장사항": recommendation,
    }


def _safe_name(value: str) -> str:
    # 리소스 이름 정규화
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    return normalized or "generated-policy"


def _yaml_list(values: list[str], indent: int = 10) -> str:
    # YAML 목록 생성
    padding = " " * indent
    return "\n".join(f'{padding}- "{value}"' for value in values)


def _latest_tag_policy(
    name: str,
    enforcement_action: str,
    excluded_namespaces: list[str],
) -> tuple[str, str, str]:
    # latest 태그 정책
    rego = dedent(
        """
        package k8sdisallowlatesttag

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          endswith(container.image, ":latest")
          msg := sprintf("container <%v> uses the latest image tag", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not contains(container.image, ":")
          msg := sprintf("container <%v> does not specify an immutable image tag", [container.name])
        }
        """
    ).strip()
    template = _template_yaml("K8sDisallowLatestTag", "k8sdisallowlatesttag", rego)
    constraint = _constraint_yaml("K8sDisallowLatestTag", name, enforcement_action, excluded_namespaces)
    return rego, template, constraint


def _non_root_policy(
    name: str,
    enforcement_action: str,
    excluded_namespaces: list[str],
) -> tuple[str, str, str]:
    # non-root 정책
    rego = dedent(
        """
        package k8srequirenonroot

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.securityContext.runAsNonRoot
          msg := sprintf("container <%v> must set securityContext.runAsNonRoot to true", [container.name])
        }
        """
    ).strip()
    template = _template_yaml("K8sRequireNonRoot", "k8srequirenonroot", rego)
    constraint = _constraint_yaml("K8sRequireNonRoot", name, enforcement_action, excluded_namespaces)
    return rego, template, constraint


def _allowed_registries_policy(
    name: str,
    enforcement_action: str,
    excluded_namespaces: list[str],
    allowed_registries: list[str],
) -> tuple[str, str, str]:
    # 레지스트리 제한 정책
    rego = dedent(
        """
        package k8sallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not starts_with_allowed_repo(container.image)
          msg := sprintf("container <%v> has an invalid image repo <%v>", [container.name, container.image])
        }

        starts_with_allowed_repo(image) {
          repo := input.parameters.repos[_]
          startswith(image, repo)
        }
        """
    ).strip()
    template = _template_yaml("K8sAllowedRepos", "k8sallowedrepos", rego, parameters=True)
    constraint = _constraint_yaml(
        "K8sAllowedRepos",
        name,
        enforcement_action,
        excluded_namespaces,
        parameters=f"  parameters:\n    repos:\n{_yaml_list(allowed_registries, indent=6)}",
    )
    return rego, template, constraint


def _host_namespace_policy(
    name: str,
    enforcement_action: str,
    excluded_namespaces: list[str],
) -> tuple[str, str, str]:
    # host namespace 정책
    rego = dedent(
        """
        package k8sdisallowhostnamespace

        violation[{"msg": "hostPID is not allowed"}] {
          input.review.object.spec.hostPID == true
        }

        violation[{"msg": "hostIPC is not allowed"}] {
          input.review.object.spec.hostIPC == true
        }

        violation[{"msg": "hostNetwork is not allowed"}] {
          input.review.object.spec.hostNetwork == true
        }
        """
    ).strip()
    template = _template_yaml("K8sDisallowHostNamespace", "k8sdisallowhostnamespace", rego)
    constraint = _constraint_yaml("K8sDisallowHostNamespace", name, enforcement_action, excluded_namespaces)
    return rego, template, constraint


def _security_context_mutation_policy(excluded_namespaces: list[str]) -> tuple[str, str, str]:
    # securityContext 주입 정책
    mutation = _assign_yaml(
        "assign-run-as-non-root",
        "securityContext.runAsNonRoot 가 없는 컨테이너에 true 를 자동 주입합니다.",
        "spec.containers[name:*].securityContext.runAsNonRoot",
        "true",
        excluded_namespaces,
        is_string=False,
    )
    mutation += "\n---\n" + _assign_yaml(
        "assign-read-only-root-filesystem",
        "securityContext.readOnlyRootFilesystem 가 없는 컨테이너에 true 를 자동 주입합니다.",
        "spec.containers[name:*].securityContext.readOnlyRootFilesystem",
        "true",
        excluded_namespaces,
        is_string=False,
    )
    mutation += "\n---\n" + _assign_yaml(
        "assign-run-as-non-root-init",
        "initContainer의 securityContext.runAsNonRoot 가 없는 경우 true 를 자동 주입합니다.",
        "spec.initContainers[name:*].securityContext.runAsNonRoot",
        "true",
        excluded_namespaces,
        is_string=False,
    )
    mutation += "\n---\n" + _assign_yaml(
        "assign-read-only-root-filesystem-init",
        "initContainer의 securityContext.readOnlyRootFilesystem 가 없는 경우 true 를 자동 주입합니다.",
        "spec.initContainers[name:*].securityContext.readOnlyRootFilesystem",
        "true",
        excluded_namespaces,
        is_string=False,
    )
    return "", "", mutation


def _resource_limits_mutation_policy(excluded_namespaces: list[str]) -> tuple[str, str, str]:
    # resource limits 주입 정책
    mutation = _assign_yaml(
        "assign-cpu-limit",
        "resources.limits.cpu 가 없는 컨테이너에 500m 을 자동 주입합니다.",
        "spec.containers[name:*].resources.limits.cpu",
        "500m",
        excluded_namespaces,
    )
    mutation += "\n---\n" + _assign_yaml(
        "assign-memory-limit",
        "resources.limits.memory 가 없는 컨테이너에 256Mi 를 자동 주입합니다.",
        "spec.containers[name:*].resources.limits.memory",
        "256Mi",
        excluded_namespaces,
    )
    mutation += "\n---\n" + _assign_yaml(
        "assign-cpu-limit-init",
        "initContainer의 resources.limits.cpu 가 없는 경우 500m 을 자동 주입합니다.",
        "spec.initContainers[name:*].resources.limits.cpu",
        "500m",
        excluded_namespaces,
    )
    mutation += "\n---\n" + _assign_yaml(
        "assign-memory-limit-init",
        "initContainer의 resources.limits.memory 가 없는 경우 256Mi 를 자동 주입합니다.",
        "spec.initContainers[name:*].resources.limits.memory",
        "256Mi",
        excluded_namespaces,
    )
    return "", "", mutation


def _network_policy(name: str, prompt: str) -> tuple[str, str, str]:
    # Kubernetes NetworkPolicy 생성
    normalized = prompt.lower()
    include_egress = "egress" in normalized or "이그레스" in normalized
    if include_egress and ("ingress" not in normalized and "인그레스" not in normalized):
        policy_types = "  policyTypes:\n    - Egress"
        rule_block = "  egress: []"
        description = "기본 egress 트래픽을 차단합니다."
    elif include_egress:
        policy_types = "  policyTypes:\n    - Ingress\n    - Egress"
        rule_block = "  ingress: []\n  egress: []"
        description = "기본 ingress와 egress 트래픽을 차단합니다."
    else:
        policy_types = "  policyTypes:\n    - Ingress"
        rule_block = "  ingress: []"
        description = "기본 ingress 트래픽을 차단합니다."

    manifest = "\n".join(
        [
            "apiVersion: networking.k8s.io/v1",
            "kind: NetworkPolicy",
            "metadata:",
            f"  name: {name}",
            "  namespace: default",
            "  annotations:",
            f'    description: "{description}"',
            "spec:",
            "  podSelector: {}",
            policy_types,
            rule_block,
        ]
    )
    return "", "", manifest


def _assign_yaml(
    name: str,
    description: str,
    location: str,
    value: str,
    excluded_namespaces: list[str],
    is_string: bool = True,
) -> str:
    # Assign YAML 생성
    rendered_value = f'"{value}"' if is_string else value
    return "\n".join(
        [
            "apiVersion: mutations.gatekeeper.sh/v1alpha1",
            "kind: Assign",
            "metadata:",
            f"  name: {name}",
            "  annotations:",
            f'    description: "{description}"',
            "spec:",
            "  applyTo:",
            '    - groups: [""]',
            '      versions: ["v1"]',
            '      kinds: ["Pod"]',
            "  match:",
            "    scope: Namespaced",
            "    excludedNamespaces:",
            _yaml_list(excluded_namespaces, indent=6),
            f'  location: "{location}"',
            "  parameters:",
            "    assign:",
            f"      value: {rendered_value}",
            "    pathTests:",
            f'      - subPath: "{location}"',
            "        condition: MustNotExist",
        ]
    )


def _template_yaml(kind: str, package: str, rego: str, parameters: bool = False) -> str:
    # ConstraintTemplate YAML 생성
    schema_lines: list[str] = []
    if parameters:
        schema_lines = [
            "      validation:",
            "        openAPIV3Schema:",
            "          type: object",
            "          properties:",
            "            repos:",
            "              type: array",
            "              items:",
            "                type: string",
        ]

    lines = [
        "apiVersion: templates.gatekeeper.sh/v1",
        "kind: ConstraintTemplate",
        "metadata:",
        f"  name: {package}",
        "spec:",
        "  crd:",
        "    spec:",
        "      names:",
        f"        kind: {kind}",
        *schema_lines,
        "  targets:",
        "    - target: admission.k8s.gatekeeper.sh",
        "      rego: |",
        _indent(rego, 8),
    ]
    return "\n".join(lines).strip()


def _constraint_yaml(
    kind: str,
    name: str,
    enforcement_action: str,
    excluded_namespaces: list[str],
    parameters: str = "",
) -> str:
    # Constraint YAML 생성
    lines = [
        "apiVersion: constraints.gatekeeper.sh/v1beta1",
        f"kind: {kind}",
        "metadata:",
        f"  name: {name}",
        "spec:",
        f"  enforcementAction: {enforcement_action}",
        "  match:",
        "    kinds:",
        '      - apiGroups: [""]',
        '        kinds: ["Pod"]',
        "    excludedNamespaces:",
        _yaml_list(excluded_namespaces, indent=6),
    ]
    if parameters:
        lines.append(parameters)
    return "\n".join(lines).strip()


def _indent(value: str, spaces: int) -> str:
    # 문자열 들여쓰기
    padding = " " * spaces
    return "\n".join(f"{padding}{line}" if line else "" for line in value.splitlines())
