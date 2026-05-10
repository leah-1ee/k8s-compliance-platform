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


def generate_policy(
    request: PolicyGenerationRequest,
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> PolicyGenerationResponse:
    # 정책 유형 판별
    policy_kind = request.policy_kind or _detect_policy_kind(request.prompt)
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
    else:
        rego, template, constraint = _resource_limits_mutation_policy(excluded_namespaces)

    prompt = build_policy_prompt(request, policy_kind)
    llm_review = ""
    llm_error = ""
    llm_used = False
    if request.use_llm:
        llm_review, llm_error = _safe_llm_review(prompt, llm_provider, llm_api_key)
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
        return (
            "",
            f"LLM 요청 실패: HTTP {error.response.status_code}. API key, provider, model 설정을 확인하세요.",
        )
    except httpx.RequestError:
        return "", "LLM 연결 실패: 네트워크 또는 provider endpoint 설정을 확인하세요."
    except Exception:
        return "", "LLM 처리 실패: provider와 model 설정을 확인하세요."


def _detect_policy_kind(prompt: str) -> PolicyKind:
    # 키워드 기반 분류
    normalized = prompt.lower()
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
    return "latest-tag"


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
