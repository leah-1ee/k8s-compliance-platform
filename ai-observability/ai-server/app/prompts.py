from app.schemas import PolicyGenerationRequest, PolicyKind


def build_policy_prompt(request: PolicyGenerationRequest, policy_kind: PolicyKind) -> str:
    # 정책 생성 프롬프트
    registries = ", ".join(request.allowed_registries) or "docker.io/library/, gcr.io/, ghcr.io/, registry.k8s.io/"
    excluded = ", ".join(request.excluded_namespaces) or "kube-system, gatekeeper-system, kube-flannel, monitoring"
    output_type = "Assign mutation YAML" if "mutation" in policy_kind else "Rego, ConstraintTemplate YAML, and Constraint YAML"
    return f"""You are a Kubernetes policy engineer.
Generate an OPA Gatekeeper policy from the user requirement.

Requirement:
{request.prompt}

Policy kind:
{policy_kind}

Constraints:
- Return {output_type}.
- Use enforcementAction: {request.enforcement_action}
- Use constraint name: {request.constraint_name}
- Exclude namespaces when appropriate: {excluded}
- Allowed registries when needed: {registries}
- Do not include privileged bypasses.
- Keep generated code reviewable and minimal.
"""
