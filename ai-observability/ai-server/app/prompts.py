from app.schemas import PolicyGenerationRequest, PolicyKind


def build_policy_prompt(request: PolicyGenerationRequest, policy_kind: PolicyKind) -> str:
    # 정책 검토 프롬프트
    registries = ", ".join(request.allowed_registries) or "docker.io/library/, gcr.io/, ghcr.io/, registry.k8s.io/"
    excluded = ", ".join(request.excluded_namespaces) or "kube-system, gatekeeper-system, kube-flannel, monitoring"
    output_type = "Assign mutation YAML" if "mutation" in policy_kind else "Rego, ConstraintTemplate YAML, and Constraint YAML"
    return f"""You are reviewing an already generated Kubernetes Gatekeeper policy.
Do not generate YAML, Rego, Markdown, or code blocks.
Return only concise Korean plain text.
Use exactly 4 short lines:
1. 정책 의도
2. 적용 범위
3. 주의할 점
4. 운영 권장사항

Requirement:
{request.prompt}

Policy kind:
{policy_kind}

Context:
- Generated artifact type: {output_type}.
- Use enforcementAction: {request.enforcement_action}
- Use constraint name: {request.constraint_name}
- Exclude namespaces when appropriate: {excluded}
- Allowed registries when needed: {registries}
"""
