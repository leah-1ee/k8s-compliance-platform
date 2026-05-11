from app.schemas import PolicyGenerationRequest, PolicyKind


def build_policy_prompt(request: PolicyGenerationRequest, policy_kind: PolicyKind) -> str:
    # 정책 검토 프롬프트
    registries = ", ".join(request.allowed_registries) or "docker.io/library/, gcr.io/, ghcr.io/, registry.k8s.io/"
    excluded = ", ".join(request.excluded_namespaces) or "kube-system, gatekeeper-system, kube-flannel, monitoring"
    output_type = "Assign mutation YAML" if "mutation" in policy_kind else "Rego, ConstraintTemplate YAML, and Constraint YAML"
    return f"""You are reviewing an already generated Kubernetes Gatekeeper policy.
Return only plain Korean text. No YAML, Rego, Markdown, or code blocks.
Write exactly 4 lines. Each line must be one complete sentence under 90 Korean characters.
Do not include extra explanations after line 4.
Use this exact format:
1. 정책 의도: (이 정책이 무엇을 막거나 강제하는지)
2. 적용 범위: (어떤 리소스, 네임스페이스에 적용되는지)
3. 주의할 점: (운영 중 발생할 수 있는 사이드이펙트나 예외)
4. 운영 권장사항: (실제 적용 전 확인해야 할 사항)

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
