from app.schemas import PolicyGenerationRequest, PolicyKind


def build_policy_prompt(
    request: PolicyGenerationRequest,
    policy_kind: PolicyKind,
    generated_artifacts: dict[str, str] | None = None,
) -> str:
    # 정책 검토 프롬프트
    registries = ", ".join(request.allowed_registries) or "docker.io/library/, gcr.io/, ghcr.io/, registry.k8s.io/"
    excluded = ", ".join(request.excluded_namespaces) or "kube-system, gatekeeper-system, kube-flannel, monitoring"
    if "mutation" in policy_kind:
        output_type = "Assign mutation YAML"
    else:
        output_type = "Rego, ConstraintTemplate YAML, and Constraint YAML"
    context_lines = [
        f"- Generated artifact type: {output_type}.",
        f"- Use constraint name: {request.constraint_name}",
        f"- Exclude namespaces when appropriate: {excluded}",
        f"- Allowed registries when needed: {registries}",
    ]
    context_lines.insert(1, f"- Use enforcementAction: {request.enforcement_action}")

    artifact_lines = ""
    if generated_artifacts:
        artifact_lines = "\nGenerated artifacts to review:\n"
        for label, value in generated_artifacts.items():
            if value:
                artifact_lines += f"\n[{label}]\n{value}\n"
    return f"""You are reviewing an already generated Kubernetes policy resource.
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
{chr(10).join(context_lines)}
{artifact_lines}
"""
