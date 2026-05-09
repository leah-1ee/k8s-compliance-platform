from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


Severity = Literal["low", "medium", "high"]


class ClassificationRequest(BaseModel):
    rule: str = Field(default="", max_length=300)
    priority: str = Field(default="", max_length=50)
    output: str = Field(default="", max_length=4000)
    output_fields: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=50)
    time: str = Field(default="", max_length=80)

    @field_validator("rule", "priority", "time")
    @classmethod
    def strip_metadata_control_chars(cls, value: str) -> str:
        # 메타데이터 제어 문자 제거
        return "".join(ch for ch in value.strip() if ch.isprintable())

    @field_validator("output")
    @classmethod
    def strip_output_control_chars(cls, value: str) -> str:
        # 로그 공백 보존
        allowed_whitespace = {"\n", "\t", "\r"}
        return "".join(
            ch for ch in value.strip() if ch.isprintable() or ch in allowed_whitespace
        )

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        # 태그 정규화
        normalized = []
        for value in values[:50]:
            if isinstance(value, str):
                normalized.append(value.strip().lower()[:80])
        return normalized


class ClassificationResponse(BaseModel):
    severity: Severity
    reason: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)


PolicyKind = Literal[
    "latest-tag",
    "non-root",
    "allowed-registries",
    "host-namespace",
    "security-context-mutation",
    "resource-limits-mutation",
]


class PolicyGenerationRequest(BaseModel):
    prompt: str = Field(min_length=5, max_length=2000)
    policy_kind: PolicyKind | None = None
    constraint_name: str = Field(default="generated-policy", max_length=80)
    enforcement_action: Literal["deny", "warn", "dryrun"] = "deny"
    allowed_registries: list[str] = Field(default_factory=list, max_length=20)
    excluded_namespaces: list[str] = Field(default_factory=list, max_length=20)
    use_llm: bool = False

    @field_validator("prompt", "constraint_name")
    @classmethod
    def strip_text_control_chars(cls, value: str) -> str:
        # 입력 제어 문자 제거
        return "".join(ch for ch in value.strip() if ch.isprintable())

    @field_validator("allowed_registries", "excluded_namespaces")
    @classmethod
    def normalize_string_list(cls, values: list[str]) -> list[str]:
        # 목록 값 정규화
        normalized = []
        for value in values[:20]:
            if isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    normalized.append(stripped[:120])
        return normalized


class PolicyGenerationResponse(BaseModel):
    policy_kind: PolicyKind
    constraint_template: str
    constraint: str
    rego: str
    review_notes: list[str]
    prompt: str
    llm_used: bool = False
    llm_review: str = ""


class ViolationAnalysisRequest(ClassificationRequest):
    cluster: str = Field(default="", max_length=120)


class ViolationAnalysisResponse(ClassificationResponse):
    summary: str = Field(min_length=1, max_length=1000)
    recommended_actions: list[str] = Field(default_factory=list, max_length=8)
