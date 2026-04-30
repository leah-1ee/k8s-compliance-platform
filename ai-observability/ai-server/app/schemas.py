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
