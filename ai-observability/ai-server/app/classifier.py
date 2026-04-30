from typing import Any

from app.schemas import ClassificationRequest, ClassificationResponse


SEVERITY_SCORE = {"low": 0, "medium": 1, "high": 2}

PRIORITY_TO_SEVERITY = {
    "emergency": "high",
    "alert": "high",
    "critical": "high",
    "error": "medium",
    "warning": "medium",
    "notice": "low",
    "informational": "low",
    "debug": "low",
}

HIGH_RISK_PATTERNS = {
    "privilege escalation",
    "reverse shell",
    "container escape",
    "crypto mining",
    "shadow",
    "credential",
}

MEDIUM_RISK_PATTERNS = {
    "shell spawned",
    "sensitive file",
    "write monitored",
    "unexpected outbound",
    "reconnaissance",
}

ATTACKER_TOOLS = {
    "nmap",
    "ncat",
    "netcat",
    "nc",
    "hydra",
    "john",
    "hashcat",
    "msfconsole",
    "msfvenom",
}

PRODUCTION_NAMESPACE_HINTS = {"prod", "production", "live", "stable"}

SENSITIVE_FIELD_KEYS = {
    "user.password",
    "password",
    "token",
    "authorization",
    "cookie",
}

SENSITIVE_FIELD_NAMES = {
    "password",
    "token",
    "authorization",
    "cookie",
    "secret",
    "api_key",
    "apikey",
}


def classify_event(payload: ClassificationRequest) -> ClassificationResponse:
    """Falco 이벤트 분류."""
    fields = _sanitize_fields(payload.output_fields)
    reasons: list[str] = []

    severity = PRIORITY_TO_SEVERITY.get(payload.priority.lower(), "medium")
    reasons.append(f"priority:{payload.priority or 'unknown'}->{severity}")

    searchable_text = " ".join(
        [
            payload.rule.lower(),
            payload.output.lower(),
            " ".join(payload.tags),
        ]
    )

    if _contains_any(searchable_text, HIGH_RISK_PATTERNS):
        severity = _max_severity(severity, "high")
        reasons.append("risk_pattern:high")
    elif _contains_any(searchable_text, MEDIUM_RISK_PATTERNS):
        severity = _max_severity(severity, "medium")
        reasons.append("risk_pattern:medium")

    context_score = _context_score(fields, reasons)
    if context_score >= 3:
        severity = _max_severity(severity, "high")
    elif context_score >= 1:
        severity = _max_severity(severity, "medium")

    confidence = _confidence(severity=severity, context_score=context_score, reasons=reasons)

    return ClassificationResponse(
        severity=severity,
        reason=" | ".join(reasons),
        confidence=confidence,
    )


def _sanitize_fields(fields: dict[str, Any]) -> dict[str, str]:
    # 민감 정보 제거
    sanitized: dict[str, str] = {}
    _sanitize_value(fields, sanitized, prefix="")
    return sanitized


def _sanitize_value(value: Any, sanitized: dict[str, str], prefix: str) -> None:
    # 중첩 필드 평탄화
    if isinstance(value, dict):
        for raw_key, child_value in value.items():
            key = str(raw_key).lower()
            next_prefix = f"{prefix}.{key}" if prefix else key
            _sanitize_value(child_value, sanitized, next_prefix)
        return

    if isinstance(value, list):
        for index, child_value in enumerate(value):
            next_prefix = f"{prefix}.{index}" if prefix else str(index)
            _sanitize_value(child_value, sanitized, next_prefix)
        return

    if _is_sensitive_key(prefix):
        sanitized[prefix] = "[REDACTED]"
        return

    sanitized[prefix] = str(value)[:500]


def _is_sensitive_key(key: str) -> bool:
    # 민감 키 판별
    if key in SENSITIVE_FIELD_KEYS:
        return True
    key_parts = set(key.replace("-", "_").split("."))
    return bool(key_parts.intersection(SENSITIVE_FIELD_NAMES))


def _context_score(fields: dict[str, str], reasons: list[str]) -> int:
    # 컨텍스트 점수
    score = 0

    user_uid = fields.get("user.uid", "")
    user_name = fields.get("user.name", "")
    if user_uid == "0" or user_name == "root":
        score += 1
        reasons.append("context:root_user")

    namespace = fields.get("k8s.ns.name", "").lower()
    if any(hint in namespace for hint in PRODUCTION_NAMESPACE_HINTS):
        score += 1
        reasons.append("context:production_namespace")

    process_name = fields.get("proc.name", "").lower()
    if process_name in ATTACKER_TOOLS:
        score += 2
        reasons.append(f"context:attacker_tool:{process_name}")

    if fields.get("container.id", "") in {"", "host"}:
        score += 1
        reasons.append("context:host_or_missing_container")

    return score


def _confidence(severity: str, context_score: int, reasons: list[str]) -> float:
    # 신뢰도 산출
    base = 0.45
    base += min(context_score * 0.12, 0.36)
    base += 0.12 if severity == "high" else 0.06 if severity == "medium" else 0.0
    base += min(len(reasons) * 0.02, 0.08)
    return round(min(base, 0.95), 2)


def _contains_any(text: str, patterns: set[str]) -> bool:
    return any(pattern in text for pattern in patterns)


def _max_severity(current: str, candidate: str) -> str:
    return max(current, candidate, key=lambda severity: SEVERITY_SCORE.get(severity, -1))
