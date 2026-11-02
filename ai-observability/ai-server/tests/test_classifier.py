from app.classifier import _sanitize_fields, classify_event
from app.schemas import ClassificationRequest


def test_privilege_escalation_is_high():
    payload = ClassificationRequest(
        rule="Compliance - Privilege Escalation in Container",
        priority="Critical",
        output="Privilege escalation attempt in production container",
        output_fields={
            "proc.name": "exploit",
            "user.name": "www-data",
            "user.uid": 33,
            "container.id": "abc123",
            "k8s.ns.name": "production",
        },
        tags=["compliance", "privilege-escalation"],
        time="2026-04-30T10:00:00Z",
    )

    result = classify_event(payload)

    assert result.severity == "high"
    assert result.confidence >= 0.6


def test_shell_spawned_is_medium():
    payload = ClassificationRequest(
        rule="Compliance - Shell Spawned in Container",
        priority="Warning",
        output="Shell spawned in container",
        output_fields={
            "proc.name": "bash",
            "user.name": "developer",
            "user.uid": 1000,
            "container.id": "abc123",
            "k8s.ns.name": "dev",
        },
        tags=["shell", "runtime"],
    )

    result = classify_event(payload)

    assert result.severity == "medium"
    assert 0.0 <= result.confidence <= 1.0


def test_attacker_tool_in_prod_is_high():
    payload = ClassificationRequest(
        rule="Compliance - Container Reconnaissance Activity",
        priority="Notice",
        output="Reconnaissance activity",
        output_fields={
            "proc.name": "nmap",
            "user.name": "root",
            "user.uid": 0,
            "container.id": "abc123",
            "k8s.ns.name": "prod",
        },
        tags=["reconnaissance"],
    )

    result = classify_event(payload)

    assert result.severity == "high"


def test_sensitive_field_is_not_exposed_in_reason():
    payload = ClassificationRequest(
        rule="Compliance - Sensitive File Access",
        priority="Warning",
        output="Sensitive file read",
        output_fields={
            "token": "secret-token-value",
            "proc.name": "cat",
            "container.id": "abc123",
        },
    )

    result = classify_event(payload)

    assert "secret-token-value" not in result.reason


def test_output_preserves_log_whitespace():
    payload = ClassificationRequest(
        rule="Compliance - Sensitive File Access",
        priority="Warning",
        output="line1\n\tline2\r\nline3\x00",
        output_fields={},
    )

    assert payload.output == "line1\n\tline2\r\nline3"


def test_nested_fields_are_flattened_and_redacted():
    fields = _sanitize_fields(
        {
            "user": {"uid": 0, "password": "secret-password"},
            "auth": {"token": "secret-token"},
            "container": {"id": "abc123"},
        }
    )

    assert fields["user.uid"] == "0"
    assert fields["user.password"] == "[REDACTED]"
    assert fields["auth.token"] == "[REDACTED]"
    assert fields["container.id"] == "abc123"
