"""Tests for src/triageai/redaction.py.

Covers: flat free-text redaction, recursive structure redaction,
numbered identity-field aliasing, and proof that redaction never
mutates the original NormalizedEvent/Case.
"""

from __future__ import annotations

from datetime import UTC, datetime

from triageai.models import Case, Confidence, NormalizedEvent, Severity
from triageai.redaction import (
    EmailAliaser,
    redact_case_for_render,
    redact_event_for_render,
    redact_free_text,
    redact_structure,
)


def _event(record_id: str, user: str | None, command_line: str | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        host="WIN-CLIENT01",
        user=user,
        source="wazuh",
        event_id="4625",
        provider="Microsoft-Windows-Security-Auditing",
        rule_id="5710",
        process=None,
        parent_process=None,
        command_line=command_line,
        source_ip="192.168.56.10",
        destination_ip=None,
        mitre_techniques=(),
    )


# --- redact_free_text ---


def test_redact_free_text_replaces_email() -> None:
    result = redact_free_text("contact alice@corp.local for access")
    assert result == "contact [REDACTED_EMAIL] for access"
    assert "alice" not in result


def test_redact_free_text_replaces_password_assignment() -> None:
    result = redact_free_text("connect --password=Sup3rSecret!")
    assert "Sup3rSecret" not in result
    assert "[REDACTED_SECRET]" in result


def test_redact_free_text_replaces_authorization_header() -> None:
    result = redact_free_text("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    assert "eyJ" not in result
    assert "[REDACTED_SECRET]" in result


def test_redact_free_text_replaces_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    result = redact_free_text(text)
    assert "MIIEpAIBAAKCAQEA" not in result
    assert result == "[REDACTED_PRIVATE_KEY]"


def test_redact_free_text_leaves_plain_text_unchanged() -> None:
    assert redact_free_text("scheduled task created successfully") == (
        "scheduled task created successfully"
    )


# --- redact_structure ---


def test_redact_structure_walks_nested_dict() -> None:
    data = {"outer": {"inner": "reach me at bob@corp.local"}}
    result = redact_structure(data)
    assert result == {"outer": {"inner": "reach me at [REDACTED_EMAIL]"}}


def test_redact_structure_walks_nested_list() -> None:
    data = {"messages": ["hi alice@corp.local", "no secrets here"]}
    result = redact_structure(data)
    assert result["messages"][0] == "hi [REDACTED_EMAIL]"
    assert result["messages"][1] == "no secrets here"


def test_redact_structure_leaves_non_string_values_unchanged() -> None:
    data = {"count": 5, "active": True, "note": None}
    assert redact_structure(data) == {"count": 5, "active": True, "note": None}


# --- EmailAliaser ---


def test_aliaser_assigns_distinct_aliases_to_distinct_values() -> None:
    aliaser = EmailAliaser(["bob@corp.local", "alice@corp.local"])
    alice_alias = aliaser.alias_for("alice@corp.local")
    bob_alias = aliaser.alias_for("bob@corp.local")
    assert alice_alias != bob_alias


def test_aliaser_same_value_gets_same_alias() -> None:
    aliaser = EmailAliaser(["alice@corp.local", "alice@corp.local"])
    assert aliaser.alias_for("alice@corp.local") == aliaser.alias_for("alice@corp.local")


def test_aliaser_orders_by_sorted_case_folded_value() -> None:
    # "alice" sorts before "bob" -- alias numbering must be deterministic,
    # not dependent on insertion order.
    aliaser = EmailAliaser(["Bob@Corp.local", "alice@corp.local"])
    assert aliaser.alias_for("alice@corp.local") == "[REDACTED_EMAIL_001]"
    assert aliaser.alias_for("Bob@Corp.local") == "[REDACTED_EMAIL_002]"


def test_aliaser_leaves_non_email_value_unchanged() -> None:
    aliaser = EmailAliaser(["alice@corp.local"])
    assert aliaser.alias_for("WIN-CLIENT01") == "WIN-CLIENT01"


# --- redact_event_for_render ---


def test_redact_event_for_render_does_not_mutate_original() -> None:
    event = _event("rec-1", user="alice@corp.local")
    aliaser = EmailAliaser(["alice@corp.local"])

    redact_event_for_render(event, aliaser)

    assert event.user == "alice@corp.local"  # original untouched


def test_redact_event_for_render_redacts_command_line_email() -> None:
    event = _event("rec-1", user="alice@corp.local", command_line="notify bob@corp.local")
    aliaser = EmailAliaser(["alice@corp.local"])

    redacted = redact_event_for_render(event, aliaser)

    assert redacted.command_line == "notify [REDACTED_EMAIL]"


# --- redact_case_for_render: the UPN fixture the locked spec requires ---


def test_redact_case_for_render_upn_users_get_distinct_aliases() -> None:
    alice_event = _event("rec-1", user="alice@corp.local")
    bob_event = _event("rec-2", user="bob@corp.local")

    case = Case(
        case_id="case-1",
        first_seen=alice_event.timestamp,
        last_seen=bob_event.timestamp,
        affected_hosts=("WIN-CLIENT01",),
        affected_users=("alice@corp.local", "bob@corp.local"),
        normalized_events=(alice_event, bob_event),
        rule_matches=(),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        observed_facts=(),
        evidence_gaps=(),
    )

    redacted_case = redact_case_for_render(case)

    # Internal, real case is untouched -- this is the property that
    # keeps correlation (built in Stage 11) safe to run BEFORE render.
    assert case.affected_users == ("alice@corp.local", "bob@corp.local")

    # Rendered copy: both users present, but as two DIFFERENT aliases --
    # neither collapsed into the other, neither left as a real email.
    assert redacted_case.affected_users[0] != redacted_case.affected_users[1]
    assert all(EMAIL_PATTERN_NOT_PRESENT(u) for u in redacted_case.affected_users)


def EMAIL_PATTERN_NOT_PRESENT(value: str) -> bool:
    return "@" not in value


def test_redact_case_for_render_does_not_mutate_original_case() -> None:
    event = _event("rec-1", user="alice@corp.local")
    case = Case(
        case_id="case-1",
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        affected_hosts=("WIN-CLIENT01",),
        affected_users=("alice@corp.local",),
        normalized_events=(event,),
        rule_matches=(),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        observed_facts=(),
        evidence_gaps=(),
    )

    redact_case_for_render(case)

    assert case.normalized_events[0].user == "alice@corp.local"
    assert case.affected_users == ("alice@corp.local",)