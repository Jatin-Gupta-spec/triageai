"""Stage 17d redaction hardening: flag-style secrets, quoted values,
Authorization and Cookie headers, user paths, full event coverage, and
the aliaser's no-crash fallback.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from triageai.models import NormalizedEvent
from triageai.redaction import (
    EmailAliaser,
    redact_event_for_render,
    redact_free_text,
    redact_text_with_aliases,
)

# --- Flag-style and quoted secrets ---


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("tool --password Hunter2 --verbose", "Hunter2"),
        ("tool -Token abc123XYZ", "abc123XYZ"),
        ("run /secret:abc123XYZ", "abc123XYZ"),
        ("tool --api-key=k123456", "k123456"),
        ("tool --client-secret v9v9v9", "v9v9v9"),
        ("tool --access_key AKIA1234", "AKIA1234"),
        ('tool -Password "a b c d"', "a b c d"),
        ("tool password='two words'", "two words"),
        ('tool password="a b c"', "a b c"),
    ],
)
def test_secret_values_are_redacted(text: str, secret: str) -> None:
    result = redact_free_text(text)
    assert secret not in result
    assert "[REDACTED_SECRET]" in result


def test_text_around_a_redacted_flag_secret_is_kept() -> None:
    assert redact_free_text("tool --password Hunter2 --verbose") == "tool [REDACTED_SECRET] --verbose"


def test_authorization_without_a_scheme_is_redacted() -> None:
    result = redact_free_text("curl -H Authorization: abc123token")
    assert "abc123token" not in result


def test_authorization_with_a_scheme_is_still_redacted() -> None:
    result = redact_free_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
    assert "eyJ" not in result


def test_cookie_header_is_redacted_to_the_end_of_the_line() -> None:
    result = redact_free_text("Cookie: session=abc; csrf=xyz")
    assert "abc" not in result
    assert "xyz" not in result


def test_set_cookie_header_is_redacted() -> None:
    assert "sess1" not in redact_free_text("Set-Cookie: id=sess1; Path=/")


@pytest.mark.parametrize(
    "text",
    [
        "passwordless: true",
        "cookies=3",
        "Get-Content -Path token.txt",
        "tokenize --input a.txt",
        "tool --password",
        "https://example.com/api/token abc",
    ],
)
def test_ordinary_text_is_not_redacted(text: str) -> None:
    assert redact_free_text(text) == text


# --- User-profile paths ---


def test_windows_user_path_is_redacted() -> None:
    result = redact_free_text(r"C:\Users\alice\AppData\evil.exe")
    assert result == r"C:\Users\[REDACTED_USER]\AppData\evil.exe"


def test_windows_user_path_with_forward_slashes_is_redacted() -> None:
    assert redact_free_text("c:/users/bob/x.exe") == "c:/users/[REDACTED_USER]/x.exe"


def test_posix_home_path_is_redacted() -> None:
    assert redact_free_text("/home/carol/.ssh/id_rsa") == "/home/[REDACTED_USER]/.ssh/id_rsa"


def test_macos_user_path_is_redacted() -> None:
    assert redact_free_text("/Users/dave/x") == "/Users/[REDACTED_USER]/x"


def test_user_path_redaction_is_idempotent() -> None:
    once = redact_free_text(r"C:\Users\alice\x.exe")
    assert redact_free_text(once) == once


def test_non_user_paths_are_unchanged() -> None:
    text = r"C:\Windows\System32\cmd.exe"
    assert redact_free_text(text) == text


def test_user_path_and_secret_in_a_rule_description_are_redacted() -> None:
    description = r"decoded successfully: C:\Users\alice\x.exe --password Hunter2"
    result = redact_text_with_aliases(description, EmailAliaser([]))
    assert "alice" not in result
    assert "Hunter2" not in result


# --- Every string field of an event is covered ---


def _event(**overrides: object) -> NormalizedEvent:
    fields: dict[str, object] = {
        "original_record_id": "rec-1",
        "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
        "host": "H1",
        "user": "alice",
        "source": "wazuh",
        "event_id": "4688",
        "provider": "prov",
        "rule_id": "5710",
        "process": "cmd.exe",
        "parent_process": "explorer.exe",
        "command_line": None,
        "source_ip": "10.0.0.5",
        "destination_ip": None,
        "mitre_techniques": ("T1110",),
    }
    fields.update(overrides)
    return NormalizedEvent(**fields)  # type: ignore[arg-type]


def test_process_and_parent_process_paths_are_redacted() -> None:
    event = _event(process=r"C:\Users\alice\tool.exe", parent_process=r"C:\Users\bob\cmd.exe")
    redacted = redact_event_for_render(event, EmailAliaser([]))
    assert redacted.process == r"C:\Users\[REDACTED_USER]\tool.exe"
    assert redacted.parent_process == r"C:\Users\[REDACTED_USER]\cmd.exe"


def test_original_record_id_is_scrubbed() -> None:
    event = _event(original_record_id=r"cmd C:\Users\alice\x --password Hunter2")
    redacted = redact_event_for_render(event, EmailAliaser([]))
    assert "alice" not in redacted.original_record_id
    assert "Hunter2" not in redacted.original_record_id


def test_event_id_source_provider_and_rule_id_are_covered() -> None:
    event = _event(
        event_id="password=abc123",
        source="token=xyz987",
        provider="Cookie: id=leak",
        rule_id="secret=qwerty",
    )
    redacted = redact_event_for_render(event, EmailAliaser([]))
    assert "abc123" not in redacted.event_id
    assert "xyz987" not in redacted.source
    assert "leak" not in redacted.provider
    assert "qwerty" not in redacted.rule_id


def test_mitre_technique_strings_are_scrubbed() -> None:
    event = _event(mitre_techniques=("T1110", r"C:\Users\alice\note.txt"))
    redacted = redact_event_for_render(event, EmailAliaser([]))
    assert redacted.mitre_techniques[0] == "T1110"
    assert "alice" not in redacted.mitre_techniques[1]


# --- The aliaser no-crash fallback ---


def test_aliaser_never_raises_for_an_unseeded_email() -> None:
    # Only seeded with alice@corp.local -- bob@corp.local was never
    # given to the aliaser in advance. Before this fix, alias_for
    # raised KeyError here instead of falling back safely.
    aliaser = EmailAliaser(["alice@corp.local"])
    assert aliaser.alias_for("bob@corp.local") == "[REDACTED_EMAIL]"


def test_unseeded_email_in_command_line_does_not_crash_redaction() -> None:
    event = _event(user="alice@corp.local", command_line="notify carol@corp.local")
    aliaser = EmailAliaser(["alice@corp.local"])
    redacted = redact_event_for_render(event, aliaser)
    assert redacted.command_line == "notify [REDACTED_EMAIL]"