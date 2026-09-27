"""Tests for PERSIST-001 -- positive, negative, boundary, and
missing-field cases, plus the spec-required legitimate-administration
fixture.
"""

from __future__ import annotations

from triageai.models import NormalizedEvent
from triageai.rules.persistence import evaluate


def _event(
    record_id: str = "rec-1",
    *,
    event_id: str | None = None,
    command_line: str | None = None,
    host: str | None = "WIN-CLIENT01",
) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=None,
        host=host,
        user=None,
        source=None,
        event_id=event_id,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=command_line,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )


# --- Positive ---


def test_event_id_4698_alone_matches() -> None:
    event = _event(event_id="4698")
    matches = evaluate((event,))
    assert len(matches) == 1
    assert matches[0].rule_id == "PERSIST-001"
    assert matches[0].mitre_technique == "T1053.005"


def test_schtasks_create_command_matches() -> None:
    event = _event(command_line=r'schtasks.exe /create /tn "Foo" /tr "C:\foo.exe" /sc daily')
    assert len(evaluate((event,))) == 1


def test_bare_schtasks_without_exe_matches() -> None:
    event = _event(command_line='schtasks /create /tn "Foo" /tr "C:\\foo.exe"')
    assert len(evaluate((event,))) == 1


def test_uppercase_create_flag_matches() -> None:
    event = _event(command_line='schtasks.exe /CREATE /tn "Foo"')
    assert len(evaluate((event,))) == 1


# --- The spec-required negative case: legitimate administration ---


def test_legitimate_administrative_task_still_matches() -> None:
    # Per spec Section 7: "Legitimate administration is a required
    # negative case" -- this rule detects the ACTION, not intent, and
    # MUST still fire here. The analyst reviewing the case decides
    # this is benign; the rule's job is only to surface the pattern.
    event = _event(
        command_line=(
            r'schtasks.exe /create /tn "Windows Update Check" '
            r'/tr "C:\Windows\System32\update_check.exe" /sc DAILY /st 03:00'
        )
    )

    matches = evaluate((event,))

    assert len(matches) == 1
    assert "does not indicate malicious intent" in matches[0].description


# --- Negative ---


def test_schtasks_query_does_not_match() -> None:
    event = _event(command_line='schtasks.exe /query /tn "Foo"')
    assert evaluate((event,)) == ()


def test_schtasks_delete_does_not_match() -> None:
    event = _event(command_line='schtasks.exe /delete /tn "Foo" /f')
    assert evaluate((event,)) == ()


def test_unrelated_event_does_not_match() -> None:
    event = _event(event_id="4624", command_line="powershell.exe -File script.ps1")
    assert evaluate((event,)) == ()


# --- Boundary ---


def test_create_as_substring_of_another_flag_does_not_match() -> None:
    # Guards against accidental substring matching -- only an exact
    # "/create" token counts, not a flag that merely contains it.
    event = _event(command_line='schtasks.exe /createlike /tn "Foo"')
    assert evaluate((event,)) == ()


def test_schtasks_mentioned_without_create_flag_does_not_match() -> None:
    event = _event(command_line='echo "run schtasks later"')
    assert evaluate((event,)) == ()


# --- Missing-field ---


def test_command_line_none_and_no_event_id_does_not_crash_or_match() -> None:
    event = _event()
    assert evaluate((event,)) == ()


def test_missing_host_still_matches_with_fallback_display() -> None:
    event = _event(event_id="4698", host=None)
    matches = evaluate((event,))
    assert len(matches) == 1
    assert "host ?" in matches[0].description


def test_empty_input_produces_no_matches() -> None:
    assert evaluate(()) == ()