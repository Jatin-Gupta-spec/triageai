"""Tests for terminal.py and markdown_report.py rendering.

Stage 11 changes both renderers' signature from a bare event tuple to
a tuple of Cases -- each case now carries its own severity,
confidence, rule matches, observed facts, and evidence gaps, all of
which the report must surface, not just the event timeline.
"""

from __future__ import annotations

from datetime import UTC, datetime

from triageai.models import Case, Confidence, NormalizedEvent, RuleMatch, Severity
from triageai.reporters.markdown_report import render_markdown
from triageai.reporters.terminal import render_text


def _event(command_line: str | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id="rec-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        host="WIN-CLIENT01",
        user="alice",
        source="wazuh",
        event_id="4625",
        provider=None,
        rule_id=None,
        process="powershell.exe",
        parent_process=None,
        command_line=command_line,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )


def _case(
    *,
    rule_matches: tuple[RuleMatch, ...] = (),
    severity: Severity = Severity.INFORMATIONAL,
    confidence: Confidence = Confidence.LOW,
    observed_facts: tuple[str, ...] = (),
    evidence_gaps: tuple[str, ...] = (),
    command_line: str | None = None,
) -> Case:
    event = _event(command_line=command_line)
    return Case(
        case_id="case-1",
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        affected_hosts=("WIN-CLIENT01",),
        affected_users=("alice",),
        normalized_events=(event,),
        rule_matches=rule_matches,
        severity=severity,
        confidence=confidence,
        observed_facts=observed_facts,
        evidence_gaps=evidence_gaps,
    )


def test_render_text_empty_cases() -> None:
    assert render_text(()) == "No events to report."


def test_render_text_includes_key_fields() -> None:
    output = render_text((_case(),))
    assert "WIN-CLIENT01" in output
    assert "alice" in output
    assert "4625" in output


def test_render_text_includes_command_line() -> None:
    output = render_text((_case(command_line="net user alice /active:yes"),))
    assert "net user alice /active:yes" in output


def test_render_text_shows_severity_and_confidence() -> None:
    output = render_text((_case(severity=Severity.HIGH, confidence=Confidence.MEDIUM),))
    assert "HIGH" in output
    assert "MEDIUM" in output


def test_render_text_shows_rule_matches() -> None:
    match = RuleMatch(
        rule_id="AUTH-001",
        mitre_technique="T1110",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        matched_event_ids=("rec-1",),
        description="5 failures in 10 minutes",
    )
    output = render_text((_case(rule_matches=(match,)),))
    assert "AUTH-001" in output
    assert "5 failures in 10 minutes" in output


def test_render_text_shows_evidence_gaps() -> None:
    output = render_text((_case(evidence_gaps=("1 event has no timestamp",)),))
    assert "1 event has no timestamp" in output


def test_render_text_marks_undated_events() -> None:
    undated_event = NormalizedEvent(
        original_record_id="rec-2",
        timestamp=None,
        host="H1",
        user=None,
        source=None,
        event_id=None,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=None,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )
    case = Case(
        case_id="case-2",
        first_seen=None,
        last_seen=None,
        affected_hosts=("H1",),
        affected_users=(),
        normalized_events=(undated_event,),
        rule_matches=(),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.LOW,
        observed_facts=(),
        evidence_gaps=(),
    )
    assert "UNDATED" in render_text((case,))


def test_render_text_separates_multiple_cases() -> None:
    output = render_text((_case(), _case()))
    assert output.count("=== Case") == 2


def test_render_markdown_empty_cases() -> None:
    assert "No events to report." in render_markdown(())


def test_render_markdown_includes_table_header() -> None:
    output = render_markdown((_case(),))
    assert "| Timestamp | Host | User | Event ID | Process | Command Line |" in output
    assert "WIN-CLIENT01" in output


def test_render_markdown_includes_command_line() -> None:
    output = render_markdown((_case(command_line="net user alice /active:yes"),))
    assert "net user alice /active:yes" in output


def test_render_markdown_shows_rule_matches() -> None:
    match = RuleMatch(
        rule_id="PS-001",
        mitre_technique="T1059.001",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        matched_event_ids=("rec-1",),
        description="Encoded PowerShell command",
    )
    output = render_markdown((_case(rule_matches=(match,)),))
    assert "PS-001" in output
    assert "Encoded PowerShell command" in output