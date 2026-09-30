"""Tests for terminal.py and markdown_report.py rendering.

Stage 18 changes both renderers' second parameter type from
AIAnalysisDraft | None to AIDraftOutcome, adds rendering of a real
rejection reason, and adds rendering of an accepted draft's own
evidence_gaps and unsupported_claims.
"""

from __future__ import annotations

from datetime import UTC, datetime

from triageai.models import (
    AIAnalysisDraft,
    AIDraftOutcome,
    Case,
    Confidence,
    NormalizedEvent,
    RuleMatch,
    Severity,
)
from triageai.reporters.markdown_report import render_markdown
from triageai.reporters.terminal import render_text


def _event(command_line: str | None = None, process: str | None = "powershell.exe") -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id="rec-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        host="WIN-CLIENT01",
        user="alice",
        source="wazuh",
        event_id="4625",
        provider=None,
        rule_id=None,
        process=process,
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
    process: str | None = "powershell.exe",
    case_id: str = "case-1",
) -> Case:
    event = _event(command_line=command_line, process=process)
    return Case(
        case_id=case_id,
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


def _draft(
    summary: str = "test summary",
    evidence_gaps: tuple[str, ...] = (),
    unsupported_claims: tuple[str, ...] = (),
) -> AIAnalysisDraft:
    return AIAnalysisDraft(
        summary=summary,
        observations=("an observation",),
        investigation_questions=("a question?",),
        evidence_gaps=evidence_gaps,
        possible_false_positives=("a false positive",),
        recommended_next_steps=("a next step",),
        unsupported_claims=unsupported_claims,
    )


def _accepted(draft: AIAnalysisDraft | None = None) -> AIDraftOutcome:
    return AIDraftOutcome(draft=draft if draft is not None else _draft())


def _rejected(reason: str = "a test rejection reason") -> AIDraftOutcome:
    return AIDraftOutcome(draft=None, rejection_reason=reason)


def test_render_text_empty_cases() -> None:
    assert render_text((), {}) == "No events to report."


def test_render_text_includes_key_fields() -> None:
    output = render_text((_case(),), {"case-1": _rejected()})
    assert "WIN-CLIENT01" in output
    assert "alice" in output
    assert "4625" in output


def test_render_text_includes_command_line() -> None:
    output = render_text(
        (_case(command_line="net user alice /active:yes"),), {"case-1": _rejected()}
    )
    assert "net user alice /active:yes" in output


def test_render_text_shows_severity_and_confidence() -> None:
    output = render_text(
        (_case(severity=Severity.HIGH, confidence=Confidence.MEDIUM),), {"case-1": _rejected()}
    )
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
    output = render_text((_case(rule_matches=(match,)),), {"case-1": _rejected()})
    assert "AUTH-001" in output
    assert "5 failures in 10 minutes" in output


def test_render_text_shows_evidence_gaps() -> None:
    output = render_text(
        (_case(evidence_gaps=("1 event has no timestamp",)),), {"case-1": _rejected()}
    )
    assert "1 event has no timestamp" in output


def test_render_text_shows_accepted_ai_draft() -> None:
    output = render_text((_case(),), {"case-1": _accepted(_draft(summary="everything looks fine"))})
    assert "everything looks fine" in output
    assert "an observation" in output
    assert "AI-generated draft requiring human review" in output


def test_render_text_shows_rejection_reason() -> None:
    output = render_text((_case(),), {"case-1": _rejected("the AI provider's output failed schema validation")})
    assert "REJECTED" in output
    assert "the AI provider's output failed schema validation" in output


def test_render_text_shows_ai_evidence_gaps_and_unsupported_claims() -> None:
    draft = _draft(evidence_gaps=("AI thinks something is missing",), unsupported_claims=("AI is unsure about X",))
    output = render_text((_case(),), {"case-1": _accepted(draft)})
    assert "AI-proposed evidence gap (unverified): AI thinks something is missing" in output
    assert "AI-flagged unsupported claim: AI is unsure about X" in output


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
    assert "UNDATED" in render_text((case,), {"case-2": _rejected()})


def test_render_text_separates_multiple_cases() -> None:
    output = render_text(
        (_case(case_id="case-1"), _case(case_id="case-2")),
        {"case-1": _rejected(), "case-2": _rejected()},
    )
    assert output.count("=== Case") == 2


def test_render_markdown_empty_cases() -> None:
    assert "No events to report." in render_markdown((), {})


def test_render_markdown_includes_table_header() -> None:
    output = render_markdown((_case(),), {"case-1": _rejected()})
    assert "| Timestamp | Host | User | Event ID | Process | Command Line |" in output
    assert "WIN-CLIENT01" in output


def test_render_markdown_includes_command_line() -> None:
    output = render_markdown(
        (_case(command_line="net user alice /active:yes"),), {"case-1": _rejected()}
    )
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
    output = render_markdown((_case(rule_matches=(match,)),), {"case-1": _rejected()})
    assert "PS-001" in output
    assert "Encoded PowerShell command" in output


def test_render_markdown_shows_accepted_ai_draft() -> None:
    output = render_markdown((_case(),), {"case-1": _accepted(_draft(summary="looks benign"))})
    assert "looks benign" in output
    assert "an observation" in output


def test_render_markdown_shows_rejection_reason() -> None:
    output = render_markdown((_case(),), {"case-1": _rejected("the AI provider could not produce output")})
    assert "REJECTED" in output
    assert "the AI provider could not produce output" in output


def test_render_markdown_shows_ai_evidence_gaps_and_unsupported_claims() -> None:
    draft = _draft(evidence_gaps=("AI gap",), unsupported_claims=("AI doubt",))
    output = render_markdown((_case(),), {"case-1": _accepted(draft)})
    assert "**AI-proposed evidence gaps (unverified):**" in output
    assert "AI gap" in output
    assert "**AI-flagged unsupported claims:**" in output
    assert "AI doubt" in output


# --- Stage 18: hostile-input injection resistance ---


def test_render_text_strips_ansi_escape_in_process_name() -> None:
    output = render_text((_case(process="\x1b[31mFAKE\x1b[0m"),), {"case-1": _rejected()})
    assert "\x1b" not in output
    assert "FAKE" in output


def test_render_markdown_escapes_pipe_in_command_line() -> None:
    output = render_markdown(
        (_case(command_line="whoami | fake_column | injected"),), {"case-1": _rejected()}
    )
    assert "whoami \\| fake_column \\| injected" in output
    assert "whoami | fake_column | injected" not in output


def test_render_markdown_neutralizes_newline_heading_injection() -> None:
    output = render_markdown(
        (_case(command_line="legit\n# FAKE INCIDENT CONFIRMED"),), {"case-1": _rejected()}
    )
    assert "\n# FAKE INCIDENT CONFIRMED" not in output
    assert "<br>" in output


def test_render_text_neutralizes_newline_injection_in_ai_summary() -> None:
    draft = _draft(summary="benign\nFAKE SYSTEM MESSAGE: incident confirmed")
    output = render_text((_case(),), {"case-1": _accepted(draft)})
    assert "\nFAKE SYSTEM MESSAGE" not in output
    assert "\\n" in output


def test_render_markdown_escapes_html_in_command_line() -> None:
    output = render_markdown(
        (_case(command_line="<img src=x onerror=alert(1)>"),), {"case-1": _rejected()}
    )
    assert "<img" not in output
    assert "&lt;img" in output


def test_render_text_handles_outcome_with_no_draft_and_no_reason() -> None:
    # Constructs the exact type-allowed-but-application-never-builds
    # state mypy flagged: outcome exists, draft is None, and
    # rejection_reason is ALSO None. Must render a safe fallback, not
    # crash and not print the literal word "None".
    outcome = AIDraftOutcome(draft=None, rejection_reason=None)
    output = render_text((_case(),), {"case-1": outcome})
    assert "REJECTED" in output
    assert "no draft was generated" in output
    assert ": None" not in output


def test_render_markdown_handles_outcome_with_no_draft_and_no_reason() -> None:
    outcome = AIDraftOutcome(draft=None, rejection_reason=None)
    output = render_markdown((_case(),), {"case-1": outcome})
    assert "REJECTED" in output
    assert "no draft was generated" in output
    assert "-- None." not in output