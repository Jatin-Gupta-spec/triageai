"""Tests for core data models.

Stage 3 only proves the shapes exist, are constructible, and are
immutable and orderable where the spec requires it. Behavior (creating
these from real input) arrives in later stages.
"""

from datetime import UTC, datetime

import pytest

from triageai.models import (
    AIAnalysisDraft,
    Case,
    Confidence,
    NormalizedEvent,
    RuleMatch,
    ScanSummary,
    Severity,
)


def _sample_event(record_id: str = "rec-1") -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        host="WIN-CLIENT01",
        user="alice",
        source="wazuh",
        event_id="4625",
        provider="Microsoft-Windows-Security-Auditing",
        rule_id="5710",
        process=None,
        parent_process=None,
        command_line=None,
        source_ip="192.168.56.10",
        destination_ip=None,
        mitre_techniques=("T1110",),
    )


def _sample_rule_match() -> RuleMatch:
    return RuleMatch(
        rule_id="AUTH-001",
        mitre_technique="T1110",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        matched_event_ids=("rec-1", "rec-2"),
        description="5 failures in 10 minutes for host WIN-CLIENT01, user alice",
    )


def test_normalized_event_is_frozen() -> None:
    event = _sample_event()
    with pytest.raises(AttributeError):
        event.host = "someone-else"  # type: ignore[misc]


def test_normalized_event_allows_missing_fields() -> None:
    event = _sample_event()
    assert event.process is None
    assert event.command_line is None


def test_severity_orders_low_to_high() -> None:
    assert Severity.INFORMATIONAL < Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_confidence_orders_low_to_high() -> None:
    assert Confidence.LOW < Confidence.MEDIUM < Confidence.HIGH


def test_rule_match_construction() -> None:
    match = _sample_rule_match()
    assert match.severity == Severity.MEDIUM


def test_rule_match_is_frozen() -> None:
    match = _sample_rule_match()
    with pytest.raises(AttributeError):
        match.severity = Severity.CRITICAL  # type: ignore[misc]


def test_case_defaults_analyst_status_to_none() -> None:
    event = _sample_event()
    case = Case(
        case_id="case-1",
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        affected_hosts=("WIN-CLIENT01",),
        affected_users=("alice",),
        normalized_events=(event,),
        rule_matches=(),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.LOW,
        observed_facts=(),
        evidence_gaps=(),
    )
    assert case.analyst_status is None


def test_ai_analysis_draft_has_fixed_warning() -> None:
    draft = AIAnalysisDraft(
        summary="",
        observations=(),
        investigation_questions=(),
        evidence_gaps=(),
        possible_false_positives=(),
        recommended_next_steps=(),
        unsupported_claims=(),
    )
    assert draft.analyst_warning == "AI-generated draft requiring human review"


def test_scan_summary_construction() -> None:
    summary = ScanSummary(
        total_records_read=0,
        duplicate_count=0,
        undated_count=0,
        cases=(),
    )
    assert summary.cases == ()