"""Tests for src/triageai/hallucination_check.py."""

from __future__ import annotations

import pytest

from triageai.hallucination_check import HallucinationError, check_for_hallucination
from triageai.models import AIAnalysisDraft, Case, Confidence, NormalizedEvent, RuleMatch, Severity


def _event(host: str = "WIN-CLIENT01", event_id: str = "4625") -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id="rec-1",
        timestamp=None,
        host=host,
        user=None,
        source=None,
        event_id=event_id,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=None,
        source_ip="192.168.1.10",
        destination_ip=None,
        mitre_techniques=("T1110",),
    )


def _case(rule_matches: tuple[RuleMatch, ...] = ()) -> Case:
    return Case(
        case_id="case-1",
        first_seen=None,
        last_seen=None,
        affected_hosts=("WIN-CLIENT01",),
        affected_users=(),
        normalized_events=(_event(),),
        rule_matches=rule_matches,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        observed_facts=(),
        evidence_gaps=(),
    )


def _draft(summary: str = "ok", observations: tuple[str, ...] = ()) -> AIAnalysisDraft:
    return AIAnalysisDraft(
        summary=summary,
        observations=observations,
        investigation_questions=(),
        evidence_gaps=(),
        possible_false_positives=(),
        recommended_next_steps=(),
        unsupported_claims=(),
    )


def test_supported_host_reference_passes() -> None:
    draft = _draft(summary="Activity observed on WIN-CLIENT01.")
    check_for_hallucination(draft, _case())  # must not raise


def test_supported_ip_reference_passes() -> None:
    draft = _draft(observations=("Traffic seen from 192.168.1.10.",))
    check_for_hallucination(draft, _case())  # must not raise


def test_supported_mitre_technique_passes() -> None:
    draft = _draft(summary="Consistent with T1110.")
    check_for_hallucination(draft, _case())  # must not raise


def test_supported_event_id_passes() -> None:
    draft = _draft(observations=("Event 4625 recorded.",))
    check_for_hallucination(draft, _case())  # must not raise


def test_unsupported_ip_is_rejected() -> None:
    draft = _draft(observations=("Traffic also seen from 10.0.0.99.",))
    with pytest.raises(HallucinationError, match="10.0.0.99"):
        check_for_hallucination(draft, _case())


def test_unsupported_mitre_technique_is_rejected() -> None:
    draft = _draft(summary="Also consistent with T1078.")
    with pytest.raises(HallucinationError, match="T1078"):
        check_for_hallucination(draft, _case())


def test_unsupported_event_id_is_rejected() -> None:
    draft = _draft(observations=("Event 9999 also recorded.",))
    with pytest.raises(HallucinationError, match="9999"):
        check_for_hallucination(draft, _case())


def test_unsupported_hostname_is_rejected() -> None:
    draft = _draft(summary="Additional activity on FAKE-HOST-99.")
    with pytest.raises(HallucinationError, match="FAKE-HOST-99"):
        check_for_hallucination(draft, _case())


def test_ordinary_english_word_is_not_flagged_as_hostname() -> None:
    draft = _draft(summary="This looks like a routine background process.")
    check_for_hallucination(draft, _case())  # must not raise -- no hyphenated tokens present


def test_investigation_questions_are_not_checked() -> None:
    # Per this module's design: only summary/observations are claims
    # of fact. A question can freely reference a hypothetical host
    # without being treated as a hallucinated factual claim.
    draft = AIAnalysisDraft(
        summary="ok",
        observations=(),
        investigation_questions=("Was FAKE-HOST-99 also involved?",),
        evidence_gaps=(),
        possible_false_positives=(),
        recommended_next_steps=(),
        unsupported_claims=(),
    )
    check_for_hallucination(draft, _case())  # must not raise


def test_empty_case_evidence_still_allows_generic_summary() -> None:
    empty_case = Case(
        case_id="case-empty",
        first_seen=None,
        last_seen=None,
        affected_hosts=(),
        affected_users=(),
        normalized_events=(),
        rule_matches=(),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.LOW,
        observed_facts=(),
        evidence_gaps=(),
    )
    draft = _draft(summary="No events were observed in this case.")
    check_for_hallucination(draft, empty_case)  # must not raise