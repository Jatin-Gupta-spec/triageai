"""Tests for the deterministic mock AI provider."""

from __future__ import annotations

import json

from triageai.models import Case, Confidence, NormalizedEvent, RuleMatch, Severity
from triageai.providers.mock import MockProvider


def _case(rule_matches: tuple[RuleMatch, ...] = ()) -> Case:
    event = NormalizedEvent(
        original_record_id="rec-1",
        timestamp=None,
        host="WIN-CLIENT01",
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
    return Case(
        case_id="case-1",
        first_seen=None,
        last_seen=None,
        affected_hosts=("WIN-CLIENT01",),
        affected_users=(),
        normalized_events=(event,),
        rule_matches=rule_matches,
        severity=Severity.INFORMATIONAL if not rule_matches else Severity.MEDIUM,
        confidence=Confidence.LOW if not rule_matches else Confidence.MEDIUM,
        observed_facts=(),
        evidence_gaps=(),
    )


def _match() -> RuleMatch:
    return RuleMatch(
        rule_id="AUTH-001",
        mitre_technique="T1110",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        matched_event_ids=("rec-1",),
        description="5 failures in 10 minutes",
    )


def test_mock_is_deterministic_across_calls() -> None:
    provider = MockProvider()
    case = _case()
    assert provider.generate(case) == provider.generate(case)


def test_mock_returns_valid_json_by_default() -> None:
    provider = MockProvider()
    parsed = json.loads(provider.generate(_case()))
    assert "summary" in parsed
    assert parsed["analyst_warning"] == "AI-generated draft requiring human review"


def test_mock_benign_case_has_no_investigation_questions() -> None:
    provider = MockProvider()
    parsed = json.loads(provider.generate(_case()))
    assert parsed["investigation_questions"] == []


def test_mock_matched_case_includes_rule_id_in_observations() -> None:
    provider = MockProvider()
    parsed = json.loads(provider.generate(_case(rule_matches=(_match(),))))
    assert any("AUTH-001" in obs for obs in parsed["observations"])


def test_mock_malformed_json_failure_mode() -> None:
    provider = MockProvider(failure_mode="malformed_json")
    raw = provider.generate(_case())
    raised = False
    try:
        json.loads(raw)
    except json.JSONDecodeError:
        raised = True
    assert raised


def test_mock_missing_field_failure_mode() -> None:
    provider = MockProvider(failure_mode="missing_field")
    parsed = json.loads(provider.generate(_case()))
    assert "analyst_warning" not in parsed


def test_mock_unsupported_claim_failure_mode() -> None:
    provider = MockProvider(failure_mode="unsupported_claim")
    parsed = json.loads(provider.generate(_case()))
    assert any("FAKE-HOST-99" in obs for obs in parsed["observations"])