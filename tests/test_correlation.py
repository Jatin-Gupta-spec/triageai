"""Tests for src/triageai/correlation.py: case grouping and the
locked severity/confidence aggregation rule.

Aggregation is tested with synthetic RuleMatch fixtures, independent
of any real rule firing, per the locked spec's test-plan requirement
("Test aggregation separately... including ties and no matches").
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from triageai.correlation import CORRELATION_GAP, aggregate_severity_confidence, build_cases
from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

_BASE = datetime(2026, 1, 1, tzinfo=UTC)


def _event(
    record_id: str,
    *,
    host: str | None = None,
    user: str | None = None,
    timestamp: datetime | None = None,
    event_id: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=timestamp,
        host=host,
        user=user,
        source=None,
        event_id=event_id,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=None,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )


def _match(severity: Severity, confidence: Confidence) -> RuleMatch:
    return RuleMatch(
        rule_id="X",
        mitre_technique="T0000",
        severity=severity,
        confidence=confidence,
        matched_event_ids=(),
        description="",
    )


# --- build_cases: grouping ---


def test_events_on_same_host_within_gap_form_one_case() -> None:
    e1 = _event("r1", host="H1", timestamp=_BASE)
    e2 = _event("r2", host="H1", timestamp=_BASE + timedelta(hours=1))

    cases = build_cases((e1, e2))

    assert len(cases) == 1
    assert set(cases[0].normalized_events) == {e1, e2}


def test_events_on_same_host_beyond_gap_split_into_two_cases() -> None:
    e1 = _event("r1", host="H1", timestamp=_BASE)
    e2 = _event("r2", host="H1", timestamp=_BASE + CORRELATION_GAP + timedelta(seconds=1))

    assert len(build_cases((e1, e2))) == 2


def test_hostless_events_become_singleton_cases() -> None:
    e1 = _event("r1", host=None)
    e2 = _event("r2", host=None)

    assert len(build_cases((e1, e2))) == 2


def test_undated_events_attach_to_first_case_for_host() -> None:
    dated = _event("r1", host="H1", timestamp=_BASE)
    undated = _event("r2", host="H1", timestamp=None)

    cases = build_cases((dated, undated))

    assert len(cases) == 1
    assert set(cases[0].normalized_events) == {dated, undated}


def test_host_with_only_undated_events_forms_one_case() -> None:
    e1 = _event("r1", host="H1", timestamp=None)
    e2 = _event("r2", host="H1", timestamp=None)

    assert len(build_cases((e1, e2))) == 1


def test_build_cases_is_deterministic_across_runs() -> None:
    e1 = _event("r1", host="H1", timestamp=_BASE)
    e2 = _event("r2", host="H2", timestamp=_BASE)

    first = [c.case_id for c in build_cases((e1, e2))]
    second = [c.case_id for c in build_cases((e1, e2))]

    assert first == second


def test_case_with_real_auth001_pattern_gets_matched_severity() -> None:
    events = tuple(
        _event(f"r{i}", host="H1", user="alice", timestamp=_BASE + timedelta(minutes=i), event_id="4625")
        for i in range(5)
    )

    cases = build_cases(events)

    assert len(cases) == 1
    assert cases[0].severity == Severity.MEDIUM
    assert len(cases[0].rule_matches) == 1
    assert cases[0].rule_matches[0].rule_id == "AUTH-001"


def test_case_with_no_matching_pattern_is_informational_low() -> None:
    cases = build_cases((_event("r1", host="H1", timestamp=_BASE),))

    assert cases[0].severity == Severity.INFORMATIONAL
    assert cases[0].confidence == Confidence.LOW


# --- aggregate_severity_confidence: the locked formula, in isolation ---


def test_aggregate_no_matches_is_informational_low() -> None:
    severity, confidence = aggregate_severity_confidence(())
    assert severity == Severity.INFORMATIONAL
    assert confidence == Confidence.LOW


def test_aggregate_single_match_uses_its_own_severity_and_confidence() -> None:
    severity, confidence = aggregate_severity_confidence(
        (_match(Severity.HIGH, Confidence.MEDIUM),)
    )
    assert severity == Severity.HIGH
    assert confidence == Confidence.MEDIUM


def test_aggregate_takes_max_severity_across_matches() -> None:
    severity, _ = aggregate_severity_confidence(
        (_match(Severity.LOW, Confidence.HIGH), _match(Severity.CRITICAL, Confidence.LOW))
    )
    assert severity == Severity.CRITICAL


def test_aggregate_confidence_only_from_matches_at_max_severity() -> None:
    # The key nuance the spec calls out: a lower-severity match's HIGH
    # confidence must NOT leak into the result just because it's the
    # highest confidence value present anywhere in the match set.
    severity, confidence = aggregate_severity_confidence(
        (_match(Severity.HIGH, Confidence.LOW), _match(Severity.MEDIUM, Confidence.HIGH))
    )
    assert severity == Severity.HIGH
    assert confidence == Confidence.LOW


def test_aggregate_ties_at_same_severity_take_max_confidence() -> None:
    severity, confidence = aggregate_severity_confidence(
        (_match(Severity.MEDIUM, Confidence.LOW), _match(Severity.MEDIUM, Confidence.HIGH))
    )
    assert severity == Severity.MEDIUM
    assert confidence == Confidence.HIGH