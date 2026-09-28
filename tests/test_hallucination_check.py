"""Tests for src/triageai/hallucination_check.py."""

from __future__ import annotations

from dataclasses import replace

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


def _match(
    rule_id: str = "AUTH-001", mitre_technique: str = "T1110", description: str = ""
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        mitre_technique=mitre_technique,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        matched_event_ids=("rec-1",),
        description=description,
    )


def _case(
    rule_matches: tuple[RuleMatch, ...] = (),
    observed_facts: tuple[str, ...] = (),
    evidence_gaps: tuple[str, ...] = (),
) -> Case:
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
        observed_facts=observed_facts,
        evidence_gaps=evidence_gaps,
    )


def _draft(
    *,
    summary: str = "ok",
    observations: tuple[str, ...] = (),
    evidence_gaps: tuple[str, ...] = (),
) -> AIAnalysisDraft:
    return AIAnalysisDraft(
        summary=summary,
        observations=observations,
        investigation_questions=(),
        evidence_gaps=evidence_gaps,
        possible_false_positives=(),
        recommended_next_steps=(),
        unsupported_claims=(),
    )


# --- Supported claims pass ---


def test_supported_host_reference_passes() -> None:
    check_for_hallucination(_draft(summary="Activity observed on WIN-CLIENT01."), _case())


def test_supported_ip_reference_passes() -> None:
    check_for_hallucination(_draft(observations=("Traffic seen from 192.168.1.10.",)), _case())


def test_supported_mitre_technique_passes() -> None:
    check_for_hallucination(_draft(summary="Consistent with T1110."), _case())


def test_supported_event_id_passes() -> None:
    check_for_hallucination(_draft(observations=("Event 4625 recorded.",)), _case())


def test_ordinary_english_word_is_not_flagged_as_hostname() -> None:
    check_for_hallucination(_draft(summary="This looks like a routine background process."), _case())


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
    check_for_hallucination(_draft(summary="No events were observed in this case."), empty_case)


# --- Unsupported claims are rejected ---


def test_unsupported_ip_is_rejected() -> None:
    draft = _draft(observations=("Traffic also seen from 10.0.0.99.",))
    with pytest.raises(HallucinationError, match="10.0.0.99"):
        check_for_hallucination(draft, _case())


def test_unsupported_mitre_technique_is_rejected() -> None:
    with pytest.raises(HallucinationError, match="T1078"):
        check_for_hallucination(_draft(summary="Also consistent with T1078."), _case())


def test_unsupported_event_id_is_rejected() -> None:
    with pytest.raises(HallucinationError, match="9999"):
        check_for_hallucination(_draft(observations=("Event 9999 also recorded.",)), _case())


def test_event_id_written_with_underscore_is_checked() -> None:
    with pytest.raises(HallucinationError, match="9999"):
        check_for_hallucination(_draft(observations=("Saw event_id=9999 on the host.",)), _case())


def test_unsupported_hostname_is_rejected() -> None:
    with pytest.raises(HallucinationError, match="FAKE-HOST-99"):
        check_for_hallucination(_draft(summary="Additional activity on FAKE-HOST-99."), _case())


def test_uppercase_hyphenated_name_without_digits_is_rejected() -> None:
    with pytest.raises(HallucinationError, match="ATTACKER-BOX"):
        check_for_hallucination(_draft(summary="Activity on ATTACKER-BOX."), _case())


# --- Every prose field is checked; unsupported_claims is not ---


@pytest.mark.parametrize(
    "field",
    [
        "summary",
        "observations",
        "investigation_questions",
        "evidence_gaps",
        "possible_false_positives",
        "recommended_next_steps",
    ],
)
def test_unsupported_hostname_is_rejected_in_every_checked_field(field: str) -> None:
    text = "Check FAKE-HOST-99 next."
    value: str | tuple[str, ...] = text if field == "summary" else (text,)
    draft = replace(_draft(), **{field: value})
    with pytest.raises(HallucinationError, match="FAKE-HOST-99"):
        check_for_hallucination(draft, _case())


def test_unsupported_claims_field_is_not_checked() -> None:
    draft = replace(_draft(), unsupported_claims=("I suspect FAKE-HOST-99 but cannot confirm.",))
    check_for_hallucination(draft, _case())  # honest self-reported doubt, must not raise


# --- Numbers and dates that are NOT event IDs ---


def test_bare_four_digit_number_is_not_treated_as_event_id() -> None:
    check_for_hallucination(_draft(observations=("The script sleeps for 5000 milliseconds.",)), _case())


def test_year_inside_a_timestamp_is_not_treated_as_event_id() -> None:
    check_for_hallucination(_draft(summary="Activity began at 2026-01-25T09:00:00Z."), _case())


def test_date_only_token_is_not_treated_as_hostname() -> None:
    check_for_hallucination(_draft(summary="Seen on 2026-01-25."), _case())


# --- Rule IDs ---


def test_rule_id_reference_in_observation_is_not_flagged_as_hallucinated_host() -> None:
    case = _case(rule_matches=(_match(rule_id="AUTH-001"),))
    draft = _draft(
        summary="1 deterministic rule match(es) found (AUTH-001) for host(s) WIN-CLIENT01.",
        observations=("AUTH-001: 5 authentication failures for user:bob on host WIN-CLIENT01",),
    )
    check_for_hallucination(draft, case)


def test_unlisted_rule_id_is_still_rejected() -> None:
    case = _case(rule_matches=(_match(rule_id="AUTH-001"),))
    with pytest.raises(HallucinationError, match="PS-001"):
        check_for_hallucination(_draft(summary="This also looks like a PS-001 finding."), case)


# --- PowerShell content ---


def test_powershell_cmdlet_style_tokens_without_digits_are_not_flagged_as_hostnames() -> None:
    draft = _draft(observations=("decoded successfully: Get-Process | Where-Object CPU -gt 90",))
    check_for_hallucination(draft, _case())


def test_full_mock_style_ps001_observation_with_decoded_payload_passes() -> None:
    case = _case(rule_matches=(_match(rule_id="PS-001", mitre_technique="T1059.001"),))
    observation_text = (
        "PS-001: Encoded PowerShell command on host WIN-CLIENT01: "
        "decoded successfully: Get-Process | Where-Object CPU -gt 90"
    )
    check_for_hallucination(_draft(observations=(observation_text,)), case)


# --- Entities that appear in Python-generated text are allowed ---


def test_ip_from_a_rule_description_is_allowed() -> None:
    description = "decoded successfully: Invoke-WebRequest http://10.9.8.7/payload"
    case = _case(
        rule_matches=(_match(rule_id="PS-001", mitre_technique="T1059.001", description=description),)
    )
    check_for_hallucination(_draft(observations=(f"PS-001: {description}",)), case)


def test_decode_error_tokens_from_a_rule_description_are_allowed() -> None:
    description = "decode attempted, failed (not valid UTF-16LE: 'utf-16-le' codec can't decode byte)"
    case = _case(
        rule_matches=(_match(rule_id="PS-001", mitre_technique="T1059.001", description=description),)
    )
    check_for_hallucination(_draft(observations=(f"PS-001: {description}",)), case)


def test_host_from_an_evidence_gap_is_allowed() -> None:
    case = _case(evidence_gaps=("Logs from SRV-2019 are missing.",))
    check_for_hallucination(_draft(evidence_gaps=("Logs from SRV-2019 are missing.",)), case)


def test_host_from_an_observed_fact_is_allowed() -> None:
    case = _case(observed_facts=("2 event(s) observed for host SRV-2019",))
    check_for_hallucination(_draft(summary="Two events were seen on SRV-2019."), case)