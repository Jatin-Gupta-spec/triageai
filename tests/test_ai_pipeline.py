"""End-to-end tests of the AI pipeline as the CLI runs it: build the
prompt, ask a provider, validate shape, validate content. Uses the
CLI's private _generate_validated_draft so misbehaving providers can be
exercised without adding anything to the locked command-line surface.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from triageai.cli import (
    REJECTION_PROVIDER_ERROR,
    REJECTION_SCHEMA_INVALID,
    REJECTION_UNSUPPORTED_CLAIM,
    _generate_validated_draft,
    main,
)
from triageai.correlation import build_cases
from triageai.models import ANALYST_WARNING, Case
from triageai.normalization import normalize_event
from triageai.providers.base import ProviderError
from triageai.providers.mock import MockProvider
from triageai.redaction import redact_case_for_render

_FIXTURES = Path(__file__).parent / "fixtures"


def _redacted_case(records: list[dict[str, str]]) -> Case:
    events = tuple(normalize_event(record) for record in records)
    return redact_case_for_render(build_cases(events)[0])


_BENIGN = [{"host": "WIN-CLIENT01", "event_id": "4624"}]


class _FailingProvider:
    def generate(self, prompt: str) -> str:
        raise ProviderError(f"simulated provider outage for a {len(prompt)}-character prompt")


def test_default_mock_draft_is_accepted_and_carries_the_application_warning() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN))
    assert outcome.draft is not None
    assert outcome.rejection_reason is None
    assert outcome.draft.analyst_warning == ANALYST_WARNING


def test_altered_warning_rejects_with_schema_reason() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN), MockProvider("altered_warning"))
    assert outcome.draft is None
    assert outcome.rejection_reason == REJECTION_SCHEMA_INVALID


def test_unknown_key_rejects_with_schema_reason() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN), MockProvider("unknown_key"))
    assert outcome.draft is None
    assert outcome.rejection_reason == REJECTION_SCHEMA_INVALID


def test_unsupported_claim_rejects_with_unsupported_claim_reason() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN), MockProvider("unsupported_claim"))
    assert outcome.draft is None
    assert outcome.rejection_reason == REJECTION_UNSUPPORTED_CLAIM


def test_malformed_json_rejects_with_schema_reason() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN), MockProvider("malformed_json"))
    assert outcome.draft is None
    assert outcome.rejection_reason == REJECTION_SCHEMA_INVALID


def test_missing_field_rejects_with_schema_reason() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN), MockProvider("missing_field"))
    assert outcome.draft is None
    assert outcome.rejection_reason == REJECTION_SCHEMA_INVALID


def test_provider_error_rejects_with_provider_error_reason_instead_of_crashing() -> None:
    outcome = _generate_validated_draft(_redacted_case(_BENIGN), _FailingProvider())
    assert outcome.draft is None
    assert outcome.rejection_reason == REJECTION_PROVIDER_ERROR


def test_real_auth001_case_draft_is_accepted() -> None:
    records = [
        {"host": "H1", "user": "alice", "event_id": "4625", "timestamp": f"2026-01-01T10:0{i}:00Z"}
        for i in range(5)
    ]
    case = _redacted_case(records)
    assert case.rule_matches  # premise: AUTH-001 really fired
    assert _generate_validated_draft(case).draft is not None


def test_ps001_utf16_decode_failure_draft_is_accepted() -> None:
    records = [
        {
            "host": "H1",
            "process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand b2Rk",
        }
    ]
    case = _redacted_case(records)
    assert "UTF-16LE" in case.rule_matches[0].description  # premise
    assert _generate_validated_draft(case).draft is not None


def test_cli_password_spray_report_asks_about_the_source_address(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _FIXTURES / "suspicious" / "SC-AUTH001-password-spray.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "REJECTED" not in captured.out
    assert "source address" in captured.out
    assert "account's owner" not in captured.out