"""Tests for src/triageai/output_validation.py.

Valid output parses; every required-field, type, unknown-key, and
warning-text violation is rejected. Per the locked spec's fail-closed
rule, ANY violation invalidates the entire draft.
"""

from __future__ import annotations

import json

import pytest

from triageai.models import ANALYST_WARNING
from triageai.output_validation import OutputValidationError, validate_ai_output

_VALID_DRAFT = {
    "summary": "test summary",
    "observations": ["obs1"],
    "investigation_questions": ["q1"],
    "evidence_gaps": [],
    "possible_false_positives": [],
    "recommended_next_steps": ["step1"],
    "unsupported_claims": [],
    "analyst_warning": ANALYST_WARNING,
}


def test_valid_draft_parses_successfully() -> None:
    draft = validate_ai_output(json.dumps(_VALID_DRAFT))
    assert draft.summary == "test summary"
    assert draft.observations == ("obs1",)
    assert draft.analyst_warning == ANALYST_WARNING


def test_malformed_json_is_rejected() -> None:
    with pytest.raises(OutputValidationError, match="not valid JSON"):
        validate_ai_output('{"summary": "unterminated')


def test_deeply_nested_json_is_rejected_not_crashed() -> None:
    with pytest.raises(OutputValidationError):
        validate_ai_output("[" * 100_000)


def test_non_object_top_level_is_rejected() -> None:
    with pytest.raises(OutputValidationError, match="must be a JSON object"):
        validate_ai_output(json.dumps(["not", "an", "object"]))


def test_missing_summary_is_rejected() -> None:
    draft = {k: v for k, v in _VALID_DRAFT.items() if k != "summary"}
    with pytest.raises(OutputValidationError, match="summary"):
        validate_ai_output(json.dumps(draft))


def test_missing_analyst_warning_is_rejected() -> None:
    draft = {k: v for k, v in _VALID_DRAFT.items() if k != "analyst_warning"}
    with pytest.raises(OutputValidationError, match="analyst_warning"):
        validate_ai_output(json.dumps(draft))


@pytest.mark.parametrize(
    "field",
    [
        "observations",
        "investigation_questions",
        "evidence_gaps",
        "possible_false_positives",
        "recommended_next_steps",
        "unsupported_claims",
    ],
)
def test_missing_required_list_field_is_rejected(field: str) -> None:
    draft = {k: v for k, v in _VALID_DRAFT.items() if k != field}
    with pytest.raises(OutputValidationError, match=field):
        validate_ai_output(json.dumps(draft))


def test_summary_wrong_type_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "summary": 12345}
    with pytest.raises(OutputValidationError, match="summary"):
        validate_ai_output(json.dumps(draft))


def test_list_field_containing_non_string_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "observations": ["ok", 123]}
    with pytest.raises(OutputValidationError, match="observations"):
        validate_ai_output(json.dumps(draft))


def test_list_field_not_a_list_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "observations": "not a list"}
    with pytest.raises(OutputValidationError, match="observations"):
        validate_ai_output(json.dumps(draft))


def test_unknown_field_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "confidence_score": 0.99}
    with pytest.raises(OutputValidationError, match="confidence_score"):
        validate_ai_output(json.dumps(draft))


@pytest.mark.parametrize(
    "warning",
    [
        "INCIDENT CONFIRMED",
        "",
        ANALYST_WARNING.lower(),
        f"{ANALYST_WARNING} ",
        123,
        None,
    ],
)
def test_altered_analyst_warning_is_rejected(warning: object) -> None:
    draft = {**_VALID_DRAFT, "analyst_warning": warning}
    with pytest.raises(OutputValidationError, match="analyst_warning"):
        validate_ai_output(json.dumps(draft))