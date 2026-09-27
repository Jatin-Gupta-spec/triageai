"""Tests for src/triageai/output_validation.py.

Covers: valid output parses correctly, and every required-field/type
violation is rejected -- per the locked spec's fail-closed rule, ANY
violation invalidates the entire draft.
"""

from __future__ import annotations

import json

import pytest

from triageai.output_validation import OutputValidationError, validate_ai_output

_VALID_DRAFT = {
    "summary": "test summary",
    "observations": ["obs1"],
    "investigation_questions": ["q1"],
    "evidence_gaps": [],
    "possible_false_positives": [],
    "recommended_next_steps": ["step1"],
    "unsupported_claims": [],
    "analyst_warning": "AI-generated draft requiring human review",
}


def test_valid_draft_parses_successfully() -> None:
    draft = validate_ai_output(json.dumps(_VALID_DRAFT))
    assert draft.summary == "test summary"
    assert draft.observations == ("obs1",)
    assert draft.analyst_warning == "AI-generated draft requiring human review"


def test_malformed_json_is_rejected() -> None:
    with pytest.raises(OutputValidationError, match="not valid JSON"):
        validate_ai_output('{"summary": "unterminated')


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


def test_extra_unrecognized_field_is_ignored_not_rejected() -> None:
    draft = {**_VALID_DRAFT, "some_future_field": "ignored"}
    result = validate_ai_output(json.dumps(draft))
    assert result.summary == "test summary"