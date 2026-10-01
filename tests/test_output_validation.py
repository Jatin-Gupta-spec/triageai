"""Tests for src/triageai/output_validation.py.

Valid output parses; every required-field, type, unknown-key, and
warning-text violation is rejected. Per the locked spec's fail-closed
rule, ANY violation invalidates the entire draft.
"""

from __future__ import annotations

import json

import pytest

from triageai.models import ANALYST_WARNING
from triageai.output_validation import (
    MAX_ITEM_CHARS,
    MAX_LIST_ITEMS,
    MAX_RAW_RESPONSE_BYTES,
    MAX_SUMMARY_CHARS,
    MAX_TOTAL_TEXT_CHARS,
    OutputValidationError,
    validate_ai_output,
)

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


# --- Stage 19: provider-output size limits ---


def test_raw_response_over_byte_limit_is_rejected_before_json_parsing() -> None:
    oversized = "a" * (MAX_RAW_RESPONSE_BYTES + 1)
    with pytest.raises(OutputValidationError, match="exceeding"):
        validate_ai_output(oversized)


def test_raw_response_error_message_does_not_echo_oversized_content() -> None:
    oversized = "SECRET_MARKER_" + "a" * MAX_RAW_RESPONSE_BYTES
    with pytest.raises(OutputValidationError) as exc_info:
        validate_ai_output(oversized)
    assert "SECRET_MARKER_" not in str(exc_info.value)


def test_raw_response_at_exactly_the_byte_limit_passes_the_size_check() -> None:
    # Exactly at the boundary, but not valid JSON -- proves the SIZE
    # check passes at this length (it fails for being non-JSON
    # instead), not that the size check is off by one.
    at_limit = "a" * MAX_RAW_RESPONSE_BYTES
    with pytest.raises(OutputValidationError, match="not valid JSON"):
        validate_ai_output(at_limit)


def test_summary_at_exactly_max_chars_is_accepted() -> None:
    draft = {**_VALID_DRAFT, "summary": "A" * MAX_SUMMARY_CHARS}
    result = validate_ai_output(json.dumps(draft))
    assert len(result.summary) == MAX_SUMMARY_CHARS


def test_summary_one_char_over_max_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "summary": "A" * (MAX_SUMMARY_CHARS + 1)}
    with pytest.raises(OutputValidationError, match="summary"):
        validate_ai_output(json.dumps(draft))


def test_list_item_at_exactly_max_chars_is_accepted() -> None:
    draft = {**_VALID_DRAFT, "observations": ["A" * MAX_ITEM_CHARS]}
    result = validate_ai_output(json.dumps(draft))
    assert len(result.observations[0]) == MAX_ITEM_CHARS


def test_list_item_one_char_over_max_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "observations": ["A" * (MAX_ITEM_CHARS + 1)]}
    with pytest.raises(OutputValidationError, match="observations"):
        validate_ai_output(json.dumps(draft))


def test_list_at_exactly_max_items_is_accepted() -> None:
    draft = {**_VALID_DRAFT, "observations": ["x"] * MAX_LIST_ITEMS}
    result = validate_ai_output(json.dumps(draft))
    assert len(result.observations) == MAX_LIST_ITEMS


def test_list_one_item_over_max_is_rejected() -> None:
    draft = {**_VALID_DRAFT, "observations": ["x"] * (MAX_LIST_ITEMS + 1)}
    with pytest.raises(OutputValidationError, match="observations"):
        validate_ai_output(json.dumps(draft))


def test_total_text_at_exactly_max_chars_is_accepted() -> None:
    summary = "A" * MAX_SUMMARY_CHARS
    remaining = MAX_TOTAL_TEXT_CHARS - MAX_SUMMARY_CHARS
    item_count, leftover = divmod(remaining, MAX_ITEM_CHARS)
    assert leftover == 0  # true for the current constants (60,000 / 2,000)
    draft = {
        **_VALID_DRAFT,
        "summary": summary,
        "observations": ["B" * MAX_ITEM_CHARS] * item_count,
        # Every OTHER string-list field must be emptied explicitly --
        # _VALID_DRAFT carries non-empty defaults for some of them
        # ("q1", "step1"), and those were silently included in the
        # real total the first time this test was written, making the
        # draft actually 64,007 characters, not exactly 64,000.
        "investigation_questions": [],
        "evidence_gaps": [],
        "possible_false_positives": [],
        "recommended_next_steps": [],
        "unsupported_claims": [],
    }
    result = validate_ai_output(json.dumps(draft))
    assert len(result.summary) + sum(len(o) for o in result.observations) == MAX_TOTAL_TEXT_CHARS


def test_total_text_one_char_over_max_is_rejected() -> None:
    summary = "A" * MAX_SUMMARY_CHARS
    remaining = MAX_TOTAL_TEXT_CHARS - MAX_SUMMARY_CHARS
    item_count, _ = divmod(remaining, MAX_ITEM_CHARS)
    items = ["B" * MAX_ITEM_CHARS] * item_count + ["C"]
    draft = {**_VALID_DRAFT, "summary": summary, "observations": items}
    with pytest.raises(OutputValidationError, match="total text"):
        validate_ai_output(json.dumps(draft))