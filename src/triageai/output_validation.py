"""Strict schema validation for raw AI provider output.

Turns a provider's raw text (see providers/base.py) into a trusted
AIAnalysisDraft, OR raises OutputValidationError -- there is no third
outcome. output_validation proves the JSON is well-formed and within
bounds; hallucination_check.py adds a SEPARATE check of CONTENT.

Stage 19 adds bounded size limits on provider output: a maximum raw
response size, checked BEFORE any JSON parsing is attempted (so a
huge non-JSON string is rejected cheaply, without the cost of trying
to parse it), plus per-field limits on the summary, each list, each
list item, and the draft's total text. The mock provider's own output
has always been comfortably inside these; they exist as a safe
boundary for when a real, untrusted provider is connected (v0.2+).
Every size violation is reported by MEASURED LENGTH ONLY -- the
oversized content itself is never echoed into the error message,
consistent with this project's redaction philosophy applying even to
its own internal error paths.
"""

from __future__ import annotations

import json
from typing import Any

from triageai.models import ANALYST_WARNING, AIAnalysisDraft

_STRING_LIST_FIELDS = (
    "observations",
    "investigation_questions",
    "evidence_gaps",
    "possible_false_positives",
    "recommended_next_steps",
    "unsupported_claims",
)
_ALLOWED_FIELDS = frozenset(("summary", *_STRING_LIST_FIELDS, "analyst_warning"))

MAX_RAW_RESPONSE_BYTES = 256 * 1024
MAX_SUMMARY_CHARS = 4_000
MAX_LIST_ITEMS = 50
MAX_ITEM_CHARS = 2_000
MAX_TOTAL_TEXT_CHARS = 64_000


class OutputValidationError(Exception):
    """Raw AI output failed schema or size validation -- the entire
    draft is invalid, per the locked spec's fail-closed rule. Never
    partially salvaged.
    """


def validate_ai_output(raw_text: str) -> AIAnalysisDraft:
    """Parse and strictly validate raw AI provider output.

    Raises OutputValidationError for: a raw response over the byte
    limit (checked first, before parsing), invalid or too deeply
    nested JSON, a non-object top level, any unknown key, any missing
    required field, any field with the wrong type, any field or the
    whole draft exceeding its size limit, or an analyst_warning that
    is not exactly ANALYST_WARNING.
    """
    raw_bytes = len(raw_text.encode("utf-8"))
    if raw_bytes > MAX_RAW_RESPONSE_BYTES:
        raise OutputValidationError(
            f"AI output is {raw_bytes:,} bytes, exceeding the "
            f"{MAX_RAW_RESPONSE_BYTES:,}-byte limit on raw provider output"
        )

    try:
        parsed: Any = json.loads(raw_text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise OutputValidationError(f"AI output is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise OutputValidationError(
            f"AI output must be a JSON object, got {type(parsed).__name__}"
        )

    unknown_fields = set(parsed) - _ALLOWED_FIELDS
    if unknown_fields:
        raise OutputValidationError(
            f"AI output contains unknown field(s): {', '.join(sorted(unknown_fields))}"
        )

    if "summary" not in parsed:
        raise OutputValidationError("AI output missing required field: summary")
    if not isinstance(parsed["summary"], str):
        raise OutputValidationError("AI output field 'summary' must be a string")
    if len(parsed["summary"]) > MAX_SUMMARY_CHARS:
        raise OutputValidationError(
            f"AI output field 'summary' is {len(parsed['summary']):,} characters, "
            f"exceeding the {MAX_SUMMARY_CHARS:,}-character limit"
        )

    for field in _STRING_LIST_FIELDS:
        if field not in parsed:
            raise OutputValidationError(f"AI output missing required field: {field}")
        _validate_string_list(parsed[field], field)

    if "analyst_warning" not in parsed:
        raise OutputValidationError("AI output missing required field: analyst_warning")
    if parsed["analyst_warning"] != ANALYST_WARNING:
        raise OutputValidationError(
            "AI output field 'analyst_warning' must exactly equal the "
            "application-defined warning text"
        )

    _validate_total_text_length(parsed)

    return AIAnalysisDraft(
        summary=parsed["summary"],
        observations=tuple(parsed["observations"]),
        investigation_questions=tuple(parsed["investigation_questions"]),
        evidence_gaps=tuple(parsed["evidence_gaps"]),
        possible_false_positives=tuple(parsed["possible_false_positives"]),
        recommended_next_steps=tuple(parsed["recommended_next_steps"]),
        unsupported_claims=tuple(parsed["unsupported_claims"]),
    )


def _validate_string_list(value: Any, field_name: str) -> None:
    if not isinstance(value, list):
        raise OutputValidationError(f"AI output field '{field_name}' must be a list")
    if len(value) > MAX_LIST_ITEMS:
        raise OutputValidationError(
            f"AI output field '{field_name}' has {len(value):,} items, exceeding the "
            f"{MAX_LIST_ITEMS:,}-item limit"
        )
    for item in value:
        if not isinstance(item, str):
            raise OutputValidationError(
                f"AI output field '{field_name}' must contain only strings"
            )
        if len(item) > MAX_ITEM_CHARS:
            raise OutputValidationError(
                f"AI output field '{field_name}' contains an item of {len(item):,} "
                f"characters, exceeding the {MAX_ITEM_CHARS:,}-character limit"
            )


def _validate_total_text_length(parsed: dict[str, Any]) -> None:
    total = len(parsed["summary"])
    for field in _STRING_LIST_FIELDS:
        total += sum(len(item) for item in parsed[field])
    if total > MAX_TOTAL_TEXT_CHARS:
        raise OutputValidationError(
            f"AI output's total text is {total:,} characters, exceeding the "
            f"{MAX_TOTAL_TEXT_CHARS:,}-character limit across the whole draft"
        )