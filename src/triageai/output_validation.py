"""Strict schema validation for raw AI provider output.

Turns a provider's raw text (see providers/base.py) into a trusted
AIAnalysisDraft, OR raises OutputValidationError -- there is no third
outcome. Per the locked spec's fail-closed AI draft rejection: a
schema/type error invalidates the ENTIRE draft, not just the
offending field. This module only checks SHAPE (required keys
present, correct types) -- Stage 14 adds a SEPARATE, ADDITIONAL check
for hallucinated CONTENT (claims not backed by evidence), layered on
top of, not instead of, this validation.
"""

from __future__ import annotations

import json
from typing import Any

from triageai.models import AIAnalysisDraft

_REQUIRED_STRING_LIST_FIELDS = (
    "observations",
    "investigation_questions",
    "evidence_gaps",
    "possible_false_positives",
    "recommended_next_steps",
    "unsupported_claims",
)


class OutputValidationError(Exception):
    """Raw AI output failed schema validation -- the entire draft is
    invalid, per the locked spec's fail-closed rule. Never partially
    salvaged.
    """


def validate_ai_output(raw_text: str) -> AIAnalysisDraft:
    """Parse and strictly validate raw AI provider output.

    Raises OutputValidationError for: invalid JSON, a non-object top
    level, any missing required field, or any field with the wrong
    type. Extra, unrecognized keys are ignored, not rejected -- this
    project doesn't need forward-incompatibility with a future
    provider that adds harmless extra fields.
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise OutputValidationError(f"AI output is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise OutputValidationError(
            f"AI output must be a JSON object, got {type(parsed).__name__}"
        )

    if "summary" not in parsed:
        raise OutputValidationError("AI output missing required field: summary")
    if not isinstance(parsed["summary"], str):
        raise OutputValidationError("AI output field 'summary' must be a string")

    for field in _REQUIRED_STRING_LIST_FIELDS:
        if field not in parsed:
            raise OutputValidationError(f"AI output missing required field: {field}")
        _validate_string_list(parsed[field], field)

    if "analyst_warning" not in parsed:
        raise OutputValidationError("AI output missing required field: analyst_warning")
    if not isinstance(parsed["analyst_warning"], str):
        raise OutputValidationError("AI output field 'analyst_warning' must be a string")

    return AIAnalysisDraft(
        summary=parsed["summary"],
        observations=tuple(parsed["observations"]),
        investigation_questions=tuple(parsed["investigation_questions"]),
        evidence_gaps=tuple(parsed["evidence_gaps"]),
        possible_false_positives=tuple(parsed["possible_false_positives"]),
        recommended_next_steps=tuple(parsed["recommended_next_steps"]),
        unsupported_claims=tuple(parsed["unsupported_claims"]),
        analyst_warning=parsed["analyst_warning"],
    )


def _validate_string_list(value: Any, field_name: str) -> None:
    if not isinstance(value, list):
        raise OutputValidationError(f"AI output field '{field_name}' must be a list")
    for item in value:
        if not isinstance(item, str):
            raise OutputValidationError(
                f"AI output field '{field_name}' must contain only strings"
            )