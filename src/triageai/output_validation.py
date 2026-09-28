"""Strict schema validation for raw AI provider output.

Turns a provider's raw text (see providers/base.py) into a trusted
AIAnalysisDraft, OR raises OutputValidationError -- there is no third
outcome. Per the locked spec's fail-closed AI draft rejection: a
schema/type error invalidates the ENTIRE draft, not just the
offending field. This module only checks SHAPE and the fixed warning
text -- hallucination_check.py adds a SEPARATE check of CONTENT.

Stage 17b changes:
- Unknown top-level keys are rejected. The schema in the locked spec
  is fixed, and extra keys are a channel for content nothing else
  validates.
- analyst_warning must EXACTLY equal the application constant
  ANALYST_WARNING. Previously any string was accepted, so a provider
  could return "INCIDENT CONFIRMED" and it would be rendered as if it
  were the trusted safety warning. The returned draft always carries
  the application's own constant, never the provider's text.
- Deeply nested JSON that exhausts the parser's recursion limit is
  rejected instead of crashing.
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


class OutputValidationError(Exception):
    """Raw AI output failed schema validation -- the entire draft is
    invalid, per the locked spec's fail-closed rule. Never partially
    salvaged.
    """


def validate_ai_output(raw_text: str) -> AIAnalysisDraft:
    """Parse and strictly validate raw AI provider output.

    Raises OutputValidationError for: invalid or too deeply nested
    JSON, a non-object top level, any unknown key, any missing
    required field, any field with the wrong type, or an
    analyst_warning that is not exactly ANALYST_WARNING.
    """
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
    for item in value:
        if not isinstance(item, str):
            raise OutputValidationError(
                f"AI output field '{field_name}' must contain only strings"
            )