"""Deterministic mock AI provider -- the ONLY provider connected in
v0.1, per the locked spec. No network calls, no randomness: the same
Case always produces the same raw JSON text for a given failure mode.

Intentionally supports FORCED FAILURE MODES, selected at construction.
Not because a mock naturally misbehaves -- because Stage 12's
output_validation and Stage 14's hallucination rejection both need
something real to reject, per the locked spec's test-plan requirement
("malformed mock-AI JSON, missing fields, and unsupported claims"). A
real provider (v0.2+) would not have this constructor argument -- its
failures would be genuine, not requested.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from triageai.models import Case

FailureMode = Literal["none", "malformed_json", "missing_field", "unsupported_claim"]

_RULE_QUESTIONS = {
    "AUTH-001": "Was this account's owner attempting to log in during this window?",
    "PS-001": "Was this PowerShell invocation part of an approved administrative script?",
    "PERSIST-001": "Was this scheduled task created as part of approved system administration?",
}

_RULE_FALSE_POSITIVES = {
    "AUTH-001": "A misconfigured service retrying with a stale credential.",
    "PS-001": "Encoded commands are commonly used by legitimate deployment tooling.",
    "PERSIST-001": "Routine software update or maintenance task creation.",
}


class MockProvider:
    """Deterministic mock. `failure_mode` defaults to "none" -- normal,
    schema-valid, non-hallucinating output.
    """

    def __init__(self, failure_mode: FailureMode = "none") -> None:
        self._failure_mode = failure_mode

    def generate(self, redacted_case: Case) -> str:
        if self._failure_mode == "malformed_json":
            return '{"summary": "unterminated'  # deliberately broken JSON

        draft: dict[str, Any] = self._build_draft_dict(redacted_case)

        if self._failure_mode == "missing_field":
            del draft["analyst_warning"]

        if self._failure_mode == "unsupported_claim":
            # A host that does NOT appear anywhere in this case's real
            # evidence -- Stage 14's hallucination check must catch
            # exactly this: a claim with no basis in the evidence
            # allow-list.
            draft["observations"] = [
                *draft["observations"],
                "Additional suspicious activity observed on host FAKE-HOST-99.",
            ]

        return json.dumps(draft)

    def _build_draft_dict(self, case: Case) -> dict[str, Any]:
        if not case.rule_matches:
            return self._benign_draft(case)
        return self._matched_draft(case)

    def _benign_draft(self, case: Case) -> dict[str, Any]:
        hosts = ", ".join(case.affected_hosts) or "no host recorded"
        return {
            "summary": (
                f"No deterministic rule matched for this case ({hosts}). "
                "No further explanation is warranted from the available evidence."
            ),
            "observations": [
                f"{len(case.normalized_events)} event(s) observed, no rule triggered."
            ],
            "investigation_questions": [],
            "evidence_gaps": list(case.evidence_gaps),
            "possible_false_positives": [],
            "recommended_next_steps": ["No action indicated by deterministic rules alone."],
            "unsupported_claims": [],
            "analyst_warning": "AI-generated draft requiring human review",
        }

    def _matched_draft(self, case: Case) -> dict[str, Any]:
        rule_ids = sorted({m.rule_id for m in case.rule_matches})
        return {
            "summary": (
                f"{len(case.rule_matches)} deterministic rule match(es) found "
                f"({', '.join(rule_ids)}) for host(s) {', '.join(case.affected_hosts) or '?'}. "
                "This is a mechanical pattern match, not a confirmed incident."
            ),
            "observations": [f"{m.rule_id}: {m.description}" for m in case.rule_matches],
            "investigation_questions": [
                _RULE_QUESTIONS.get(r, f"What is the context behind this {r} match?")
                for r in rule_ids
            ],
            "evidence_gaps": list(case.evidence_gaps),
            "possible_false_positives": [
                _RULE_FALSE_POSITIVES.get(
                    r, "Unknown -- no documented false positive for this rule."
                )
                for r in rule_ids
            ],
            "recommended_next_steps": [
                "Review the full case timeline and confirm whether this activity was authorized."
            ],
            "unsupported_claims": [],
            "analyst_warning": "AI-generated draft requiring human review",
        }