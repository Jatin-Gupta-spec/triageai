"""Deterministic mock AI provider -- the ONLY provider connected in
v0.1, per the locked spec. No network calls, no randomness: the same
prompt always produces the same raw JSON text for a given failure mode.

Stage 17b: the mock now consumes the same input a real provider will,
the final prompt text from prompt_builder.build_prompt, instead of a
Case object. It parses ONLY the fixed layout that prompt_builder
defines (shared constants, one definition). Parsing is strict about
structure so untrusted evidence cannot forge it:
- exactly one BEGIN and one END marker line;
- rule matches, gaps, and hosts are read only inside their own
  sections, and event counts only from the header. Untrusted field
  values always sit after a fixed prefix on a single line, so they
  cannot become a structural line.
A prompt that does not have the expected layout raises ProviderError.

Intentionally supports FORCED FAILURE MODES, selected at construction,
because output_validation and hallucination_check both need something
real to reject. A real provider would not have this constructor
argument -- its failures would be genuine, not requested.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from triageai import prompt_builder
from triageai.models import ANALYST_WARNING
from triageai.providers.base import ProviderError

FailureMode = Literal[
    "none",
    "malformed_json",
    "missing_field",
    "unsupported_claim",
    "unknown_key",
    "altered_warning",
]

_MISSING_VALUE = "?"
_RULE_LINE_PATTERN = re.compile(r"([A-Z]+-[0-9]{3}) \((T[0-9]{4}(?:\.[0-9]{3})?)\): (.*)")
_EVENT_COUNT_PATTERN = re.compile(re.escape(prompt_builder.EVENT_COUNT_PREFIX) + r"([0-9]+)")
_AUTH_VARIANT_PATTERN = re.compile(r"authentication failures for (user|ip):")

_TRUNCATION_GAP = (
    "The evidence supplied to the assistant was truncated at the prompt size limit, "
    "so this draft may be incomplete."
)

_QUESTIONS: dict[tuple[str, str], str] = {
    ("AUTH-001", "user"): "Was this account's owner attempting to log in during this window?",
    ("AUTH-001", "ip"): "Is this source address expected to authenticate to several accounts on this host?",
    ("PS-001", ""): "Was this PowerShell invocation part of an approved administrative script?",
    ("PERSIST-001", ""): "Was this scheduled task created as part of approved system administration?",
}

_FALSE_POSITIVES: dict[tuple[str, str], str] = {
    ("AUTH-001", "user"): "A misconfigured service retrying with a stale credential.",
    ("AUTH-001", "ip"): "A shared gateway or proxy presenting many users from one address, or a service retrying against several accounts.",
    ("PS-001", ""): "Encoded commands are commonly used by legitimate deployment tooling.",
    ("PERSIST-001", ""): "Routine software update or maintenance task creation.",
}


@dataclass(frozen=True, slots=True)
class _RuleLine:
    rule_id: str
    technique: str
    description: str


@dataclass(frozen=True, slots=True)
class _Evidence:
    event_count: int
    rules: tuple[_RuleLine, ...]
    gaps: tuple[str, ...]
    hosts: tuple[str, ...]
    truncated: bool


def _parse_evidence(prompt: str) -> _Evidence:
    lines = prompt.split("\n")
    if (
        lines.count(prompt_builder.UNTRUSTED_BEGIN) != 1
        or lines.count(prompt_builder.UNTRUSTED_END) != 1
    ):
        raise ProviderError("prompt must contain exactly one untrusted-evidence marker pair")

    begin = lines.index(prompt_builder.UNTRUSTED_BEGIN)
    end = lines.index(prompt_builder.UNTRUSTED_END)
    if end < begin:
        raise ProviderError("prompt markers are in the wrong order")

    list_prefix = prompt_builder.LIST_ITEM_PREFIX
    host_prefix = prompt_builder.HOST_LINE_PREFIX

    section = "header"
    event_count: int | None = None
    rules: list[_RuleLine] = []
    gaps: list[str] = []
    hosts: set[str] = set()
    truncated = False

    for line in lines[begin + 1 : end]:
        if line == prompt_builder.EVIDENCE_TRUNCATED_LINE:
            truncated = True
        elif line == prompt_builder.RULE_MATCHES_HEADER:
            section = "rules"
        elif line == prompt_builder.EVIDENCE_GAPS_HEADER:
            section = "gaps"
        elif line in (prompt_builder.RULE_MATCHES_NONE, prompt_builder.EVIDENCE_GAPS_NONE):
            section = "other"
        elif line == prompt_builder.EVENTS_HEADER:
            section = "events"
        elif section == "header":
            count_match = _EVENT_COUNT_PATTERN.fullmatch(line)
            if count_match is not None and event_count is None:
                event_count = int(count_match.group(1))
        elif section == "rules" and line.startswith(list_prefix):
            rule_match = _RULE_LINE_PATTERN.fullmatch(line[len(list_prefix) :])
            if rule_match is None:
                raise ProviderError("malformed rule-match line in prompt")
            rules.append(_RuleLine(rule_match.group(1), rule_match.group(2), rule_match.group(3)))
        elif section == "gaps" and line.startswith(list_prefix):
            gaps.append(line[len(list_prefix) :])
        elif section == "events" and line.startswith(host_prefix):
            host = line[len(host_prefix) :]
            if host != _MISSING_VALUE:
                hosts.add(host)

    if event_count is None:
        raise ProviderError("prompt is missing the event count")

    return _Evidence(
        event_count=event_count,
        rules=tuple(rules),
        gaps=tuple(gaps),
        hosts=tuple(sorted(hosts)),
        truncated=truncated,
    )


def _variant(rule: _RuleLine) -> str:
    """Which AUTH-001 dimension matched ("user" or "ip"); "" otherwise."""
    if rule.rule_id != "AUTH-001":
        return ""
    found = _AUTH_VARIANT_PATTERN.search(rule.description)
    return found.group(1) if found else ""


def _question_for(rule_id: str, variant: str) -> str:
    return _QUESTIONS.get((rule_id, variant)) or f"What is the context behind this {rule_id} match?"


def _false_positive_for(rule_id: str, variant: str) -> str:
    return _FALSE_POSITIVES.get((rule_id, variant)) or (
        "Unknown -- no documented false positive for this rule."
    )


def _build_draft(evidence: _Evidence) -> dict[str, Any]:
    gaps = list(evidence.gaps)
    if evidence.truncated:
        gaps.append(_TRUNCATION_GAP)

    if not evidence.rules:
        return _benign_draft(evidence, gaps)
    return _matched_draft(evidence, gaps)


def _benign_draft(evidence: _Evidence, gaps: list[str]) -> dict[str, Any]:
    hosts = ", ".join(evidence.hosts) or "no host recorded"
    return {
        "summary": (
            f"No deterministic rule matched for this case ({hosts}). "
            "No further explanation is warranted from the available evidence."
        ),
        "observations": [f"{evidence.event_count} event(s) observed, no rule triggered."],
        "investigation_questions": [],
        "evidence_gaps": gaps,
        "possible_false_positives": [],
        "recommended_next_steps": ["No action indicated by deterministic rules alone."],
        "unsupported_claims": [],
        "analyst_warning": ANALYST_WARNING,
    }


def _matched_draft(evidence: _Evidence, gaps: list[str]) -> dict[str, Any]:
    rule_ids = sorted({rule.rule_id for rule in evidence.rules})
    keys = sorted({(rule.rule_id, _variant(rule)) for rule in evidence.rules})
    hosts = ", ".join(evidence.hosts) or "?"
    return {
        "summary": (
            f"{len(evidence.rules)} deterministic rule match(es) found ({', '.join(rule_ids)}) "
            f"for host(s) {hosts}. This is a mechanical pattern match, not a confirmed incident."
        ),
        "observations": [f"{rule.rule_id}: {rule.description}" for rule in evidence.rules],
        "investigation_questions": list(dict.fromkeys(_question_for(*key) for key in keys)),
        "evidence_gaps": gaps,
        "possible_false_positives": list(
            dict.fromkeys(_false_positive_for(*key) for key in keys)
        ),
        "recommended_next_steps": [
            "Review the full case timeline and confirm whether this activity was authorized."
        ],
        "unsupported_claims": [],
        "analyst_warning": ANALYST_WARNING,
    }


class MockProvider:
    """Deterministic mock. `failure_mode` defaults to "none" -- normal,
    schema-valid, non-hallucinating output.
    """

    def __init__(self, failure_mode: FailureMode = "none") -> None:
        self._failure_mode = failure_mode

    def generate(self, prompt: str) -> str:
        evidence = _parse_evidence(prompt)

        if self._failure_mode == "malformed_json":
            return '{"summary": "unterminated'  # deliberately broken JSON

        draft = _build_draft(evidence)

        if self._failure_mode == "missing_field":
            del draft["analyst_warning"]
        elif self._failure_mode == "unsupported_claim":
            # A host that does NOT appear anywhere in this case's real
            # evidence -- hallucination_check must catch exactly this.
            draft["observations"] = [
                *draft["observations"],
                "Additional suspicious activity observed on host FAKE-HOST-99.",
            ]
        elif self._failure_mode == "unknown_key":
            draft["confidence_score"] = 0.99
        elif self._failure_mode == "altered_warning":
            draft["analyst_warning"] = "INCIDENT CONFIRMED"

        return json.dumps(draft)