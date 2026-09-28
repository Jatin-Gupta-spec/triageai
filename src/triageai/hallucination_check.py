"""Validates AI-claimed structured entities against the case's own
evidence allow-list -- layered ON TOP OF output_validation.py's shape
checking. output_validation proves the JSON is well-formed; this
module proves its CONTENT doesn't invent evidence.

Four entity types are checked: hostnames, IP addresses, Windows event
IDs, and MITRE technique IDs. Free-text prose naming none of these is
left alone: it stays explicitly unverified and human-reviewed.

Stage 17b changes:

1. Every prose field is checked: summary, observations, investigation
   questions, evidence gaps, possible false positives, and recommended
   next steps. unsupported_claims is NOT checked: it is where a
   provider lists things it could not confirm, so an entity there is
   an honest doubt, not a claim of fact.

2. The allow-list now also includes entities found in text that Python
   itself produced: rule-match descriptions, observed facts, and
   evidence gaps. The spec allows claims traceable to "evidence or
   deterministic rule output", and the AI is shown those texts. This
   also fixes a real false rejection: a rule description such as a
   decode-error message contains tokens like "UTF-16LE" that used to
   be flagged as fabricated hostnames.

3. An event ID is only recognized when the word "event" (or "event
   ID") comes right before the number. Previously any standalone
   4-digit number was treated as an event ID, so a year inside a
   timestamp, or "Start-Sleep 5000" in a decoded payload, got the
   whole draft rejected.

4. Hostname heuristic, stated explicitly: a token is a candidate host
   if it is hyphenated, at least 4 characters, alphanumeric plus
   hyphens, contains a letter, does not end in a hyphen, AND either
   contains a digit or is all uppercase. That still catches
   WIN-CLIENT01 and ATTACKER-BOX but not PowerShell cmdlets such as
   Get-Process, and not date-like tokens such as 2026-01-25.

This case's own real rule IDs (AUTH-001 and so on) are allow-listed.

Documented limits, not silently assumed solved: claims about users,
processes, and timestamps are not checked; fully qualified domain
names and hostnames without a hyphen are not detected; an event ID is
only checked for the first number after "event"; a lookalike or
obfuscated entity is not detected.

Per the locked spec's fail-closed rule (Section 8): ANY single
unsupported structured claim invalidates the ENTIRE draft.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from triageai.models import AIAnalysisDraft, Case

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_EVENT_ID_PATTERN = re.compile(r"\bevents?(?:[\s_]*ids?)?\s*[:=#]?\s*(\d{4})\b", re.IGNORECASE)
_HOSTNAME_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{3,}")
_TOKEN_STRIP_CHARS = ".,:;()[]\"'"


class HallucinationError(Exception):
    """The AI draft contains a structured claim unsupported by the
    case's own evidence allow-list. Per the locked spec's fail-closed
    rule, this invalidates the ENTIRE draft.
    """


@dataclass(frozen=True, slots=True)
class _AllowList:
    ips: frozenset[str]
    techniques: frozenset[str]
    event_ids: frozenset[str]
    hosts: frozenset[str]  # lowercased; includes this case's own rule IDs


def _looks_like_hostname(token: str) -> bool:
    if not _HOSTNAME_SHAPE.fullmatch(token):
        return False
    if "-" not in token or token.endswith("-"):
        return False
    if not any(char.isalpha() for char in token):
        return False
    return any(char.isdigit() for char in token) or token.isupper()


def _hostname_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for raw_token in text.split():
        token = raw_token.strip(_TOKEN_STRIP_CHARS)
        if _looks_like_hostname(token):
            tokens.append(token)
    return tokens


def _build_allow_list(case: Case) -> _AllowList:
    ips: set[str] = set()
    techniques: set[str] = set()
    event_ids: set[str] = set()
    hosts: set[str] = set()

    for event in case.normalized_events:
        if event.host is not None:
            hosts.add(event.host.lower())
        if event.source_ip is not None:
            ips.add(event.source_ip)
        if event.destination_ip is not None:
            ips.add(event.destination_ip)
        if event.event_id is not None:
            event_ids.add(event.event_id)
        techniques.update(event.mitre_techniques)

    trusted_texts: list[str] = [*case.observed_facts, *case.evidence_gaps]
    for match in case.rule_matches:
        techniques.add(match.mitre_technique)
        hosts.add(match.rule_id.lower())
        trusted_texts.append(match.description)

    for text in trusted_texts:
        ips.update(_IP_PATTERN.findall(text))
        techniques.update(_MITRE_PATTERN.findall(text))
        event_ids.update(_EVENT_ID_PATTERN.findall(text))
        hosts.update(token.lower() for token in _hostname_tokens(text))

    return _AllowList(
        ips=frozenset(ips),
        techniques=frozenset(techniques),
        event_ids=frozenset(event_ids),
        hosts=frozenset(hosts),
    )


def _find_unsupported_claims(text: str, allow_list: _AllowList) -> list[str]:
    unsupported: list[str] = []

    for ip in _IP_PATTERN.findall(text):
        if ip not in allow_list.ips:
            unsupported.append(f"IP address {ip!r} not present in this case's evidence")

    for technique in _MITRE_PATTERN.findall(text):
        if technique not in allow_list.techniques:
            unsupported.append(f"MITRE technique {technique!r} not present in this case's evidence")

    for event_id in _EVENT_ID_PATTERN.findall(text):
        if event_id not in allow_list.event_ids:
            unsupported.append(f"event ID {event_id!r} not present in this case's evidence")

    for token in _hostname_tokens(text):
        if token.lower() not in allow_list.hosts:
            unsupported.append(f"host {token!r} not present in this case's evidence")

    return unsupported


def _checked_texts(draft: AIAnalysisDraft) -> list[str]:
    return [
        draft.summary,
        *draft.observations,
        *draft.investigation_questions,
        *draft.evidence_gaps,
        *draft.possible_false_positives,
        *draft.recommended_next_steps,
    ]


def check_for_hallucination(draft: AIAnalysisDraft, case: Case) -> None:
    """Raise HallucinationError if ANY structured claim in any checked
    prose field is unsupported by the case's own evidence allow-list.
    """
    allow_list = _build_allow_list(case)

    all_unsupported: list[str] = []
    for text in _checked_texts(draft):
        all_unsupported.extend(_find_unsupported_claims(text, allow_list))

    if all_unsupported:
        raise HallucinationError("; ".join(dict.fromkeys(all_unsupported)))