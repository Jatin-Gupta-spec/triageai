"""Validates AI-claimed structured entities against the case's own
evidence allow-list -- layered ON TOP OF output_validation.py's shape
checking, not instead of it. output_validation proves the JSON is
well-formed; this module proves its CONTENT doesn't invent evidence.

Per the locked spec: "Mechanically reject structured entity claims not
present in the evidence allow-list." Four structured entity types are
checked: hostnames, IP addresses, Windows event IDs, and MITRE
technique IDs. Free-text prose that names none of these is left alone,
per the spec: "Free-text prose remains explicitly unverified and
human-reviewed."

STAGE 15 -- two real bugs found by actually running the mock pipeline
against real fixtures, not caught by any unit test until then:

1. This project's own rule catalogue IDs (AUTH-001, PS-001,
   PERSIST-001) are themselves short, hyphenated, alphanumeric tokens
   -- exactly the shape the hostname heuristic looks for. Since the
   mock provider's observations always begin with "{rule_id}: ...",
   EVERY case with a real rule match got its entire AI draft rejected,
   which defeats the whole point of drafting AI commentary on
   suspicious activity. Fixed by recognizing a case's own real
   rule_ids (drawn from case.rule_matches -- genuine, deterministically
   computed evidence, never an AI invention) as their own allow-listed
   category, checked BEFORE the hostname heuristic. A rule ID NOT
   actually present in THIS case's own rule_matches is still correctly
   rejected -- see test_unlisted_rule_id_is_still_rejected.

2. PowerShell's own naming convention is hyphenated Verb-Noun
   (Get-Process, Where-Object, Set-ExecutionPolicy...) -- exactly what
   a decoded PS-001 payload preview embeds directly into an AI
   observation (see rules/powershell.py, mock.py). The bare "hyphen +
   alphanumeric" heuristic would have misidentified ordinary decoded
   PowerShell content as fabricated hostnames the moment a real
   payload was decoded. Fixed by additionally requiring the candidate
   token to contain at least one digit -- true of every real hostname
   in this project's own data (WIN-CLIENT01, WIN-CLIENT02...) and
   false of ordinary PowerShell cmdlet names. Documented, accepted
   trade-off: a fabricated hostname containing NO digit at all (e.g.
   "ATTACKER-BOX") would not be caught by this specific check -- a
   real, honest limitation, not silently assumed solved (see
   LIMITATIONS.md).

Per the locked spec's fail-closed rule (Section 8): ANY single
unsupported structured claim invalidates the ENTIRE draft -- there is
no partial acceptance, no stripping just the offending claim.
"""

from __future__ import annotations

import re

from triageai.models import AIAnalysisDraft, Case

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_EVENT_ID_PATTERN = re.compile(r"\b\d{4}\b")


class HallucinationError(Exception):
    """The AI draft contains a structured claim unsupported by the
    case's own evidence allow-list. Per the locked spec's fail-closed
    rule, this invalidates the ENTIRE draft.
    """


def _build_allow_list(case: Case) -> dict[str, set[str]]:
    """Every real, redacted value the case's own evidence supports,
    grouped by structured entity type.

    "rule_ids" (Stage 15 addition) is this case's own real,
    deterministically-computed rule matches -- not an AI claim, so
    referencing one by name is never a hallucination.
    """
    hosts: set[str] = set()
    ips: set[str] = set()
    event_ids: set[str] = set()
    techniques: set[str] = set()

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

    rule_ids = {match.rule_id for match in case.rule_matches}
    for match in case.rule_matches:
        techniques.add(match.mitre_technique)

    return {
        "hosts": hosts,
        "ips": ips,
        "event_ids": event_ids,
        "techniques": techniques,
        "rule_ids": rule_ids,
    }


def _find_unsupported_claims(text: str, allow_list: dict[str, set[str]]) -> list[str]:
    unsupported: list[str] = []

    for ip in _IP_PATTERN.findall(text):
        if ip not in allow_list["ips"]:
            unsupported.append(f"IP address {ip!r} not present in this case's evidence")

    for technique in _MITRE_PATTERN.findall(text):
        if technique not in allow_list["techniques"]:
            unsupported.append(
                f"MITRE technique {technique!r} not present in this case's evidence"
            )

    for event_id in _EVENT_ID_PATTERN.findall(text):
        if event_id not in allow_list["event_ids"]:
            unsupported.append(f"event ID {event_id!r} not present in this case's evidence")

    for token in text.split():
        stripped = token.strip(".,:;()[]")
        if stripped in allow_list["rule_ids"]:
            continue  # this case's own real rule-catalogue ID, not a claimed host

        cleaned = stripped.lower()
        if _looks_like_hostname(cleaned) and cleaned not in allow_list["hosts"]:
            unsupported.append(f"host {stripped!r} not present in this case's evidence")

    return unsupported


def _looks_like_hostname(token: str) -> bool:
    """Narrow heuristic: hyphenated, alphanumeric, length >= 4, AND
    contains at least one digit -- true of every real hostname in this
    project's own data, false of ordinary PowerShell cmdlet names.
    Trade-off documented in this module's docstring and LIMITATIONS.md.
    """
    return (
        bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{3,}", token))
        and "-" in token
        and any(char.isdigit() for char in token)
    )


def check_for_hallucination(draft: AIAnalysisDraft, case: Case) -> None:
    """Raise HallucinationError if ANY structured claim in the
    draft's summary or observations is unsupported by the case's own
    evidence allow-list. Checked fields are summary and observations --
    investigation_questions and recommended_next_steps are inherently
    speculative/forward-looking and were never claims of observed fact.
    """
    allow_list = _build_allow_list(case)

    all_unsupported: list[str] = []
    all_unsupported.extend(_find_unsupported_claims(draft.summary, allow_list))
    for observation in draft.observations:
        all_unsupported.extend(_find_unsupported_claims(observation, allow_list))

    if all_unsupported:
        raise HallucinationError("; ".join(all_unsupported))