"""Validates AI-claimed structured entities against the case's own
evidence allow-list -- layered ON TOP OF output_validation.py's shape
checking, not instead of it. output_validation proves the JSON is
well-formed; this module proves its CONTENT doesn't invent evidence.

Per the locked spec: "Mechanically reject structured entity claims not
present in the evidence allow-list." Four structured entity types are
checked: hostnames, IP addresses, Windows event IDs, and MITRE
technique IDs. Free-text prose that names none of these is NOT
verifiable this way and is intentionally left alone -- per the spec,
"Free-text prose remains explicitly unverified and human-reviewed."

Detection heuristic, stated explicitly (this module's own documented
interpretation, same pattern as every rule's own detection logic):
- An IP-shaped token (dotted-quad pattern) is extracted and checked
  directly.
- A MITRE-technique-shaped token (T#### or T####.###) is extracted
  and checked directly.
- A 4-digit token is treated as a candidate Windows event ID.
- Any remaining whitespace-delimited token is checked against the
  allow-listed HOSTNAMES only if it exactly matches one (case-
  insensitive) -- this deliberately does NOT attempt fuzzy or
  substring hostname matching, which would risk both false accusations
  of hallucination (a real host name that happens to be a common
  English word) and missed detections (a hallucinated host disguised
  inside a longer word). Exact, case-insensitive token match only.

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
    grouped by structured entity type. Built from the ALREADY-REDACTED
    Case -- so an alias like [REDACTED_EMAIL_001] is itself a
    legitimate allow-listed "host/user" value; the AI never sees real
    identities to begin with (see redaction.py, prompt_builder.py).
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

    for match in case.rule_matches:
        techniques.add(match.mitre_technique)

    return {"hosts": hosts, "ips": ips, "event_ids": event_ids, "techniques": techniques}


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
            unsupported.append(
                f"event ID {event_id!r} not present in this case's evidence"
            )

    for token in text.split():
        cleaned = token.strip(".,:;()[]").lower()
        if _looks_like_hostname(cleaned) and cleaned not in allow_list["hosts"]:
            unsupported.append(f"host {token.strip('.,:;()[]')!r} not present in this case's evidence")

    return unsupported


def _looks_like_hostname(token: str) -> bool:
    """A deliberately narrow heuristic: uppercase-style machine names
    (hyphens, digits, letters, length >= 4) -- narrow enough to avoid
    flagging ordinary English words in AI prose as suspected hostname
    claims.
    """
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{3,}", token)) and "-" in token


def check_for_hallucination(draft: AIAnalysisDraft, case: Case) -> None:
    """Raise HallucinationError if ANY structured claim in the
    draft's summary or observations is unsupported by the case's own
    evidence allow-list. Per the locked spec, checked fields are
    summary and observations -- the fields where the AI is drafting
    claims ABOUT the evidence, not investigation_questions or
    recommended_next_steps, which are inherently speculative/
    forward-looking by design and were never claims of observed fact.
    """
    allow_list = _build_allow_list(case)

    all_unsupported: list[str] = []
    all_unsupported.extend(_find_unsupported_claims(draft.summary, allow_list))
    for observation in draft.observations:
        all_unsupported.extend(_find_unsupported_claims(observation, allow_list))

    if all_unsupported:
        raise HallucinationError("; ".join(all_unsupported))