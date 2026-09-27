"""Render-boundary redaction: reports and AI prompts only.

Internal NormalizedEvent/Case objects are never mutated -- this module
produces REDACTED COPIES for rendering, per the locked spec (Sections
5, 8, 11). See models.py's module docstring for why real values are
kept internally in the first place.

Three distinct redaction behaviors, not to be confused with each other:

1. Free-text redaction (command lines, arbitrary strings): every
   email-like substring becomes a flat, unnumbered "[REDACTED_EMAIL]"
   token. Known secret PATTERNS (a "password=" or "Authorization:
   Bearer ..." appearing INSIDE a string's own text) similarly become
   flat tokens.

2. Identity-field redaction (structured fields, rule-match
   descriptions, and -- as of this fix -- observed_facts and
   evidence_gaps too): each distinct email-like value gets its own
   numbered alias. This is what lets two different accounts stay
   distinguishable in a rendered report, and lets the SAME identity be
   recognized consistently wherever it appears.

3. Key-aware secret redaction (this fix): redact_structure(), used for
   arbitrary nested evidence structures, now inspects the KEY name
   during traversal, not just the string VALUE. Behavior #1 above only
   catches a secret when "key: value" text appears literally INSIDE
   one string -- it never caught a genuine JSON field like
   {"password": "hunter2"}, because the value "hunter2" alone matches
   no pattern. Any key whose name (case-insensitively, ignoring
   separators) contains password, passwd, pwd, token, authorization,
   cookie, secret, or private key now has its ENTIRE value replaced
   with "[REDACTED_SECRET]", regardless of that value's own shape.

Documented, deliberate consequence, unchanged since Stage 11: the SAME
email address renders differently depending on which REDACTION
CATEGORY touched it -- flat if it appeared in genuinely free text,
numbered if it appeared as a structured identity field, rule
description, observed fact, or evidence gap.

Scope decision, unchanged since Stage 6: identity fields that do NOT
look like an email (a plain "alice", not "alice@corp.local") are NOT
aliased by this module -- a real product decision this project hasn't
made yet, not an oversight.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from triageai.models import Case, NormalizedEvent, RuleMatch

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"), "[REDACTED_SECRET]"),
    (re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*\S+"), "[REDACTED_SECRET]"),
    (re.compile(r"(?i)authorization:\s*(bearer|basic)\s+\S+"), "[REDACTED_SECRET]"),
    (re.compile(r"(?i)(cookie|set-cookie):\s*\S+"), "[REDACTED_SECRET]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
)

# Key names (not string content) that mark an entire value as
# sensitive, regardless of that value's own shape. Deliberately narrow
# -- matches the audit's own enumerated list plus the obvious
# abbreviations of the same words (passwd/pwd), not an invented,
# broader guess. Separators and case are normalized away first, so
# "Private-Key", "private_key", and "PRIVATE KEY" all match the same
# way.
_SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "authorization",
    "cookie",
    "secret",
    "privatekey",
)
_SENSITIVE_VALUE_TOKEN = "[REDACTED_SECRET]"
_SEPARATOR_PATTERN = re.compile(r"[^a-z0-9]")


def _is_sensitive_key(key: str) -> bool:
    normalized = _SEPARATOR_PATTERN.sub("", key.lower())
    return any(substring in normalized for substring in _SENSITIVE_KEY_SUBSTRINGS)


def redact_free_text(text: str) -> str:
    """Replace email-like substrings and known secret patterns in free text.

    Every match becomes a flat, unnumbered token -- this function has
    no notion of "distinct values," unlike EmailAliaser below, and (by
    design) has no notion of a surrounding key name either -- see
    redact_structure for key-aware redaction of a nested structure.
    """
    redacted = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_structure(value: Any) -> Any:
    """Recursively redact a nested structure (dicts, lists, strings).

    Two mechanisms, applied together: any dict VALUE whose KEY name is
    sensitive (see _is_sensitive_key) is replaced wholesale with
    "[REDACTED_SECRET]", regardless of that value's own type or shape
    -- a nested dict or list sitting under a sensitive key is not
    descended into; the whole thing is secret. Every other string, at
    any depth, still gets redact_free_text's pattern-based redaction.
    """
    if isinstance(value, str):
        return redact_free_text(value)
    if isinstance(value, dict):
        return {
            key: (
                _SENSITIVE_VALUE_TOKEN
                if isinstance(key, str) and _is_sensitive_key(key)
                else redact_structure(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    return value


class EmailAliaser:
    """Assigns stable, numbered aliases to email-like identity values.

    Build ONE instance per case/report and reuse it across every
    event, rule match, observed fact, and evidence gap being rendered
    together, so the same account always gets the same alias.
    """

    def __init__(self, values: Iterable[str]) -> None:
        unique_keys = sorted({self._fold(v) for v in values if EMAIL_PATTERN.fullmatch(v)})
        self._alias_by_key: dict[str, str] = {
            key: f"[REDACTED_EMAIL_{index + 1:03d}]" for index, key in enumerate(unique_keys)
        }

    @staticmethod
    def _fold(value: str) -> str:
        return unicodedata.normalize("NFC", value).casefold()

    def alias_for(self, value: str) -> str:
        """Return this value's alias if it's email-like, else the value unchanged."""
        if not EMAIL_PATTERN.fullmatch(value):
            return value
        return self._alias_by_key[self._fold(value)]


def redact_text_with_aliases(text: str, aliaser: EmailAliaser) -> str:
    """Full redaction for text embedded in a rule-match description,
    observed fact, or evidence gap: secret patterns are scrubbed to
    flat tokens FIRST, THEN any remaining email-like substring is
    replaced with its STABLE, numbered alias.
    """
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return EMAIL_PATTERN.sub(lambda m: aliaser.alias_for(m.group(0)), redacted)


def redact_event_for_render(event: NormalizedEvent, aliaser: EmailAliaser) -> NormalizedEvent:
    """Produce a REDACTED COPY of one event, safe to include in a report or prompt."""
    return replace(
        event,
        host=aliaser.alias_for(event.host) if event.host is not None else None,
        user=aliaser.alias_for(event.user) if event.user is not None else None,
        source_ip=aliaser.alias_for(event.source_ip) if event.source_ip is not None else None,
        destination_ip=(
            aliaser.alias_for(event.destination_ip) if event.destination_ip is not None else None
        ),
        command_line=(
            redact_free_text(event.command_line) if event.command_line is not None else None
        ),
    )


def redact_rule_match_for_render(match: RuleMatch, aliaser: EmailAliaser) -> RuleMatch:
    """Produce a REDACTED COPY of one RuleMatch, safe for a report or prompt."""
    return replace(match, description=redact_text_with_aliases(match.description, aliaser))


def _collect_identity_seed_values(case: Case) -> list[str]:
    """Every value that must be in the aliaser's dictionary BEFORE
    alias_for() is called on it anywhere -- structured identity fields
    from every event, plus any email-like substring already sitting in
    a rule-match description, observed fact, or evidence gap (the
    latter two were previously never scanned at all).
    """
    values: list[str] = []
    for event in case.normalized_events:
        for field in (event.host, event.user, event.source_ip, event.destination_ip):
            if field is not None:
                values.append(field)
    for match in case.rule_matches:
        values.extend(EMAIL_PATTERN.findall(match.description))
    for fact in case.observed_facts:
        values.extend(EMAIL_PATTERN.findall(fact))
    for gap in case.evidence_gaps:
        values.extend(EMAIL_PATTERN.findall(gap))
    return values


def redact_case_for_render(case: Case) -> Case:
    """Produce a REDACTED COPY of a case, safe to render in a report or prompt.

    Fix: observed_facts and evidence_gaps are now included in the
    redaction pass -- previously only normalized_events, rule_matches,
    affected_users, and affected_hosts were redacted, leaving a real
    identity embedded in an observed-fact sentence (e.g. "1 event(s)
    observed for host alice@corp.local") exposed unredacted in every
    rendered report, even though the structured host field right next
    to it WAS correctly aliased. The original `case` is never mutated.
    """
    aliaser = EmailAliaser(_collect_identity_seed_values(case))

    redacted_events = tuple(
        redact_event_for_render(event, aliaser) for event in case.normalized_events
    )
    redacted_matches = tuple(
        redact_rule_match_for_render(match, aliaser) for match in case.rule_matches
    )
    redacted_users = tuple(aliaser.alias_for(user) for user in case.affected_users)
    redacted_hosts = tuple(aliaser.alias_for(host) for host in case.affected_hosts)
    redacted_observed_facts = tuple(
        redact_text_with_aliases(fact, aliaser) for fact in case.observed_facts
    )
    redacted_evidence_gaps = tuple(
        redact_text_with_aliases(gap, aliaser) for gap in case.evidence_gaps
    )

    return replace(
        case,
        normalized_events=redacted_events,
        rule_matches=redacted_matches,
        affected_users=redacted_users,
        affected_hosts=redacted_hosts,
        observed_facts=redacted_observed_facts,
        evidence_gaps=redacted_evidence_gaps,
    )