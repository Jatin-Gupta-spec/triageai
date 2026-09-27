"""Render-boundary redaction: reports and AI prompts only.

Internal NormalizedEvent/Case objects are never mutated -- this module
produces REDACTED COPIES for rendering, per the locked spec (Sections
5, 8, 11). See models.py's module docstring for why real values are
kept internally in the first place.

Two distinct redaction behaviors, not to be confused with each other:

1. Free-text redaction (command lines, arbitrary strings): every
   email-like substring becomes a flat, unnumbered "[REDACTED_EMAIL]"
   token. Known secret patterns similarly become flat tokens.

2. Identity-field redaction (structured fields, AND -- as of Stage 11
   -- rule-match descriptions derived from those same fields): each
   *distinct* value gets its own numbered alias, assigned by sorting
   unique NFC-normalized, case-folded values. This is what lets two
   different accounts stay distinguishable in a rendered report
   without revealing who they are, and what lets the SAME identity be
   recognized consistently whether it appears in a structured field or
   inside a RuleMatch.description string this project's own rules
   generated.

Documented, deliberate consequence, still true after Stage 11: the
SAME email address renders differently depending on which REDACTION
CATEGORY touched it -- flat if it appeared in genuinely free text
(a command line), numbered if it appeared as a structured identity
field or in a rule description. This is intentional: free text
carries no correlation requirement, so there is nothing to preserve by
numbering it.

Scope decision, unchanged from Stage 6: identity fields that do NOT
look like an email (a plain "alice", not "alice@corp.local") are NOT
redacted by this module -- a real product decision this project
hasn't made yet, not an oversight.
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


def redact_free_text(text: str) -> str:
    """Replace email-like substrings and known secret patterns in free text.

    Every match becomes a flat, unnumbered token -- this function has
    no notion of "distinct values," unlike EmailAliaser below.
    """
    redacted = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_structure(value: Any) -> Any:
    """Recursively apply redact_free_text to every string in a nested structure."""
    if isinstance(value, str):
        return redact_free_text(value)
    if isinstance(value, dict):
        return {key: redact_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    return value


class EmailAliaser:
    """Assigns stable, numbered aliases to email-like identity values.

    Build ONE instance per case/report and reuse it across every
    event AND rule match being rendered together, so the same account
    always gets the same alias -- this is what proves UPN-format users
    stay distinguishable, and stay CONSISTENT across every place they
    appear, in a rendered report.
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
    """Replace every email-like substring in `text` with its STABLE,
    numbered alias -- unlike redact_free_text's flat, unnumbered
    token, this keeps one identity mapped to one alias everywhere it
    appears in a rendered case, including inside a RuleMatch
    description this project's own rules generated.
    """
    return EMAIL_PATTERN.sub(lambda m: aliaser.alias_for(m.group(0)), text)


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
    """Produce a REDACTED COPY of one RuleMatch, safe for a report or prompt.

    Known, documented, accepted limitation, same as elsewhere in this
    module: a PLAIN (non-email-shaped) identity in `description` --
    e.g. a bare hostname like "WIN-CLIENT01" -- is NOT redacted here.
    """
    return replace(match, description=redact_text_with_aliases(match.description, aliaser))


def _collect_identity_seed_values(case: Case) -> list[str]:
    """Every value that must be in the aliaser's dictionary BEFORE
    alias_for() is called on it anywhere -- structured identity fields
    from every event, plus any email-like substring already sitting in
    a rule-match description. Missing a value here was the exact
    latent bug this function fixes: alias_for() raises KeyError on an
    email-shaped value it was never told about in advance.
    """
    values: list[str] = []
    for event in case.normalized_events:
        for field in (event.host, event.user, event.source_ip, event.destination_ip):
            if field is not None:
                values.append(field)
    for match in case.rule_matches:
        values.extend(EMAIL_PATTERN.findall(match.description))
    return values


def redact_case_for_render(case: Case) -> Case:
    """Produce a REDACTED COPY of a case, safe to render in a report or prompt.

    One EmailAliaser, seeded from every identity-bearing value in this
    case (events AND rule matches), is reused across the whole
    rendering -- guaranteeing one identity maps to one alias
    everywhere it appears. The original `case` is never mutated.
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

    return replace(
        case,
        normalized_events=redacted_events,
        rule_matches=redacted_matches,
        affected_users=redacted_users,
        affected_hosts=redacted_hosts,
    )