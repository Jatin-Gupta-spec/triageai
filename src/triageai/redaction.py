"""Render-boundary redaction: reports and AI prompts only.

Internal NormalizedEvent/Case objects are never mutated -- this module
produces REDACTED COPIES for rendering, per the locked spec (Sections
5, 8, 11). See models.py's module docstring for why real values are
kept internally in the first place.

Two distinct redaction behaviors, not to be confused with each other:

1. Free-text redaction (command lines, arbitrary strings): every
   email-like substring becomes a flat, unnumbered "[REDACTED_EMAIL]"
   token. Known secret patterns (password/token assignments,
   Authorization headers, cookies, private-key blocks) similarly
   become flat "[REDACTED_SECRET]" / "[REDACTED_PRIVATE_KEY]" tokens.

2. Identity-field redaction (e.g. a NormalizedEvent.user field that is
   itself in UPN/email form): each *distinct* value gets its own
   numbered alias -- "[REDACTED_EMAIL_001]", "[REDACTED_EMAIL_002]" --
   assigned by sorting unique NFC-normalized, case-folded values. This
   is what lets two different accounts stay distinguishable in a
   rendered report without revealing who they are.

Documented, deliberate consequence: the SAME email address renders
differently depending on which path touched it -- flat if it appeared
in free text, numbered if it appeared as a structured identity field.
This is intentional, not a bug: free text carries no correlation
requirement, so there is nothing to preserve by numbering it.

Scope decision, stated explicitly rather than left implicit: identity
fields that do NOT look like an email (a plain "alice", not
"alice@corp.local") are NOT redacted by this module. The locked spec
only pins down concrete redaction behavior for email-like values;
redacting plain usernames is a real product decision this project
hasn't made yet, not an oversight in this stage.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from triageai.models import Case, NormalizedEvent

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*\S+"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)authorization:\s*(bearer|basic)\s+\S+"),
        "[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)(cookie|set-cookie):\s*\S+"),
        "[REDACTED_SECRET]",
    ),
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
    """Recursively apply redact_free_text to every string in a nested structure.

    Walks dicts and lists at any depth. Intended for arbitrary
    supplementary evidence structures (e.g. an AI prompt's evidence
    package, built in a later stage) -- NOT for NormalizedEvent, which
    has its own dedicated redact_event_for_render below.
    """
    if isinstance(value, str):
        return redact_free_text(value)
    if isinstance(value, dict):
        return {key: redact_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    return value


class EmailAliaser:
    """Assigns stable, numbered aliases to email-like identity values.

    Build ONE instance per case/report and reuse it across every event
    being rendered together, so the same account always gets the same
    alias, and two different accounts never collide -- this is what
    proves UPN-format users stay distinguishable in a report even
    though they're both redacted.
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


def redact_event_for_render(event: NormalizedEvent, aliaser: EmailAliaser) -> NormalizedEvent:
    """Produce a REDACTED COPY of one event, safe to include in a report or prompt.

    dataclasses.replace() always returns a new frozen instance --
    `event` itself is never touched.
    """
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


def redact_case_for_render(case: Case) -> Case:
    """Produce a REDACTED COPY of a case, safe to render in a report or prompt.

    One EmailAliaser is built from every user value in this case, so
    the same account maps to the same alias throughout the whole
    rendered output. The original `case` and its `normalized_events`
    are never mutated.
    """
    aliaser = EmailAliaser(event.user for event in case.normalized_events if event.user is not None)

    redacted_events = tuple(
        redact_event_for_render(event, aliaser) for event in case.normalized_events
    )
    redacted_users = tuple(aliaser.alias_for(user) for user in case.affected_users)

    return replace(case, normalized_events=redacted_events, affected_users=redacted_users)