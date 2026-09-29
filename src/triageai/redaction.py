"""Render-boundary redaction: reports and AI prompts only.

Internal NormalizedEvent/Case objects are never mutated -- this module
produces REDACTED COPIES for rendering, per the locked spec (Sections
5, 8, 11). See models.py's module docstring for why real values are
kept internally in the first place.

Three redaction behaviors, not to be confused with each other:

1. Free-text redaction (command lines, process paths, every other
   free-text field): every email-like substring becomes a flat
   "[REDACTED_EMAIL]"; known secret patterns become flat
   "[REDACTED_SECRET]" / "[REDACTED_PRIVATE_KEY]"; the account-name
   part of a user-profile path becomes "[REDACTED_USER]".

2. Identity-field redaction (host, user, IPs, rule descriptions,
   observed facts, evidence gaps): each distinct email-like identity
   gets its own numbered alias, so two accounts stay distinguishable.
   An email-like value the aliaser was never given falls back to the
   flat token instead of raising, so redaction can never crash a run.

3. Key-aware redaction (redact_structure): for nested dicts, the KEY
   name decides -- a value under a sensitive key is replaced whole.
   Currently a utility for future evidence structures; no live code
   path calls it, because NormalizedEvent keeps only flat fields.

Stage 17d hardening of the secret patterns:
- Flag-style secrets: --password X, -Token X, /secret:X, --api-key=X.
- Quoted values with spaces are consumed whole.
- "Authorization:" no longer needs a scheme word.
- A Cookie header is redacted to the end of its line.
- User-profile paths (C:\\Users\\name, /home/name) are redacted.
- Every string field of an event is redacted, not just command_line:
  process, parent_process, event_id, source, provider, rule_id, MITRE
  IDs, and a supplied original_record_id.
Over-redaction is accepted on purpose: "--token --verbose" also
redacts "--verbose".

Documented limits (see LIMITATIONS.md): positional secrets such as
"net use ... /user:bob Hunter2" are not recognized; a profile folder
whose name contains a space is only partly redacted; plain (non-email)
hostnames and usernames are not aliased, by an earlier scope decision.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from triageai.models import Case, NormalizedEvent, RuleMatch

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_FLAT_EMAIL = "[REDACTED_EMAIL]"
_FLAT_SECRET = "[REDACTED_SECRET]"

# A value is a double-quoted string, a single-quoted string, or one
# whitespace-delimited token.
_VALUE = r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|\S+)"""
_KEYWORDS = (
    r"(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret)"
)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Flag style: --password X, -Token "a b", /secret:X, --api-key=X
    (re.compile(rf"(?i)(?<!\w)(?:--?|/){_KEYWORDS}[=:\s]+{_VALUE}"), _FLAT_SECRET),
    # key=value or key: value anywhere
    (re.compile(rf"(?i){_KEYWORDS}\s*[:=]\s*{_VALUE}"), _FLAT_SECRET),
    # Authorization header, with or without a scheme word
    (
        re.compile(
            rf"(?i)authorization\s*[:=]\s*(?:(?:bearer|basic|digest|negotiate|ntlm)\s+)?{_VALUE}"
        ),
        _FLAT_SECRET,
    ),
    # Cookie / Set-Cookie: everything to the end of the line
    (re.compile(r"(?i)(?:set-)?cookie\s*[:=]\s*[^\r\n]+"), _FLAT_SECRET),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
)

# User-profile paths. The replacement keeps the folder prefix (group 1)
# and replaces only the account name. \x22 and \x27 are the two quote
# characters.
_PATH_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(\b[a-z]:[\\/]users[\\/])[^\\/\s\x22\x27]+"), r"\1[REDACTED_USER]"),
    (re.compile(r"(/(?:home|Users)/)[^/\s\x22\x27]+"), r"\1[REDACTED_USER]"),
)

# Key names (not string content) that mark an entire value as
# sensitive. Separators and case are normalized away first, so
# "Private-Key", "private_key" and "PRIVATE KEY" all match.
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
_SEPARATOR_PATTERN = re.compile(r"[^a-z0-9]")


def _is_sensitive_key(key: str) -> bool:
    normalized = _SEPARATOR_PATTERN.sub("", key.lower())
    return any(substring in normalized for substring in _SENSITIVE_KEY_SUBSTRINGS)


def _scrub(text: str) -> str:
    """Secret and user-path patterns only (no email handling)."""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    for pattern, replacement in _PATH_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_free_text(text: str) -> str:
    """Replace email-like substrings, secret patterns, and user-profile
    paths in free text. Every match becomes a flat token.
    """
    return _scrub(EMAIL_PATTERN.sub(_FLAT_EMAIL, text))


def redact_structure(value: Any) -> Any:
    """Recursively redact a nested structure (dicts, lists, strings).

    A dict VALUE whose KEY name is sensitive is replaced wholesale with
    "[REDACTED_SECRET]" (a nested dict or list under such a key is not
    descended into). Every other string, at any depth, gets
    redact_free_text.
    """
    if isinstance(value, str):
        return redact_free_text(value)
    if isinstance(value, dict):
        return {
            key: (
                _FLAT_SECRET
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
        """Return this value's alias if it's email-like, else the value
        unchanged. An email-like value that was never seeded gets the
        flat token: never leaked, never an exception.
        """
        if not EMAIL_PATTERN.fullmatch(value):
            return value
        return self._alias_by_key.get(self._fold(value), _FLAT_EMAIL)


def redact_text_with_aliases(text: str, aliaser: EmailAliaser) -> str:
    """Redaction for text embedded in a rule-match description,
    observed fact, or evidence gap: secret patterns and user paths are
    scrubbed to flat tokens FIRST, THEN any remaining email-like
    substring is replaced with its stable, numbered alias.
    """
    scrubbed = _scrub(text)
    return EMAIL_PATTERN.sub(lambda m: aliaser.alias_for(m.group(0)), scrubbed)


def _text(value: str | None) -> str | None:
    return redact_free_text(value) if value is not None else None


def _identity(value: str | None, aliaser: EmailAliaser) -> str | None:
    """Alias an email-like identity, then still scrub secrets and paths."""
    return redact_free_text(aliaser.alias_for(value)) if value is not None else None


def redact_event_for_render(event: NormalizedEvent, aliaser: EmailAliaser) -> NormalizedEvent:
    """Produce a REDACTED COPY of one event, safe to include in a report
    or prompt. Every string field is covered; the original is unchanged.
    """
    return replace(
        event,
        original_record_id=redact_free_text(event.original_record_id),
        host=_identity(event.host, aliaser),
        user=_identity(event.user, aliaser),
        source=_text(event.source),
        event_id=_text(event.event_id),
        provider=_text(event.provider),
        rule_id=_text(event.rule_id),
        process=_text(event.process),
        parent_process=_text(event.parent_process),
        command_line=_text(event.command_line),
        source_ip=_identity(event.source_ip, aliaser),
        destination_ip=_identity(event.destination_ip, aliaser),
        mitre_techniques=tuple(redact_free_text(t) for t in event.mitre_techniques),
    )


def redact_rule_match_for_render(match: RuleMatch, aliaser: EmailAliaser) -> RuleMatch:
    """Produce a REDACTED COPY of one RuleMatch, safe for a report or prompt."""
    return replace(match, description=redact_text_with_aliases(match.description, aliaser))


def _collect_identity_seed_values(case: Case) -> list[str]:
    """Every email-like identity the aliaser must know in advance:
    structured identity fields from every event, plus any email-like
    substring in a rule description, observed fact, or evidence gap.
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
    """Produce a REDACTED COPY of a case, safe to render in a report or
    prompt. One EmailAliaser is reused across the whole rendering so
    one identity maps to one alias everywhere. The original `case` is
    never mutated.
    """
    aliaser = EmailAliaser(_collect_identity_seed_values(case))

    return replace(
        case,
        normalized_events=tuple(
            redact_event_for_render(event, aliaser) for event in case.normalized_events
        ),
        rule_matches=tuple(
            redact_rule_match_for_render(match, aliaser) for match in case.rule_matches
        ),
        affected_users=tuple(
            redact_free_text(aliaser.alias_for(user)) for user in case.affected_users
        ),
        affected_hosts=tuple(
            redact_free_text(aliaser.alias_for(host)) for host in case.affected_hosts
        ),
        observed_facts=tuple(redact_text_with_aliases(fact, aliaser) for fact in case.observed_facts),
        evidence_gaps=tuple(redact_text_with_aliases(gap, aliaser) for gap in case.evidence_gaps),
    )