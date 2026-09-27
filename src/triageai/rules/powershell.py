"""PS-001: encoded PowerShell command indicators.

Locked default (spec Section 7): Medium severity / Medium confidence,
mapped to MITRE T1059.001. Detects the PRESENCE of an -EncodedCommand
style flag in a PowerShell invocation -- NOT whether the encoded
payload is actually malicious. Per the spec: "Encoding is not
automatically malicious."

Detection heuristic (this rule's own documented interpretation, not
spec-locked): an event is a candidate PowerShell invocation if its
`process` field names powershell.exe or pwsh.exe, OR its
`command_line` mentions either interpreter by name. Within a candidate
event, the rule fires if `command_line` contains a whitespace-
delimited flag token matching a known -EncodedCommand abbreviation
(`-enc` through the full `-encodedcommand`, case-insensitive). Bare
`-e` / `-en` are deliberately EXCLUDED -- ambiguous with unrelated
tools' flags.

Decoding is opportunistic evidence enrichment, not a precondition to
fire. Single-pass, never recursive, capped at 64 KiB (MAX_DECODED_
BYTES). -EncodedCommand payloads are UTF-16LE encoded by PowerShell
itself before base64; decoding as strict UTF-16LE is deliberate. A
decode failure produces a recorded decode_error, never raw undecoded
bytes formatted as text.

Stage 15 addition: a BOUNDED preview of the actual decoded text (up to
DESCRIPTION_PREVIEW_CHARS) is now included in the RuleMatch
description -- previously only the fact that decoding succeeded was
reported, which gave an analyst nothing to actually investigate. This
preview passes through redact_rule_match_for_render at render time
(see redaction.py), which as of this same stage runs FULL secret-
pattern scrubbing on rule descriptions, not just email aliasing --
closing a real gap where a decoded payload's own embedded secret could
have rendered unredacted.

Known, cross-cutting, still-open item: RuleMatch.description embeds
plain (non-email-shaped) hostnames directly (e.g. "host WIN-CLIENT01")
-- per redaction.py's documented scope decision, a bare hostname is
not itself redacted anywhere in this project yet. Unchanged from
Stages 9-11; recorded here again, and in LIMITATIONS.md, so it isn't
lost.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "PS-001"
MITRE_TECHNIQUE = "T1059.001"
MAX_DECODED_BYTES = 64 * 1024
DESCRIPTION_PREVIEW_CHARS = 300

_POWERSHELL_PROCESS_NAMES = ("powershell.exe", "pwsh.exe")
_ENCODED_COMMAND_FLAGS = frozenset(
    {
        "-enc",
        "-enco",
        "-encod",
        "-encode",
        "-encoded",
        "-encodedc",
        "-encodedco",
        "-encodedcom",
        "-encodedcomm",
        "-encodedcomma",
        "-encodedcomman",
        "-encodedcommand",
    }
)


@dataclass(frozen=True, slots=True)
class DecodedCommand:
    """Result of attempting to decode one -EncodedCommand payload."""

    decoded_text: str | None
    decode_error: str | None
    truncated: bool


def _is_powershell_event(event: NormalizedEvent) -> bool:
    process = (event.process or "").lower()
    command_line = (event.command_line or "").lower()
    if any(process.endswith(name) for name in _POWERSHELL_PROCESS_NAMES):
        return True
    return any(name.removesuffix(".exe") in command_line for name in _POWERSHELL_PROCESS_NAMES)


def _has_encoded_flag(command_line: str) -> bool:
    return any(token.lower() in _ENCODED_COMMAND_FLAGS for token in command_line.split())


def _find_encoded_payload(command_line: str) -> str | None:
    """Return the base64 payload following a recognized flag, or None."""
    tokens = command_line.split()
    for index, token in enumerate(tokens):
        if token.lower() in _ENCODED_COMMAND_FLAGS and index + 1 < len(tokens):
            return tokens[index + 1]
    return None


def decode_encoded_command(payload: str) -> DecodedCommand:
    """Single-pass, bounded, inert decode of one base64 -EncodedCommand payload.

    Never executed, never recursively decoded. Decoded output is
    capped at MAX_DECODED_BYTES; a UTF-16LE decode failure yields
    decode_error plus None, never raw undecoded bytes formatted as text.
    """
    try:
        raw_bytes = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        return DecodedCommand(decoded_text=None, decode_error=f"invalid base64: {exc}", truncated=False)

    truncated = len(raw_bytes) > MAX_DECODED_BYTES
    bounded_bytes = raw_bytes[:MAX_DECODED_BYTES]

    try:
        text = bounded_bytes.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        return DecodedCommand(
            decoded_text=None, decode_error=f"not valid UTF-16LE: {exc}", truncated=truncated
        )

    return DecodedCommand(decoded_text=text, decode_error=None, truncated=truncated)


def _describe_decode_result(decoded: DecodedCommand) -> str:
    if decoded.decode_error is not None:
        return f"decode attempted, failed ({decoded.decode_error})"

    assert decoded.decoded_text is not None
    truncation_note = " (decoding truncated at 64 KiB)" if decoded.truncated else ""

    preview = decoded.decoded_text[:DESCRIPTION_PREVIEW_CHARS]
    if len(decoded.decoded_text) > DESCRIPTION_PREVIEW_CHARS:
        preview += "...[preview truncated]"

    return f"decoded successfully{truncation_note}: {preview}"


def evaluate(events: tuple[NormalizedEvent, ...]) -> tuple[RuleMatch, ...]:
    """Flag every PowerShell invocation carrying an -EncodedCommand-style flag."""
    matches: list[RuleMatch] = []

    for event in events:
        command_line = event.command_line
        if not _is_powershell_event(event) or command_line is None:
            continue
        if not _has_encoded_flag(command_line):
            continue

        payload = _find_encoded_payload(command_line)
        if payload is None:
            status = "encoded-command flag present, no payload token found"
        else:
            status = _describe_decode_result(decode_encoded_command(payload))

        matches.append(
            RuleMatch(
                rule_id=RULE_ID,
                mitre_technique=MITRE_TECHNIQUE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                matched_event_ids=(event.original_record_id,),
                description=f"Encoded PowerShell command on host {event.host or '?'}: {status}",
            )
        )

    return tuple(matches)