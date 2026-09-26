"""PS-001: encoded PowerShell command indicators.

Locked default (spec Section 7): Medium severity / Medium confidence,
mapped to MITRE T1059.001. Detects the PRESENCE of an -EncodedCommand
style flag in a PowerShell invocation -- NOT whether the encoded
payload is actually malicious. Per the spec: "Encoding is not
automatically malicious." Legitimate administration frequently uses
encoded commands (e.g. to safely pass complex scripts through multiple
layers of quoting) -- this rule flags the pattern for human review, it
does not conclude anything about intent.

Detection heuristic, stated explicitly (not spec-locked -- this rule's
own documented interpretation, same pattern as AUTH-001's event-ID
list): an event is a candidate PowerShell invocation if its `process`
field names powershell.exe or pwsh.exe, OR its `command_line` mentions
either interpreter by name -- covering cases where a parent shell's
command_line shows the full invocation but `process` itself was not
populated by the source SIEM. Within a candidate event, the rule fires
if `command_line` contains a whitespace-delimited flag token matching
a known -EncodedCommand abbreviation (`-enc` through the full
`-encodedcommand`, case-insensitive).

Bare `-e` / `-en` are deliberately EXCLUDED from the accepted
abbreviation list: PowerShell itself accepts them as valid unambiguous
prefixes, but including them here would make this rule match many
unrelated flags in unrelated tools' command lines by coincidental
substring overlap -- a deliberate precision-over-recall tradeoff, not
an oversight.

Decoding is opportunistic evidence enrichment, not a precondition for
the rule to fire: a malformed or missing encoded payload still
produces a match (the flag's presence is the actual detection), it
simply carries a decode_error/status note instead of decoded text.
Decoding is single-pass (one base64 decode, never recursive), and
decoded output is hard-capped at 64 KiB, per the locked operational
contract -- a payload whose decoded bytes exceed that cap is
truncated, never fully retained. -EncodedCommand payloads are
UTF-16LE encoded by PowerShell itself before base64; decoding as
strict UTF-16LE is deliberate, not a guess. A UTF-16LE decode failure
falls back to a recorded decode_error, never raw undecoded bytes
formatted as if they were text.

Known, cross-cutting gap surfaced by writing this rule -- and it
turns out to ALSO already apply to AUTH-001, not just here: neither
RuleMatch nor Case currently has a field for a decoded-content preview
or any other rendering-safe evidence blob, and Case.rule_matches is
NOT touched by Stage 6's redact_case_for_render at all. That means
RuleMatch.description in both this rule and AUTH-001 embeds real,
unredacted host/identity values directly into a plain string that
bypasses the render-boundary redaction entirely. It hasn't caused a
leak yet only because nothing renders rule_matches into a report yet
(terminal.py/markdown_report.py currently render events only). This is
a tracked, open item, not something silently ignored -- it needs
fixing before Stage 11 wires rule_matches into an actual rendered
report, most likely by extending redact_case_for_render to also
redact RuleMatch.description.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "PS-001"
MITRE_TECHNIQUE = "T1059.001"
MAX_DECODED_BYTES = 64 * 1024

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
            decoded = decode_encoded_command(payload)
            if decoded.decode_error is not None:
                status = f"decode attempted, failed ({decoded.decode_error})"
            else:
                assert decoded.decoded_text is not None
                note = " (truncated at 64 KiB)" if decoded.truncated else ""
                status = f"decoded successfully, {len(decoded.decoded_text)} chars{note}"

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