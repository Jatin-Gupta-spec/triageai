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
fire. Stage 17c makes the locked decode bounds real:
- ONE base64 decode, never recursive, never executed.
- A payload whose text is longer than MAX_ENCODED_CHARS cannot fit in
  MAX_DECODED_BYTES, so it is REFUSED before the decoder runs. A
  shorter payload can decode to at most about 64 KiB, and the exact
  MAX_DECODED_BYTES limit is checked right after. An oversized payload
  is refused, not truncated: no decoded text is retained. (The 5 MiB
  input-file cap already bounded the old behaviour to a few MB, so
  this was a contract violation more than an attack.)
- The bytes are interpreted as strict UTF-16LE, which is how
  PowerShell encodes them before base64.
- On a UTF-16LE failure only a short hex preview of the first
  BYTE_PREVIEW_BYTES bytes and the byte count are kept, never the
  decoded bytes as text. Error texts are fixed wording, not copies of
  an exception message.

A bounded preview of successfully decoded text (up to
DESCRIPTION_PREVIEW_CHARS) is included in the RuleMatch description.
It passes through redaction at render time, which scrubs secret
patterns in rule descriptions.

Known, still-open item: RuleMatch.description embeds plain
(non-email-shaped) hostnames directly. Per redaction.py's documented
scope decision, a bare hostname is not itself redacted anywhere in
this project yet; see LIMITATIONS.md.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "PS-001"
MITRE_TECHNIQUE = "T1059.001"
MAX_DECODED_BYTES = 64 * 1024
# Longest base64 text that can still decode to MAX_DECODED_BYTES bytes:
# 4 characters per 3 bytes, rounded up to whole 4-character groups.
MAX_ENCODED_CHARS = ((MAX_DECODED_BYTES + 2) // 3) * 4
BYTE_PREVIEW_BYTES = 16
DESCRIPTION_PREVIEW_CHARS = 300

_REFUSED_MESSAGE = "encoded payload is longer than the 64 KiB decode limit allows"

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
    """Result of attempting to decode one -EncodedCommand payload.

    Exactly one of these holds: decoded_text is set (success);
    refused is True (payload over the size limit, decoder not
    trusted with it); or decode_error is set (invalid base64 or not
    UTF-16LE). byte_preview is set only for a UTF-16LE failure.
    """

    decoded_text: str | None
    decode_error: str | None
    byte_preview: str | None
    refused: bool = False


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

    Never executed, never recursively decoded. The size limit is
    enforced before the decoder runs (see the module docstring), so
    the decoder is never handed a payload that could exceed it.
    """
    if len(payload) > MAX_ENCODED_CHARS:
        return DecodedCommand(
            decoded_text=None, decode_error=_REFUSED_MESSAGE, byte_preview=None, refused=True
        )

    try:
        raw_bytes = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return DecodedCommand(decoded_text=None, decode_error="invalid base64", byte_preview=None)

    if len(raw_bytes) > MAX_DECODED_BYTES:
        return DecodedCommand(
            decoded_text=None, decode_error=_REFUSED_MESSAGE, byte_preview=None, refused=True
        )

    try:
        text = raw_bytes.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        preview = raw_bytes[:BYTE_PREVIEW_BYTES].hex()
        return DecodedCommand(
            decoded_text=None,
            decode_error=f"not valid UTF-16LE; {len(raw_bytes)} bytes, first bytes {preview}",
            byte_preview=preview,
        )

    return DecodedCommand(decoded_text=text, decode_error=None, byte_preview=None)


def _describe_decode_result(decoded: DecodedCommand) -> str:
    if decoded.refused:
        return f"decode refused ({decoded.decode_error})"
    if decoded.decode_error is not None:
        return f"decode attempted, failed ({decoded.decode_error})"

    assert decoded.decoded_text is not None
    preview = decoded.decoded_text[:DESCRIPTION_PREVIEW_CHARS]
    if len(decoded.decoded_text) > DESCRIPTION_PREVIEW_CHARS:
        preview += "...[preview truncated]"

    return f"decoded successfully: {preview}"


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