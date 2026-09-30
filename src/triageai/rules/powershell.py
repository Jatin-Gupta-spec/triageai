"""PS-001: encoded PowerShell command indicators.

Locked default (spec Section 7): Medium severity / Medium confidence,
mapped to MITRE T1059.001. Detects the PRESENCE of an -EncodedCommand
style flag in a PowerShell invocation -- NOT whether the encoded
payload is actually malicious.

Stage 18 fix to the executable-detection heuristic: previously
checked whether the SUBSTRING "powershell" (or "pwsh") appeared
anywhere in process or command_line. That wrongly matched text that
only PRINTS the word (cmd.exe /c echo powershell -enc AAAA), or an
unrelated executable whose name happens to contain it
(not-powershell.exe). The rule now requires one of:
  (a) `process`'s own basename (command_line.py) is exactly
      powershell(.exe) or pwsh(.exe);
  (b) the FIRST token of command_line has that basename; or
  (c) a token immediately following a known "run a sub-command" flag
      (/c, /k from cmd.exe; -c, -Command from a POSIX shell or
      PowerShell itself) has that basename -- this is what still
      recognizes `cmd.exe /c powershell -EncodedCommand ...`, a
      genuine and common technique, while (a)/(b) alone would miss it
      since the actual PowerShell process may never be separately
      logged by the source SIEM.

Decoding is opportunistic evidence enrichment, not a precondition to
fire. Single-pass, never recursive, capped at 64 KiB, refused (not
truncated) if the payload could exceed that before decoding, bytes
interpreted as strict UTF-16LE, a failure keeps only a 16-byte hex
preview and byte count. See DESCRIPTION_PREVIEW_CHARS for the
successful-decode preview shown in the match description.

Known, cross-cutting, still-open item: RuleMatch.description embeds
plain (non-email-shaped) hostnames directly. Per redaction.py's
documented scope decision, a bare hostname is not itself redacted
anywhere in this project yet; see LIMITATIONS.md.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from itertools import pairwise

from triageai.command_line import basename
from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "PS-001"
MITRE_TECHNIQUE = "T1059.001"
MAX_DECODED_BYTES = 64 * 1024
MAX_ENCODED_CHARS = ((MAX_DECODED_BYTES + 2) // 3) * 4
BYTE_PREVIEW_BYTES = 16
DESCRIPTION_PREVIEW_CHARS = 300

_REFUSED_MESSAGE = "encoded payload is longer than the 64 KiB decode limit allows"

_POWERSHELL_EXECUTABLE_NAMES = frozenset({"powershell.exe", "powershell", "pwsh.exe", "pwsh"})
_SUBCOMMAND_FLAGS = frozenset({"/c", "/k", "-c", "-command"})
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
    byte_preview: str | None
    refused: bool = False


def _is_powershell_event(event: NormalizedEvent) -> bool:
    if event.process is not None and basename(event.process) in _POWERSHELL_EXECUTABLE_NAMES:
        return True

    command_line = event.command_line
    if command_line is None:
        return False

    tokens = command_line.split()
    if not tokens:
        return False

    if basename(tokens[0]) in _POWERSHELL_EXECUTABLE_NAMES:
        return True

    for previous, current in pairwise(tokens):
        if previous.lower() in _SUBCOMMAND_FLAGS and basename(current) in _POWERSHELL_EXECUTABLE_NAMES:
            return True

    return False


def _has_encoded_flag(command_line: str) -> bool:
    return any(token.lower() in _ENCODED_COMMAND_FLAGS for token in command_line.split())


def _find_encoded_payload(command_line: str) -> str | None:
    tokens = command_line.split()
    for index, token in enumerate(tokens):
        if token.lower() in _ENCODED_COMMAND_FLAGS and index + 1 < len(tokens):
            return tokens[index + 1]
    return None


def decode_encoded_command(payload: str) -> DecodedCommand:
    """Single-pass, bounded, inert decode of one base64 -EncodedCommand payload."""
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