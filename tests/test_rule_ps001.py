"""Tests for PS-001 -- positive, negative, boundary, and
missing-field cases, per the locked spec's test requirements.
"""

from __future__ import annotations

import base64

from triageai.models import NormalizedEvent
from triageai.rules.powershell import MAX_DECODED_BYTES, decode_encoded_command, evaluate


def _event(
    record_id: str = "rec-1",
    *,
    process: str | None = "powershell.exe",
    command_line: str | None,
    host: str | None = "WIN-CLIENT01",
) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=None,
        host=host,
        user=None,
        source=None,
        event_id=None,
        provider=None,
        rule_id=None,
        process=process,
        parent_process=None,
        command_line=command_line,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )


def _encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def test_full_flag_with_valid_payload_matches() -> None:
    payload = _encode("Get-Process")
    event = _event(command_line=f"powershell.exe -EncodedCommand {payload}")

    matches = evaluate((event,))

    assert len(matches) == 1
    assert matches[0].rule_id == "PS-001"
    assert matches[0].mitre_technique == "T1059.001"
    assert "decoded successfully" in matches[0].description


def test_abbreviated_flag_enc_matches() -> None:
    payload = _encode("Get-Process")
    event = _event(process="pwsh.exe", command_line=f"pwsh -enc {payload}")

    assert len(evaluate((event,))) == 1


def test_command_line_only_mention_of_powershell_matches() -> None:
    payload = _encode("Get-Process")
    event = _event(process=None, command_line=f"cmd.exe /c powershell -EncodedCommand {payload}")

    assert len(evaluate((event,))) == 1


def test_powershell_without_encoded_flag_does_not_match() -> None:
    event = _event(command_line="powershell.exe -File script.ps1")
    assert evaluate((event,)) == ()


def test_non_powershell_process_does_not_match() -> None:
    payload = _encode("whoami")
    event = _event(process="cmd.exe", command_line=f"cmd.exe -enc {payload}")
    assert evaluate((event,)) == ()


def test_excluded_short_abbreviation_e_does_not_match() -> None:
    payload = _encode("Get-Process")
    event = _event(command_line=f"powershell.exe -e {payload}")
    assert evaluate((event,)) == ()


def test_decoded_output_at_exactly_max_bytes_is_not_truncated() -> None:
    text = "A" * (MAX_DECODED_BYTES // 2)
    result = decode_encoded_command(_encode(text))

    assert result.decode_error is None
    assert result.truncated is False
    assert result.decoded_text is not None
    assert len(result.decoded_text) == MAX_DECODED_BYTES // 2


def test_decoded_output_one_char_over_max_is_truncated() -> None:
    text = "A" * ((MAX_DECODED_BYTES // 2) + 1)
    result = decode_encoded_command(_encode(text))

    assert result.truncated is True


def test_shortest_accepted_abbreviation_enc_matches() -> None:
    payload = _encode("x")
    event = _event(command_line=f"powershell.exe -enc {payload}")
    assert len(evaluate((event,))) == 1


def test_command_line_none_does_not_crash_or_match() -> None:
    event = _event(command_line=None)
    assert evaluate((event,)) == ()


def test_encoded_flag_with_no_following_token_does_not_crash() -> None:
    event = _event(command_line="powershell.exe -EncodedCommand")
    matches = evaluate((event,))
    assert len(matches) == 1
    assert "no payload token found" in matches[0].description


def test_invalid_base64_payload_still_matches_with_decode_error() -> None:
    event = _event(command_line="powershell.exe -EncodedCommand not-valid-base64!!!")
    matches = evaluate((event,))
    assert len(matches) == 1
    assert "decode attempted, failed" in matches[0].description


def test_valid_base64_but_not_utf16le_still_matches_with_decode_error() -> None:
    odd_bytes_payload = base64.b64encode(b"odd").decode("ascii")
    event = _event(command_line=f"powershell.exe -EncodedCommand {odd_bytes_payload}")

    matches = evaluate((event,))
    assert len(matches) == 1
    assert "decode attempted, failed" in matches[0].description


def test_empty_input_produces_no_matches() -> None:
    assert evaluate(()) == ()


def test_decoded_payload_content_appears_in_description() -> None:
    # Stage 15 fix: previously only "decoded successfully, N chars"
    # was reported -- the actual content is now surfaced so an
    # analyst has something real to investigate.
    payload = _encode("Get-Process | Where-Object CPU -gt 100")
    event = _event(command_line=f"powershell.exe -EncodedCommand {payload}")

    matches = evaluate((event,))

    assert "Get-Process" in matches[0].description