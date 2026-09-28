"""Tests for PS-001 -- positive, negative, boundary, and missing-field
cases, per the locked spec's test requirements, plus (Stage 17c) the
decode-size bounds and the bounded byte preview.
"""

from __future__ import annotations

import base64

import pytest

from triageai.models import NormalizedEvent
from triageai.rules.powershell import (
    BYTE_PREVIEW_BYTES,
    MAX_DECODED_BYTES,
    MAX_ENCODED_CHARS,
    decode_encoded_command,
    evaluate,
)


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


def _encode_bytes(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# --- Positive ---


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


def test_decoded_payload_content_appears_in_description() -> None:
    payload = _encode("Get-Process | Where-Object CPU -gt 100")
    event = _event(command_line=f"powershell.exe -EncodedCommand {payload}")

    matches = evaluate((event,))

    assert "Get-Process" in matches[0].description


# --- Negative ---


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


# --- Boundary: the 64 KiB decode limit ---


def test_decoded_output_at_exactly_max_bytes_is_accepted() -> None:
    text = "A" * (MAX_DECODED_BYTES // 2)
    result = decode_encoded_command(_encode(text))

    assert result.decode_error is None
    assert result.refused is False
    assert result.decoded_text is not None
    assert len(result.decoded_text) == MAX_DECODED_BYTES // 2


@pytest.mark.parametrize("extra_chars", [1, 2, 1000])
def test_decoded_output_over_max_bytes_is_refused_not_truncated(extra_chars: int) -> None:
    # extra_chars=1 is exactly two bytes over the limit and still passes
    # the cheap length check, so it exercises the exact post-decode check.
    text = "A" * ((MAX_DECODED_BYTES // 2) + extra_chars)
    result = decode_encoded_command(_encode(text))

    assert result.refused is True
    assert result.decoded_text is None
    assert result.byte_preview is None


def test_oversized_payload_is_refused_without_calling_the_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _must_not_run(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("the decoder must not run for an oversized payload")

    monkeypatch.setattr("triageai.rules.powershell.base64.b64decode", _must_not_run)

    result = decode_encoded_command("A" * (MAX_ENCODED_CHARS + 4))

    assert result.refused is True


def test_oversized_payload_still_produces_a_match() -> None:
    payload = "A" * (MAX_ENCODED_CHARS + 4)
    event = _event(command_line=f"powershell.exe -EncodedCommand {payload}")

    matches = evaluate((event,))

    assert len(matches) == 1
    assert "decode refused" in matches[0].description
    assert payload not in matches[0].description


def test_shortest_accepted_abbreviation_enc_matches() -> None:
    payload = _encode("x")
    event = _event(command_line=f"powershell.exe -enc {payload}")
    assert len(evaluate((event,))) == 1


# --- Failure handling: only a short, fixed-wording record is kept ---


def test_invalid_base64_records_a_fixed_error() -> None:
    payload = "not-valid-base64!!!"
    result = decode_encoded_command(payload)

    assert result.decode_error == "invalid base64"
    assert result.refused is False
    assert result.byte_preview is None
    assert payload not in (result.decode_error or "")


def test_utf16_failure_keeps_only_a_short_hex_preview() -> None:
    raw = b"\x00\xd8" * 50  # 100 bytes; a lone surrogate is invalid UTF-16LE
    result = decode_encoded_command(_encode_bytes(raw))

    assert result.decoded_text is None
    assert result.byte_preview == raw[:BYTE_PREVIEW_BYTES].hex()
    assert result.decode_error is not None
    assert "UTF-16LE" in result.decode_error
    assert "100 bytes" in result.decode_error
    assert raw.hex() not in result.decode_error


def test_odd_length_bytes_fail_utf16_with_preview() -> None:
    result = decode_encoded_command(_encode_bytes(b"odd"))

    assert result.decoded_text is None
    assert result.byte_preview == "6f6464"


# --- Missing-field ---


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
    payload = _encode_bytes(b"odd")
    event = _event(command_line=f"powershell.exe -EncodedCommand {payload}")

    matches = evaluate((event,))

    assert len(matches) == 1
    assert "decode attempted, failed" in matches[0].description
    assert "UTF-16LE" in matches[0].description
    assert "6f6464" in matches[0].description


def test_empty_input_produces_no_matches() -> None:
    assert evaluate(()) == ()