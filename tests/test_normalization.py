"""Tests for src/triageai/normalization.py.

Covers: canonicalization determinism, raw-vs-redacted ID derivation,
timestamp parsing/UTC conversion, and missing/wrong-typed field
handling in normalize_event.
"""

from __future__ import annotations

from datetime import UTC, datetime

from triageai.normalization import (
    canonicalize,
    derive_record_id,
    normalize_event,
    parse_timestamp,
)


def test_canonicalize_sorts_keys_regardless_of_input_order() -> None:
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b


def test_canonicalize_preserves_array_order() -> None:
    a = canonicalize({"items": [1, 2, 3]})
    b = canonicalize({"items": [3, 2, 1]})
    assert a != b


def test_canonicalize_nfc_normalizes_unicode_equivalents() -> None:
    # "é" as a single codepoint vs. "e" + combining acute accent.
    composed = canonicalize({"user": "caf\u00e9"})
    decomposed = canonicalize({"user": "cafe\u0301"})
    assert composed == decomposed


def test_derive_record_id_differs_for_different_secrets() -> None:
    # Per the locked spec: two records differing only in a value that
    # would later be redacted identically must still get different IDs.
    record_a = {"user": "alice", "command_line": "connect --token abc123"}
    record_b = {"user": "alice", "command_line": "connect --token xyz789"}

    assert derive_record_id(record_a) != derive_record_id(record_b)


def test_derive_record_id_is_deterministic() -> None:
    record = {"host": "WIN-CLIENT01", "user": "alice"}
    assert derive_record_id(record) == derive_record_id(dict(record))


def test_parse_timestamp_converts_to_utc() -> None:
    result = parse_timestamp("2026-01-01T10:00:00-05:00")
    assert result == datetime(2026, 1, 1, 15, 0, 0, tzinfo=UTC)


def test_parse_timestamp_rejects_naive_timestamp() -> None:
    assert parse_timestamp("2026-01-01T10:00:00") is None


def test_parse_timestamp_rejects_garbage() -> None:
    assert parse_timestamp("not-a-timestamp") is None


def test_parse_timestamp_rejects_non_string() -> None:
    assert parse_timestamp(12345) is None


def test_normalize_event_preserves_supplied_record_id() -> None:
    event = normalize_event({"original_record_id": "custom-id-1", "host": "H1"})
    assert event.original_record_id == "custom-id-1"


def test_normalize_event_derives_id_when_absent() -> None:
    event = normalize_event({"host": "H1", "user": "alice"})
    assert len(event.original_record_id) == 64  # SHA-256 hex digest length


def test_normalize_event_missing_field_becomes_none_not_invented() -> None:
    event = normalize_event({"host": "H1"})
    assert event.user is None
    assert event.command_line is None


def test_normalize_event_wrong_typed_field_becomes_none() -> None:
    # host given as a number, not a string -- must not be coerced/invented.
    event = normalize_event({"host": 12345})
    assert event.host is None


def test_normalize_event_undated_record_has_null_timestamp() -> None:
    event = normalize_event({"host": "H1", "timestamp": "not-valid"})
    assert event.timestamp is None


def test_normalize_event_extracts_mitre_techniques() -> None:
    event = normalize_event({"mitre_techniques": ["T1110", "T1059.001"]})
    assert event.mitre_techniques == ("T1110", "T1059.001")


def test_normalize_event_mitre_techniques_defaults_to_empty() -> None:
    event = normalize_event({"host": "H1"})
    assert event.mitre_techniques == ()