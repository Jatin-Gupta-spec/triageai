"""Turns raw, untyped JSON records into NormalizedEvent objects.

Two responsibilities, deliberately kept separate:
  1. Canonicalization + SHA-256 identity, per the locked spec (Section 5).
  2. Field-by-field normalization into NormalizedEvent (timestamps to
     UTC; missing fields stay None, never invented).

Nothing here evaluates rules or performs redaction -- command_line and
every identity field are stored REAL. See models.py's module docstring.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from typing import Any

from triageai.models import NormalizedEvent


def canonicalize(record: dict[str, Any]) -> bytes:
    """Produce the exact, spec-locked canonical byte form of a raw record.

    Keys and string values are NFC-normalized, object keys are sorted
    by Unicode code point, array order is preserved, and the result is
    serialized as UTF-8 with no BOM, no insignificant whitespace,
    ensure_ascii=False. Non-finite floats (NaN/Infinity) are rejected
    by json.dumps's default allow_nan=False -- correct here, since the
    locked spec requires rejecting them and json.loads(strict) never
    produces one from valid JSON input in the first place.

    Duplicate-key rejection already happened in Stage 4's reader, so
    this function assumes `record` is already a plain dict.
    """
    normalized = _nfc_normalize(record)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _nfc_normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {_nfc_normalize(k): _nfc_normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_nfc_normalize(item) for item in value]
    return value


def derive_record_id(record: dict[str, Any]) -> str:
    """SHA-256 over the canonical bytes of the RAW record, before redaction.

    Per the locked spec: two records differing only in a value that
    would later be redacted identically must still receive different
    IDs, so they are never wrongly deduplicated.
    """
    return hashlib.sha256(canonicalize(record)).hexdigest()


def parse_timestamp(raw: Any) -> datetime | None:
    """Parse a timezone-AWARE ISO-8601 timestamp, normalized to UTC.

    Returns None for anything invalid or timezone-naive -- per the
    locked spec, such records are retained as undated evidence, not
    rejected outright. This function only classifies one field; the
    caller is responsible for counting/reporting undated records.
    """
    if not isinstance(raw, str):
        return None

    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None  # timezone-naive: explicitly rejected by the spec

    return parsed.astimezone(UTC)


def _string_or_none(value: Any) -> str | None:
    """Coerce a raw field to str, or None if absent/wrong type.

    Deliberately does NOT invent a value for a wrong-typed field (e.g.
    a JSON number where a string was expected) -- it becomes None,
    same as if the field were simply missing, per the locked spec's
    "must not be invented" rule.
    """
    return value if isinstance(value, str) else None


def _mitre_techniques_or_empty(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def normalize_event(raw_record: dict[str, Any]) -> NormalizedEvent:
    """Build a NormalizedEvent from one raw, decoded JSON object.

    Field presence follows the locked NormalizedEvent shape exactly.
    A supplied original_record_id is honored; otherwise it is derived
    from the raw record before any of this normalization occurs.
    """
    supplied_id = raw_record.get("original_record_id")
    record_id = supplied_id if isinstance(supplied_id, str) else derive_record_id(raw_record)

    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=parse_timestamp(raw_record.get("timestamp")),
        host=_string_or_none(raw_record.get("host")),
        user=_string_or_none(raw_record.get("user")),
        source=_string_or_none(raw_record.get("source")),
        event_id=_string_or_none(raw_record.get("event_id")),
        provider=_string_or_none(raw_record.get("provider")),
        rule_id=_string_or_none(raw_record.get("rule_id")),
        process=_string_or_none(raw_record.get("process")),
        parent_process=_string_or_none(raw_record.get("parent_process")),
        command_line=_string_or_none(raw_record.get("command_line")),
        source_ip=_string_or_none(raw_record.get("source_ip")),
        destination_ip=_string_or_none(raw_record.get("destination_ip")),
        mitre_techniques=_mitre_techniques_or_empty(raw_record.get("mitre_techniques")),
    )