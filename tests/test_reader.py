"""Tests for src/triageai/readers/wazuh_json.py.

Stage 4 proves safe reading -- size limits, encoding rules,
duplicate-key rejection, empty-input handling, and the per-analysis
record cap. This fix adds rejection of non-finite JSON numeric
constants (NaN/Infinity/-Infinity).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triageai.errors import TriageInputError
from triageai.readers.wazuh_json import MAX_FILE_BYTES, read_input


def test_reads_single_json_object(tmp_path: Path) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_bytes(json.dumps({"event_id": "4625"}).encode("utf-8"))

    result = read_input(file_path)

    assert len(result.raw_records) == 1
    assert result.raw_records[0].data == {"event_id": "4625"}
    assert result.files_read == 1


def test_reads_json_array_as_multiple_records(tmp_path: Path) -> None:
    file_path = tmp_path / "many.json"
    file_path.write_bytes(json.dumps([{"a": 1}, {"a": 2}, {"a": 3}]).encode("utf-8"))

    result = read_input(file_path)

    assert len(result.raw_records) == 3


def test_empty_array_is_valid_zero_events(tmp_path: Path) -> None:
    file_path = tmp_path / "empty.json"
    file_path.write_bytes(b"[]")

    result = read_input(file_path)

    assert result.raw_records == ()
    assert result.files_read == 1


def test_empty_directory_is_valid_zero_events(tmp_path: Path) -> None:
    result = read_input(tmp_path)

    assert result.raw_records == ()
    assert result.files_read == 0


def test_zero_byte_file_is_malformed(tmp_path: Path) -> None:
    file_path = tmp_path / "empty_file.json"
    file_path.write_bytes(b"")

    with pytest.raises(TriageInputError, match="zero-byte"):
        read_input(file_path)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "big.json"
    oversized_content = b'{"x": "' + (b"a" * (MAX_FILE_BYTES + 1)) + b'"}'
    file_path.write_bytes(oversized_content)

    with pytest.raises(TriageInputError, match="exceeds"):
        read_input(file_path)


def test_utf8_bom_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "bom.json"
    file_path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"a": 1}).encode("utf-8"))

    with pytest.raises(TriageInputError, match="byte-order mark"):
        read_input(file_path)


def test_invalid_utf8_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "bad_encoding.json"
    file_path.write_bytes(b"\xff\xfe\xfa\xfb not valid utf-8 at all")

    with pytest.raises(TriageInputError):
        read_input(file_path)


def test_duplicate_object_keys_are_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "dup.json"
    file_path.write_bytes(b'{"event_id": "1", "event_id": "2"}')

    with pytest.raises(TriageInputError, match="duplicate"):
        read_input(file_path)


def test_malformed_json_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "broken.json"
    file_path.write_bytes(b'{"event_id": ')

    with pytest.raises(TriageInputError, match="invalid JSON"):
        read_input(file_path)


def test_directory_reads_json_files_in_sorted_order(tmp_path: Path) -> None:
    (tmp_path / "b.json").write_bytes(json.dumps({"name": "b"}).encode("utf-8"))
    (tmp_path / "a.json").write_bytes(json.dumps({"name": "a"}).encode("utf-8"))
    (tmp_path / "notjson.txt").write_bytes(b"ignored")

    result = read_input(tmp_path)

    assert [record.data["name"] for record in result.raw_records] == ["a", "b"]
    assert result.files_read == 2


def test_record_cap_aggregates_across_directory(tmp_path: Path) -> None:
    (tmp_path / "one.json").write_bytes(json.dumps([{"i": i} for i in range(3)]).encode("utf-8"))
    (tmp_path / "two.json").write_bytes(json.dumps([{"i": i} for i in range(2)]).encode("utf-8"))

    result = read_input(tmp_path)

    assert len(result.raw_records) == 5


def test_record_cap_exceeded_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "toomany.json"
    file_path.write_bytes(json.dumps([{"i": i} for i in range(10_001)]).encode("utf-8"))

    with pytest.raises(TriageInputError, match="10,000"):
        read_input(file_path)


# --- This fix: non-finite JSON constants ---


def test_nan_constant_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "nan.json"
    file_path.write_bytes(b'{"cpu_usage": NaN}')

    with pytest.raises(TriageInputError, match="NaN"):
        read_input(file_path)


def test_infinity_constant_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "inf.json"
    file_path.write_bytes(b'{"value": Infinity}')

    with pytest.raises(TriageInputError, match="Infinity"):
        read_input(file_path)


def test_negative_infinity_constant_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "neg_inf.json"
    file_path.write_bytes(b'{"value": -Infinity}')

    with pytest.raises(TriageInputError, match="Infinity"):
        read_input(file_path)