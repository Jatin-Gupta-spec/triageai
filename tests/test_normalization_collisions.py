"""The Unicode key-collision check must run for EVERY record, including
one that supplies its own original_record_id (Stage 17d fix).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triageai.cli import main
from triageai.errors import TriageInputError
from triageai.normalization import normalize_event

_COMPOSED = "caf\u00e9"
_DECOMPOSED = "cafe\u0301"


def test_supplied_id_does_not_skip_the_collision_check() -> None:
    record = {"original_record_id": "rec-1", _COMPOSED: "a", _DECOMPOSED: "b"}
    with pytest.raises(TriageInputError, match="normalize to the same"):
        normalize_event(record)


def test_derived_id_still_rejects_collisions() -> None:
    record = {_COMPOSED: "a", _DECOMPOSED: "b"}
    with pytest.raises(TriageInputError, match="normalize to the same"):
        normalize_event(record)


def test_nested_key_collision_is_rejected() -> None:
    record = {"original_record_id": "rec-1", "outer": {_COMPOSED: 1, _DECOMPOSED: 2}}
    with pytest.raises(TriageInputError, match="normalize to the same"):
        normalize_event(record)


def test_collision_inside_a_list_of_objects_is_rejected() -> None:
    record = {"original_record_id": "rec-1", "items": [{_COMPOSED: 1, _DECOMPOSED: 2}]}
    with pytest.raises(TriageInputError, match="normalize to the same"):
        normalize_event(record)


def test_record_without_collisions_is_accepted() -> None:
    event = normalize_event({"original_record_id": "rec-1", "host": "H1", _COMPOSED: "x"})
    assert event.original_record_id == "rec-1"


def test_cli_rejects_a_collision_with_exit_code_2(tmp_path: Path) -> None:
    file_path = tmp_path / "collision.json"
    file_path.write_text(
        json.dumps({"original_record_id": "rec-1", _COMPOSED: "a", _DECOMPOSED: "b"}),
        encoding="utf-8",
    )

    assert main(["analyze", str(file_path)]) == 2