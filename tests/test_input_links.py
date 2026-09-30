"""Tests that symlinks and Windows junctions are never followed.

Creating a symlink on Windows needs Developer Mode or admin rights, so
those tests skip when it cannot be done; CI runs on Ubuntu, where they
always run. Junction tests run only on Windows and need no privileges.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from triageai.cli import main
from triageai.errors import TriageInputError
from triageai.readers.wazuh_json import _is_link_like, read_input

_WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows")


def _write_json(path: Path, data: object) -> None:
    path.write_bytes(json.dumps(data).encode("utf-8"))


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks in this environment")


def _junction(link: Path, target: Path) -> None:
    try:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    except (ImportError, AttributeError, OSError):
        pytest.skip("cannot create a junction in this environment")


# --- _is_link_like ---


def test_regular_file_and_directory_are_not_links(tmp_path: Path) -> None:
    file_path = tmp_path / "one.json"
    _write_json(file_path, {"a": 1})

    assert _is_link_like(file_path) is False
    assert _is_link_like(tmp_path) is False


def test_missing_path_is_not_a_link(tmp_path: Path) -> None:
    assert _is_link_like(tmp_path / "missing.json") is False


# --- Symlinks as the direct input ---


def test_direct_symlink_to_a_file_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    _write_json(real, {"a": 1})
    link = tmp_path / "link.json"
    _symlink(link, real)

    with pytest.raises(TriageInputError, match="symbolic link or junction"):
        read_input(link)


def test_direct_symlink_to_a_directory_is_rejected(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    _write_json(real_dir / "a.json", {"a": 1})
    link = tmp_path / "linkdir"
    _symlink(link, real_dir)

    with pytest.raises(TriageInputError, match="symbolic link or junction"):
        read_input(link)


def test_dangling_symlink_is_rejected_as_a_link(tmp_path: Path) -> None:
    link = tmp_path / "dangling.json"
    _symlink(link, tmp_path / "does-not-exist.json")

    with pytest.raises(TriageInputError, match="symbolic link or junction"):
        read_input(link)


def test_cli_rejects_a_direct_symlink_input_with_exit_code_2(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    _write_json(real, {"host": "H1"})
    link = tmp_path / "link.json"
    _symlink(link, real)

    assert main(["analyze", str(link)]) == 2


# --- Symlinks found while scanning a directory ---


def test_symlinked_file_inside_a_directory_is_skipped_and_counted(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    _write_json(outside, {"name": "outside"})
    scan = tmp_path / "scan"
    scan.mkdir()
    _write_json(scan / "b.json", {"name": "b"})
    _symlink(scan / "link.json", outside)

    result = read_input(scan)

    assert [record.data for record in result.raw_records] == [{"name": "b"}]
    assert result.files_read == 1
    assert result.files_skipped_symlink == 1


def test_symlinked_directory_inside_a_directory_is_not_descended(tmp_path: Path) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    _write_json(outside_dir / "a.json", {"name": "a"})
    scan = tmp_path / "scan"
    scan.mkdir()
    _write_json(scan / "b.json", {"name": "b"})
    _symlink(scan / "linkdir", outside_dir)

    result = read_input(scan)

    assert [record.data for record in result.raw_records] == [{"name": "b"}]


# --- Windows junctions ---


@_WINDOWS_ONLY
def test_junction_is_detected_as_a_link(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    junction = tmp_path / "junction"
    _junction(junction, real_dir)

    assert _is_link_like(junction) is True
    assert _is_link_like(real_dir) is False


@_WINDOWS_ONLY
def test_direct_junction_input_is_rejected(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    _write_json(real_dir / "a.json", {"a": 1})
    junction = tmp_path / "junction"
    _junction(junction, real_dir)

    with pytest.raises(TriageInputError, match="symbolic link or junction"):
        read_input(junction)


@_WINDOWS_ONLY
def test_junction_inside_a_directory_is_not_descended(tmp_path: Path) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    _write_json(outside_dir / "a.json", {"name": "a"})
    scan = tmp_path / "scan"
    scan.mkdir()
    _write_json(scan / "b.json", {"name": "b"})
    _junction(scan / "junction", outside_dir)

    result = read_input(scan)

    assert [record.data for record in result.raw_records] == [{"name": "b"}]


def test_direct_input_reached_through_a_linked_parent_is_rejected(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_file = real_dir / "a.json"
    _write_json(real_file, {"a": 1})
    linked_parent = tmp_path / "linked_parent"
    _symlink(linked_parent, real_dir)

    with pytest.raises(TriageInputError, match="reached through"):
        read_input(linked_parent / "a.json")


def test_normal_file_read_succeeds_with_identity_check_in_place(tmp_path: Path) -> None:
    # Confirms the new pre/post-open identity comparison does not
    # reject an ordinary, unmodified file -- only a genuine mismatch.
    file_path = tmp_path / "one.json"
    _write_json(file_path, {"host": "H1"})

    result = read_input(file_path)

    assert len(result.raw_records) == 1