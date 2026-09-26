"""Safe, deterministic reading of sanitized Wazuh-style JSON input.

This module turns bytes on disk into raw, decoded JSON values. It
performs NO event-shape validation and NO rule evaluation -- only:
size limits, encoding rules, duplicate-key rejection, symlink-safe
directory traversal, and the per-analysis record cap. Schema
validation and normalization into NormalizedEvent happen in Stage 5.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from triageai.errors import TriageInputError

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB, per the locked operational contract
MAX_RECORDS_PER_ANALYSIS = 10_000

# Order matters: the 4-byte UTF-32 marks are checked before the 2-byte
# UTF-16 marks, since UTF-32LE's BOM shares its first two bytes with
# UTF-16LE's BOM.
_UTF_BOMS: tuple[bytes, ...] = (
    b"\x00\x00\xfe\xff",  # UTF-32 BE
    b"\xff\xfe\x00\x00",  # UTF-32 LE
    b"\xfe\xff",          # UTF-16 BE
    b"\xff\xfe",          # UTF-16 LE
    b"\xef\xbb\xbf",      # UTF-8
)


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One decoded JSON value, not yet validated, with its source file.

    This is Stage 4 plumbing, distinct from the locked NormalizedEvent
    model in models.py -- that shape doesn't exist until Stage 5.
    """

    source_path: Path
    data: object


@dataclass(frozen=True, slots=True)
class ReadResult:
    """Everything Stage 4 produces from one `analyze` invocation."""

    raw_records: tuple[RawRecord, ...]
    files_read: int
    files_skipped_symlink: int


def read_input(path: Path) -> ReadResult:
    """Read one JSON file, or every .json file in a directory tree.

    Raises:
        TriageInputError: for a missing path, an oversized file, a BOM
            or encoding violation, malformed JSON, a duplicate object
            key, or if the per-analysis record cap would be exceeded.
    """
    if path.is_dir():
        return _read_directory(path)
    if path.is_file():
        return _read_single_file(path)
    raise TriageInputError(f"path does not exist or is not a regular file/directory: {path}")


def _read_directory(root: Path) -> ReadResult:
    kept: list[Path] = []
    skipped_symlinks = 0

    # followlinks=False is the load-bearing safety guarantee here: it
    # has been stdlib os.walk behavior since long before Python 3.11,
    # so it is correct on every Python version this project supports
    # -- unlike Path.rglob()'s recurse_symlinks keyword, which only
    # exists from Python 3.13 onward and would silently do nothing on
    # the 3.11 interpreter this project's own CI runs.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current_dir = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not (current_dir / d).is_symlink()]

        for filename in filenames:
            candidate = current_dir / filename
            if candidate.suffix.lower() != ".json":
                continue
            if candidate.is_symlink():
                skipped_symlinks += 1
                continue
            kept.append(candidate)

    kept.sort(key=lambda p: _root_relative_posix(p, root))

    all_records: list[RawRecord] = []
    for file_path in kept:
        result = _read_single_file(file_path, running_total=len(all_records))
        all_records.extend(result.raw_records)

    return ReadResult(
        raw_records=tuple(all_records),
        files_read=len(kept),
        files_skipped_symlink=skipped_symlinks,
    )


def _root_relative_posix(path: Path, root: Path) -> str:
    return PurePosixPath(path.relative_to(root)).as_posix()


def _read_single_file(path: Path, running_total: int = 0) -> ReadResult:
    data = _read_bounded_bytes(path)

    if len(data) == 0:
        raise TriageInputError(f"{path}: zero-byte file is not valid JSON")

    text = _decode_strict_utf8_no_bom(data, path)

    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:
        raise TriageInputError(f"{path}: invalid JSON: {exc}") from exc

    items = parsed if isinstance(parsed, list) else [parsed]

    new_total = running_total + len(items)
    if new_total > MAX_RECORDS_PER_ANALYSIS:
        raise TriageInputError(
            f"analysis exceeds the {MAX_RECORDS_PER_ANALYSIS:,}-record cap "
            f"(would reach record {new_total:,})"
        )

    records = tuple(RawRecord(source_path=path, data=item) for item in items)
    return ReadResult(raw_records=records, files_read=1, files_skipped_symlink=0)


def _read_bounded_bytes(path: Path) -> bytes:
    # The stat check is a fast-path optimization only. The real limit
    # is the bounded read below, which is TOCTOU-safe: it stays
    # correct even if the file grows between this stat call and the
    # read that follows it.
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise TriageInputError(f"cannot stat {path}: {exc}") from exc

    if stat_result.st_size > MAX_FILE_BYTES:
        raise TriageInputError(
            f"{path}: {stat_result.st_size:,} bytes exceeds the {MAX_FILE_BYTES:,}-byte limit"
        )

    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)

    if len(data) > MAX_FILE_BYTES:
        raise TriageInputError(
            f"{path}: exceeds the {MAX_FILE_BYTES:,}-byte limit (confirmed by bounded read)"
        )

    return data


def _decode_strict_utf8_no_bom(data: bytes, path: Path) -> str:
    for bom in _UTF_BOMS:
        if data.startswith(bom):
            raise TriageInputError(
                f"{path}: byte-order mark detected; strict UTF-8 without BOM is required"
            )

    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TriageInputError(f"{path}: not valid strict UTF-8: {exc}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate object key: {key!r}")
        seen[key] = value
    return seen