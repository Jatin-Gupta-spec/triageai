"""Safe, deterministic reading of sanitized Wazuh-style JSON input.

This module turns bytes on disk into raw, decoded JSON values. It
performs NO event-shape validation and NO rule evaluation -- only:
size limits, encoding rules, duplicate-key rejection, non-finite
numeric constant rejection, symlink-safe directory traversal, and the
per-analysis record cap. Schema validation and normalization into
NormalizedEvent happen in normalization.py.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn

from triageai.errors import TriageInputError

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB, per the locked operational contract
MAX_RECORDS_PER_ANALYSIS = 10_000

_UTF_BOMS: tuple[bytes, ...] = (
    b"\x00\x00\xfe\xff",  # UTF-32 BE
    b"\xff\xfe\x00\x00",  # UTF-32 LE
    b"\xfe\xff",          # UTF-16 BE
    b"\xff\xfe",          # UTF-16 LE
    b"\xef\xbb\xbf",      # UTF-8
)


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One decoded JSON value, not yet validated, with its source file."""

    source_path: Path
    data: object


@dataclass(frozen=True, slots=True)
class ReadResult:
    """Everything the reader produces from one `analyze` invocation."""

    raw_records: tuple[RawRecord, ...]
    files_read: int
    files_skipped_symlink: int


def read_input(path: Path) -> ReadResult:
    """Read one JSON file, or every .json file in a directory tree.

    Raises:
        TriageInputError: for a missing path, an oversized file, a BOM
            or encoding violation, malformed JSON, a duplicate object
            key, a non-finite numeric constant (NaN/Infinity/
            -Infinity -- rejected here rather than crashing later in
            canonicalize(); see _reject_non_finite_constant), or if
            the per-analysis record cap would be exceeded.
    """
    if path.is_dir():
        return _read_directory(path)
    if path.is_file():
        return _read_single_file(path)
    raise TriageInputError(f"path does not exist or is not a regular file/directory: {path}")


def _read_directory(root: Path) -> ReadResult:
    kept: list[Path] = []
    skipped_symlinks = 0

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
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
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


def _reject_non_finite_constant(constant: str) -> NoReturn:
    """Callback for json.loads's parse_constant hook.

    Fix: Python's json module, by default, accepts the literal tokens
    NaN, Infinity, and -Infinity as valid JSON numbers (a non-standard
    extension). Left unhandled, a non-finite float later reached
    normalization.py's canonicalize(), which calls json.dumps(...,
    allow_nan=False) -- correctly rejecting it, but as an UNCAUGHT
    ValueError, crashing with a raw traceback instead of a controlled
    TriageInputError / exit code 2. Rejecting the constant here closes
    that gap for all three constants at once, at the earliest point.
    """
    raise ValueError(f"non-finite numeric constant not allowed in JSON: {constant}")