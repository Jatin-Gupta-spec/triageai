"""Safe, deterministic reading of sanitized Wazuh-style JSON input.

This module turns bytes on disk into raw, decoded JSON values. It
performs NO event-shape validation and NO rule evaluation -- only:
size limits, encoding rules, duplicate-key rejection, non-finite
numeric constant rejection, link-safe traversal, and the per-analysis
record cap. Normalization into NormalizedEvent happens in
normalization.py.

Stage 17c link policy. The locked spec says "do not follow symlinks or
Windows junctions". A path is treated as a link (_is_link_like) if it
is a symbolic link, a Windows junction, or a Windows reparse point
whose tag is symlink or mount point. Other reparse points, such as
OneDrive cloud placeholders, are ordinary files and are read.
- The input path itself: rejected with an error (exit code 2). Before
  this, a symlink given directly on the command line was followed.
- Files inside a scanned directory: skipped and counted.
- Directories inside a scanned directory: not descended into.

Documented limits (also in LIMITATIONS.md): only the final path
component and entries found during a scan are checked, not parent
folders of the input path; the check happens before the read, so a
link swapped in between is not caught.
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

# Windows reparse tags that make a path a link: symlink and mount point
# (a directory junction). Defined here so the code type-checks and runs
# the same on every platform.
_LINK_REPARSE_TAGS = frozenset({0xA000000C, 0xA0000003})


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


def _is_link_like(path: Path) -> bool:
    """True if `path` itself is a symlink, a junction, or a symlink/
    mount-point reparse point. Missing or unreadable paths are not
    links; the caller's normal existence checks report those.
    """
    try:
        if path.is_symlink():
            return True
        stat_result = path.lstat()
    except OSError:
        return False

    if getattr(stat_result, "st_reparse_tag", 0) in _LINK_REPARSE_TAGS:
        return True

    is_junction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return bool(is_junction is not None and is_junction(path))


def read_input(path: Path) -> ReadResult:
    """Read one JSON file, or every .json file in a directory tree.

    Raises:
        TriageInputError: for an input path that is a symlink or
            junction, a missing path, an oversized file, a BOM or
            encoding violation, malformed JSON, a duplicate object
            key, a non-finite numeric constant, or if the per-analysis
            record cap would be exceeded.
    """
    if _is_link_like(path):
        raise TriageInputError(
            f"input path is a symbolic link or junction; refusing to follow it: {path}"
        )
    if path.is_dir():
        return _read_directory(path)
    if path.is_file():
        return _read_single_file(path)
    raise TriageInputError(f"path does not exist or is not a regular file/directory: {path}")


def _read_directory(root: Path) -> ReadResult:
    kept: list[Path] = []
    skipped_links = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current_dir = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not _is_link_like(current_dir / d)]

        for filename in filenames:
            candidate = current_dir / filename
            if candidate.suffix.lower() != ".json":
                continue
            if _is_link_like(candidate):
                skipped_links += 1
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
        files_skipped_symlink=skipped_links,
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

    Python's json module accepts NaN, Infinity and -Infinity by
    default. Rejecting them here, at the earliest point, keeps a
    non-finite float from reaching canonicalize() and crashing there.
    """
    raise ValueError(f"non-finite numeric constant not allowed in JSON: {constant}")