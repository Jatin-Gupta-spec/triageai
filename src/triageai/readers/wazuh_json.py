"""Safe, deterministic reading of sanitized Wazuh-style JSON input.

Stage 18 link policy, extending Stage 17c:
- The input path's own PARENT DIRECTORIES are now also checked. Before
  this, `analyze linked-parent/real-file.json` would pass, because
  only the final path component was checked, even though the
  directory it sits inside was reached through a link.
- The read itself now takes a small extra step to reduce, not fully
  close, the gap between checking a path and opening it: on platforms
  that support it (POSIX), the file is opened with O_NOFOLLOW, so the
  OS itself refuses to follow a symlink swapped in at the very last
  moment; and the identity (device + inode) of the file actually
  opened is compared against the identity seen by the earlier stat --
  a mismatch means the path was swapped between the check and the
  open, and the read is refused.

Documented limits (also in LIMITATIONS.md): the ancestor check does
not resolve ".." segments in the input path, since resolving would
mean following symlinks along the way, defeating the point; a plain
path with no ".." is unaffected. st_ino/st_dev identity comparison is
well-established on POSIX; its behavior on Windows for this exact
scenario has not been independently verified beyond what this
project's own tests exercise.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, NoReturn

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


def _has_linked_ancestor(path: Path) -> bool:
    """True if any PARENT directory of `path` is itself a link.

    Uses .absolute() (prefixes cwd if relative) rather than .resolve()
    (which follows symlinks and would defeat the point of this check).
    A ".." segment in the input path is not collapsed, so this check
    only reliably covers a plain path with no ".." components.
    """
    return any(_is_link_like(parent) for parent in path.absolute().parents)


def _open_without_following_symlink(path: Path) -> IO[bytes]:
    """Open `path` for reading, refusing to follow a symlink at the
    final path component where the platform supports that (POSIX's
    O_NOFOLLOW). No equivalent flag is used on Windows here; the
    caller's identity comparison is the defense on that platform.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(path, flags)
    return os.fdopen(file_descriptor, "rb")


def read_input(path: Path) -> ReadResult:
    """Read one JSON file, or every .json file in a directory tree.

    Raises:
        TriageInputError: for an input path (or any of its parent
            directories) that is a symlink or junction, a missing
            path, an oversized file, a BOM or encoding violation,
            malformed JSON, a duplicate object key, a non-finite
            numeric constant, a file whose identity changed between
            the size check and the read, or if the per-analysis record
            cap would be exceeded.
    """
    if _is_link_like(path) or _has_linked_ancestor(path):
        raise TriageInputError(
            f"input path is, or is reached through, a symbolic link or junction; "
            f"refusing to follow it: {path}"
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
        pre_open_stat = path.stat()
    except OSError as exc:
        raise TriageInputError(f"cannot stat {path}: {exc}") from exc

    if pre_open_stat.st_size > MAX_FILE_BYTES:
        raise TriageInputError(
            f"{path}: {pre_open_stat.st_size:,} bytes exceeds the {MAX_FILE_BYTES:,}-byte limit"
        )

    try:
        handle = _open_without_following_symlink(path)
    except OSError as exc:
        raise TriageInputError(f"cannot open {path}: {exc}") from exc

    with handle:
        post_open_stat = os.fstat(handle.fileno())
        if (post_open_stat.st_dev, post_open_stat.st_ino) != (
            pre_open_stat.st_dev,
            pre_open_stat.st_ino,
        ):
            raise TriageInputError(
                f"{path}: file identity changed between the size check and the read; "
                "refusing to process"
            )

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
    default. Rejecting them here keeps a non-finite float from
    reaching canonicalize() and crashing there.
    """
    raise ValueError(f"non-finite numeric constant not allowed in JSON: {constant}")