"""Command-line interface for TriageAI.

main(argv) contains all real logic and is fully testable in isolation,
without ever invoking a subprocess or touching sys.argv.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from triageai.errors import TriageInputError
from triageai.readers.wazuh_json import read_input


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triageai",
        description="Offline-first, human-in-the-loop SOC triage assistant.",
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze a sanitized JSON export.")
    analyze.add_argument("path", help="Path to a JSON file or a directory of .json files.")
    analyze.add_argument(
        "--format",
        choices=("text", "markdown"),
        default="text",
        help="Report output format (rendering arrives in Stage 7).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TriageAI CLI.

    Returns:
        0 on success (including valid, empty input), 2 for any
        input-reading error, 3 for a usage error.
    """
    args = list(argv) if argv is not None else sys.argv[1:]
    parser = _build_parser()

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        # argparse prints its own message and exits itself on bad
        # input (default exit code 2) or on --help (exit code 0). We
        # only remap the error case to this project's own exit code 3
        # for usage errors; a genuine --help exit passes through as 0.
        return 3 if exc.code != 0 else 0

    if parsed.command is None:
        parser.print_usage(sys.stderr)
        return 3

    try:
        result = read_input(Path(parsed.path))
    except TriageInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"Read {len(result.raw_records)} record(s) from {result.files_read} file(s) "
        f"(format={parsed.format}, skipped {result.files_skipped_symlink} symlinked path(s))."
    )
    return 0