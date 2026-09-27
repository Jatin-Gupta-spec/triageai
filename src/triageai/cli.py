"""Command-line interface for TriageAI.

main(argv) contains all real logic and is fully testable in isolation,
without ever invoking a subprocess or touching sys.argv.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from triageai.correlation import build_cases
from triageai.errors import TriageInputError
from triageai.models import NormalizedEvent
from triageai.normalization import normalize_event
from triageai.readers.wazuh_json import RawRecord, read_input
from triageai.redaction import redact_case_for_render
from triageai.reporters.markdown_report import render_markdown
from triageai.reporters.terminal import render_text


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
        help="Report output format.",
    )

    return parser


def _normalize_records(raw_records: tuple[RawRecord, ...]) -> tuple[NormalizedEvent, ...]:
    """Validate each raw record is a JSON object, then normalize it."""
    events: list[NormalizedEvent] = []
    for record in raw_records:
        if not isinstance(record.data, dict):
            raise TriageInputError(
                f"{record.source_path}: record is not a JSON object "
                f"(got {type(record.data).__name__})"
            )
        events.append(normalize_event(record.data))
    return tuple(events)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TriageAI CLI.

    Returns:
        0 on success (including valid, empty input), 2 for any
        input-reading or record-validation error, 3 for a usage error.
    """
    args = list(argv) if argv is not None else sys.argv[1:]
    parser = _build_parser()

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return 3 if exc.code != 0 else 0

    if parsed.command is None:
        parser.print_usage(sys.stderr)
        return 3

    try:
        result = read_input(Path(parsed.path))
        events = _normalize_records(result.raw_records)
    except TriageInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cases = build_cases(events)
    redacted_cases = tuple(redact_case_for_render(case) for case in cases)

    if parsed.format == "markdown":
        print(render_markdown(redacted_cases))
    else:
        print(render_text(redacted_cases))

    return 0