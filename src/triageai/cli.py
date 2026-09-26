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
from triageai.models import Case, Confidence, NormalizedEvent, Severity
from triageai.normalization import normalize_event
from triageai.readers.wazuh_json import RawRecord, read_input
from triageai.redaction import redact_case_for_render
from triageai.reporters.markdown_report import render_markdown
from triageai.reporters.terminal import render_text
from triageai.reporters.timeline import build_timeline


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
    """Validate each raw record is a JSON object, then normalize it.

    A JSON array element that is not itself an object (e.g. a bare
    number or string) is not a valid Wazuh-style record -- per the
    locked spec's evidence-integrity principle, TriageAI must not
    silently skip or invent structure for it. It is treated the same
    as any other malformed input: a TriageInputError, exit code 2.
    """
    events: list[NormalizedEvent] = []
    for record in raw_records:
        if not isinstance(record.data, dict):
            raise TriageInputError(
                f"{record.source_path}: record is not a JSON object "
                f"(got {type(record.data).__name__})"
            )
        events.append(normalize_event(record.data))
    return tuple(events)


def _build_case_for_display(events: tuple[NormalizedEvent, ...], case_id: str) -> Case:
    # Stage 7 only: a single, unscored placeholder Case wrapping every
    # event read this run, purely so redact_case_for_render (which
    # operates on Case, not a bare event list) has something to take.
    # Real correlation into multiple, properly-scored cases arrives in
    # Stage 11 -- this function is deliberately temporary and will be
    # replaced outright, not extended, when that stage lands.
    users = tuple(sorted({e.user for e in events if e.user is not None}))
    hosts = tuple(sorted({e.host for e in events if e.host is not None}))
    dated_timestamps = sorted(e.timestamp for e in events if e.timestamp is not None)

    return Case(
        case_id=case_id,
        first_seen=dated_timestamps[0] if dated_timestamps else None,
        last_seen=dated_timestamps[-1] if dated_timestamps else None,
        affected_hosts=hosts,
        affected_users=users,
        normalized_events=events,
        rule_matches=(),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.LOW,
        observed_facts=(),
        evidence_gaps=(),
    )


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

    case = _build_case_for_display(events, case_id="stage7-placeholder")
    redacted_case = redact_case_for_render(case)
    ordered_events = build_timeline(redacted_case.normalized_events)

    if parsed.format == "markdown":
        print(render_markdown(ordered_events))
    else:
        print(render_text(ordered_events))

    return 0