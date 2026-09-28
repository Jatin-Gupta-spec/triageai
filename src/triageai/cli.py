"""Command-line interface for TriageAI.

main(argv) contains all real logic and is fully testable in isolation,
without ever invoking a subprocess or touching sys.argv.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from triageai.correlation import build_cases
from triageai.errors import TriageInputError
from triageai.hallucination_check import HallucinationError, check_for_hallucination
from triageai.models import AIAnalysisDraft, Case, NormalizedEvent, ScanSummary
from triageai.normalization import normalize_event
from triageai.output_validation import OutputValidationError, validate_ai_output
from triageai.prompt_builder import build_prompt
from triageai.providers.base import AIProvider, ProviderError
from triageai.providers.mock import MockProvider
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


@dataclass(frozen=True, slots=True)
class _NormalizationResult:
    """Result of validating, normalizing, and deduplicating raw records."""

    events: tuple[NormalizedEvent, ...]
    total_records_read: int
    duplicate_count: int


def _normalize_records(raw_records: tuple[RawRecord, ...]) -> _NormalizationResult:
    """Validate each raw record is a JSON object, normalize it, and
    deduplicate by original_record_id. The FIRST occurrence of a given
    ID, in the deterministic file/record order read_input produces, is
    kept; every later occurrence is counted as a duplicate and dropped.
    """
    seen_ids: set[str] = set()
    events: list[NormalizedEvent] = []
    duplicate_count = 0

    for record in raw_records:
        if not isinstance(record.data, dict):
            raise TriageInputError(
                f"{record.source_path}: record is not a JSON object "
                f"(got {type(record.data).__name__})"
            )
        event = normalize_event(record.data)
        if event.original_record_id in seen_ids:
            duplicate_count += 1
            continue
        seen_ids.add(event.original_record_id)
        events.append(event)

    return _NormalizationResult(
        events=tuple(events),
        total_records_read=len(raw_records),
        duplicate_count=duplicate_count,
    )


def _generate_validated_draft(
    redacted_case: Case, provider: AIProvider | None = None
) -> AIAnalysisDraft | None:
    """Run the full AI pipeline for one case: build the prompt, ask the
    provider, validate shape, validate content. Returns None if the
    provider fails or EITHER validation layer rejects the draft -- per
    the locked spec's fail-closed rule.

    `provider` exists so tests can exercise the rejection paths with a
    misbehaving provider. The CLI itself always uses the default mock;
    the locked v0.1 command-line surface is unchanged.
    """
    active_provider = provider if provider is not None else MockProvider()
    prompt = build_prompt(redacted_case)

    try:
        raw_text = active_provider.generate(prompt)
    except ProviderError:
        return None

    try:
        draft = validate_ai_output(raw_text)
    except OutputValidationError:
        return None

    try:
        check_for_hallucination(draft, redacted_case)
    except HallucinationError:
        return None

    return draft


def _format_scan_summary(summary: ScanSummary) -> str:
    return (
        f"Scan summary: {summary.total_records_read} record(s) read, "
        f"{summary.duplicate_count} duplicate(s) skipped, "
        f"{summary.undated_count} undated, "
        f"{len(summary.cases)} case(s)."
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TriageAI CLI.

    Returns:
        0 on success (including valid, empty input), 2 for any
        input-reading, record-validation, or normalization error, 3
        for a usage error.
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
        normalization = _normalize_records(result.raw_records)
    except TriageInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cases = build_cases(normalization.events)
    redacted_cases = tuple(redact_case_for_render(case) for case in cases)

    undated_count = sum(1 for event in normalization.events if event.timestamp is None)
    scan_summary = ScanSummary(
        total_records_read=normalization.total_records_read,
        duplicate_count=normalization.duplicate_count,
        undated_count=undated_count,
        cases=cases,
    )

    ai_drafts: dict[str, AIAnalysisDraft | None] = {
        case.case_id: _generate_validated_draft(case) for case in redacted_cases
    }

    print(_format_scan_summary(scan_summary))
    if parsed.format == "markdown":
        print(render_markdown(redacted_cases, ai_drafts))
    else:
        print(render_text(redacted_cases, ai_drafts))

    return 0