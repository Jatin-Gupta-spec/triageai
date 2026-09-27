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
from triageai.hallucination_check import HallucinationError, check_for_hallucination
from triageai.models import AIAnalysisDraft, Case, NormalizedEvent
from triageai.normalization import normalize_event
from triageai.output_validation import OutputValidationError, validate_ai_output
from triageai.prompt_builder import build_prompt
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


def _generate_validated_draft(redacted_case: Case) -> AIAnalysisDraft | None:
    """Run the full mock-AI pipeline for one case: generate, validate
    shape, validate content. Returns None if EITHER validation layer
    rejects the draft -- per the locked spec's fail-closed rule, there
    is no partial AI content ever rendered. The caller is responsible
    for still rendering the deterministic report regardless.
    """
    provider = MockProvider()
    raw_text = provider.generate(redacted_case)

    try:
        draft = validate_ai_output(raw_text)
    except OutputValidationError:
        return None

    try:
        check_for_hallucination(draft, redacted_case)
    except HallucinationError:
        return None

    return draft


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

    # AI drafts are generated from the prompt (proving the full
    # pipeline runs end to end, including prompt construction) but
    # the draft itself -- not the prompt text -- is what gets
    # rendered. The prompt is what a real provider would receive;
    # the mock ignores it and works from redacted_case directly,
    # which is why build_prompt's result is unused here beyond
    # exercising it. See prompt_builder.py.
    ai_drafts: dict[str, AIAnalysisDraft | None] = {}
    for case in redacted_cases:
        build_prompt(case)  # exercises the full pipeline; see note above
        ai_drafts[case.case_id] = _generate_validated_draft(case)

    if parsed.format == "markdown":
        print(render_markdown(redacted_cases, ai_drafts))
    else:
        print(render_text(redacted_cases, ai_drafts))

    return 0