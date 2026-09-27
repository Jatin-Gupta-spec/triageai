"""Tests for the CLI entry point.

Wires normalization, redaction, correlation, and the mock-AI pipeline
together. This fix adds deduplication by original_record_id and a
printed scan summary (records read / duplicates skipped / undated /
cases) -- both previously spec'd (Section 5) but never implemented.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triageai.cli import main


def test_no_arguments_is_usage_error() -> None:
    assert main([]) == 3


def test_unknown_command_is_usage_error() -> None:
    assert main(["not-a-real-command"]) == 3


def test_analyze_without_path_is_usage_error() -> None:
    assert main(["analyze"]) == 3


def test_analyze_bad_format_value_is_usage_error(tmp_path: Path) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"a": 1}), encoding="utf-8")

    assert main(["analyze", str(file_path), "--format", "yaml"]) == 3


def test_analyze_missing_path_is_input_error() -> None:
    assert main(["analyze", "/this/path/does/not/exist.json"]) == 2


def test_analyze_malformed_json_is_input_error(tmp_path: Path) -> None:
    file_path = tmp_path / "broken.json"
    file_path.write_text('{"a": ', encoding="utf-8")

    assert main(["analyze", str(file_path)]) == 2


def test_analyze_non_object_array_element_is_input_error(tmp_path: Path) -> None:
    file_path = tmp_path / "scalars.json"
    file_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    assert main(["analyze", str(file_path)]) == 2


def test_analyze_text_format_prints_host(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"host": "WIN-CLIENT01"}), encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "WIN-CLIENT01" in captured.out


def test_analyze_markdown_format_prints_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"host": "WIN-CLIENT01"}), encoding="utf-8")

    exit_code = main(["analyze", str(file_path), "--format", "markdown"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "| Timestamp | Host | User | Event ID | Process | Command Line |" in captured.out


def test_analyze_empty_array_succeeds_with_no_events_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file_path = tmp_path / "empty.json"
    file_path.write_text("[]", encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No events to report." in captured.out


def test_analyze_redacts_email_distinctly_in_user_vs_command_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(
        json.dumps(
            {"host": "H1", "user": "alice@corp.local", "command_line": "notify bob@corp.local"}
        ),
        encoding="utf-8",
    )

    main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert "alice@corp.local" not in captured.out
    assert "bob@corp.local" not in captured.out
    assert "[REDACTED_EMAIL_001]" in captured.out
    assert "[REDACTED_EMAIL]" in captured.out


def test_analyze_shows_accepted_ai_draft_for_benign_case(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"host": "H1"}), encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AI draft" in captured.out
    assert "REJECTED" not in captured.out
    assert "AI-generated draft requiring human review" in captured.out


def test_analyze_shows_rule_match_and_ai_observation_for_auth001(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    records = [
        {
            "host": "H1",
            "user": "alice",
            "event_id": "4625",
            "timestamp": f"2026-01-01T10:0{i}:00Z",
        }
        for i in range(5)
    ]
    file_path = tmp_path / "burst.json"
    file_path.write_text(json.dumps(records), encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AUTH-001" in captured.out
    assert "MEDIUM" in captured.out
    assert "REJECTED" not in captured.out
    assert "AI-generated draft requiring human review" in captured.out


# --- This fix: deduplication and scan summary ---


def test_analyze_deduplicates_supplied_ids(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    records = [
        {"original_record_id": "dup-1", "host": "H1", "event_id": "4624"},
        {"original_record_id": "dup-1", "host": "H1", "event_id": "4624"},
    ]
    file_path = tmp_path / "dups.json"
    file_path.write_text(json.dumps(records), encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Scan summary: 2 record(s) read, 1 duplicate(s) skipped" in captured.out


def test_analyze_deduplicates_derived_ids_for_identical_records(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No original_record_id supplied on either -- both derive the SAME
    # SHA-256 ID because their raw content is byte-for-byte identical.
    records = [{"host": "H1", "event_id": "4624"}, {"host": "H1", "event_id": "4624"}]
    file_path = tmp_path / "derived_dups.json"
    file_path.write_text(json.dumps(records), encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "1 duplicate(s) skipped" in captured.out


def test_analyze_deduplicates_across_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a.json").write_text(
        json.dumps({"original_record_id": "shared-id", "host": "H1"}), encoding="utf-8"
    )
    (tmp_path / "b.json").write_text(
        json.dumps({"original_record_id": "shared-id", "host": "H1"}), encoding="utf-8"
    )

    exit_code = main(["analyze", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "1 duplicate(s) skipped" in captured.out


def test_analyze_no_duplicates_reports_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"host": "H1"}), encoding="utf-8")

    exit_code = main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "0 duplicate(s) skipped" in captured.out


def test_analyze_scan_summary_line_present(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"host": "H1"}), encoding="utf-8")

    main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert captured.out.startswith("Scan summary:")