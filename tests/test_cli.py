"""Tests for the CLI entry point.

Stage 7 wires normalization, redaction, timeline ordering, and both
report formats together -- this replaces Stage 4's record-count
placeholder output with an actual rendered report.
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
    # Two DIFFERENT addresses: one as the structured user field, one
    # only in free text. This is what actually proves the two
    # redaction paths behave differently -- unlike a single shared
    # address, which could pass even if one path were broken.
    file_path = tmp_path / "one.json"
    file_path.write_text(
        json.dumps(
            {
                "host": "H1",
                "user": "alice@corp.local",
                "command_line": "notify bob@corp.local",
            }
        ),
        encoding="utf-8",
    )

    main(["analyze", str(file_path)])
    captured = capsys.readouterr()

    assert "alice@corp.local" not in captured.out
    assert "bob@corp.local" not in captured.out
    assert "[REDACTED_EMAIL_001]" in captured.out  # the user field's numbered alias
    assert "[REDACTED_EMAIL]" in captured.out  # the command line's flat token