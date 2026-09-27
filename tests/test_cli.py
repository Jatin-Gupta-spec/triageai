"""Tests for the CLI entry point.

Stage 14 wires the full mock-AI pipeline (generate -> validate shape
-> validate against evidence) into main(). Every existing behavior
(exit codes, input handling) is unchanged; the report content now also
includes an AI draft or an explicit rejection notice per case.
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
    # Stage 15 regression guard: a real rule match must NOT cause the
    # AI draft to be rejected -- this is exactly the bug found by
    # running the real fixtures by hand.
    assert "REJECTED" not in captured.out
    assert "AI-generated draft requiring human review" in captured.out