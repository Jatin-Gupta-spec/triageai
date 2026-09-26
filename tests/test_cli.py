"""Tests for the CLI entry point.

Stage 4 replaces Stage 2's placeholder argument handling with real
argparse-based parsing wired to the actual file reader.
"""

from __future__ import annotations

import json
from pathlib import Path

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


def test_analyze_valid_file_succeeds(tmp_path: Path) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"event_id": "4625"}), encoding="utf-8")

    assert main(["analyze", str(file_path)]) == 0


def test_analyze_malformed_json_is_input_error(tmp_path: Path) -> None:
    file_path = tmp_path / "broken.json"
    file_path.write_text('{"a": ', encoding="utf-8")

    assert main(["analyze", str(file_path)]) == 2


def test_analyze_accepts_markdown_format(tmp_path: Path) -> None:
    file_path = tmp_path / "one.json"
    file_path.write_text(json.dumps({"a": 1}), encoding="utf-8")

    assert main(["analyze", str(file_path), "--format", "markdown"]) == 0