"""Tests for the CLI entry point.

Stage 2 only proves argv handling and exit codes work end to end.
Real analysis behavior arrives in later stages.
"""

from triageai.cli import main


def test_no_arguments_returns_usage_error() -> None:
    exit_code = main([])
    assert exit_code == 3


def test_with_arguments_returns_success() -> None:
    exit_code = main(["some_path"])
    assert exit_code == 0