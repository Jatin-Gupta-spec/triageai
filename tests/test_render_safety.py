"""Tests for src/triageai/render_safety.py."""

from __future__ import annotations

from triageai.render_safety import sanitize_for_markdown_cell, sanitize_for_terminal


def test_sanitize_for_terminal_strips_ansi_escape() -> None:
    hostile = "\x1b[31mFAKE ALERT\x1b[0m"
    result = sanitize_for_terminal(hostile)
    assert "\x1b" not in result
    assert "FAKE ALERT" in result


def test_sanitize_for_terminal_strips_c0_control_chars() -> None:
    hostile = "before\x07\x00after"
    result = sanitize_for_terminal(hostile)
    assert "\x07" not in result
    assert "\x00" not in result


def test_sanitize_for_terminal_strips_c1_control_chars() -> None:
    hostile = "before\x9bmalicious\x85after"
    result = sanitize_for_terminal(hostile)
    assert "\x9b" not in result
    assert "\x85" not in result


def test_sanitize_for_terminal_replaces_newline_with_visible_marker() -> None:
    hostile = "line one\nFAKE SECOND LINE"
    result = sanitize_for_terminal(hostile)
    assert "\n" not in result
    assert "\\n" in result
    assert "FAKE SECOND LINE" in result


def test_sanitize_for_terminal_normalizes_crlf() -> None:
    hostile = "line one\r\nFAKE SECOND LINE"
    result = sanitize_for_terminal(hostile)
    assert "\r" not in result
    assert "\n" not in result


def test_sanitize_for_markdown_cell_escapes_pipe() -> None:
    hostile = "value | fake_column | injected"
    result = sanitize_for_markdown_cell(hostile)
    assert result == "value \\| fake_column \\| injected"


def test_sanitize_for_markdown_cell_replaces_newline_with_br() -> None:
    hostile = "row one\n# FAKE HEADING"
    result = sanitize_for_markdown_cell(hostile)
    assert "\n" not in result
    assert "<br>" in result
    assert "FAKE HEADING" in result


def test_sanitize_for_markdown_cell_strips_control_chars() -> None:
    hostile = "value\x1b[2Jmore"
    result = sanitize_for_markdown_cell(hostile)
    assert "\x1b" not in result