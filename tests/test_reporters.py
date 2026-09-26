"""Tests for terminal.py and markdown_report.py rendering."""

from __future__ import annotations

from datetime import UTC, datetime

from triageai.models import NormalizedEvent
from triageai.reporters.markdown_report import render_markdown
from triageai.reporters.terminal import render_text


def _event(command_line: str | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id="rec-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        host="WIN-CLIENT01",
        user="alice",
        source="wazuh",
        event_id="4625",
        provider=None,
        rule_id=None,
        process="powershell.exe",
        parent_process=None,
        command_line=command_line,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )


def test_render_text_empty_events() -> None:
    assert render_text(()) == "No events to report."


def test_render_text_includes_key_fields() -> None:
    output = render_text((_event(),))
    assert "WIN-CLIENT01" in output
    assert "alice" in output
    assert "4625" in output


def test_render_text_includes_command_line() -> None:
    output = render_text((_event(command_line="net user alice /active:yes"),))
    assert "net user alice /active:yes" in output


def test_render_text_marks_undated_events() -> None:
    undated = NormalizedEvent(
        original_record_id="rec-2",
        timestamp=None,
        host="H1",
        user=None,
        source=None,
        event_id=None,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=None,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )
    assert "UNDATED" in render_text((undated,))


def test_render_markdown_empty_events() -> None:
    output = render_markdown(())
    assert "No events to report." in output


def test_render_markdown_includes_table_header() -> None:
    output = render_markdown((_event(),))
    assert "| Timestamp | Host | User | Event ID | Process | Command Line |" in output
    assert "WIN-CLIENT01" in output


def test_render_markdown_includes_command_line() -> None:
    output = render_markdown((_event(command_line="net user alice /active:yes"),))
    assert "net user alice /active:yes" in output