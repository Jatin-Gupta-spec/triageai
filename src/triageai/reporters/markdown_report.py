"""Markdown report rendering. Renders REDACTED copies only -- see the
same caller responsibility note in terminal.py.
"""

from __future__ import annotations

from triageai.models import NormalizedEvent


def render_markdown(events: tuple[NormalizedEvent, ...]) -> str:
    """Render a Markdown table timeline. Caller must pass redacted events."""
    if not events:
        return "## TriageAI Timeline\n\nNo events to report.\n"

    lines = [
        "## TriageAI Timeline",
        "",
        "| Timestamp | Host | User | Event ID | Process | Command Line |",
        "|---|---|---|---|---|---|",
    ]
    for event in events:
        when = event.timestamp.isoformat() if event.timestamp is not None else "UNDATED"
        lines.append(
            f"| {when} | {event.host or '?'} | {event.user or '?'} | "
            f"{event.event_id or '?'} | {event.process or '?'} | {event.command_line or '?'} |"
        )
    lines.append("")
    return "\n".join(lines)