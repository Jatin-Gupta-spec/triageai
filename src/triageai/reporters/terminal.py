"""Plain-text report rendering. Renders REDACTED copies only -- callers
are responsible for passing already-redacted events/cases (see
redaction.py); this module does not redact anything itself.
"""

from __future__ import annotations

from triageai.models import NormalizedEvent


def render_text(events: tuple[NormalizedEvent, ...]) -> str:
    """Render a plain-text timeline. Caller must pass redacted events."""
    if not events:
        return "No events to report."

    lines: list[str] = []
    for event in events:
        when = event.timestamp.isoformat() if event.timestamp is not None else "UNDATED"
        lines.append(
            f"[{when}] host={event.host or '?'} user={event.user or '?'} "
            f"event_id={event.event_id or '?'} process={event.process or '?'} "
            f"command_line={event.command_line or '?'}"
        )
    return "\n".join(lines)