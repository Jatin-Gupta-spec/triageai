"""Shared sanitization for untrusted values rendered into reports.

Both terminal.py and markdown_report.py display fields that originate
from untrusted event data. Without sanitization, raw control
characters (including ANSI escape sequences) can manipulate a
terminal, and pipe/newline characters can break a Markdown table,
letting untrusted content forge rows, headings, or misleading output.

Stage 17d changes:
- Control and hidden formatting characters are now ENCODED VISIBLY
  (as \\xNN or \\uNNNN text) instead of silently dropped, so an
  analyst can see that a value contained something unusual. Covered:
  C0 and C1 controls, zero-width characters, left-to-right and
  right-to-left marks and overrides, isolates, and the byte-order
  mark (which is also a zero-width character).
- The Unicode line and paragraph separators U+2028 and U+2029 are
  treated as line breaks, like CR and LF.

Documented limits: Markdown or HTML syntax other than pipes and
newlines (links, emphasis, backticks, raw HTML) is NOT escaped; view
Markdown reports as plain text or in a viewer that sanitizes HTML.
"""

from __future__ import annotations

import re

_HIDDEN_CHAR_PATTERN = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]"
)
_LINE_BREAKS = ("\r\n", "\r", "\u2028", "\u2029")


def _encode_hidden(match: re.Match[str]) -> str:
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _single_line(value: str, marker: str) -> str:
    """Replace every kind of line break with a visible marker."""
    for line_break in _LINE_BREAKS:
        value = value.replace(line_break, "\n")
    return value.replace("\n", marker)


def sanitize_for_terminal(value: str) -> str:
    """Make a value safe to print to a terminal: line breaks become a
    visible \\n marker and every other control or hidden formatting
    character becomes visible escape text.
    """
    return _HIDDEN_CHAR_PATTERN.sub(_encode_hidden, _single_line(value, "\\n"))


def sanitize_for_markdown_cell(value: str) -> str:
    """Make a value safe inside a Markdown table cell (and anywhere
    else in a Markdown report): line breaks become a visible <br>
    marker, hidden characters are encoded visibly, and a literal pipe
    is escaped so it cannot be mistaken for a column boundary.
    """
    encoded = _HIDDEN_CHAR_PATTERN.sub(_encode_hidden, _single_line(value, "<br>"))
    return encoded.replace("|", "\\|")