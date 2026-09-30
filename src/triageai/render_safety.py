"""Shared sanitization for untrusted values rendered into reports.

Both terminal.py and markdown_report.py display fields that originate
from untrusted event data. Without sanitization: raw control
characters (including ANSI escape sequences) can manipulate a
terminal; pipe/newline characters can break a Markdown table; and raw
HTML (<script>, <img onerror=...>, an HTML comment) can become live
content wherever the Markdown is rendered, since most Markdown
renderers -- including GitHub's own -- pass untouched HTML through
unless it's escaped first.

Stage 18 adds HTML escaping for the Markdown path (&, <, > -> HTML
entities). This must run BEFORE this module's own <br> line-break
marker and \\| pipe escape are inserted, since those are deliberate,
intentional raw output, not untrusted content -- escaping happens
first, then the intentional markers are added on top.

Hidden and control characters (including CR/LF and the Unicode line
separators U+2028/U+2029) are folded to a single internal '\\n' first,
THEN every OTHER hidden or control character is re-encoded as VISIBLE
text (\\xNN / \\uNNNN) rather than silently dropped, so an analyst can
see that a value contained something unusual, before the caller-
specific line-break marker (\\n for terminal, <br> for Markdown) is
inserted in its place.

Documented limits: Markdown or HTML syntax other than &, <, >, a
literal pipe, and a line break (backticks, emphasis, links) is not
escaped; view a Markdown report as plain text or in a viewer that
independently sanitizes HTML if that matters for your use.
"""

from __future__ import annotations

import html
import re

# Excludes \x0a (LF), \x0d (CR), \u2028, and \u2029 deliberately --
# those four are folded to a canonical '\n' by _normalize_line_breaks
# first, and re-inserted as the caller's own line-break marker at the
# end, rather than being treated as "hidden" characters to encode.
_HIDDEN_CHAR_PATTERN = re.compile(
    r"[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)
_LINE_BREAKS = ("\r\n", "\r", "\u2028", "\u2029")


def _encode_hidden(match: re.Match[str]) -> str:
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _normalize_line_breaks(value: str) -> str:
    """Fold every recognized line-break form down to a single '\\n'."""
    for line_break in _LINE_BREAKS:
        value = value.replace(line_break, "\n")
    return value


def sanitize_for_terminal(value: str) -> str:
    """Make a value safe to print to a terminal: line breaks become a
    visible \\n marker and every other control or hidden formatting
    character becomes visible escape text.
    """
    normalized = _normalize_line_breaks(value)
    encoded = _HIDDEN_CHAR_PATTERN.sub(_encode_hidden, normalized)
    return encoded.replace("\n", "\\n")


def sanitize_for_markdown_cell(value: str) -> str:
    """Make a value safe inside a Markdown table cell, and anywhere
    else in a rendered Markdown report: line breaks become a visible
    <br> marker, hidden characters are encoded visibly, raw HTML
    special characters are escaped to entities so untrusted content
    cannot become active markup, and a literal pipe is escaped so it
    cannot be mistaken for a column boundary.
    """
    normalized = _normalize_line_breaks(value)
    encoded = _HIDDEN_CHAR_PATTERN.sub(_encode_hidden, normalized)
    escaped = html.escape(encoded, quote=False)
    with_breaks = escaped.replace("\n", "<br>")
    return with_breaks.replace("|", "\\|")