"""Shared sanitization for untrusted values rendered into reports.

Both terminal.py and markdown_report.py display fields that originate
from untrusted event data (host, command_line, AI-drafted text, rule
descriptions, observed facts, evidence gaps). Without sanitization,
raw control characters (including ANSI escape sequences) can
manipulate a terminal's display, and raw pipe/newline characters can
break a Markdown table's structure -- letting untrusted event content
forge fake rows, headings, or misleading output. This is the exact
same class of problem prompt_builder.py already solves for the AI
PROMPT boundary; this module applies the equivalent defense to the
DETERMINISTIC REPORT boundary, which was previously left unprotected
-- a real gap an external audit caught that this project's own
Stage 15 pass missed entirely.
"""

from __future__ import annotations

import re

# C0 controls (0x00-0x1F) and DEL (0x7F), plus the C1 control range
# (0x80-0x9F) -- C1 controls are less commonly discussed but are still
# interpreted by some terminals as part of 8-bit escape sequences, and
# are rejected here for the same reason C0/DEL are.
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_for_terminal(value: str) -> str:
    """Strip every control character (including ANSI escape bytes) from
    a value before it is printed to a terminal. Newlines are replaced
    with a visible marker rather than silently dropped, so a
    multi-line injection attempt is still visible as one line, not
    hidden.
    """
    single_line = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")
    return _CONTROL_CHAR_PATTERN.sub("", single_line)


def sanitize_for_markdown_cell(value: str) -> str:
    """Escape a value for safe inclusion inside a single Markdown table
    cell -- or, deliberately, anywhere else in a rendered Markdown
    report: control characters are stripped, real newlines become a
    visible <br> marker (a raw newline could otherwise break a table
    row, or start a new line that renders as a heading if it happens
    to begin with '#'), and a literal pipe is escaped so it cannot be
    mistaken for a column boundary.
    """
    single_line = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")
    stripped = _CONTROL_CHAR_PATTERN.sub("", single_line)
    return stripped.replace("|", "\\|")