"""Shared helpers for reading the executable token from a command line.

Both PERSIST-001 and PS-001 need to know which EXECUTABLE a command
line actually invokes, not just whether a related word appears
anywhere in the text -- a substring or "anywhere in the line" check
matches an unrelated tool whose name happens to contain the same word
(not-schtasks-tool, schtasks-backup.exe, not-powershell.exe), or text
that only PRINTS the word rather than executing it (echo schtasks
/create, a message that mentions "powershell -enc" without running it).

Tokenization here is intentionally simple: split on whitespace, and
strip one pair of surrounding matching quote characters from a single
token if present. A command line whose executable path itself
contains an internal, unquoted space, or whose quoting uses escaped
characters, is not correctly tokenized by this approach. Full
Windows-aware command-line parsing is a documented, deferred
improvement -- see LIMITATIONS.md.
"""

from __future__ import annotations

_QUOTE_CHARS = "\"'"


def basename(token: str) -> str:
    """Lowercased final path component of a single token.

    A single pair of surrounding matching quote characters is
    stripped first. Both '\\' and '/' are treated as path separators,
    so a bare name and a full path (Windows or POSIX style) resolve
    to the same comparison value.
    """
    stripped = token
    if len(stripped) >= 2 and stripped[0] in _QUOTE_CHARS and stripped[-1] == stripped[0]:
        stripped = stripped[1:-1]
    return stripped.replace("\\", "/").rsplit("/", 1)[-1].lower()


def executable_basename(command_line: str) -> str | None:
    """basename() of the FIRST token in `command_line`, or None if the
    line has no tokens at all.
    """
    tokens = command_line.split()
    if not tokens:
        return None
    result = basename(tokens[0])
    return result or None