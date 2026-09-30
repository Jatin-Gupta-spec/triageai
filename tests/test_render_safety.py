"""Tests for src/triageai/render_safety.py."""

from __future__ import annotations

from triageai.render_safety import sanitize_for_markdown_cell, sanitize_for_terminal


def test_plain_text_is_unchanged() -> None:
    assert sanitize_for_terminal("WIN-CLIENT01 net user") == "WIN-CLIENT01 net user"
    assert sanitize_for_markdown_cell("WIN-CLIENT01 net user") == "WIN-CLIENT01 net user"


def test_terminal_encodes_ansi_escape_visibly() -> None:
    result = sanitize_for_terminal("\x1b[31mFAKE ALERT\x1b[0m")
    assert "\x1b" not in result
    assert "\\x1b" in result
    assert "FAKE ALERT" in result


def test_terminal_encodes_c0_control_chars() -> None:
    result = sanitize_for_terminal("before\x07\x00after")
    assert "\x07" not in result
    assert "\x00" not in result
    assert "\\x07" in result


def test_terminal_encodes_c1_control_chars() -> None:
    result = sanitize_for_terminal("before\x9bmalicious\x85after")
    assert "\x9b" not in result
    assert "\x85" not in result


def test_terminal_replaces_newline_with_visible_marker() -> None:
    result = sanitize_for_terminal("line one\nFAKE SECOND LINE")
    assert "\n" not in result
    assert "\\n" in result
    assert "FAKE SECOND LINE" in result


def test_terminal_normalizes_crlf() -> None:
    result = sanitize_for_terminal("line one\r\nFAKE SECOND LINE")
    assert "\r" not in result
    assert "\n" not in result


def test_terminal_treats_unicode_line_separators_as_line_breaks() -> None:
    result = sanitize_for_terminal("one\u2028two\u2029three")
    assert "\u2028" not in result
    assert "\u2029" not in result
    assert result == "one\\ntwo\\nthree"


def test_terminal_encodes_bidi_override_visibly() -> None:
    result = sanitize_for_terminal("admin\u202enimda")
    assert "\u202e" not in result
    assert "\\u202e" in result


def test_terminal_encodes_zero_width_and_bom_characters() -> None:
    result = sanitize_for_terminal("a\u200bb\ufeffc")
    assert "\u200b" not in result
    assert "\ufeff" not in result
    assert "\\u200b" in result
    assert "\\ufeff" in result


def test_terminal_does_not_html_escape() -> None:
    # Terminal output is plain text, not markup -- & < > must survive
    # untouched, unlike the markdown path.
    assert sanitize_for_terminal("Tom & Jerry <b>bold</b>") == "Tom & Jerry <b>bold</b>"


def test_markdown_escapes_pipe() -> None:
    result = sanitize_for_markdown_cell("value | fake_column | injected")
    assert result == "value \\| fake_column \\| injected"


def test_markdown_replaces_newline_with_br() -> None:
    result = sanitize_for_markdown_cell("row one\n# FAKE HEADING")
    assert "\n" not in result
    assert "<br>" in result
    assert "FAKE HEADING" in result


def test_markdown_treats_unicode_line_separators_as_line_breaks() -> None:
    assert sanitize_for_markdown_cell("a\u2028b") == "a<br>b"


def test_markdown_encodes_control_chars_visibly() -> None:
    result = sanitize_for_markdown_cell("value\x1b[2Jmore")
    assert "\x1b" not in result
    assert "\\x1b" in result


def test_markdown_encodes_bidi_override_visibly() -> None:
    result = sanitize_for_markdown_cell("admin\u202enimda")
    assert "\u202e" not in result
    assert "\\u202e" in result


# --- Stage 18: HTML escaping ---


def test_markdown_escapes_ampersand() -> None:
    assert sanitize_for_markdown_cell("Tom & Jerry") == "Tom &amp; Jerry"


def test_markdown_escapes_script_tag() -> None:
    result = sanitize_for_markdown_cell("<script>alert(1)</script>")
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


def test_markdown_escapes_img_onerror() -> None:
    result = sanitize_for_markdown_cell("<img src=x onerror=alert(1)>")
    assert "<img" not in result
    assert "&lt;img" in result


def test_markdown_escapes_html_comment() -> None:
    result = sanitize_for_markdown_cell("<!-- comment -->")
    assert "<!--" not in result
    assert "&lt;!--" in result


def test_markdown_own_br_insertion_stays_raw_and_unescaped() -> None:
    # The <br> WE insert for a line break must remain literal HTML,
    # not get caught by the escaping step -- escaping happens before
    # the <br> is inserted, never after.
    result = sanitize_for_markdown_cell("line1\nline2")
    assert "<br>" in result
    assert "&lt;br&gt;" not in result


def test_markdown_escapes_ampersand_that_would_otherwise_form_an_entity() -> None:
    # Confirms escaping doesn't double-escape: a literal "&amp;" typed
    # by an attacker becomes "&amp;amp;", not silently collapsed back
    # into a real entity.
    assert sanitize_for_markdown_cell("&amp;") == "&amp;amp;"