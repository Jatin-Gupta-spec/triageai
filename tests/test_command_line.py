"""Tests for src/triageai/command_line.py."""

from __future__ import annotations

from triageai.command_line import basename, executable_basename


def test_basename_plain_name() -> None:
    assert basename("schtasks.exe") == "schtasks.exe"


def test_basename_full_windows_path() -> None:
    assert basename(r"C:\Windows\System32\schtasks.exe") == "schtasks.exe"


def test_basename_full_posix_style_path() -> None:
    assert basename("/usr/bin/schtasks") == "schtasks"


def test_basename_is_case_insensitive() -> None:
    assert basename("SCHTASKS.EXE") == "schtasks.exe"


def test_basename_strips_surrounding_double_quotes() -> None:
    assert basename('"schtasks.exe"') == "schtasks.exe"


def test_basename_strips_surrounding_single_quotes() -> None:
    assert basename("'schtasks.exe'") == "schtasks.exe"


def test_basename_does_not_strip_mismatched_quotes() -> None:
    assert basename("\"schtasks.exe'") == '"schtasks.exe\''


def test_executable_basename_reads_the_first_token() -> None:
    assert executable_basename("schtasks.exe /create /tn Foo") == "schtasks.exe"


def test_executable_basename_ignores_later_tokens() -> None:
    assert executable_basename("echo schtasks /create") == "echo"


def test_executable_basename_returns_none_for_empty_line() -> None:
    assert executable_basename("") is None
    assert executable_basename("   ") is None