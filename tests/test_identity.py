"""Tests for src/triageai/identity.py."""

from __future__ import annotations

from triageai.identity import normalize_identity


def test_none_returns_none() -> None:
    assert normalize_identity(None) is None


def test_blank_values_return_none() -> None:
    assert normalize_identity("") is None
    assert normalize_identity("   ") is None
    assert normalize_identity("\t\n") is None


def test_surrounding_whitespace_is_stripped() -> None:
    assert normalize_identity("  Alice ") == "alice"


def test_case_is_folded() -> None:
    assert normalize_identity("ALICE") == normalize_identity("alice")


def test_unicode_equivalent_forms_match() -> None:
    assert normalize_identity("caf\u00e9") == normalize_identity("cafe\u0301")


def test_casefold_handles_sharp_s() -> None:
    assert normalize_identity("STRASSE") == normalize_identity("Stra\u00dfe")


def test_different_values_stay_different() -> None:
    assert normalize_identity("alice") != normalize_identity("alicia")