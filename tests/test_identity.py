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


# --- Stage 18: IP-aware normalization ---


def test_compressed_and_expanded_ipv6_are_equal() -> None:
    assert normalize_identity("2001:db8::1") == normalize_identity(
        "2001:0db8:0000:0000:0000:0000:0000:0001"
    )


def test_ipv6_hex_case_is_unified_via_canonicalization() -> None:
    assert normalize_identity("2001:DB8::1") == normalize_identity("2001:db8::1")


def test_ipv4_dotted_quad_round_trips_unchanged() -> None:
    assert normalize_identity("192.168.1.1") == "192.168.1.1"


def test_ipv6_zone_id_is_preserved() -> None:
    assert normalize_identity("fe80::1%eth0") == "fe80::1%eth0"


def test_out_of_range_octet_falls_back_to_ordinary_text_comparison() -> None:
    # Not a valid IP -- ipaddress rejects it, so it's compared as text,
    # not silently dropped or treated as equal to something else.
    assert normalize_identity("192.168.1.999") == "192.168.1.999"


def test_ordinary_hostname_is_unaffected_by_ip_handling() -> None:
    assert normalize_identity("WIN-CLIENT01") == "win-client01"