"""Regression tests running the real CLI against checked-in fixture
files under tests/fixtures/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from triageai.cli import main

_FIXTURES = Path(__file__).parent / "fixtures"


def test_benign_case_produces_informational_report(capsys: pytest.CaptureFixture[str]) -> None:
    path = _FIXTURES / "benign" / "normal_login.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "INFORMATIONAL" in captured.out
    assert "Rule matches: none" in captured.out


def test_auth001_fixture_triggers_auth001(capsys: pytest.CaptureFixture[str]) -> None:
    path = _FIXTURES / "suspicious" / "SC-AUTH001-bruteforce.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AUTH-001" in captured.out
    assert "MEDIUM" in captured.out
    assert "REJECTED" not in captured.out


def test_auth001_bruteforce_fixture_reports_exactly_one_match(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The fixture has the same user AND the same source IP on all five
    # events, so both AUTH-001 dimensions find the same event set.
    # Stage 17a deduplicates that to a single match.
    path = _FIXTURES / "suspicious" / "SC-AUTH001-bruteforce.json"
    main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert captured.out.count("  - AUTH-001") == 1


def test_auth001_password_spray_fixture_is_detected_by_source_ip(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _FIXTURES / "suspicious" / "SC-AUTH001-password-spray.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AUTH-001" in captured.out
    assert "ip:198.51.100.7" in captured.out
    assert "REJECTED" not in captured.out


def test_ps001_fixture_triggers_ps001(capsys: pytest.CaptureFixture[str]) -> None:
    path = _FIXTURES / "suspicious" / "SC-PS001-encoded-powershell.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "PS-001" in captured.out
    assert "decoded successfully" in captured.out
    assert "REJECTED" not in captured.out


def test_persist001_fixture_triggers_persist001(capsys: pytest.CaptureFixture[str]) -> None:
    path = _FIXTURES / "suspicious" / "SC-PERSIST001-scheduled-task.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "PERSIST-001" in captured.out
    assert "REJECTED" not in captured.out


def test_contradictory_fixture_triggers_both_rules(capsys: pytest.CaptureFixture[str]) -> None:
    path = _FIXTURES / "contradictory" / "mixed-signals.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AUTH-001" in captured.out
    assert "PERSIST-001" in captured.out
    assert "REJECTED" not in captured.out


def test_malformed_fixture_is_rejected_with_exit_2() -> None:
    path = _FIXTURES / "malformed" / "duplicate_keys.json"
    assert main(["analyze", str(path)]) == 2


def test_prompt_injection_fixture_remains_inert_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _FIXTURES / "prompt_injection" / "injected_instruction.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "=== Case" in captured.out
    assert "ignore all previous instructions" in captured.out  # present as data
    assert "INFORMATIONAL" in captured.out  # severity unaffected by the injected text