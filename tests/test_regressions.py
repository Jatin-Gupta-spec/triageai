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


def test_ps001_fixture_triggers_ps001(capsys: pytest.CaptureFixture[str]) -> None:
    path = _FIXTURES / "suspicious" / "SC-PS001-encoded-powershell.json"
    exit_code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "PS-001" in captured.out
    # This will FAIL until the placeholder PAYLOAD_HERE in the fixture
    # file is replaced with real base64 -- that's deliberate: it forces
    # the fixture to actually demonstrate the decoded-content preview
    # feature, not silently pass with broken input.
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