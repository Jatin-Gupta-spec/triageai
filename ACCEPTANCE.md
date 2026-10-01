# TriageAI v0.1 — Acceptance Record

**Scope version:** v0.1
**Date:** <fill in>
**Git commit:** <output of `git rev-parse HEAD`>

## Supported platforms
- OS: Ubuntu, Windows (CI-verified — see `.github/workflows/ci.yml`)
- Python: 3.11, 3.13

## Verification commands and results

Run from a fresh virtual environment (see the release-verification
checklist), then paste the real output below each command.

```powershell
python -m pytest -q
```
<paste result>

```powershell
python -m ruff check .
```
<paste result>

```powershell
python -m mypy src
```
<paste result>

```powershell
python -m pip_audit
```
<paste result>

## Security controls tested

- Recursive, key-aware secret redaction (`redaction.py`, `tests/test_redaction_hardening.py`)
- Render-boundary identity aliasing, including observed facts and evidence gaps (`tests/test_redaction.py`)
- Deduplication by `original_record_id` (`tests/test_cli.py`)
- Non-finite JSON constant rejection (`tests/test_reader.py`)
- Unicode key-collision rejection, on every record including one with a supplied ID (`tests/test_normalization_collisions.py`)
- Markdown/terminal structural and HTML injection resistance (`tests/test_render_safety.py`, `tests/test_reporters.py`)
- Symlink/junction rejection at the input path, its parents, and during directory scans (`tests/test_input_links.py`)
- PERSIST-001 and PS-001 exact-executable-token matching (`tests/test_rule_persist001.py`, `tests/test_rule_ps001.py`)
- AUTH-001 independent user/IP dimensions and case-insensitive identity comparison (`tests/test_rule_auth001.py`)
- Prompt-injection boundary and forgery neutralization (`tests/test_prompt_builder.py`)
- Strict AI output schema, fixed application-owned warning text, provider-output size limits (`tests/test_output_validation.py`)
- Hallucination rejection against this case's own evidence (`tests/test_hallucination_check.py`)

## Known limitations

See LIMITATIONS.md.

## Deferred requirements

See LIMITATIONS.md items 1, 2 (full structured-entity validation, marked
as a v0.2 acceptance requirement), and 8.

## Release decision

<fill in: accepted for portfolio release / not yet>