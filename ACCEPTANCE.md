# TriageAI v0.1 — Acceptance Record

**Scope version:** v0.1
**Date:** <2 OCT 2026>
**Git commit:** <683b99cf87028ce91c08553959c62dcf123845c4>

## Supported platforms
- OS: Ubuntu, Windows (CI-verified — see `.github/workflows/ci.yml`)
- Python: 3.11, 3.13

## Verification commands and results

Run from a fresh virtual environment (`.release-venv`), built from
scratch with no state carried over from the development `.venv`.

```powershell
python -m pytest -q
```

424 passed, 7 skipped in 1.56s

The 7 skips are the symlink tests in `tests/test_input_links.py` that
require Developer Mode or administrator rights on Windows to create a
real symlink — expected, and not a gap: these same tests run and pass
for real on CI's `windows-latest` runner (see THREAT_MODEL.md, row
"Symlinks and Windows junctions").

```powershell
python -m ruff check .
```

All checks passed!


```powershell
python -m mypy src
```

Success: no issues found in 27 source files


```powershell
python -m pip_audit
```

No known vulnerabilities found
Name Skip Reason

triageai Dependency not found on PyPI and could not be audited: triageai (0.1.0)

The skip line is expected: `triageai` itself isn't a published PyPI
package, so pip-audit correctly can't check it against a public
vulnerability database — it checks every real third-party dependency,
which all came back clean.

## Security controls tested

- Recursive, key-aware secret redaction (`redaction.py`, `tests/test_redaction_hardening.py`)
- Render-boundary identity aliasing, including observed facts and evidence gaps (`tests/test_redaction.py`)
- Deduplication by `original_record_id` (`tests/test_cli.py`)
- Non-finite JSON constant rejection (`tests/test_reader.py`)
- Unicode key-collision rejection, on every record including one with a supplied ID (`tests/test_normalization_collisions.py`)
- Markdown/terminal structural and HTML injection resistance (`tests/test_render_safety.py`, `tests/test_reporters.py`)
- Symlink/junction rejection at the input path, its parents, and during directory scans, plus open/verify identity checking (`tests/test_input_links.py`)
- PERSIST-001 and PS-001 exact-executable-token matching (`tests/test_rule_persist001.py`, `tests/test_rule_ps001.py`)
- AUTH-001 independent user/IP dimensions and case-insensitive, IP-aware identity comparison (`tests/test_rule_auth001.py`, `tests/test_identity.py`)
- Prompt-injection boundary and forgery neutralization (`tests/test_prompt_builder.py`)
- Strict AI output schema, fixed application-owned warning text, provider-output size limits (`tests/test_output_validation.py`)
- Hallucination rejection against this case's own evidence (`tests/test_hallucination_check.py`)
- End-to-end AI pipeline rejection paths with safe, fixed rejection reasons (`tests/test_ai_pipeline.py`)

## Known limitations

See [LIMITATIONS.md](LIMITATIONS.md).

## Deferred requirements

See LIMITATIONS.md item 2 (full structured-entity AI-claim validation,
explicitly marked as a v0.2 acceptance requirement) and item 1 (a real
Wazuh/Sysmon field-mapping layer).

## Release decision

<fill in: accepted for portfolio release / not yet, once you've also
completed items 10-14 of the release checklist (determinism check,
manual canary check, repository cleanliness, source archive, and tag)>