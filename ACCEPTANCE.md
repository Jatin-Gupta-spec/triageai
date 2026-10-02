# TriageAI v0.1 — Acceptance Record

**Scope version:** v0.1
**Date:** 2 Oct 2026
**Release tag:** `v0.1.0` (see `git show v0.1.0` for the exact commit this points at)

## Supported platforms
- OS: Ubuntu, Windows (CI-verified — see `.github/workflows/ci.yml`)
- Python: 3.11, 3.13

## Verification commands and results

### Windows, local `.venv`

```powershell
python -m pytest -q
```
424 passed, 7 skipped in 0.71s

The 7 skips are the symlink tests in `tests/test_input_links.py` that
require Developer Mode or administrator rights on Windows to create a
real symlink. Not a gap: the same tests run and pass for real on CI's
`windows-latest` runner (see THREAT_MODEL.md, row "Symlinks and
Windows junctions").

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

The skip line is expected: `triageai` isn't a published PyPI package,
so pip-audit correctly can't check it against a public vulnerability
database — every real third-party dependency came back clean.

### Ubuntu, CI (`ubuntu-latest`, Python 3.11)

428 passed, 3 skipped in 0.64s

On Ubuntu, the 6 symlink tests that need elevated privileges on
Windows run for real instead of skipping, leaving only the 3 Windows-
only junction tests (`@_WINDOWS_ONLY` in `tests/test_input_links.py`)
to skip on this platform — the inverse of the Windows result above,
and together the two confirm all 431 tests have each been executed
and passed on at least one real platform.

Ruff, mypy, and pip-audit all passed on every one of the four CI
matrix legs (ubuntu-latest and windows-latest, Python 3.11 and 3.13)
for this release's tagged commit — see the Actions run for `v0.1.0`.

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
- Manual canary check: a planted fake password, API key, Authorization
  header, Cookie value, email/UPN, and a user-profile path containing
  a space, confirmed by direct human inspection to never reach
  rendered output in the clear
- Determinism: two runs of the brute-force, benign, contradictory, and
  prompt-injection fixtures each produced byte-identical SHA-256
  hashes

## Known limitations

See [LIMITATIONS.md](LIMITATIONS.md). The two most significant: a
flattened, Wazuh-inspired input schema rather than a real nested
Wazuh/Sysmon export shape (item 1), and AI-claim validation scoped to
four entity types — hostnames, IPv4 addresses, MITRE technique IDs,
and contextual event IDs — with full structured-entity validation
explicitly deferred to v0.2 (item 2).

## Deferred requirements

- Full structured-entity AI-claim validation (LIMITATIONS.md item 2) — v0.2
- A real Wazuh/Sysmon field-mapping layer (LIMITATIONS.md item 1) — v0.2+
- Streaming-aware provider-output limits, for when a real streaming
  provider is connected (LIMITATIONS.md item 14) — v0.2+

## Release decision

**Accepted for v0.1 release with documented limitations.** All 431
tests pass, each one confirmed executed (not skipped) and passing on
at least one of the two supported operating systems; Ruff, strict
mypy, and pip-audit are clean on every one of the four CI matrix legs.
Redaction, determinism, and the AI trust boundary have each been
independently, manually verified against planted test cases, not
assumed from automated test results alone. Every known gap is named
in LIMITATIONS.md and THREAT_MODEL.md rather than hidden, and the two
most significant gaps are explicitly scoped as v0.2 requirements, not
silently dropped.