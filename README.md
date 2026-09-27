# TriageAI

Offline-first, human-in-the-loop SOC triage assistant.

**Status:** v0.1 complete — 15 stages built, tested, and acceptance-audited.

## What this is

TriageAI reads JSON security event records using a flattened,
Wazuh/Sysmon-inspired field schema (see [LIMITATIONS.md](LIMITATIONS.md)
for the current gap versus a real, nested Wazuh export), validates and
normalizes them with deterministic Python, builds evidence-based
timelines, correlates related events into cases, scores them against
three deterministic rules, and optionally uses a mock AI model to draft
plain-English explanations — which are then validated against the
case's own evidence before being shown to anyone.

**Core principle:** Python establishes facts. AI explains supplied facts.
A human analyst decides.

TriageAI never confirms an incident, executes event content, connects
to live endpoints or SIEMs, performs containment, or uploads raw logs.
Every AI-generated draft is explicitly marked as unverified and requires
human review — and is rejected outright, with the deterministic report
unaffected, if it fails schema validation or claims something the
evidence doesn't support.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m triageai analyze tests/fixtures/suspicious/SC-AUTH001-bruteforce.json
```

## Sample cases

Real, checked-in fixture files you can open and run directly — no
synthetic in-memory test data:

| Case | Path | What it demonstrates |
|---|---|---|
| Benign | `tests/fixtures/benign/normal_login.json` | A single successful login; INFORMATIONAL severity, no rule matches |
| Suspicious (AUTH-001) | `tests/fixtures/suspicious/SC-AUTH001-bruteforce.json` | 5 failed logons in 8 minutes, same host/user |
| Suspicious (PS-001) | `tests/fixtures/suspicious/SC-PS001-encoded-powershell.json` | Encoded PowerShell command, decoded preview shown |
| Suspicious (PERSIST-001) | `tests/fixtures/suspicious/SC-PERSIST001-scheduled-task.json` | Scheduled task creation — fires even though it's a routine update task, per design |
| Contradictory | `tests/fixtures/contradictory/mixed-signals.json` | A legitimate-looking admin task and a genuine brute-force burst on the same host |
| Malformed | `tests/fixtures/malformed/duplicate_keys.json` | Duplicate JSON object key — rejected, exit code 2 |
| Prompt injection | `tests/fixtures/prompt_injection/injected_instruction.json` | Injected instruction text stays inert evidence, never alters report structure |

## Expected output (abridged)

=== Case fb6b52993c1cdaa5 ===
Severity: MEDIUM | Confidence: MEDIUM
Hosts: WIN-CLIENT02
Users: ?
Rule matches:

AUTH-001 (T1110): 5 authentication failures for ip:203.0.113.50 on host WIN-CLIENT02 within 10 minutes
AI draft:
Summary: 1 deterministic rule match(es) found (AUTH-001) for host(s) WIN-CLIENT02. This is a mechanical pattern match, not a confirmed incident.
...
[AI-generated draft requiring human review]
Timeline:
[2026-01-20T14:00:00+00:00] host=WIN-CLIENT02 user=? event_id=4625 process=? command_line=?
...


## Rule catalogue

See [RULES.md](RULES.md) for every rule's required fields, time window,
detection logic, fixtures, evidence gaps, false positives, and
recommended investigation steps.

## Known limitations

See [LIMITATIONS.md](LIMITATIONS.md) — recorded honestly, not hidden.

## Safety and privacy

See [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md).

## Development

```powershell
python -m pytest -q
python -m mypy src
python -m ruff check .
python -m pip_audit
```

CI runs all four on every push (`.github/workflows/ci.yml`).

## License

MIT — see [LICENSE](LICENSE).