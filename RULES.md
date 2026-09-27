# TriageAI Rule Catalogue

Every rule below follows the locked spec's required fields (Section 7):
rule ID, required fields, time window, severity, confidence, MITRE
mapping, positive/negative fixtures, evidence gaps, false positives,
and recommended investigation steps.

All three rules currently ship at fixed **Medium / Medium**
severity/confidence — this is a locked v0.1 default (Section 7), not
this catalogue's own choice. Case-level aggregation across multiple
rule matches follows a separate, documented formula in
`src/triageai/correlation.py`.

---

## AUTH-001 — Repeated Authentication Failures

- **MITRE:** T1110 (Brute Force)
- **Required fields:** `host`; either `user` or `source_ip`; `event_id`; a valid, timezone-aware `timestamp`
- **Time window:** 10 minutes, sliding (not a fixed clock-aligned bucket)
- **Threshold:** 5+ matching failures in that window
- **Detects:** `event_id` 4625 (Windows failed logon) or 4771 (Kerberos pre-auth failure), grouped by host + (user OR source_ip)
- **Design decision:** does **not** reset on a subsequent successful login (4624) — see `src/triageai/rules/authentication.py`'s docstring for the full reasoning (an evasion-resistance vs. false-positive tradeoff)
- **Positive fixture:** `tests/fixtures/suspicious/SC-AUTH001-bruteforce.json`
- **Negative fixture:** `tests/fixtures/benign/normal_login.json` (single event, no burst); unit-level negatives in `tests/test_rule_auth001.py` (4 failures, different users, different hosts, non-failure event IDs)
- **Evidence gaps:** does not confirm the account owner attempted the logins; does not distinguish user error from a real attack
- **False positives:** a misconfigured service retrying with a stale credential; a user who forgot a recently changed password
- **Recommended investigation steps:** confirm with the account owner whether they attempted these logins; check for a subsequent successful login and treat it as a separate signal, not evidence the burst was benign; check source IP reputation if available

---

## PS-001 — Encoded PowerShell Command Indicators

- **MITRE:** T1059.001 (Command and Scripting Interpreter: PowerShell)
- **Required fields:** `process` naming `powershell.exe`/`pwsh.exe`, OR `command_line` mentioning either; `command_line` containing an accepted `-EncodedCommand` abbreviation (`-enc` through `-encodedcommand`; bare `-e`/`-en` deliberately excluded — see the rule's docstring)
- **Time window:** none (single-event rule)
- **Detects:** the flag's presence, not payload maliciousness. Decoding (single-pass, UTF-16LE, capped at 64 KiB) is opportunistic enrichment; a bounded preview of the decoded content is now included in the match description (Stage 15 fix — previously only decode success/failure was reported)
- **Positive fixture:** `tests/fixtures/suspicious/SC-PS001-encoded-powershell.json`
- **Negative fixture:** unit-level in `tests/test_rule_ps001.py` (`powershell.exe -File script.ps1`, no encoded flag)
- **Evidence gaps:** does not evaluate whether the decoded content is actually harmful
- **False positives:** legitimate deployment/remote-administration tooling frequently uses encoded commands specifically to survive multiple layers of shell quoting
- **Recommended investigation steps:** read the decoded preview in the rule match description; if truncated or the preview looks incomplete, retrieve the full original event from the source SIEM; correlate with the parent process to establish whether this was operator- or tool-initiated

---

## PERSIST-001 — Scheduled Task Creation

- **MITRE:** T1053.005 (Scheduled Task/Job: Scheduled Task)
- **Required fields:** `event_id` 4698, OR `command_line` invoking `schtasks`/`schtasks.exe` with an exact `/create` token
- **Time window:** none (single-event rule)
- **Detects:** the creation action itself — **required to still fire on plainly legitimate administration** (per spec Section 7); this rule makes no judgment about intent
- **Design note:** `event_id` 4698 is the primary signal, checked before the command-line heuristic — deliberately, because this project's own `soc-lab` work (SC-003/INV-004) documented that `schtasks.exe` process-creation events are *not* logged by that lab's current Sysmon configuration. Relying on command-line matching alone would silently inherit that exact blind spot.
- **Positive/required-negative fixture:** `tests/fixtures/suspicious/SC-PERSIST001-scheduled-task.json` — a routine-update-check task, proving the rule fires on a plainly benign action, per spec
- **Evidence gaps:** `Register-ScheduledTask` (the PowerShell cmdlet alternative) is not recognized by the command-line heuristic — an open gap, not silently covered (see LIMITATIONS.md)
- **False positives:** routine software update or maintenance task creation (this is the *expected*, required-to-match case, not an error)
- **Recommended investigation steps:** check the task's target executable and trigger schedule against known-good administrative baselines; confirm who created the task and whether it was scripted/automated administration