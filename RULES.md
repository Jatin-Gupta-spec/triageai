# TriageAI Rule Catalogue

Every rule follows the locked spec's required fields (Section 7): rule
ID, required fields, time window, severity, confidence, MITRE
mapping, positive/negative fixtures, evidence gaps, false positives,
and recommended investigation steps.

All three rules ship at a fixed **Medium / Medium** severity/confidence
per rule match — a locked v0.1 default (Section 7), not this
catalogue's own choice. Case-level severity/confidence across every
matched rule in a case is a separate, documented formula in
`src/triageai/correlation.py`.

---

## AUTH-001 — Repeated Authentication Failures

- **MITRE:** T1110 (Brute Force)
- **Required fields:** `host`; `event_id` of `4625` (failed logon) or
  `4771` (Kerberos pre-auth failure); a valid, timezone-aware
  `timestamp`; and at least one of `user` or `source_ip`
- **Time window:** 10 minutes, sliding
- **Threshold:** 5+ matching failures in that window

**Two independent dimensions.** A single `user OR source IP` check
would miss password spraying (one address trying many accounts, each
under the per-user threshold). AUTH-001 evaluates both:
- `host + user`
- `host + source IP`

An event with both fields feeds both dimensions. If a user-dimension
match and an IP-dimension match cover the exact same set of events,
only the user-dimension match is kept, since they are the same
finding. If the event sets differ, both are kept as separate findings
— for example, one account under sustained attack, plus a wider spray
from the same address.

**Identity comparison is case-insensitive and Unicode-normalized**
(`src/triageai/identity.py`): `Alice`, `ALICE`, and `alice` group
together, because Windows account and host names are case-insensitive.
A blank or whitespace-only value is treated as absent, not as its own
group. Rendered output keeps the spelling from the earliest event in
the matched window.

**Design decision — does not reset on a successful login (event_id
4624):** resetting would let an attacker interleave one success to
clear the counter, and the analyst reviewing the full case timeline
already sees any success sitting right after a failure burst.

- **Positive fixture (per-user):** `tests/fixtures/suspicious/SC-AUTH001-bruteforce.json`
- **Positive fixture (password spray):** `tests/fixtures/suspicious/SC-AUTH001-password-spray.json`
- **Negative/boundary/missing-field fixtures:** unit-level in `tests/test_rule_auth001.py` — different users, different hosts, non-failure event IDs, exact 10-minute boundary, missing host, missing both user and source IP, case folding, IPv6 hex folding, blank values
- **Evidence gaps:** does not confirm the account owner attempted the logins; does not distinguish user error from a real attack; identity comparison does not know about `DOMAIN\user` or `user@domain` forms, so the same account under a different notation is not unified
- **False positives, user dimension:** a misconfigured service retrying a stale credential
- **False positives, IP dimension:** a shared gateway, VPN, or NAT address presenting many real users, or a service retrying against several accounts from one address
- **Recommended investigation steps:** for a user-dimension match, confirm with the account owner whether they attempted these logins, and check for a subsequent success as its own signal, not proof the burst was benign; for an IP-dimension match, check whether the address is a known shared egress point before escalating

---

## PS-001 — Encoded PowerShell Command Indicators

- **MITRE:** T1059.001 (Command and Scripting Interpreter: PowerShell)
- **Required fields:** `process` naming `powershell.exe`/`pwsh.exe`, OR
  `command_line` mentioning either; `command_line` containing an
  accepted `-EncodedCommand` abbreviation (`-enc` through
  `-encodedcommand`; bare `-e`/`-en` deliberately excluded)
- **Time window:** none (single-event rule)
- **Detects:** the flag's presence, not payload maliciousness

**Decode bounds are enforced before decoding, not after.** A payload
whose base64 text is longer than roughly 87,000 characters cannot
possibly decode to 64 KiB or less, so it is refused without ever
calling the decoder. A shorter payload is decoded once, and if the
result still exceeds the 64 KiB limit, it is refused just the same —
no decoded text is retained either way, only a fixed "decode refused"
note in the match description. This replaces an earlier version that
decoded the full payload before checking its size.

Bytes are interpreted as strict UTF-16LE, matching how PowerShell
itself encodes `-EncodedCommand` payloads. On a UTF-16LE failure, only
a 16-byte hexadecimal preview and the byte count are kept — never the
full raw bytes, and never Python's own exception text. On success, a
bounded preview (up to 300 characters) of the decoded text is included
in the match description, which is redacted the same way as any other
rule-match text.

- **Positive fixture:** `tests/fixtures/suspicious/SC-PS001-encoded-powershell.json`
- **Negative/boundary fixtures:** unit-level in `tests/test_rule_ps001.py` — no encoded flag, non-PowerShell process, oversized payload refused without calling the decoder, invalid base64, valid base64 that fails UTF-16LE decoding
- **Evidence gaps:** does not evaluate whether decoded content is actually harmful; only the `-EncodedCommand` family of flags is recognized, not other ways a script could be smuggled onto a command line
- **False positives:** legitimate deployment and remote-administration tooling frequently uses encoded commands specifically to survive multiple layers of shell quoting
- **Recommended investigation steps:** read the decoded preview in the match description; if it says "decode refused" or the preview looks truncated, retrieve the full original event from the source SIEM; correlate with the parent process to establish whether this was operator- or tool-initiated

---

## PERSIST-001 — Scheduled Task Creation

- **MITRE:** T1053.005 (Scheduled Task/Job: Scheduled Task)
- **Required fields:** `event_id` `4698`, OR `command_line` invoking
  `schtasks`/`schtasks.exe` with an exact `/create` token
- **Time window:** none (single-event rule)
- **Detects:** the creation action itself — **required to still fire
  on plainly legitimate administration** (per spec Section 7); this
  rule makes no judgment about intent

**Design note:** `event_id` `4698` is checked before the command-line
heuristic, deliberately. This project's own `soc-lab` work documented
that `schtasks.exe` process-creation events are not logged by that
lab's current Sysmon configuration. A rule relying only on
command-line matching would silently inherit that same blind spot.

- **Positive/required-negative fixture:** `tests/fixtures/suspicious/SC-PERSIST001-scheduled-task.json` — a routine update-check task, proving the rule fires on plainly benign activity, per spec
- **Evidence gaps:** `Register-ScheduledTask` (the PowerShell cmdlet alternative to `schtasks.exe`) is not recognized by the command-line heuristic — only caught if the source SIEM also emits a `4698` for it
- **False positives:** routine software update or maintenance task creation — this is the *expected*, required-to-match case, not an error
- **Recommended investigation steps:** check the task's target executable and trigger schedule against known-good administrative baselines; confirm who created the task and whether it was scripted/automated administration