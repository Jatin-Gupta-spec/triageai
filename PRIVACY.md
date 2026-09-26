# Privacy Policy

## What data this project processes

TriageAI is designed to process **sanitized or synthetic** SOC lab data only —
never real production logs, real credentials, or real personal data.

## What is redacted, and when

Internally, TriageAI preserves real identity fields (host, user/UPN, source and
destination IP) so correlation and detection logic work on real relationships
between events.

Redaction happens only at the **render boundary** — when building a report or an
AI prompt:

- Free-text fields (command lines, messages) have email-like substrings replaced
  with `[REDACTED_EMAIL]`; known secret patterns (passwords, tokens, cookies,
  authorization headers, private keys) are removed.
- Structured identity fields shown in a report get distinct, deterministic
  aliases (e.g. `[REDACTED_EMAIL_001]`, `[REDACTED_EMAIL_002]`), so two accounts
  stay distinguishable without revealing who they are.

## What is sent to an AI provider

- **v0.1 uses a mock AI provider only. No data leaves your machine, ever, in
  this version.**
- Any future local or cloud provider (v0.2+) receives only the same redacted
  evidence package used for reports — never raw input, credentials, or
  unredacted identity fields.
- A cloud provider (v0.4+, not yet built) requires explicit opt-in
  (`--allow-cloud-ai`), a payload preview, and confirmation before anything is
  transmitted.

## Retention

v0.1 writes no files to disk and persists no state between runs. Everything is
read once, processed in memory, and printed to standard output.