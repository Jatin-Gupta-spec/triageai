# Security Policy

## Scope and threat model

TriageAI processes **sanitized, lab-generated, or otherwise authorized** security
alert exports only. It must never be pointed at production logs, live credentials,
or systems containing real personal data.

Every input record is treated as **untrusted data**, including free-text fields
such as command lines, usernames, and process paths. Text that resembles an
instruction (e.g. "ignore previous instructions") is evidence, never a command.

## What TriageAI will never do

- Execute, evaluate, decode-and-run, download, or open any content from an event.
- Connect to live endpoints, SIEMs, EDRs, production systems, or remote targets.
- Disable user accounts, terminate processes, isolate hosts, or modify firewall rules.
- Upload raw logs, credentials, tokens, cookies, or private keys anywhere.
- Treat AI output as a confirmed incident, or silently promote an AI claim into
  observed evidence.
- Follow instructions embedded inside any log field.

## Data handling

- All processing in v0.1 is fully offline. No network calls are made.
- Redaction is applied only at the point a report or AI prompt is built — see
  PRIVACY.md.
- Decoded content (e.g. base64) is treated strictly as inert data: capped in
  size, never executed, never recursively decoded.

## Reporting a concern

This is a personal learning project, not a maintained security product. If you
find a way sanitized test data could leak, or a way redaction/validation could
be bypassed, please open an issue describing the input that triggers it.