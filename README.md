# TriageAI

Offline-first, human-in-the-loop SOC triage assistant.

**Status:** Under active development (v0.1, not yet functional). This project
supersedes an earlier prototype, [SOC-IQ](https://github.com/Jatin-Gupta-spec/SOC-IQ),
with a stricter, fully offline, deterministic-first architecture.

## What this is

TriageAI reads sanitized Wazuh, Sysmon, and Windows alert exports, validates and
normalizes them with deterministic Python, builds evidence-based timelines,
correlates related events, and optionally uses an AI model to draft explanations,
investigation questions, and evidence gaps.

**Core principle:** Python establishes facts. AI explains supplied facts. A human
analyst decides.

TriageAI never confirms an incident, executes event content, connects to live
endpoints or SIEMs, performs containment, or uploads raw logs. Every AI-generated
draft is explicitly marked as unverified and requires human review.

## Progress

Built stage by stage, in public — see commit history. Nothing is functional yet;
this README will grow as each stage lands.

## Safety

See [SECURITY.md](SECURITY.md) for the full safety model, and
[PRIVACY.md](PRIVACY.md) for data-handling policy.

## License

MIT — see [LICENSE](LICENSE).