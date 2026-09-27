# Known Limitations

Honest, current gaps — not hidden, not silently worked around. Recorded
here as part of the Stage 15 acceptance audit rather than glossed over.

## 1. Input format does not yet match a real Wazuh export's actual JSON shape

The project statement says TriageAI reads "sanitized Wazuh, Sysmon, and
Windows alert exports." In its current form, `normalize_event()` reads
fields directly off the top level of each JSON record (`host`, `user`,
`event_id`, etc.) — a **flattened schema that borrows Wazuh's field
concepts, not Wazuh's actual nested JSON structure** (real Wazuh alerts
nest data under `data.win.eventdata`, `rule.id`, `agent.name`, and so
on). TriageAI today does not parse a genuine, unmodified
`alerts.json` export. Building a mapping layer from real Wazuh/Sysmon
export structure into this flattened schema is real, scoped future
work — not attempted in v0.1, and not silently assumed solved.

## 2. The CLI cannot itself demonstrate an AI draft being rejected, or show a constructed prompt

`MockProvider` is always constructed with `failure_mode="none"` in
`cli.py`'s real wiring, so a genuinely rejected draft can never occur
through `analyze` in normal use. `build_prompt()`'s output is computed
(to exercise the full pipeline) but never rendered anywhere. This is
deliberate, not an oversight: Section 4 of the locked spec fixes the
CLI's entire surface at `analyze <path> [--format text|markdown]` —
adding a debug/reveal flag would itself violate that lock. The
sanctioned way to demonstrate both behaviors is the test suite itself
(`tests/test_provider_mock.py`'s failure modes, `tests/
test_hallucination_check.py`, `tests/test_prompt_builder.py`), run
live.

## 3. Symlink-skip logic has no test on this project's own development machine

`readers/wazuh_json.py` skips symlinked files/directories during
traversal, but creating a real symlink in a test generally requires
Developer Mode or admin rights on Windows, making a real symlink test
unreliably runnable in this project's local dev environment. The
logic is exercised indirectly (`os.walk(..., followlinks=False)` is a
long-standing stdlib guarantee), but there is no fixture proving it on
this machine. CI runs on Ubuntu, where this is trivial to add.

## 4. Redaction does not cover plain (non-email-shaped) identities

A bare hostname like `WIN-CLIENT01` or a plain username like `alice`
(no `@domain`) is never redacted anywhere in this project — only
email-like values get aliased or tokenized. This is a stated, current
scope decision (see `redaction.py`'s module docstring), not an
oversight: the locked spec only pins down concrete behavior for
email-like values.

## 5. PERSIST-001 does not recognize `Register-ScheduledTask`

Only `schtasks.exe`/`schtasks` command-line invocations and event ID
4698 are recognized. The PowerShell cmdlet alternative for creating
scheduled tasks is not covered unless the source SIEM happens to also
emit a 4698 for it regardless of which tool created the task.

## 6. Marker-forgery neutralization is exact-substring, not visual-similarity

`prompt_builder.py`'s boundary-marker defense catches an exact,
case-sensitive copy of the marker text appearing in untrusted
evidence. A Unicode homoglyph or lookalike sequence crafted to visually
resemble but not exactly match the marker would not be caught. Closing
this fully is a genuinely harder problem, left open rather than
falsely claimed solved.

## 7. Correlation's 24-hour case-boundary gap is this project's own heuristic

The locked spec requires correlation "by host, user, source IP, and a
documented time window" but does not itself define the grouping
algorithm. `correlation.py` documents its own choice (host as primary
key, 24-hour gap splits a host's activity into separate cases, undated
events attach to a host's first case) — a defensible, but not
spec-mandated, design.