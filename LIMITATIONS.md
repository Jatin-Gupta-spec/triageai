# Known Limitations

Honest, current gaps — recorded rather than hidden. This project went
through an external security audit (15 findings); 13 are fixed and
covered by the test suite, one was about a local packaging habit
outside this repository, and this document is the last one. What's
below is the current, complete list of what remains open by design or
by scope, not a leftover from before that audit.

## 1. Input format does not yet match a real Wazuh export's actual JSON shape

`normalize_event()` reads fields directly off the top level of each
JSON record — a flattened schema that borrows Wazuh's field concepts,
not Wazuh's actual nested structure (real Wazuh alerts nest data under
`data.win.eventdata`, `rule.id`, `agent.name`, and so on). Building a
mapping layer from real Wazuh/Sysmon export structure is scoped future
work, not attempted in v0.1.

## 2. AUTH-001 identity comparison does not unify all real-world notations

`Alice`, `ALICE`, and `alice` are treated as the same account, and the
same hostname in different case is unified. `DOMAIN\alice`,
`alice@domain`, and plain `alice` are NOT unified — they are three
different identities to this rule. Textually different but equivalent
IPv6 address forms (for example a compressed and an expanded form of
the same address) are also not unified; only hex-digit case is folded.

## 3. AI hallucination checks have a documented, narrow scope

- An event ID is only recognized when the word "event" (or "event
  ID") appears immediately before the number, so a bare number
  elsewhere in AI prose is never checked either way.
- A candidate hostname must be hyphenated; a fully qualified domain
  name (`server.corp.local`) or a hostname with no hyphen is not
  checked, because that pattern also matches ordinary file names.
- Claims about a specific user, process name, or timestamp are not
  mechanically checked at all — only hostnames, IP addresses, MITRE
  technique IDs, and event IDs are.
- A deliberately obfuscated or lookalike entity (for example a
  homoglyph) is not detected.

## 4. Redaction has documented gaps, even after hardening

- Positional secrets, where the value follows a flag without a `=`,
  `:`, or a keyword immediately before it (for example `net use ...
  /user:bob Hunter2`, where `Hunter2` is a separate token with no
  keyword attached to it), are not recognized.
- A user-profile folder whose name itself contains a space is only
  partly redacted.
- Plain (non-email-shaped) identities — a bare hostname like
  `WIN-CLIENT01`, or a plain username with no `@domain` — are not
  aliased anywhere in this project. Only email-like values are.
- Markdown or HTML syntax other than a literal pipe and a line break
  (links, emphasis, backticks, raw HTML tags) is not escaped in a
  rendered report.

## 5. Symlink and junction handling has a narrow, stated scope

Only the input path itself, and files/directories found while scanning
a directory, are checked. A symlink or junction earlier in the path
(a parent folder) is not checked, and the check happens immediately
before the read, so a link swapped in between is not caught. OneDrive
placeholder files are deliberately NOT treated as links — they are a
different kind of Windows reparse point, and rejecting them would
break normal use of a synced folder.

## 6. PERSIST-001 does not recognize `Register-ScheduledTask`

Only `schtasks.exe`/`schtasks` command-line invocations and event ID
`4698` are recognized. The PowerShell cmdlet alternative for creating
scheduled tasks is not covered unless the source SIEM also emits a
`4698` for it regardless of which tool created the task.

## 7. Marker-forgery neutralization is exact-substring, not visual-similarity

The prompt builder's boundary-marker defense catches an exact,
case-sensitive copy of the marker text appearing in untrusted
evidence. A Unicode homoglyph or lookalike sequence crafted to
visually resemble but not exactly match the marker would not be
caught.

## 8. Correlation's grouping algorithm is this project's own documented choice

The locked spec requires correlation "by host, user, source IP, and a
documented time window" but does not define the grouping algorithm
itself. This project's choice: an event with a host is grouped by host
alone; a hostless event is grouped only by the exact pair of user and
source IP, and only if both are present; a single shared identifier
alone never joins two events; and links do not chain transitively (if
A matches B and B matches C, A and C are not merged unless they match
each other directly). This is a documented, defensible design, not the
only one that would satisfy the spec's wording.

## 9. The CLI cannot itself demonstrate an AI draft being rejected

The mock provider is always constructed with its default, well-behaved
mode in `cli.py`'s real wiring, so a genuinely rejected draft never
occurs through `analyze` in normal use, and the actual layout of the
prompt sent to a provider is never printed anywhere the CLI shows.
This is deliberate: Section 4 of the locked spec fixes the CLI's
entire surface at `analyze <path> [--format text|markdown]`, and
adding a debug/reveal flag would itself violate that lock. The
sanctioned way to demonstrate rejection and the real prompt boundary
is the test suite, run live — `tests/test_ai_pipeline.py`,
`tests/test_provider_mock.py`, and `tests/test_prompt_builder.py`.

## 10. Provider output has no size cap yet, and the prompt doesn't declare its own schema

Both belong with v0.2, when a real local or cloud provider exists to
make either one meaningful. The mock's own output is bounded by
construction, so neither has mattered yet.

## 11. The mock provider depends on the prompt's exact layout

`providers/mock.py` parses the fixed structure `prompt_builder.py`
produces (shared constants, one definition, tested together). A real
provider (v0.2+) will not need to parse anything; this coupling is
specific to the mock's design as a stand-in.

## 12. Symlink coverage on the developer's own machine

Creating a real symlink in a test generally needs Developer Mode or
administrator rights on Windows, so six of the symlink tests skip on
a typical Windows development machine and run for real on this
project's CI, which uses Ubuntu. The three Windows-junction tests do
run locally on Windows and do not need special privileges.