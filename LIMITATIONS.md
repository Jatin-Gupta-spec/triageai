# Known Limitations

Honest, current gaps -- recorded rather than hidden. This document is
kept accurate against the actual current code, not appended to
indefinitely; when a fix closes an item, that item is corrected or
removed here in the same change, not left stale.

## 1. Input format does not match a real Wazuh export's actual JSON shape

`normalize_event()` reads a flattened schema that borrows Wazuh's field
names, not a real nested export's structure (`data.win.eventdata.
targetUserName`, `rule.id`, `agent.name`, and so on). Building that
mapping, and defining precedence when the same value exists at more
than one source path, is scoped future work, comparable in size to the
original 15-stage build, not attempted in v0.1.

## 2. AI hallucination-claim validation scope is a deliberate, explicit v0.1 acceptance decision

Validated entity types: hostnames (hyphenated shape, with at least one
digit or fully uppercase), IPv4 addresses, MITRE technique IDs, and
Windows event IDs (only when the word "event" or "event ID" appears
immediately before the number). **Not validated:** specific users,
process names, timestamps, fully qualified domain names, hostnames
without a hyphen, and **IPv6 addresses as AI claims**. That last point
is worth stating precisely, because it is easy to conflate with a
different, already-fixed capability: `identity.py` normalizes IPv6
addresses (including unifying compressed and expanded forms) for
*correlation* grouping -- a completely separate system from
`hallucination_check.py`'s claim validation, whose IP pattern only
matches IPv4's dotted-quad shape. Correlation being IPv6-aware does
not mean AI-claimed IPv6 addresses are checked; they are not.

Full structured-entity AI-claim validation -- every AI observation
declaring its own host/user/process/timestamp/IP/event-ID/MITRE-
technique lists, checked mechanically rather than extracted via regex
from prose -- is an explicit **v0.2 acceptance requirement**, not
attempted here. Building it now would mean inventing a structured-
output contract for a mock provider with no organic need for one; the
locked spec's own "free-text prose remains explicitly unverified and
human-reviewed" already sanctions the narrower v0.1 scope described
above.

## 3. AUTH-001 identity comparison does not unify all real-world account notations

`DOMAIN\alice`, `alice@domain`, and plain `alice` are three different
identities to this rule, not merged. Case-folding and Unicode
normalization ARE applied (see `identity.py`); domain-notation
unification is not.

## 4. Positional secrets are not detected

A secret with no keyword or flag adjacent to it (`net use \\host\share
/user:bob Hunter2`, where `Hunter2` is a bare token) is not recognized
by the keyword- and flag-based redaction in `redaction.py`. Detecting
it generically means knowing the argument syntax of every command a
given tool might appear in -- a per-command-syntax problem, not a
redaction rule.

## 5. Command-line tokenization is intentionally simple

`command_line.py` splits on whitespace and strips one pair of
surrounding matching quote characters from a single token. A path
containing an internal, unquoted space, or quoting that uses escaped
characters, is not correctly tokenized. Full Windows-aware
command-line parsing is a deferred improvement.

## 6. PERSIST-001 does not recognize `Register-ScheduledTask`

Only `schtasks`/`schtasks.exe`, matched by exact executable basename,
and Windows event ID `4698`, are recognized. The PowerShell cmdlet
alternative is not covered unless the source SIEM also emits a `4698`
for it regardless of which tool created the task.

## 7. Prompt boundary-marker forgery neutralization is exact-substring only

A Unicode homoglyph or lookalike sequence crafted to visually resemble
but not exactly match the fixed marker text (`prompt_builder.py`)
would not be caught.

## 8. Correlation's grouping algorithm is this project's own documented choice, and is not configurable

Host-first grouping, with a hostless event correlating only by the
exact pair of user and source IP, no transitive chaining, and a
24-hour time gap splitting a group into separate cases -- a
defensible design that satisfies the locked spec's wording, not the
only one that would. Making the strategy selectable, and attaching
machine-readable correlation-reason metadata to each event, are
deferred, schema-changing additions.

## 9. Symlink and junction defenses are real but narrowed, not absolute

As of Stage 18: the input path itself, every **parent directory** of
the input path, and every entry found while scanning a directory, are
all checked for a symlink, junction, or symlink/mount-point reparse
point. What remains open:
- A `..` segment in the input path is not resolved before this check
  runs, since resolving it would mean following symlinks along the
  way -- defeating the point. A plain path with no `..` is unaffected.
- The remaining check-then-open race is **narrowed**, not eliminated:
  the file is opened with `O_NOFOLLOW` where the platform supports it,
  and the file's identity (device + inode) is compared before and
  after opening, catching a swap that happens in between -- but a
  swap timed to exactly the wrong instant on a platform without
  `O_NOFOLLOW` support is still a gap.

CI now exercises this on both Ubuntu and Windows (Stage 18); the three
Windows-junction tests ran and passed for real on GitHub's own
`windows-latest` runner, confirmed directly from this project's own CI
logs, not assumed from a local Windows machine alone.

## 10. Raw HTML is escaped in Markdown reports only, not in terminal output

`sanitize_for_markdown_cell` escapes `&`, `<`, and `>` to HTML
entities, since Markdown renderers (including GitHub's own) pass raw
HTML through untouched otherwise. `sanitize_for_terminal` deliberately
does **not** HTML-escape -- terminal output isn't markup, and escaping
it would corrupt plain text for no benefit. Markdown or HTML syntax
other than `&`, `<`, `>`, a literal pipe, and a line break (backticks,
emphasis, links) is not escaped in either output.

## 11. Provider-output size limits exist, but have never been exercised by a real provider

`output_validation.py` now bounds raw response size, summary length,
list length and item length, and total draft text (Stage 19). The
mock provider's own output has always been comfortably inside every
one of these; the limits exist as a safe boundary for when a real
local or cloud provider is connected in v0.2+, not because the mock
has ever needed them.

## 12. The mock provider depends on the prompt's exact layout

`providers/mock.py` parses the fixed structure `prompt_builder.py`
produces (shared constants, one definition, tested together). A real
provider will not need to parse anything; this coupling is specific
to the mock's role as a stand-in.