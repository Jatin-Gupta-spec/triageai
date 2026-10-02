# Changelog

All notable changes to TriageAI are recorded here. Dates are when the
change was committed, not when the stage began.

## [0.1.0]

Initial portfolio release. Built in 15 locked stages per the original
specification, then hardened through two rounds of external security
audit.

### Added
- Offline, deterministic reading, validation, and normalization of
  sanitized security event JSON (Stage 4-5).
- Render-boundary redaction, preserving real identities internally
  for correlation while aliasing them only at report/prompt time
  (Stage 6, hardened Stage 17d/18).
- Three deterministic detection rules: AUTH-001 (repeated
  authentication failures, independent user and source-IP
  dimensions), PS-001 (encoded PowerShell, bounded decode), and
  PERSIST-001 (scheduled-task creation) (Stages 8-10, tightened
  Stage 18).
- Host- and identity-based correlation with a documented, Unicode-
  and case-aware grouping algorithm (Stage 11, extended Stage 17a).
- A deterministic mock AI provider, consuming the same bounded,
  injection-resistant prompt a real provider will (Stages 12-13,
  rebuilt Stage 17b).
- Strict AI output schema validation, a fixed application-owned
  analyst warning, and fail-closed hallucination checking against
  this case's own evidence (Stage 14, hardened Stage 17b, Stage 19).
- Deduplication by `original_record_id`, non-finite JSON constant
  rejection, Unicode key-collision rejection, and structural/HTML
  injection resistance in rendered reports (post-audit hardening,
  Stage 16/18).
- Symlink and Windows-junction rejection at the input path, its
  parent directories, and during directory scans, with an open/
  verify file-identity check narrowing the remaining TOCTOU race
  (Stage 17c, extended Stage 18).
- Provider-output size limits: raw response bytes, summary length,
  list length, item length, and total draft text (Stage 19).
- CI across Ubuntu and Windows, Python 3.11 and 3.13, running
  pytest, Ruff, strict mypy, and pip-audit on every push.
- `RULES.md`, `LIMITATIONS.md`, `SECURITY.md`, `PRIVACY.md`,
  `THREAT_MODEL.md`, and `ACCEPTANCE.md`.

### Fixed (via external audit)
Two independent audit passes found and this project fixed: an
entirely unimplemented deduplication requirement; a redaction gap in
observed facts and evidence gaps; a crash on NaN/Infinity JSON
input; silently discarded Unicode key collisions; unsanitized
Markdown/terminal report output (pipes, control characters, and raw
HTML); a password-spraying blind spot in AUTH-001; a CI workflow
that had never successfully installed the project itself; a
substring-based PERSIST-001/PS-001 match that fired on unrelated
tools merely mentioning the right words; a provider-controlled
`analyst_warning` field; a prompt layout that lost rule matches
under truncation; and several narrower hallucination-check false
positives (rule IDs and PowerShell cmdlet names misread as fake
hosts).

### Known limitations
See `LIMITATIONS.md`. The two largest: a flattened, Wazuh-inspired
schema rather than a real nested Wazuh/Sysmon export shape; and
AI-claim validation scoped to four entity types, with full structured
-entity validation deferred to v0.2.