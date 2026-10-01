# TriageAI — Threat Model

For every threat: the trust boundary it crosses, the control that
defends it, where it's tested, and what residual risk remains after
the control. "Module" references point at the actual code; "Tests"
point at the actual test file.

| Threat | Trust boundary | Control | Tests | Residual risk |
|---|---|---|---|---|
| Malformed JSON | Input file → reader | Strict parse, wrapped in `TriageInputError`, exit code 2 | `test_reader.py` | None known |
| Duplicate JSON object keys | Input file → reader | `object_pairs_hook` rejects a repeated key | `test_reader.py` | None known |
| Non-finite numbers (NaN/Infinity) | Input file → reader | `parse_constant` hook rejects all three | `test_reader.py` | None known |
| Unicode key collisions (NFC) | Raw record → canonicalization | Reject the record if two keys normalize to the same value | `test_normalization_collisions.py` | None known |
| Oversized input file | Input file → reader | Stat check, then a bounded read that catches a post-stat size change | `test_reader.py` | None known |
| Record-limit exhaustion | Reader → CLI | Hard 10,000-record cap, stops before the next record, exit code 2 | `test_reader.py` | None known |
| Invalid encoding / BOM | Input file → reader | Strict UTF-8, no BOM accepted in any form | `test_reader.py` | None known |
| Symlinks and Windows junctions | Input path → reader | Root path, parent directories, and scanned entries all checked; open with `O_NOFOLLOW` where supported | `test_input_links.py` | `..` segments not resolved before the check; race narrowed, not eliminated (LIMITATIONS.md item 9) |
| File replaced during reading (TOCTOU) | Reader's stat vs. open | Before/after device+inode identity comparison | `test_reader.py` | Timing window on platforms without `O_NOFOLLOW` |
| Secret leakage (passwords, tokens, keys, cookies, user paths) | Evidence → render boundary | Key-aware and pattern-based redaction, applied to every event field | `test_redaction.py`, `test_redaction_hardening.py` | Positional secrets with no adjacent keyword (LIMITATIONS.md item 4) |
| UPN/email correlation collapse | Redaction → correlation | Redaction runs only after correlation, never before; real identities used throughout the deterministic pipeline | `test_redaction.py`, `test_correlation.py` | None known |
| Terminal escape-sequence injection | Event data → terminal report | Control and hidden characters encoded visibly, never executed | `test_render_safety.py` | None known |
| Markdown/HTML injection | Event data → Markdown report | `&`/`<`/`>` escaped, pipes escaped, line breaks neutralized | `test_render_safety.py`, `test_reporters.py` | Other Markdown syntax (links, emphasis) not escaped (LIMITATIONS.md item 10) |
| Prompt injection | Evidence → AI prompt | Fixed boundary markers, forged-marker neutralization, control-char stripping, field and prompt truncation at line boundaries | `test_prompt_builder.py` | Unicode homoglyph of the marker (LIMITATIONS.md item 7) |
| Provider schema manipulation | Provider output → validation | Strict schema, unknown keys rejected, `analyst_warning` must exactly match the application constant | `test_output_validation.py` | None known |
| Unsupported AI claims (hallucination) | Validated draft → report | Entity claims checked against this case's real evidence allow-list, whole draft rejected on any mismatch | `test_hallucination_check.py`, `test_ai_pipeline.py` | Scope is deliberately narrow (LIMITATIONS.md item 2) |
| Oversized provider output | Provider → validation | Raw byte cap, per-field and total-text caps, checked before/during parsing | `test_output_validation.py` | None known |
| Model/provider failure | Provider call → CLI | `ProviderError` caught, rendered as a safe fixed rejection reason, never a raw exception | `test_ai_pipeline.py` | None known |
| Automation bias (over-trusting AI output) | AI draft → analyst | Every draft is explicitly labeled unverified; fail-closed rejection; evidence/rule/AI/analyst categories kept visually and structurally separate | `test_reporters.py`, project-wide design (`models.py`) | Inherent to any human-in-the-loop system; mitigated, not eliminated, by design |
| Out-of-scope production data | Operator behavior | SECURITY.md and PRIVACY.md state sanitized/synthetic data only; no live credentials, no network calls in v0.1 | Documentation, not code-enforced | Relies on the operator following stated scope |