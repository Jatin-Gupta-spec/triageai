"""Markdown report rendering. Renders REDACTED copies only -- see the
same caller responsibility note in terminal.py.
"""

from __future__ import annotations

from triageai.models import AIDraftOutcome, Case
from triageai.render_safety import sanitize_for_markdown_cell
from triageai.reporters.timeline import build_timeline


def render_markdown(cases: tuple[Case, ...], ai_drafts: dict[str, AIDraftOutcome]) -> str:
    """Render one section per case: severity/confidence, rule matches,
    evidence gaps, observed facts, AI draft (or rejection reason), then
    a sorted event timeline table.
    """
    if not cases:
        return "## TriageAI Report\n\nNo events to report.\n"

    lines: list[str] = ["# TriageAI Report", ""]
    for case in cases:
        hosts = ", ".join(sanitize_for_markdown_cell(h) for h in case.affected_hosts) or "?"
        users = ", ".join(sanitize_for_markdown_cell(u) for u in case.affected_users) or "?"

        lines.append(f"## Case {case.case_id}")
        lines.append("")
        lines.append(f"**Severity:** {case.severity.name} | **Confidence:** {case.confidence.name}")
        lines.append("")
        lines.append(f"**Hosts:** {hosts}")
        lines.append(f"**Users:** {users}")
        lines.append("")

        lines.append("### Rule matches")
        if case.rule_matches:
            lines.extend(
                f"- `{m.rule_id}` ({m.mitre_technique}): {sanitize_for_markdown_cell(m.description)}"
                for m in case.rule_matches
            )
        else:
            lines.append("- none")
        lines.append("")

        if case.evidence_gaps:
            lines.append("### Evidence gaps")
            lines.extend(f"- {sanitize_for_markdown_cell(gap)}" for gap in case.evidence_gaps)
            lines.append("")

        if case.observed_facts:
            lines.append("### Observed facts")
            lines.extend(f"- {sanitize_for_markdown_cell(fact)}" for fact in case.observed_facts)
            lines.append("")

        outcome = ai_drafts.get(case.case_id)
        lines.append("### AI draft")
        lines.append("")
        if outcome is None or outcome.draft is None:
            # See terminal.py's matching comment: outcome.rejection_reason
            # is typed str | None regardless of draft's value, so a safe
            # fallback is used whenever it isn't actually set.
            reason = (
                outcome.rejection_reason
                if outcome is not None and outcome.rejection_reason is not None
                else "no draft was generated"
            )
            lines.append(
                f"> **REJECTED** -- {sanitize_for_markdown_cell(reason)}. The deterministic "
                "evidence above is unaffected."
            )
        else:
            draft = outcome.draft
            lines.append(f"**Summary:** {sanitize_for_markdown_cell(draft.summary)}")
            lines.append("")
            if draft.observations:
                lines.append("**Observations:**")
                lines.extend(f"- {sanitize_for_markdown_cell(obs)}" for obs in draft.observations)
                lines.append("")
            if draft.investigation_questions:
                lines.append("**Investigation questions:**")
                lines.extend(
                    f"- {sanitize_for_markdown_cell(q)}" for q in draft.investigation_questions
                )
                lines.append("")
            if draft.possible_false_positives:
                lines.append("**Possible false positives:**")
                lines.extend(
                    f"- {sanitize_for_markdown_cell(fp)}" for fp in draft.possible_false_positives
                )
                lines.append("")
            if draft.recommended_next_steps:
                lines.append("**Recommended next steps:**")
                lines.extend(
                    f"- {sanitize_for_markdown_cell(step)}" for step in draft.recommended_next_steps
                )
                lines.append("")
            if draft.evidence_gaps:
                lines.append("**AI-proposed evidence gaps (unverified):**")
                lines.extend(f"- {sanitize_for_markdown_cell(gap)}" for gap in draft.evidence_gaps)
                lines.append("")
            if draft.unsupported_claims:
                lines.append("**AI-flagged unsupported claims:**")
                lines.extend(
                    f"- {sanitize_for_markdown_cell(claim)}" for claim in draft.unsupported_claims
                )
                lines.append("")
            lines.append(f"> {sanitize_for_markdown_cell(draft.analyst_warning)}")
            lines.append("")

        lines.append("### Timeline")
        lines.append("")
        lines.append("| Timestamp | Host | User | Event ID | Process | Command Line |")
        lines.append("|---|---|---|---|---|---|")
        for event in build_timeline(case.normalized_events):
            when = event.timestamp.isoformat() if event.timestamp is not None else "UNDATED"
            host = sanitize_for_markdown_cell(event.host) if event.host is not None else "?"
            user = sanitize_for_markdown_cell(event.user) if event.user is not None else "?"
            event_id = (
                sanitize_for_markdown_cell(event.event_id) if event.event_id is not None else "?"
            )
            process = (
                sanitize_for_markdown_cell(event.process) if event.process is not None else "?"
            )
            command_line = (
                sanitize_for_markdown_cell(event.command_line)
                if event.command_line is not None
                else "?"
            )
            lines.append(f"| {when} | {host} | {user} | {event_id} | {process} | {command_line} |")
        lines.append("")

    return "\n".join(lines)