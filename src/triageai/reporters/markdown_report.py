"""Markdown report rendering. Renders REDACTED copies only -- see the
same caller responsibility note in terminal.py.

Fix: every untrusted field is now sanitized via render_safety.py.
Pipe escaping specifically defends the timeline table's structure; the
same escaping is applied everywhere else in the report too (not just
inside the literal table) because a raw newline in prose can still
start a new Markdown line that renders as a heading if it happens to
begin with '#' -- escaping a stray '|' outside a table is harmless, so
using one consistent sanitizer everywhere is simpler and safer than
having two subtly different ones.
"""

from __future__ import annotations

from triageai.models import AIAnalysisDraft, Case
from triageai.render_safety import sanitize_for_markdown_cell
from triageai.reporters.timeline import build_timeline


def render_markdown(cases: tuple[Case, ...], ai_drafts: dict[str, AIAnalysisDraft | None]) -> str:
    """Render one section per case: severity/confidence, rule matches,
    evidence gaps, observed facts, AI draft (or rejection notice), then
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

        draft = ai_drafts.get(case.case_id)
        lines.append("### AI draft")
        lines.append("")
        if draft is None:
            lines.append(
                "> **REJECTED** -- the AI provider's output failed schema or evidence "
                "validation and has been withheld. The deterministic evidence above is "
                "unaffected."
            )
        else:
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
            lines.append(
                f"| {when} | {host} | {user} | {event_id} | {process} | {command_line} |"
            )
        lines.append("")

    return "\n".join(lines)