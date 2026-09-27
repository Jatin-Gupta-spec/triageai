"""Markdown report rendering. Renders REDACTED copies only -- see the
same caller responsibility note in terminal.py.
"""

from __future__ import annotations

from triageai.models import AIAnalysisDraft, Case
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
        lines.append(f"## Case {case.case_id}")
        lines.append("")
        lines.append(f"**Severity:** {case.severity.name} | **Confidence:** {case.confidence.name}")
        lines.append("")
        lines.append(f"**Hosts:** {', '.join(case.affected_hosts) or '?'}")
        lines.append(f"**Users:** {', '.join(case.affected_users) or '?'}")
        lines.append("")

        lines.append("### Rule matches")
        if case.rule_matches:
            lines.extend(
                f"- `{m.rule_id}` ({m.mitre_technique}): {m.description}" for m in case.rule_matches
            )
        else:
            lines.append("- none")
        lines.append("")

        if case.evidence_gaps:
            lines.append("### Evidence gaps")
            lines.extend(f"- {gap}" for gap in case.evidence_gaps)
            lines.append("")

        if case.observed_facts:
            lines.append("### Observed facts")
            lines.extend(f"- {fact}" for fact in case.observed_facts)
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
            lines.append(f"**Summary:** {draft.summary}")
            lines.append("")
            if draft.observations:
                lines.append("**Observations:**")
                lines.extend(f"- {obs}" for obs in draft.observations)
                lines.append("")
            if draft.investigation_questions:
                lines.append("**Investigation questions:**")
                lines.extend(f"- {q}" for q in draft.investigation_questions)
                lines.append("")
            if draft.possible_false_positives:
                lines.append("**Possible false positives:**")
                lines.extend(f"- {fp}" for fp in draft.possible_false_positives)
                lines.append("")
            if draft.recommended_next_steps:
                lines.append("**Recommended next steps:**")
                lines.extend(f"- {step}" for step in draft.recommended_next_steps)
                lines.append("")
            lines.append(f"> {draft.analyst_warning}")
            lines.append("")

        lines.append("### Timeline")
        lines.append("")
        lines.append("| Timestamp | Host | User | Event ID | Process | Command Line |")
        lines.append("|---|---|---|---|---|---|")
        for event in build_timeline(case.normalized_events):
            when = event.timestamp.isoformat() if event.timestamp is not None else "UNDATED"
            lines.append(
                f"| {when} | {event.host or '?'} | {event.user or '?'} | "
                f"{event.event_id or '?'} | {event.process or '?'} | {event.command_line or '?'} |"
            )
        lines.append("")

    return "\n".join(lines)