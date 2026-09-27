"""Markdown report rendering. Renders REDACTED copies only -- see the
same caller responsibility note in terminal.py.
"""

from __future__ import annotations

from triageai.models import Case
from triageai.reporters.timeline import build_timeline


def render_markdown(cases: tuple[Case, ...]) -> str:
    """Render one section per case: severity/confidence, rule matches,
    evidence gaps, observed facts, then a sorted event timeline table.
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
            lines.extend(f"- `{m.rule_id}` ({m.mitre_technique}): {m.description}" for m in case.rule_matches)
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