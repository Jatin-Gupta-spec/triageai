"""Plain-text report rendering. Renders REDACTED copies only -- callers
are responsible for passing already-redacted cases (see redaction.py).
"""

from __future__ import annotations

from triageai.models import AIAnalysisDraft, Case
from triageai.reporters.timeline import build_timeline


def render_text(cases: tuple[Case, ...], ai_drafts: dict[str, AIAnalysisDraft | None]) -> str:
    """Render one section per case: severity/confidence, rule matches,
    evidence gaps, observed facts, AI draft (or rejection notice), then
    a sorted event timeline.
    """
    if not cases:
        return "No events to report."

    sections: list[str] = []
    for case in cases:
        lines = [
            f"=== Case {case.case_id} ===",
            f"Severity: {case.severity.name} | Confidence: {case.confidence.name}",
            f"Hosts: {', '.join(case.affected_hosts) or '?'}",
            f"Users: {', '.join(case.affected_users) or '?'}",
        ]

        if case.rule_matches:
            lines.append("Rule matches:")
            lines.extend(
                f"  - {m.rule_id} ({m.mitre_technique}): {m.description}" for m in case.rule_matches
            )
        else:
            lines.append("Rule matches: none")

        if case.evidence_gaps:
            lines.append("Evidence gaps:")
            lines.extend(f"  - {gap}" for gap in case.evidence_gaps)

        if case.observed_facts:
            lines.append("Observed facts:")
            lines.extend(f"  - {fact}" for fact in case.observed_facts)

        draft = ai_drafts.get(case.case_id)
        lines.append("AI draft:")
        if draft is None:
            lines.append(
                "  [REJECTED -- the AI provider's output failed schema or evidence "
                "validation and has been withheld. The deterministic evidence above "
                "is unaffected.]"
            )
        else:
            lines.append(f"  Summary: {draft.summary}")
            for obs in draft.observations:
                lines.append(f"  - Observation: {obs}")
            for question in draft.investigation_questions:
                lines.append(f"  - Investigation question: {question}")
            for fp in draft.possible_false_positives:
                lines.append(f"  - Possible false positive: {fp}")
            for step in draft.recommended_next_steps:
                lines.append(f"  - Recommended next step: {step}")
            lines.append(f"  [{draft.analyst_warning}]")

        lines.append("Timeline:")
        for event in build_timeline(case.normalized_events):
            when = event.timestamp.isoformat() if event.timestamp is not None else "UNDATED"
            lines.append(
                f"  [{when}] host={event.host or '?'} user={event.user or '?'} "
                f"event_id={event.event_id or '?'} process={event.process or '?'} "
                f"command_line={event.command_line or '?'}"
            )

        sections.append("\n".join(lines))

    return "\n\n".join(sections)