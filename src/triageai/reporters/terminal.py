"""Plain-text report rendering. Renders REDACTED copies only -- callers
are responsible for passing already-redacted cases (see redaction.py).
"""

from __future__ import annotations

from triageai.models import AIDraftOutcome, Case
from triageai.render_safety import sanitize_for_terminal
from triageai.reporters.timeline import build_timeline


def render_text(cases: tuple[Case, ...], ai_drafts: dict[str, AIDraftOutcome]) -> str:
    """Render one section per case: severity/confidence, rule matches,
    evidence gaps, observed facts, AI draft (or rejection reason), then
    a sorted event timeline.
    """
    if not cases:
        return "No events to report."

    sections: list[str] = []
    for case in cases:
        hosts = ", ".join(sanitize_for_terminal(h) for h in case.affected_hosts) or "?"
        users = ", ".join(sanitize_for_terminal(u) for u in case.affected_users) or "?"

        lines = [
            f"=== Case {case.case_id} ===",
            f"Severity: {case.severity.name} | Confidence: {case.confidence.name}",
            f"Hosts: {hosts}",
            f"Users: {users}",
        ]

        if case.rule_matches:
            lines.append("Rule matches:")
            lines.extend(
                f"  - {m.rule_id} ({m.mitre_technique}): {sanitize_for_terminal(m.description)}"
                for m in case.rule_matches
            )
        else:
            lines.append("Rule matches: none")

        if case.evidence_gaps:
            lines.append("Evidence gaps:")
            lines.extend(f"  - {sanitize_for_terminal(gap)}" for gap in case.evidence_gaps)

        if case.observed_facts:
            lines.append("Observed facts:")
            lines.extend(f"  - {sanitize_for_terminal(fact)}" for fact in case.observed_facts)

        outcome = ai_drafts.get(case.case_id)
        lines.append("AI draft:")
        if outcome is None or outcome.draft is None:
            # outcome.rejection_reason is typed str | None -- nothing
            # at the type level guarantees it's set whenever draft is
            # None, even though every real construction in cli.py does
            # set it. Fall back to a fixed, safe string rather than
            # ever passing None where a str is required.
            reason = (
                outcome.rejection_reason
                if outcome is not None and outcome.rejection_reason is not None
                else "no draft was generated"
            )
            lines.append(
                f"  [REJECTED -- {sanitize_for_terminal(reason)}. The deterministic "
                "evidence above is unaffected.]"
            )
        else:
            draft = outcome.draft
            lines.append(f"  Summary: {sanitize_for_terminal(draft.summary)}")
            for obs in draft.observations:
                lines.append(f"  - Observation: {sanitize_for_terminal(obs)}")
            for question in draft.investigation_questions:
                lines.append(f"  - Investigation question: {sanitize_for_terminal(question)}")
            for fp in draft.possible_false_positives:
                lines.append(f"  - Possible false positive: {sanitize_for_terminal(fp)}")
            for step in draft.recommended_next_steps:
                lines.append(f"  - Recommended next step: {sanitize_for_terminal(step)}")
            for gap in draft.evidence_gaps:
                lines.append(
                    f"  - AI-proposed evidence gap (unverified): {sanitize_for_terminal(gap)}"
                )
            for claim in draft.unsupported_claims:
                lines.append(f"  - AI-flagged unsupported claim: {sanitize_for_terminal(claim)}")
            lines.append(f"  [{sanitize_for_terminal(draft.analyst_warning)}]")

        lines.append("Timeline:")
        for event in build_timeline(case.normalized_events):
            when = event.timestamp.isoformat() if event.timestamp is not None else "UNDATED"
            host = sanitize_for_terminal(event.host) if event.host is not None else "?"
            user = sanitize_for_terminal(event.user) if event.user is not None else "?"
            event_id = sanitize_for_terminal(event.event_id) if event.event_id is not None else "?"
            process = sanitize_for_terminal(event.process) if event.process is not None else "?"
            command_line = (
                sanitize_for_terminal(event.command_line) if event.command_line is not None else "?"
            )
            lines.append(
                f"  [{when}] host={host} user={user} "
                f"event_id={event_id} process={process} "
                f"command_line={command_line}"
            )

        sections.append("\n".join(lines))

    return "\n\n".join(sections)