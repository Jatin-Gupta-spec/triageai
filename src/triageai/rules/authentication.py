"""AUTH-001: repeated authentication failures.

Locked default (spec Section 7): 5 failures in a 10-minute window,
grouped by host plus (user OR source IP), Medium severity / Medium
confidence, mapped to MITRE T1110.

Detection heuristic, stated explicitly: an event counts as an
authentication failure if event_id == "4625" (Windows failed-logon
event ID) OR event_id == "4771" (Kerberos pre-auth failure). This is
NOT a spec-locked list -- it's this rule's own detection logic, and
the spec is intentionally silent on which literal event IDs count as
"a failure," leaving that to the rule's own documented interpretation.
Extending this set is a deliberate future change, not a bug fix.

Explicitly NOT proof of brute force (per spec Section 7) -- this rule
only proves the deterministic PATTERN existed in the input, exactly 5
or more matching events within a 10-minute sliding window for the same
grouping key. Legitimate causes (a misconfigured service retrying with
a stale password, a user who forgot they changed it) are real,
undocumented-here evidence gaps, not something this rule can rule out.

Design decision -- does NOT reset on a successful login (event_id
4624): deliberately excluded from consideration entirely. Resetting on
success would create a trivial evasion (an automated tool interleaves
one occasional success specifically to clear the counter), and the
analyst reviewing the full case timeline (Stage 7) already sees any
subsequent success sitting right after the failure burst regardless --
the rule doesn't need to be clever about that sequence, the human
reviewing the whole case is.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "AUTH-001"
MITRE_TECHNIQUE = "T1110"
FAILURE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=10)
_FAILURE_EVENT_IDS = frozenset({"4625", "4771"})


def _is_failure_event(event: NormalizedEvent) -> bool:
    return event.event_id in _FAILURE_EVENT_IDS


def _grouping_key(event: NormalizedEvent) -> tuple[str, str] | None:
    """Group by host + (user OR source_ip), per the locked spec.

    Returns None if there isn't enough identity information to group
    this event at all -- such an event cannot participate in AUTH-001,
    and is silently excluded from this rule's matching (not from the
    overall report; the caller still sees it in the timeline).
    """
    if event.host is None:
        return None
    if event.user is not None:
        return (event.host, f"user:{event.user}")
    if event.source_ip is not None:
        return (event.host, f"ip:{event.source_ip}")
    return None


def evaluate(events: tuple[NormalizedEvent, ...]) -> tuple[RuleMatch, ...]:
    """Find every group of 5+ failures within any 10-minute window.

    Only dated events participate -- an undated event has no place in
    a time-windowed calculation by definition (consistent with Stage 5
    /7's undated-record handling elsewhere in this project).

    Sliding-window approach: for each group, sort its failures by
    time, then for every failure, count how many OTHER failures in
    that same group fall within TIME_WINDOW after it. This correctly
    finds "5 in any 10-minute span," not just "5 in a fixed clock-
    aligned bucket" -- the spec says "in 10 minutes," not "per
    10-minute bucket," and those are genuinely different behaviors.
    """
    groups: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)

    for event in events:
        if event.timestamp is None or not _is_failure_event(event):
            continue
        key = _grouping_key(event)
        if key is not None:
            groups[key].append(event)

    matches: list[RuleMatch] = []

    for (host, identity), group_events in groups.items():
        ordered = sorted(group_events, key=lambda e: e.timestamp)  # type: ignore[arg-type,return-value]

        if len(ordered) < FAILURE_THRESHOLD:
            continue

        for start_index in range(len(ordered)):
            window_start = ordered[start_index].timestamp
            assert window_start is not None  # guaranteed by the filter above

            window_events = [
                e
                for e in ordered[start_index:]
                if e.timestamp is not None and e.timestamp - window_start <= TIME_WINDOW
            ]

            if len(window_events) >= FAILURE_THRESHOLD:
                matches.append(
                    RuleMatch(
                        rule_id=RULE_ID,
                        mitre_technique=MITRE_TECHNIQUE,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        matched_event_ids=tuple(e.original_record_id for e in window_events),
                        description=(
                            f"{len(window_events)} authentication failures for {identity} "
                            f"on host {host} within 10 minutes"
                        ),
                    )
                )
                break  # one match per group is enough; avoid N overlapping near-duplicates

    return tuple(matches)