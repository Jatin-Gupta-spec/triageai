"""Correlates normalized events into Cases, then aggregates severity/
confidence from each case's own deterministic rule matches.

See this module's own inline design notes for the correlation
algorithm (host as primary key, 24-hour case-boundary gap, undated
events attach to a host's first case) -- this is this module's own
documented interpretation, since the locked spec requires correlation
"by host, user, source IP, and a documented time window" but does not
itself define the grouping algorithm, same pattern as every rule's own
detection heuristic.
"""

from __future__ import annotations

import hashlib
import itertools
from collections import defaultdict
from datetime import timedelta

from triageai.models import Case, Confidence, NormalizedEvent, RuleMatch, Severity
from triageai.rules import authentication, persistence, powershell

CORRELATION_GAP = timedelta(hours=24)

_RULES = (authentication.evaluate, powershell.evaluate, persistence.evaluate)


def _case_id_for(events: tuple[NormalizedEvent, ...]) -> str:
    """Deterministic case ID: SHA-256 over the sorted, joined record IDs.

    Sorting first guarantees the same set of events always produces
    the same case_id, independent of dict/iteration order -- required
    for byte-identical determinism across runs.
    """
    joined = ",".join(sorted(event.original_record_id for event in events))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _split_by_time_gap(dated_events: list[NormalizedEvent]) -> list[list[NormalizedEvent]]:
    if not dated_events:
        return []

    ordered = sorted(dated_events, key=lambda e: e.timestamp)  # type: ignore[arg-type,return-value]
    groups: list[list[NormalizedEvent]] = [[ordered[0]]]

    for previous, current in itertools.pairwise(ordered):
        assert previous.timestamp is not None and current.timestamp is not None
        if current.timestamp - previous.timestamp > CORRELATION_GAP:
            groups.append([current])
        else:
            groups[-1].append(current)

    return groups


def aggregate_severity_confidence(
    rule_matches: tuple[RuleMatch, ...],
) -> tuple[Severity, Confidence]:
    """Locked spec, Section 5: Case severity = max matched-rule severity.
    Case confidence = max confidence AMONG MATCHES AT THAT SEVERITY --
    NOT the global max confidence across every match regardless of its
    severity. No matches = Informational / Low.

    Exposed as a public, standalone function specifically so it can be
    tested with synthetic RuleMatch fixtures independent of any real
    rule firing, per the locked spec's test-plan requirement.
    """
    if not rule_matches:
        return Severity.INFORMATIONAL, Confidence.LOW

    max_severity = max(match.severity for match in rule_matches)
    confidences_at_max_severity = [
        match.confidence for match in rule_matches if match.severity == max_severity
    ]
    return max_severity, max(confidences_at_max_severity)


def _build_case(events: tuple[NormalizedEvent, ...]) -> Case:
    hosts = tuple(sorted({e.host for e in events if e.host is not None}))
    users = tuple(sorted({e.user for e in events if e.user is not None}))
    dated_timestamps = sorted(e.timestamp for e in events if e.timestamp is not None)
    undated_count = sum(1 for e in events if e.timestamp is None)

    rule_matches: tuple[RuleMatch, ...] = tuple(
        match for rule_evaluate in _RULES for match in rule_evaluate(events)
    )
    severity, confidence = aggregate_severity_confidence(rule_matches)

    observed_facts = tuple(
        f"{len(events)} event(s) observed for host {host}" for host in hosts
    ) or (f"{len(events)} event(s) observed with no host recorded",)

    evidence_gaps: tuple[str, ...] = ()
    if undated_count:
        gap_message = (
            f"{undated_count} event(s) in this case have no valid timestamp and are "
            "excluded from timeline ordering and time-windowed rule matching"
        )
        evidence_gaps = (gap_message,)

    return Case(
        case_id=_case_id_for(events),
        first_seen=dated_timestamps[0] if dated_timestamps else None,
        last_seen=dated_timestamps[-1] if dated_timestamps else None,
        affected_hosts=hosts,
        affected_users=users,
        normalized_events=events,
        rule_matches=rule_matches,
        severity=severity,
        confidence=confidence,
        observed_facts=observed_facts,
        evidence_gaps=evidence_gaps,
    )


def build_cases(events: tuple[NormalizedEvent, ...]) -> tuple[Case, ...]:
    """Group events into Cases, run every rule against each case's own
    events, and aggregate severity/confidence. See module docstring
    for the grouping algorithm.
    """
    by_host: dict[str | None, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        by_host[event.host].append(event)

    cases: list[Case] = []

    for host, host_events in by_host.items():
        if host is None:
            for event in host_events:
                cases.append(_build_case((event,)))
            continue

        dated = [e for e in host_events if e.timestamp is not None]
        undated = tuple(e for e in host_events if e.timestamp is None)

        time_groups = _split_by_time_gap(dated)

        if not time_groups:
            cases.append(_build_case(undated))
            continue

        time_groups[0] = time_groups[0] + list(undated)
        for group in time_groups:
            cases.append(_build_case(tuple(group)))

    cases.sort(key=lambda c: c.case_id)  # deterministic output order
    return tuple(cases)