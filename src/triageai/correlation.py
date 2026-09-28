"""Correlates normalized events into Cases, then aggregates severity/
confidence from each case's own deterministic rule matches.

The locked spec requires correlation "by host, user, source IP, and a
documented time window" but does not define the grouping algorithm.
This module's documented interpretation:

1. Identity key (Stage 17a):
   - An event WITH a host is keyed by that host alone (case-
     insensitive, Unicode-normalized; see identity.py).
   - An event WITHOUT a host is keyed by the PAIR (user, source IP),
     and only if BOTH are present.
   - Anything else stays a single-event case.
   A single weak identifier is never enough to join events: two
   hostless events sharing only a user, or only an IP, stay separate.
   Hostless events never attach to a host-based case.

2. No identity chaining: because the key is an exact match on the
   host, or on the (user, IP) pair, event A matching B and B matching
   C never merges A and C unless they match each other directly.

3. Time window: within one identity group, dated events are sorted
   and a gap larger than CORRELATION_GAP (24 hours) between
   consecutive events starts a new case. Consecutive events within
   the gap do chain, so a long, steady stream stays one case.

4. Undated events attach to the first case of their identity group,
   since they cannot be placed in time.

Known limitation: AUTH-001 requires a host, so hostless events that
correlate by user+IP are grouped into a case but cannot match
AUTH-001.
"""

from __future__ import annotations

import hashlib
import itertools
from collections import defaultdict
from datetime import timedelta

from triageai.identity import normalize_identity
from triageai.models import Case, Confidence, NormalizedEvent, RuleMatch, Severity
from triageai.rules import authentication, persistence, powershell

CORRELATION_GAP = timedelta(hours=24)

_RULES = (authentication.evaluate, powershell.evaluate, persistence.evaluate)


def _case_id_for(events: tuple[NormalizedEvent, ...]) -> str:
    """Deterministic case ID: SHA-256 over the sorted, joined record IDs."""
    joined = ",".join(sorted(event.original_record_id for event in events))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _identity_group_key(event: NormalizedEvent) -> tuple[str, ...] | None:
    """Return the identity key for grouping, or None for a single-event case."""
    host = normalize_identity(event.host)
    if host is not None:
        return ("host", host)

    user = normalize_identity(event.user)
    source_ip = normalize_identity(event.source_ip)
    if user is not None and source_ip is not None:
        return ("user-ip", user, source_ip)

    return None


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

    Public and standalone so it can be tested with synthetic
    RuleMatch fixtures independent of any real rule firing.
    """
    if not rule_matches:
        return Severity.INFORMATIONAL, Confidence.LOW

    max_severity = max(match.severity for match in rule_matches)
    confidences_at_max_severity = [
        match.confidence for match in rule_matches if match.severity == max_severity
    ]
    return max_severity, max(confidences_at_max_severity)


def _build_case(events: tuple[NormalizedEvent, ...]) -> Case:
    hosts = tuple(sorted({e.host for e in events if e.host is not None and e.host.strip()}))
    users = tuple(sorted({e.user for e in events if e.user is not None and e.user.strip()}))
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
    by_identity: dict[tuple[str, ...], list[NormalizedEvent]] = defaultdict(list)
    cases: list[Case] = []

    for event in events:
        key = _identity_group_key(event)
        if key is None:
            cases.append(_build_case((event,)))
        else:
            by_identity[key].append(event)

    for identity_events in by_identity.values():
        dated = [e for e in identity_events if e.timestamp is not None]
        undated = tuple(e for e in identity_events if e.timestamp is None)

        time_groups = _split_by_time_gap(dated)

        if not time_groups:
            cases.append(_build_case(undated))
            continue

        time_groups[0] = time_groups[0] + list(undated)
        for group in time_groups:
            cases.append(_build_case(tuple(group)))

    cases.sort(key=lambda c: c.case_id)  # deterministic output order
    return tuple(cases)