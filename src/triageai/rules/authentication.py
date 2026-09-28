"""AUTH-001: repeated authentication failures.

Locked default (spec Section 7): 5 failures in a 10-minute window,
grouped by host plus user OR source IP, Medium severity / Medium
confidence, mapped to MITRE T1110.

Stage 17a change: "user OR source IP" is now evaluated as two
INDEPENDENT dimensions, not a preference order. Previously, if an
event had a user, source IP was never considered. That made password
spraying (one source IP trying many accounts, each below the
per-user threshold) invisible. Now:
  - dimension "user": host + normalized user
  - dimension "ip":   host + normalized source IP
An event with both fields feeds both dimensions.

Identity comparison is case-insensitive and Unicode-normalized (see
identity.py) because Windows account and host names are
case-insensitive. Reports display the spelling from the earliest
event in the matched window.

Deduplication: if the user-dimension match and the IP-dimension
match cover exactly the same set of events, only the user-dimension
match is kept. If the event sets differ (for example one account
under attack plus a wider spray from the same IP), both are kept,
because they are different findings.

Detection heuristic, stated explicitly: an event counts as an
authentication failure if event_id is "4625" (Windows failed logon)
or "4771" (Kerberos pre-auth failure). This list is this rule's own
interpretation, not spec-locked.

Explicitly NOT proof of brute force (per spec Section 7) -- this rule
only proves the deterministic PATTERN existed in the input. A
misconfigured service retrying a stale password produces the same
pattern.

Design decision -- does NOT reset on a successful login (event_id
4624): resetting would create a trivial evasion (interleave an
occasional success to clear the counter), and the analyst reviewing
the full case timeline already sees any success sitting right after
the failure burst.

One match per group: the first qualifying 10-minute window in each
group produces the match; later windows in the same group do not
produce additional matches.

Known limitation: an event with no host cannot participate in this
rule, because the spec groups by host.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from triageai.identity import normalize_identity
from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "AUTH-001"
MITRE_TECHNIQUE = "T1110"
FAILURE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=10)
_FAILURE_EVENT_IDS = frozenset({"4625", "4771"})

_GroupKey = tuple[str, str]  # (normalized host, normalized identity)


@dataclass(frozen=True, slots=True)
class _Failure:
    timestamp: datetime
    event: NormalizedEvent


def _is_failure_event(event: NormalizedEvent) -> bool:
    return event.event_id in _FAILURE_EVENT_IDS


def _collect_groups(
    events: tuple[NormalizedEvent, ...],
) -> tuple[dict[_GroupKey, list[_Failure]], dict[_GroupKey, list[_Failure]]]:
    """Split dated failure events into the user and IP dimensions."""
    user_groups: dict[_GroupKey, list[_Failure]] = defaultdict(list)
    ip_groups: dict[_GroupKey, list[_Failure]] = defaultdict(list)

    for event in events:
        timestamp = event.timestamp
        if timestamp is None or not _is_failure_event(event):
            continue

        host = normalize_identity(event.host)
        if host is None:
            continue

        failure = _Failure(timestamp=timestamp, event=event)

        user = normalize_identity(event.user)
        if user is not None:
            user_groups[(host, user)].append(failure)

        source_ip = normalize_identity(event.source_ip)
        if source_ip is not None:
            ip_groups[(host, source_ip)].append(failure)

    return user_groups, ip_groups


def _first_qualifying_window(failures: list[_Failure]) -> list[_Failure] | None:
    """Return every failure in the first qualifying 10-minute window.

    The list is sorted by time, so a window starting at index i holds
    at least FAILURE_THRESHOLD failures exactly when the
    FAILURE_THRESHOLD-th failure from i is within TIME_WINDOW of it.
    The window then extends over every later failure still inside
    TIME_WINDOW of the start.
    """
    ordered = sorted(failures, key=lambda f: (f.timestamp, f.event.original_record_id))

    for start_index in range(len(ordered) - FAILURE_THRESHOLD + 1):
        start_time = ordered[start_index].timestamp
        last_required = ordered[start_index + FAILURE_THRESHOLD - 1].timestamp
        if last_required - start_time > TIME_WINDOW:
            continue

        end_index = start_index + FAILURE_THRESHOLD
        while end_index < len(ordered) and ordered[end_index].timestamp - start_time <= TIME_WINDOW:
            end_index += 1
        return ordered[start_index:end_index]

    return None


def _build_match(dimension: str, window: list[_Failure]) -> RuleMatch:
    first = window[0].event
    identity = (first.user if dimension == "user" else first.source_ip) or "?"
    return RuleMatch(
        rule_id=RULE_ID,
        mitre_technique=MITRE_TECHNIQUE,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        matched_event_ids=tuple(f.event.original_record_id for f in window),
        description=(
            f"{len(window)} authentication failures for {dimension}:{identity} "
            f"on host {first.host or '?'} within 10 minutes"
        ),
    )


def evaluate(events: tuple[NormalizedEvent, ...]) -> tuple[RuleMatch, ...]:
    """Find every group of 5+ failures within a 10-minute window.

    Only dated failure events with a host participate. Output order is
    deterministic: user-dimension matches first, then IP-dimension
    matches, each sorted by group key.
    """
    user_groups, ip_groups = _collect_groups(events)

    matches: list[RuleMatch] = []
    seen_event_sets: set[frozenset[str]] = set()

    for dimension, groups in (("user", user_groups), ("ip", ip_groups)):
        for key in sorted(groups):
            window = _first_qualifying_window(groups[key])
            if window is None:
                continue

            match = _build_match(dimension, window)
            event_set = frozenset(match.matched_event_ids)
            if event_set in seen_event_sets:
                continue

            seen_event_sets.add(event_set)
            matches.append(match)

    return tuple(matches)