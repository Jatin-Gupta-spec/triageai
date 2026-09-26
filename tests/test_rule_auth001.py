"""Tests for AUTH-001 -- positive, negative, boundary, and
missing-field cases, per the locked spec's test requirements.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from triageai.models import NormalizedEvent
from triageai.rules.authentication import evaluate


def _event(
    record_id: str,
    *,
    timestamp: datetime | None,
    host: str | None = "WIN-CLIENT01",
    user: str | None = "alice",
    source_ip: str | None = None,
    event_id: str | None = "4625",
) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=timestamp,
        host=host,
        user=user,
        source=None,
        event_id=event_id,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=None,
        source_ip=source_ip,
        destination_ip=None,
        mitre_techniques=(),
    )


def _burst(count: int, *, start: datetime, spacing: timedelta, **kwargs) -> tuple[NormalizedEvent, ...]:
    return tuple(
        _event(f"rec-{i}", timestamp=start + spacing * i, **kwargs) for i in range(count)
    )


_BASE_TIME = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)


# --- Positive: the textbook case ---


def test_five_failures_within_ten_minutes_matches() -> None:
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=2))  # spans 8 minutes

    matches = evaluate(events)

    assert len(matches) == 1
    assert matches[0].rule_id == "AUTH-001"
    assert matches[0].mitre_technique == "T1110"
    assert len(matches[0].matched_event_ids) == 5


def test_groups_by_host_and_source_ip_when_user_absent() -> None:
    events = _burst(
        5, start=_BASE_TIME, spacing=timedelta(minutes=1), user=None, source_ip="192.168.56.10"
    )

    matches = evaluate(events)

    assert len(matches) == 1


# --- Negative: patterns that must NOT match ---


def test_four_failures_does_not_match() -> None:
    events = _burst(4, start=_BASE_TIME, spacing=timedelta(minutes=1))

    assert evaluate(events) == ()


def test_five_failures_for_different_users_does_not_match() -> None:
    events = tuple(
        _event(f"rec-{i}", timestamp=_BASE_TIME + timedelta(minutes=i), user=f"user{i}")
        for i in range(5)
    )

    assert evaluate(events) == ()


def test_five_failures_on_different_hosts_does_not_match() -> None:
    events = tuple(
        _event(f"rec-{i}", timestamp=_BASE_TIME + timedelta(minutes=i), host=f"HOST-{i}")
        for i in range(5)
    )

    assert evaluate(events) == ()


def test_non_failure_event_ids_do_not_count() -> None:
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=1), event_id="4624")  # success

    assert evaluate(events) == ()


# --- Boundary: the exact edges the spec's thresholds imply ---


def test_exactly_five_failures_at_exactly_ten_minutes_matches() -> None:
    # Failures at t+0, t+2:30, t+5:00, t+7:30, t+10:00 -- last one is
    # EXACTLY at the 10-minute boundary, inclusive per this rule's "<="
    # window comparison.
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=2, seconds=30))

    matches = evaluate(events)

    assert len(matches) == 1


def test_five_failures_spanning_just_over_ten_minutes_does_not_match() -> None:
    # Same as above, but the last failure lands one second past the
    # boundary -- proving the window is not simply "5 events total,"
    # it genuinely enforces the 10-minute span.
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=2, seconds=30, milliseconds=250))

    assert evaluate(events) == ()


def test_six_failures_where_only_five_fit_the_window_still_matches() -> None:
    # 5 failures tightly packed, then a 6th well outside the window --
    # the rule must still find the qualifying group of 5, not be
    # thrown off by the 6th event's presence.
    tight = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=1))
    late = _event("rec-late", timestamp=_BASE_TIME + timedelta(hours=1))

    matches = evaluate((*tight, late))

    assert len(matches) == 1
    assert "rec-late" not in matches[0].matched_event_ids


# --- Missing-field: incomplete evidence must not crash or invent identity ---


def test_undated_events_are_excluded_from_matching() -> None:
    dated = _burst(4, start=_BASE_TIME, spacing=timedelta(minutes=1))
    undated = _event("rec-undated", timestamp=None)

    assert evaluate((*dated, undated)) == ()  # only 4 dated failures: correctly no match


def test_event_missing_host_is_excluded() -> None:
    events = tuple(
        _event(f"rec-{i}", timestamp=_BASE_TIME + timedelta(minutes=i), host=None)
        for i in range(5)
    )

    assert evaluate(events) == ()


def test_event_missing_both_user_and_source_ip_is_excluded() -> None:
    events = tuple(
        _event(f"rec-{i}", timestamp=_BASE_TIME + timedelta(minutes=i), user=None, source_ip=None)
        for i in range(5)
    )

    assert evaluate(events) == ()


def test_empty_input_produces_no_matches() -> None:
    assert evaluate(()) == ()