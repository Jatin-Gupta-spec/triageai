"""Tests for AUTH-001 -- positive, negative, boundary, and
missing-field cases, plus (Stage 17a) independent user/IP dimensions,
case-insensitive identity comparison, and match deduplication.
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


def _burst(
    count: int, *, start: datetime, spacing: timedelta, **kwargs: str | None
) -> tuple[NormalizedEvent, ...]:
    return tuple(
        _event(f"rec-{i}", timestamp=start + spacing * i, **kwargs) for i in range(count)
    )


_BASE_TIME = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)


# --- Positive ---


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

    assert len(evaluate(events)) == 1


# --- Negative ---


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
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=1), event_id="4624")

    assert evaluate(events) == ()


# --- Boundary ---


def test_exactly_five_failures_at_exactly_ten_minutes_matches() -> None:
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=2, seconds=30))

    assert len(evaluate(events)) == 1


def test_five_failures_spanning_just_over_ten_minutes_does_not_match() -> None:
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=2, seconds=30, milliseconds=250))

    assert evaluate(events) == ()


def test_six_failures_where_only_five_fit_the_window_still_matches() -> None:
    tight = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=1))
    late = _event("rec-late", timestamp=_BASE_TIME + timedelta(hours=1))

    matches = evaluate((*tight, late))

    assert len(matches) == 1
    assert "rec-late" not in matches[0].matched_event_ids


# --- Missing-field ---


def test_undated_events_are_excluded_from_matching() -> None:
    dated = _burst(4, start=_BASE_TIME, spacing=timedelta(minutes=1))
    undated = _event("rec-undated", timestamp=None)

    assert evaluate((*dated, undated)) == ()


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


# --- Stage 17a: password spraying (independent source-IP dimension) ---


def test_password_spraying_one_ip_many_users_matches() -> None:
    events = tuple(
        _event(
            f"rec-{i}",
            timestamp=_BASE_TIME + timedelta(minutes=i),
            user=f"user{i}",
            source_ip="198.51.100.7",
        )
        for i in range(5)
    )

    matches = evaluate(events)

    assert len(matches) == 1
    assert "ip:198.51.100.7" in matches[0].description
    assert len(matches[0].matched_event_ids) == 5


def test_spraying_below_threshold_does_not_match() -> None:
    events = tuple(
        _event(
            f"rec-{i}",
            timestamp=_BASE_TIME + timedelta(minutes=i),
            user=f"user{i}",
            source_ip="198.51.100.7",
        )
        for i in range(4)
    )

    assert evaluate(events) == ()


def test_spraying_from_different_ips_does_not_match() -> None:
    events = tuple(
        _event(
            f"rec-{i}",
            timestamp=_BASE_TIME + timedelta(minutes=i),
            user=f"user{i}",
            source_ip=f"198.51.100.{i}",
        )
        for i in range(5)
    )

    assert evaluate(events) == ()


# --- Stage 17a: case-insensitive identity comparison ---


def test_user_grouping_is_case_insensitive() -> None:
    names = ["Alice", "ALICE", "alice", "aLiCe", "ALICE"]
    events = tuple(
        _event(f"rec-{i}", timestamp=_BASE_TIME + timedelta(minutes=i), user=name)
        for i, name in enumerate(names)
    )

    matches = evaluate(events)

    assert len(matches) == 1
    assert "user:Alice" in matches[0].description  # spelling from the earliest event


def test_host_grouping_is_case_insensitive() -> None:
    hosts = ["WIN-CLIENT01", "win-client01", "Win-Client01", "WIN-CLIENT01", "win-client01"]
    events = tuple(
        _event(f"rec-{i}", timestamp=_BASE_TIME + timedelta(minutes=i), host=name)
        for i, name in enumerate(hosts)
    )

    matches = evaluate(events)

    assert len(matches) == 1
    assert "host WIN-CLIENT01" in matches[0].description


def test_source_ip_grouping_folds_ipv6_hex_case() -> None:
    addresses = ["2001:DB8::1", "2001:db8::1", "2001:Db8::1", "2001:DB8::1", "2001:db8::1"]
    events = tuple(
        _event(
            f"rec-{i}",
            timestamp=_BASE_TIME + timedelta(minutes=i),
            user=None,
            source_ip=address,
        )
        for i, address in enumerate(addresses)
    )

    assert len(evaluate(events)) == 1


# --- Stage 17a: deduplication between the two dimensions ---


def test_same_events_in_both_dimensions_yield_single_match() -> None:
    events = _burst(
        5, start=_BASE_TIME, spacing=timedelta(minutes=1), source_ip="203.0.113.50"
    )

    matches = evaluate(events)

    assert len(matches) == 1
    assert "user:alice" in matches[0].description


def test_different_event_sets_in_both_dimensions_yield_two_matches() -> None:
    bob_events = tuple(
        _event(
            f"bob-{i}",
            timestamp=_BASE_TIME + timedelta(minutes=i),
            user="bob",
            source_ip="203.0.113.50",
        )
        for i in range(5)
    )
    others = tuple(
        _event(
            f"other-{i}",
            timestamp=_BASE_TIME + timedelta(minutes=5 + i),
            user=name,
            source_ip="203.0.113.50",
        )
        for i, name in enumerate(["carol", "dave", "erin"])
    )

    matches = evaluate((*bob_events, *others))

    assert len(matches) == 2
    user_match = next(m for m in matches if "user:bob" in m.description)
    ip_match = next(m for m in matches if "ip:203.0.113.50" in m.description)
    assert len(user_match.matched_event_ids) == 5
    assert len(ip_match.matched_event_ids) == 8


# --- Stage 17a: blank values behave like missing values ---


def test_blank_user_is_treated_as_missing() -> None:
    events = _burst(5, start=_BASE_TIME, spacing=timedelta(minutes=1), user="   ")

    assert evaluate(events) == ()


def test_blank_user_with_source_ip_still_groups_by_ip() -> None:
    events = _burst(
        5, start=_BASE_TIME, spacing=timedelta(minutes=1), user="   ", source_ip="203.0.113.50"
    )

    matches = evaluate(events)

    assert len(matches) == 1
    assert "ip:203.0.113.50" in matches[0].description


# --- Stage 17a: determinism ---


def test_result_is_independent_of_input_order() -> None:
    events = _burst(6, start=_BASE_TIME, spacing=timedelta(minutes=1))

    assert evaluate(events) == evaluate(tuple(reversed(events)))