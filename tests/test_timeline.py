"""Tests for src/triageai/reporters/timeline.py."""

from __future__ import annotations

from datetime import UTC, datetime

from triageai.models import NormalizedEvent
from triageai.reporters.timeline import build_timeline


def _event(record_id: str, timestamp: datetime | None) -> NormalizedEvent:
    return NormalizedEvent(
        original_record_id=record_id,
        timestamp=timestamp,
        host=None,
        user=None,
        source=None,
        event_id=None,
        provider=None,
        rule_id=None,
        process=None,
        parent_process=None,
        command_line=None,
        source_ip=None,
        destination_ip=None,
        mitre_techniques=(),
    )


def test_sorts_dated_events_chronologically() -> None:
    early = _event("rec-1", datetime(2026, 1, 1, tzinfo=UTC))
    late = _event("rec-2", datetime(2026, 1, 2, tzinfo=UTC))

    result = build_timeline((late, early))

    assert result == (early, late)


def test_undated_events_sort_after_dated_events() -> None:
    dated = _event("rec-1", datetime(2026, 1, 1, tzinfo=UTC))
    undated = _event("rec-2", None)

    result = build_timeline((undated, dated))

    assert result == (dated, undated)


def test_ties_break_by_record_id() -> None:
    same_time = datetime(2026, 1, 1, tzinfo=UTC)
    b = _event("rec-b", same_time)
    a = _event("rec-a", same_time)

    result = build_timeline((b, a))

    assert result == (a, b)


def test_multiple_undated_events_sort_by_record_id() -> None:
    z = _event("rec-z", None)
    a = _event("rec-a", None)

    result = build_timeline((z, a))

    assert result == (a, z)


def test_no_events_lost_or_duplicated() -> None:
    events = tuple(_event(f"rec-{i}", None) for i in range(5))
    result = build_timeline(events)
    assert len(result) == 5
    assert set(result) == set(events)