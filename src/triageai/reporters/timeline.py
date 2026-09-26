"""Builds a deterministic, sorted timeline from normalized events.

Sorting rule, stated explicitly because the locked spec doesn't pin
one down for this exact case: primarily by timestamp, ascending.
Undated events (timestamp is None) sort AFTER all dated events, per
Section 5's "exclude undated records from ... the timeline" -- read
here as "exclude from the ORDERING logic," not "never show them at
all," since evidence integrity means an undated event must still be
visible somewhere, just not mixed into time-based ordering. Within
equal timestamps (dated) or among undated events, original_record_id
breaks ties, since it's the one other value guaranteed unique and
stable.
"""

from __future__ import annotations

from triageai.models import NormalizedEvent


def build_timeline(events: tuple[NormalizedEvent, ...]) -> tuple[NormalizedEvent, ...]:
    """Return events sorted for deterministic display.

    Does not filter or mutate -- every event supplied is present in
    the output, dated events sorted chronologically first, undated
    events listed afterward.
    """
    dated = [e for e in events if e.timestamp is not None]
    undated = [e for e in events if e.timestamp is None]

    dated.sort(key=lambda e: (e.timestamp, e.original_record_id))
    undated.sort(key=lambda e: e.original_record_id)

    return tuple(dated) + tuple(undated)