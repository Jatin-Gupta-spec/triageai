"""Core data models for TriageAI.

All models here represent evidence, not conclusions. They are frozen
(immutable) because once an event or case has been constructed, nothing
downstream -- not a rule, not correlation, not an AI provider -- is
allowed to silently rewrite what was observed.

Redaction is NOT applied to any field here. These models hold real,
internal values (see command_line, host, user, source_ip,
destination_ip) so that rules and correlation can compare real
identities. Redaction is applied only later, at the point a report or
AI prompt is actually rendered -- never here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum

# The one analyst-facing warning an AI draft may carry. It is defined
# here, in the application, so it can never depend on what a provider
# returns: output_validation.py requires a provider's text to match it
# exactly, and AIAnalysisDraft always carries this constant.
ANALYST_WARNING = "AI-generated draft requiring human review"


class Severity(IntEnum):
    """Case/rule severity, ordered low to high per the locked spec."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(IntEnum):
    """Case/rule confidence, ordered low to high per the locked spec."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """A single validated, normalized security event.

    Every field except `original_record_id` may be None if the source
    record did not provide it. Missing data is represented as None,
    never invented or defaulted to a placeholder value.

    `command_line` holds the REAL, unredacted command line. Redaction
    happens only when this event is rendered into a report or AI
    prompt -- never here.
    """

    original_record_id: str
    timestamp: datetime | None
    host: str | None
    user: str | None
    source: str | None
    event_id: str | None
    provider: str | None
    rule_id: str | None
    process: str | None
    parent_process: str | None
    command_line: str | None
    source_ip: str | None
    destination_ip: str | None
    mitre_techniques: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A deterministic detection produced by one of TriageAI's own rules.

    `rule_id` here is TriageAI's own catalogue ID (e.g. "AUTH-001") --
    not to be confused with NormalizedEvent.rule_id, which is whatever
    rule identifier the *source* SIEM (Wazuh) assigned to the raw
    event. Same field name, two different namespaces.
    """

    rule_id: str
    mitre_technique: str
    severity: Severity
    confidence: Confidence
    matched_event_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True, slots=True)
class Case:
    """A correlated group of events, with deterministic rule findings.

    `analyst_status` is always None in v0.1: this version has no
    interactive input and writes no state, so there is no mechanism
    yet for a human conclusion to be recorded. The field exists now so
    the shape doesn't change when that capability is added later.
    """

    case_id: str
    first_seen: datetime | None
    last_seen: datetime | None
    affected_hosts: tuple[str, ...]
    affected_users: tuple[str, ...]
    normalized_events: tuple[NormalizedEvent, ...]
    rule_matches: tuple[RuleMatch, ...]
    severity: Severity
    confidence: Confidence
    observed_facts: tuple[str, ...]
    evidence_gaps: tuple[str, ...]
    analyst_status: str | None = None


@dataclass(frozen=True, slots=True)
class AIAnalysisDraft:
    """An AI provider's structured, untrusted draft output.

    Every field is unverified prose or a claim awaiting validation
    except `analyst_warning`, which is always the application-defined
    ANALYST_WARNING constant -- never text supplied by a provider.
    """

    summary: str
    observations: tuple[str, ...]
    investigation_questions: tuple[str, ...]
    evidence_gaps: tuple[str, ...]
    possible_false_positives: tuple[str, ...]
    recommended_next_steps: tuple[str, ...]
    unsupported_claims: tuple[str, ...]
    analyst_warning: str = ANALYST_WARNING


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Run-level statistics for one complete `analyze` invocation."""

    total_records_read: int
    duplicate_count: int
    undated_count: int
    cases: tuple[Case, ...]

@dataclass(frozen=True, slots=True)
class AIDraftOutcome:
    """The result of one case's AI draft pipeline: either an accepted,
    validated draft, or a rejection with a short, fixed-wording reason.

    This is not observed evidence -- it is the shared contract between
    cli.py (which runs the pipeline) and the reporters (which render
    its result), which is why it lives alongside the evidence models
    rather than inside cli.py or a reporter module.

    `rejection_reason`, when present, is always one of a small set of
    fixed, short strings (see cli.py's REJECTION_* constants) -- never
    raw provider output, so a misbehaving or compromised provider can
    never inject arbitrary text into a rendered report through this
    field.
    """

    draft: AIAnalysisDraft | None
    rejection_reason: str | None = None