"""Deterministic triage rules. Each rule is a pure function:
tuple[NormalizedEvent, ...] -> tuple[RuleMatch, ...].
"""