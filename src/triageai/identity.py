"""Shared identity normalization for rules and correlation.

Windows host names and account names are case-insensitive, and the
same visible text can be encoded in more than one Unicode form. Both
AUTH-001 and correlation must compare identities the same way,
otherwise a rule and the case grouping around it can disagree about
whether two events involve the same account or machine.

This module is for COMPARISON KEYS only. Reports keep displaying the
original spelling of a value; only grouping uses the normalized form.

Documented limits, not silently assumed solved:
- "DOMAIN\\alice", "alice@domain" and "alice" are NOT unified.
- Textually different but equivalent IPv6 forms (for example a
  compressed and an expanded form) are NOT unified. IPv6 hex case
  is unified by casefolding.
"""

from __future__ import annotations

import unicodedata


def normalize_identity(value: str | None) -> str | None:
    """Return a comparison key for a host, user, or IP value.

    Returns None for a missing or blank value, so callers treat
    "" and "   " exactly like an absent field instead of grouping
    unrelated events under an empty identity.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    composed = unicodedata.normalize("NFC", stripped)
    return unicodedata.normalize("NFC", composed.casefold())