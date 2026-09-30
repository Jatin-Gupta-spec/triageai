"""Shared identity normalization for rules and correlation.

Windows host names and account names are case-insensitive, and the
same visible text can be encoded in more than one Unicode form. Both
AUTH-001 and correlation must compare identities the same way.

Stage 18 addition: a value that parses as a valid IPv4 or IPv6
address (via the standard ipaddress module) is normalized to its
canonical string form instead of only being case-folded. This unifies
COMPRESSED and EXPANDED forms of the same IPv6 address
(2001:db8::1 vs 2001:0db8:0000:...:0001), which plain case-folding
never could. A value that is not IP-shaped falls through to the
previous NFC + casefold behavior unchanged.

This is for COMPARISON KEYS only. Reports keep displaying the
original spelling of a value; only grouping uses the normalized form.

Documented limits, not silently assumed solved:
- "DOMAIN\\alice", "alice@domain" and "alice" are NOT unified.
- A malformed or out-of-range IP-shaped string (e.g. an octet over
  255) simply fails ipaddress parsing and falls back to ordinary
  text comparison, same as any other string.
"""

from __future__ import annotations

import ipaddress
import unicodedata


def normalize_identity(value: str | None) -> str | None:
    """Return a comparison key for a host, user, IP, or similar value.

    Returns None for a missing or blank value, so callers treat ""
    and "   " exactly like an absent field instead of grouping
    unrelated events under an empty identity.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None

    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        pass

    composed = unicodedata.normalize("NFC", stripped)
    return unicodedata.normalize("NFC", composed.casefold())