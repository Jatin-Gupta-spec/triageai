"""Interface every AI provider must implement.

A provider receives an ALREADY-REDACTED Case (see redaction.py) and
returns RAW TEXT -- the same shape a real HTTP API response would
take, whether or not this particular provider is actually an API.
Nothing at this boundary is trusted: output_validation.py is solely
responsible for turning that raw text into a trusted AIAnalysisDraft,
or rejecting it outright. This project's core principle applies
without exception here: nothing a provider returns is treated as fact
until validated.
"""

from __future__ import annotations

from typing import Protocol

from triageai.models import Case


class AIProvider(Protocol):
    def generate(self, redacted_case: Case) -> str:
        """Return raw text, expected to be a JSON object matching the
        locked AI output schema -- but this method makes no such
        guarantee. Malformed or incomplete text is exactly what
        output_validation.py exists to catch.
        """
        ...