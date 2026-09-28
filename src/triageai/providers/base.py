"""Interface every AI provider must implement.

Stage 17b: a provider now receives the FINAL, bounded prompt text --
exactly what prompt_builder.build_prompt produced from an already-
redacted Case -- and returns RAW TEXT. Previously the mock received a
Case object directly, so the injection-resistant prompt boundary this
project built was never the boundary a provider actually consumed.
Every provider, including future local or cloud ones, gets the same
input type.

Nothing a provider returns is trusted: output_validation.py and
hallucination_check.py decide whether it is accepted.
"""

from __future__ import annotations

from typing import Protocol


class ProviderError(Exception):
    """A provider could not produce output at all (for example, its
    prompt was malformed or a backend was unavailable). The caller
    treats this exactly like a rejected draft: no AI content is shown
    and the deterministic report is unaffected.
    """


class AIProvider(Protocol):
    def generate(self, prompt: str) -> str:
        """Return raw text, expected to be a JSON object matching the
        locked AI output schema -- but this method makes no such
        guarantee. Raise ProviderError if no output can be produced.
        """
        ...