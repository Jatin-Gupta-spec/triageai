"""Shared exception types for TriageAI's input pipeline."""

from __future__ import annotations


class TriageInputError(Exception):
    """Any problem reading, decoding, parsing, or bounding input.

    Always corresponds to CLI exit code 2 (input/validation/processing
    error) per the locked operational contract. Usage errors (missing
    arguments, bad flags) are handled separately in cli.py and use
    exit code 3, never this exception.
    """