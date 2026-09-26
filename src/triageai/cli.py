"""Command-line interface for TriageAI.

main(argv) contains all real logic and is fully testable in isolation,
without ever invoking a subprocess or touching sys.argv.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TriageAI CLI.

    Args:
        argv: Command-line arguments, excluding the program name.
            Defaults to sys.argv[1:] when None.

    Returns:
        Process exit code: 0 on success, 2 for input/processing errors,
        3 for usage errors.
    """
    args = list(argv) if argv is not None else sys.argv[1:]

    if not args:
        print("usage: triageai analyze <path> [--format text|markdown]", file=sys.stderr)
        return 3

    print(f"TriageAI stage 2 placeholder. Received args: {args}")
    return 0