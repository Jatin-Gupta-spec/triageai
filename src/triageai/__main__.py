"""Enables `python -m triageai ...`."""

import sys

from triageai.cli import main

if __name__ == "__main__":
    sys.exit(main())