#!/usr/bin/env python3
"""Disabled repository mutation helper.

AGENTS.md forbids script-based changes to code in this repository. This file is
kept only as an audit artifact so historical references do not break.
"""

import sys


def main() -> int:
    print(
        "allow_clippy_tests.py is disabled: AGENTS.md forbids script-based code rewrites.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
