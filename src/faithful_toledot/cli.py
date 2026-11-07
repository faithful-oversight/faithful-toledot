# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point."""

from __future__ import annotations

import argparse
from enum import IntEnum
from typing import TYPE_CHECKING

from faithful_toledot import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence


class ExitCode(IntEnum):
    """Process exit codes. These values are part of the public interface."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    INPUT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="toledot",
        description="AD Change Narrative.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return an exit code."""
    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else int(ExitCode.USAGE)
    parser.print_help()
    return int(ExitCode.OK)
