# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Argument types shared by the commands."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def moment(text: str) -> datetime:
    """Parse a date and time that states its UTC offset, and return it in UTC.

    A time without an offset is refused: read on another computer it would mean
    another moment.
    """
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        value = None
    if value is None or value.tzinfo is None:
        msg = (
            f"{text!r} is not a time with a UTC offset; write it like "
            "2026-11-03T14:00:00Z or 2026-11-03T08:00:00-06:00"
        )
        raise argparse.ArgumentTypeError(msg)
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        msg = (
            f"{text!r} is outside the years toledot can handle; "
            "give a time that is still within the years 1 to 9999 in UTC"
        )
        raise argparse.ArgumentTypeError(msg) from None


def bounded(low: int, high: int, what: str) -> Callable[[str], int]:
    """Return an argument type that accepts a whole number from ``low`` to ``high``."""

    def check(text: str) -> int:
        if not text.isdigit() or not low <= int(text) <= high:
            msg = f"give {what} from {low} to {high}"
            raise argparse.ArgumentTypeError(msg)
        return int(text)

    check.__name__ = what
    return check
