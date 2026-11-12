# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Writing times as text the same way on every platform."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


def date_and_time(moment: datetime, separator: str = "T") -> str:
    """Return ``YYYY-MM-DD`` and ``HH:MM:SS`` joined by ``separator``.

    ``strftime("%Y")`` is not used: on Linux it writes year 1 as ``1`` rather than
    ``0001``, which no reader of these files accepts.
    """
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}{separator}"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
    )
