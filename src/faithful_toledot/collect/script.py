# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The packaged PowerShell collector."""

from __future__ import annotations

import re
from importlib.resources import files

NAME = "Collect-ToledotEvents.ps1"
_VERSION = re.compile(r"^\$CollectorVersion = '([0-9]+\.[0-9]+\.[0-9]+)'$", re.MULTILINE)


def text() -> str:
    """Return the collector script.

    It is pure ASCII, so Windows PowerShell 5.1, which reads a file without a byte
    order mark in the system code page, reads it the same as PowerShell 7 does.
    """
    return files("faithful_toledot").joinpath(f"data/{NAME}").read_text(encoding="ascii")


def version() -> str:
    """Return the collector's own version, as it writes it into each file."""
    match = _VERSION.search(text())
    if match is None:  # pragma: no cover - guarded by a test on the packaged script
        msg = "the collector script states no version"
        raise ValueError(msg)
    return match.group(1)
