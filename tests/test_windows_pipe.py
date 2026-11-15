# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Windows reports a closed pipe as OSError EINVAL, not BrokenPipeError."""

from __future__ import annotations

import errno
import io
import sys
from typing import TYPE_CHECKING

from faithful_toledot import console

if TYPE_CHECKING:
    import pytest


class ClosedPipe(io.StringIO):
    """A stdout whose reader has gone away, as Windows reports it."""

    def write(self, _text: str) -> int:
        raise OSError(errno.EINVAL, "Invalid argument")

    def flush(self) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")


def test_a_windows_closed_pipe_stops_printing_and_replaces_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = ClosedPipe()
    monkeypatch.setattr(sys, "stdout", closed)
    console.say("x")
    replacement = sys.stdout
    try:
        assert replacement is not closed
        replacement.write("after\n")
        replacement.flush()
    finally:
        if replacement is not closed:
            replacement.close()
