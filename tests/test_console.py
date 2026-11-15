# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Printing helpers that keep a finished run's exit code."""

from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING

from faithful_toledot import console

if TYPE_CHECKING:
    import pytest


class _Refusing(io.StringIO):
    def reconfigure(self, **_: object) -> None:
        msg = "this stream cannot be reconfigured"
        raise ValueError(msg)


class _Full(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError(28, "No space left on device")


def test_a_stream_that_refuses_reconfiguration_is_left_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _Refusing()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", _Refusing())
    console.harden_streams()
    console.say("still prints")
    assert stream.getvalue() == "still prints\n"


def test_a_stream_that_can_be_reconfigured_escapes_what_it_cannot_encode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", newline="\n")
    monkeypatch.setattr(sys, "stdout", stream)
    console.harden_streams()
    console.say("na\u00efve")
    assert raw.getvalue() == b"na\\xefve\n"


def test_a_stdout_that_cannot_take_the_text_stops_printing_without_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdout", _Full())
    console.harden_streams()
    console.say("one")
    console.say("two")  # skipped: output has stopped


def test_a_broken_stderr_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stderr", _Full())
    console.say("a message", error=True)
