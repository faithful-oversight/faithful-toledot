# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the command-line entry point."""

from __future__ import annotations

import runpy
import sys

import pytest
from hypothesis import given
from hypothesis import strategies as st

from faithful_toledot import __version__
from faithful_toledot.cli import ExitCode, main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == ExitCode.OK
    assert __version__ in capsys.readouterr().out


def test_no_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == ExitCode.OK
    assert "usage: toledot" in capsys.readouterr().out


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-such-option"]) == ExitCode.USAGE
    assert "unrecognized arguments" in capsys.readouterr().err


def test_exit_codes_are_stable() -> None:
    assert [int(code) for code in ExitCode] == [0, 1, 2, 3]


@given(st.lists(st.text().map(lambda s: "--x" + s), min_size=1))
def test_unknown_options_never_crash(argv: list[str]) -> None:
    assert main(argv) == ExitCode.USAGE


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["toledot", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("faithful_toledot", run_name="__main__")
    assert exc.value.code == ExitCode.OK
