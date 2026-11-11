# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - parametrised cases read best one per line
"""Tests for the command-line entry point."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import sys
from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from faithful_toledot import __version__
from faithful_toledot.cli import ExitCode, main

if TYPE_CHECKING:
    from pathlib import Path


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == ExitCode.OK
    assert __version__ in capsys.readouterr().out


def test_no_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == ExitCode.USAGE
    assert "usage: toledot" in capsys.readouterr().err


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-such-option"]) == ExitCode.USAGE
    assert "unrecognized arguments" in capsys.readouterr().err


def test_exit_codes_are_stable() -> None:
    assert [int(code) for code in ExitCode] == [0, 1, 2, 3, 4]


@given(st.lists(st.text().map(lambda s: "--x" + s), min_size=1))
def test_unknown_options_never_crash(argv: list[str]) -> None:
    assert main(argv) == ExitCode.USAGE


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["toledot", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("faithful_toledot", run_name="__main__")
    assert exc.value.code == ExitCode.OK


# --- example, report, events, schema --------------------------------------------------------


@pytest.fixture
def sample(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    folder = tmp_path / "my sample"
    assert main(["example", str(folder)]) == ExitCode.OK
    printed = capsys.readouterr().out
    assert "toledot report" in printed
    assert "'" in printed or '"' in printed  # the folder name with a space is quoted
    return folder


def files_of(folder: Path) -> list[str]:
    return sorted(str(path) for path in folder.glob("*.jsonl"))


def test_the_example_reads_as_an_incomplete_account(
    sample: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1762905600")
    out = sample / "report"
    assert main(["report", *files_of(sample), "-o", str(out)]) == ExitCode.FINDINGS
    printed = capsys.readouterr().out
    assert "15 changes described, but the account is incomplete" in printed
    assert "Reports written to" in printed
    names = sorted(path.name for path in out.iterdir())
    assert names == [
        "toledot-changes.csv", "toledot-manifest.json", "toledot-report.html",
        "toledot-report.json", "toledot-report.md",
    ]  # fmt: skip
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    assert report["generated_at"] == "2025-11-12T00:00:00Z"
    assert [item["format"] for item in report["inputs"]] == ["collection", "collection"]
    assert (
        main(["report", *files_of(sample), "-o", str(out), "--fail-on", "never", "--force"])
        == ExitCode.OK
    )


def test_the_window_and_formats_are_applied(sample: Path) -> None:
    out = sample / "window"
    args = ["report", *files_of(sample), "-o", str(out), "-f", "json, md",
            "--since", "2026-11-03T00:00:00Z", "--until", "2026-11-04T00:00:00+00:00"]  # fmt: skip
    main(args)
    assert sorted(path.name for path in out.iterdir()) == [
        "toledot-manifest.json", "toledot-report.json", "toledot-report.md",
    ]  # fmt: skip
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    assert report["window"] == {"since": "2026-11-03T00:00:00Z", "until": "2026-11-04T00:00:00Z"}
    assert {change["time"][:10] for change in report["changes"]} == {"2026-11-03"}


@pytest.mark.skipif(
    sys.platform in ("win32", "darwin"),
    reason="this file system rejects file names that are not valid UTF-8",
)
def test_a_file_name_that_is_not_utf8_is_shown_escaped(sample: Path) -> None:
    bad = os.fsdecode(os.fsencode(sample) + b"/bad\xff.jsonl")
    shutil.copy(files_of(sample)[0], bad)
    out = sample / "badname"
    assert main(["report", bad, "-o", str(out), "--fail-on", "never"]) == ExitCode.OK
    document = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in document["inputs"]] == ["bad\\xff.jsonl"]
    assert "xff.jsonl" in (out / "toledot-report.md").read_text(
        encoding="utf-8"
    )  # escaped by Markdown


def test_whole_logs_make_absent_records_missing_events(sample: Path) -> None:
    out = sample / "whole"
    main(["report", files_of(sample)[0], "-o", str(out), "--whole-logs", "-f", "json"])
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    assert report["inputs"][0]["scope"] == "unfiltered"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            ["--since", "2026-11-05T00:00:00Z", "--until", "2026-11-04T00:00:00Z"],
            "--since must be earlier",
        ),
    ],
)
def test_report_errors(
    sample: Path, capsys: pytest.CaptureFixture[str], extra: list[str], message: str
) -> None:
    assert main(["report", *files_of(sample), "-o", str(sample / "r"), *extra]) == ExitCode.USAGE
    assert message in capsys.readouterr().err


def test_the_same_file_twice_and_unknown_files_are_input_errors(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = files_of(sample)[0]
    assert main(["report", first, first, "-o", str(sample / "r")]) == ExitCode.INPUT_ERROR
    assert "has the same contents as" in capsys.readouterr().err
    odd = sample / "notes.txt"
    odd.write_text("hello", encoding="utf-8")
    assert main(["report", str(odd), "-o", str(sample / "r")]) == ExitCode.INPUT_ERROR
    assert "is not an event log toledot can read" in capsys.readouterr().err
    assert (
        main(["report", str(sample / "gone.evtx"), "-o", str(sample / "r")]) == ExitCode.INPUT_ERROR
    )


@pytest.mark.parametrize(
    "extra",
    [
        ["--since", "2026-11-03"],
        ["--since", "soon"],
        ["--since", "9999-12-31T23:59:59-14:00"],
        ["--until", "0001-01-01T00:00:00+14:00"],
        ["--local-offset", "6"],
        ["--local-offset", "+15:00"],
        ["--local-offset", "+14:30"],
        ["--local-offset", "-05:60"],
        ["-f", "pdf"],
        ["-f", ","],
        ["--date-order", "year-first"],
    ],
)
def test_option_values_are_checked(sample: Path, extra: list[str]) -> None:
    assert main(["report", *files_of(sample), "-o", str(sample / "r"), *extra]) == ExitCode.USAGE


@pytest.mark.parametrize(
    "extra",
    [
        ["--since", "9999-12-31T23:59:59-14:00"],
        ["--until", "0001-01-01T00:00:00+14:00"],
    ],
)
def test_out_of_range_times_are_usage_errors_not_crashes(
    sample: Path, capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    code = main(["report", *files_of(sample), "-o", str(sample / "r"), *extra])
    captured = capsys.readouterr().err
    assert code == ExitCode.USAGE
    assert "outside the years toledot can handle" in captured
    assert "Traceback" not in captured
    assert "internal error" not in captured


def test_csv_options_reach_the_reader(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    csv_file = tmp_path / "viewer.csv"
    csv_file.write_text(
        "Level,Date and Time,Source,Event ID,Task Category\r\n"
        "Information,03/11/2026 14:00:00,Microsoft Windows security auditing.,4725,User Account Management,"
        '"A user account was disabled.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-1-2-3-1104\r\n'
        "\tAccount Name:\t\talice\r\n\tAccount Domain:\t\tCORP\r\n\tLogon ID:\t\t0x5F1A2\r\n\r\n"
        "Target Account:\r\n\tSecurity ID:\t\tS-1-5-21-1-2-3-1105\r\n\tAccount Name:\t\tbob\r\n"
        '\tAccount Domain:\t\tCORP"\r\n',
        encoding="utf-8",
    )
    out = tmp_path / "r"
    assert main(["report", str(csv_file), "-o", str(out)]) == ExitCode.INPUT_ERROR
    assert "--local-offset" in capsys.readouterr().err
    args = ["report", str(csv_file), "-o", str(out), "-f", "json", "--local-offset", "-06:00",
            "--date-order", "day-first", "--fail-on", "never"]  # fmt: skip
    assert main(args) == ExitCode.OK
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    (change,) = report["changes"]
    assert (change["time"], change["action"]) == ("2026-11-03T20:00:00Z", "disabled")


def test_events_lists_the_catalog(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["events"]) == ExitCode.OK
    printed = capsys.readouterr().out
    assert "4728" in printed
    assert "partly inferred" in printed


@pytest.mark.parametrize("name", ["report", "events", "manifest"])
def test_schema_prints_valid_json(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema", name]) == ExitCode.OK
    assert json.loads(capsys.readouterr().out)["$schema"].startswith("https://json-schema.org/")


def test_an_internal_error_is_reported_as_a_bug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from faithful_toledot import cli  # noqa: PLC0415

    def boom(_: object) -> int:
        msg = "unexpected"
        raise RuntimeError(msg)

    monkeypatch.setattr(cli, "_events", boom)
    assert main(["events"]) == ExitCode.INTERNAL_ERROR
    assert "This is a bug in toledot" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["", "abc", "99999999999999999999"])
def test_a_bad_source_date_epoch_falls_back_to_the_clock(
    sample: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", value)
    out = sample / "clock"
    main(["report", *files_of(sample), "-o", str(out), "-f", "json", "--force"])
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    assert report["generated_at"].startswith("20")
