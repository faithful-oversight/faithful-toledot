# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - parametrised cases read best one per line
"""Tests for the command-line entry point."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from faithful_toledot import __version__
from faithful_toledot.cli import ExitCode, main
from faithful_toledot.formats.bundle import encode

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


def test_two_inputs_with_the_same_name_are_refused_before_analysis(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first, second = files_of(sample)
    (sample / "a").mkdir()
    (sample / "b").mkdir()
    shutil.copy(first, sample / "a" / "events.jsonl")
    shutil.copy(second, sample / "b" / "events.jsonl")
    out = sample / "dup"
    args = ["report", str(sample / "a" / "events.jsonl"), str(sample / "b" / "events.jsonl")]
    assert main([*args, "-o", str(out)]) == ExitCode.INPUT_ERROR
    err = capsys.readouterr().err
    assert "two input files are named events.jsonl" in err
    assert "rename one so every citation names one file" in err
    assert not out.exists()


@pytest.mark.skipif(
    sys.platform in ("win32", "darwin"),
    reason="this file system rejects file names that are not valid UTF-8",
)
def test_names_that_only_match_once_escaped_are_refused(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first, second = files_of(sample)
    raw = os.fsdecode(os.fsencode(sample) + b"/dup\xff.jsonl")  # a real 0xff byte
    literal = sample / "dup\\xff.jsonl"  # the four characters backslash, x, f, f
    shutil.copy(first, raw)
    shutil.copy(second, literal)
    assert main(["report", raw, str(literal), "-o", str(sample / "esc")]) == ExitCode.INPUT_ERROR
    assert "two input files are named dup\\xff.jsonl" in capsys.readouterr().err


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


@pytest.mark.parametrize(
    "when",
    [datetime(1, 1, 1, tzinfo=UTC), datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)],
)
def test_events_at_the_ends_of_time_are_reported_not_crashed_on(
    tmp_path: Path, when: datetime
) -> None:
    from tests.helpers import logon, member_added  # noqa: PLC0415
    from tests.test_formats_bundle import header  # noqa: PLC0415

    events = [replace(e, time=when) for e in (logon(), member_added(), member_added(1))]
    path = tmp_path / "edge.jsonl"
    path.write_bytes(encode(header(), events))
    out = tmp_path / "out"
    assert (
        main(["report", str(path), "-o", str(out), "-f", "json", "--fail-on", "never"])
        == ExitCode.OK
    )
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    assert [c["related_total"] for c in report["changes"]] == [1, 1]


@pytest.mark.parametrize("formats", ["html", "md", "html,md,csv"])
def test_a_report_without_json_never_points_to_it(tmp_path: Path, formats: str) -> None:
    from tests.helpers import event  # noqa: PLC0415
    from tests.test_formats_bundle import header  # noqa: PLC0415

    cleared = [event(1102, {"SubjectUserSid": "S-1-5-21-1-2-3-1104"}, seconds=i) for i in range(30)]
    path = tmp_path / "cleared.jsonl"
    path.write_bytes(encode(header(), cleared))
    out = tmp_path / "out"
    assert main(["report", str(path), "-o", str(out), "-f", formats]) == ExitCode.FINDINGS
    for written in out.iterdir():
        text = written.read_text(encoding="utf-8")
        assert "JSON report" not in text, written.name
    assert "toledot-report.json" not in {p.name for p in out.iterdir()}


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="a backslash separates folders on Windows, so no file name can hold the text \\u200b",
)
def test_names_that_print_the_same_are_refused(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hidden = sample / "dc\u200b01.jsonl"
    literal = sample / "dc\\u200b01.jsonl"
    data = (sample / "dc01-events.jsonl").read_bytes()
    hidden.write_bytes(data)
    literal.write_bytes(data + b"\n")
    assert (
        main(["report", str(hidden), str(literal), "-o", str(sample / "r")]) == ExitCode.INPUT_ERROR
    )
    assert "rename one" in capsys.readouterr().err


# --- printing never changes the exit code ------------------------------------------------------


class _ClosedPipe:
    """A stdout whose reader has gone away."""

    def write(self, text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        raise BrokenPipeError(32, "Broken pipe")


FIVE_FILES = [
    "toledot-changes.csv",
    "toledot-manifest.json",
    "toledot-report.html",
    "toledot-report.json",
    "toledot-report.md",
]


def _run_with_stdout(stream: object, monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "stdout", stream)
    return main(argv)


def test_a_closed_pipe_keeps_the_real_exit_code_and_complete_files(
    sample: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "reports"
    argv = ["report", *files_of(sample), "-o", str(out)]
    # The example is an incomplete account: exit 1, not 4.
    assert _run_with_stdout(_ClosedPipe(), monkeypatch, argv) == ExitCode.FINDINGS
    assert sorted(p.name for p in out.iterdir()) == FIVE_FILES
    json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    again = tmp_path / "never"
    assert (
        _run_with_stdout(_ClosedPipe(), monkeypatch, [*argv[:-1], str(again), "--fail-on", "never"])
        == ExitCode.OK
    )


@pytest.mark.parametrize("command", [["events"], ["schema", "report"], ["--help"], ["--version"]])
def test_a_closed_pipe_is_never_an_internal_error(
    command: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run_with_stdout(_ClosedPipe(), monkeypatch, command) == ExitCode.OK


def test_example_and_collector_survive_a_closed_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run_with_stdout(_ClosedPipe(), monkeypatch, ["example", str(tmp_path / "e")]) == 0
    assert len(list((tmp_path / "e").iterdir())) == 2
    argv = ["collector", "-o", str(tmp_path / "c" / "Collect.ps1")]
    assert _run_with_stdout(_ClosedPipe(), monkeypatch, argv) == 0
    assert (tmp_path / "c" / "Collect.ps1").is_file()


def test_ascii_only_output_with_a_non_ascii_path_keeps_the_exit_code(
    sample: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out-é中"
    env = {**os.environ, "PYTHONIOENCODING": "ascii", "SOURCE_DATE_EPOCH": "1762905600"}
    env.pop("PYTHONUTF8", None)
    run = subprocess.run(  # noqa: S603 - the interpreter running these tests
        [sys.executable, "-m", "faithful_toledot", "report", *files_of(sample), "-o", str(out)],
        env=env, capture_output=True, check=False, timeout=120,
    )  # fmt: skip
    assert run.returncode == ExitCode.FINDINGS, run.stderr
    assert b"internal error" not in run.stderr
    assert b"out-\\xe9\\u4e2d" in run.stdout
    assert sorted(p.name for p in out.iterdir()) == FIVE_FILES


def test_a_closed_pipe_in_a_real_pipeline_is_not_exit_4() -> None:
    reader, writer = os.pipe()
    os.close(reader)  # nobody will read: every write fails with a broken pipe
    run = subprocess.run(
        [sys.executable, "-m", "faithful_toledot", "events"],
        stdout=writer, stderr=subprocess.PIPE, check=False, timeout=120,
    )  # fmt: skip
    os.close(writer)
    assert run.returncode == ExitCode.OK, run.stderr
    assert b"internal error" not in run.stderr


def test_an_unreadable_input_is_named_with_the_path_the_user_gave(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "no" / "such" / "dir" / "a.jsonl"
    assert main(["report", str(missing), "-o", str(tmp_path / "r")]) == ExitCode.INPUT_ERROR
    err = capsys.readouterr().err
    assert str(missing) in err
    assert "cannot read" in err


def test_the_secret_help_names_the_vault_form_the_docs_and_errors_use(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["collect", "--help"]) == ExitCode.OK
    help_text = " ".join(capsys.readouterr().out.split())
    assert "vault:MOUNT/PATH#FIELD" in help_text


def test_the_events_command_explains_the_catalog(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["events", "--help"]) == ExitCode.OK
    assert "catalog" in " ".join(capsys.readouterr().out.split())


# --- review finding TOL-2: one unnumbered event leaves a log unconfirmed -----------------------


def _run_numbered(
    tmp_path: Path, numbers: list[int | None], *flags: str
) -> tuple[int, dict[str, Any]]:
    from tests.test_formats_json import record  # noqa: PLC0415

    path = tmp_path / "events.json"
    path.write_text(
        json.dumps([record(RecordId=number, Id=4720) for number in numbers]), encoding="utf-8"
    )
    out = tmp_path / "out"
    code = main(["report", str(path), "-o", str(out), "-f", "json", *flags])
    report = json.loads((out / "toledot-report.json").read_text(encoding="utf-8"))
    return code, report


@pytest.mark.parametrize(
    ("numbers", "code", "completeness", "continuity", "unnumbered"),
    [
        ([100, 101], ExitCode.OK, "complete", "complete", 0),
        ([None, None], ExitCode.FINDINGS, "unconfirmed", "unnumbered", 2),
        ([100, None], ExitCode.FINDINGS, "unconfirmed", "partly-numbered", 1),
        ([100, 101, None, None], ExitCode.FINDINGS, "unconfirmed", "partly-numbered", 2),
    ],
)
def test_one_event_without_a_record_number_fails_the_unconfirmed_gate(  # noqa: PLR0913, PLR0917 - one argument per column of the case
    tmp_path: Path,
    numbers: list[int | None],
    code: int,
    completeness: str,
    continuity: str,
    unnumbered: int,
) -> None:
    exit_code, report = _run_numbered(tmp_path, numbers, "--whole-logs")
    assert exit_code == code
    assert report["summary"]["completeness"] == completeness
    assert report["summary"]["complete"] is (completeness == "complete")
    (log,) = report["coverage"]
    assert (log["continuity"], log["unnumbered"], log["checked"]) == (
        continuity,
        unnumbered,
        completeness == "complete",
    )
    assert ("cannot tell" in log["statement"]) is (unnumbered > 0)


def test_unnumbered_events_are_not_incomplete_only_unconfirmed(tmp_path: Path) -> None:
    code, report = _run_numbered(tmp_path, [100, None], "--whole-logs", "--fail-on", "incomplete")
    assert code == ExitCode.OK
    assert report["summary"]["completeness"] == "unconfirmed"


# --- an output is never an input (the PAK-1 / MER-1 class) -------------------------------------


def _events_file(path: Path) -> bytes:
    """Write a readable collection file at path and return its bytes."""
    from tests.helpers import member_added  # noqa: PLC0415
    from tests.test_formats_bundle import header  # noqa: PLC0415

    data = encode(header(), [member_added()])
    path.write_bytes(data)
    return data


@pytest.mark.parametrize(
    "name", ["toledot-report.json", "toledot-manifest.json", "toledot-changes.csv"]
)
@pytest.mark.parametrize("kind", ["same path", "dotdot", "symlink", "hardlink"])
def test_a_report_never_replaces_an_input_even_with_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str, kind: str
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    evidence = tmp_path / "evidence.jsonl"
    data = _events_file(evidence)
    target = out / name
    given = evidence
    try:
        if kind == "symlink":
            target.symlink_to(evidence)
        elif kind == "hardlink":
            os.link(evidence, target)
        elif kind == "dotdot":
            data = _events_file(target)
            given = out / ".." / "out" / name
        else:
            data = _events_file(target)
            given = target
    except (OSError, NotImplementedError):
        pytest.skip(f"{kind}s are not available here")
    before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    code = main(["report", str(given), "-o", str(out), "--force", "--fail-on", "never"])
    assert code == ExitCode.INPUT_ERROR
    assert "same file as the input file" in capsys.readouterr().err
    after = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before
    assert (given if kind not in {"symlink", "hardlink"} else evidence).read_bytes() == data
    assert not list(out.glob(".toledot-*"))
    assert sorted(p.name for p in out.iterdir()) == [name]  # nothing else was published


def test_a_report_into_the_inputs_own_folder_still_works_when_no_name_collides(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "events.jsonl"
    data = _events_file(evidence)
    assert main(["report", str(evidence), "-o", str(tmp_path), "--fail-on", "never"]) == ExitCode.OK
    assert evidence.read_bytes() == data
