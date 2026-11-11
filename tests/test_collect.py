# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - parametrised cases read best one per line
"""Remote collection over PowerShell remoting, and the collect commands.

Set ``TOLEDOT_REQUIRE_LIVE=1`` to fail instead of skipping when the ``live`` extra
(pypsrp) is missing.
"""

from __future__ import annotations

import errno
import importlib
import os
import sys
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from faithful_toledot.cli import ExitCode, main
from faithful_toledot.collect import names, remote, script, secrets
from faithful_toledot.collect.remote import Target, collect, parameters, settings
from faithful_toledot.errors import CollectionError
from faithful_toledot.events import Event, Problem, ReadOptions
from faithful_toledot.formats import bundle
from faithful_toledot.formats.bundle import encode, read_bundle
from tests.helpers import at, logon, member_added
from tests.test_formats_bundle import header

if os.environ.get("TOLEDOT_REQUIRE_LIVE") == "1":  # pragma: no cover - set in CI
    # Fail at collection, not skip, when the live extra is missing. Imported by name so
    # type checking does not need the extra installed.
    importlib.import_module("pypsrp")

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

SECRET = 'p@ss w/rd%"\\ü'  # noqa: S105 - synthetic
SERVER = "dc01.corp.example"
TARGET = Target(SERVER, "kerberos", "CORP\\auditor", SECRET)
GOOD = encode(
    header(collector={"name": "c", "version": "0.1.0", "method": "psrp"}), [logon(), member_added()]
)
LINES = GOOD.decode("ascii").splitlines()
RUNNING, COMPLETED, FAILED = 1, 4, 5


# --- names ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "problem"),
    [
        ("10.0.0.5", "is an IP address"),
        ("[fe80::1]", "is an IP address"),
        ("dc01", "not a fully qualified DNS name"),
        ("dc01.corp.example/x", "not a fully qualified DNS name"),
        ("u:p@dc01.corp.example", "not a fully qualified DNS name"),
        ("-dc.corp.example", "not a fully qualified DNS name"),
        ("dc01.10", "not a fully qualified DNS name"),
        ("a" * 64 + ".corp.example", "not a fully qualified DNS name"),
        ("a." * 127 + "example", "not a fully qualified DNS name"),
    ],
)
def test_server_must_be_a_dns_name(server: str, problem: str) -> None:
    with pytest.raises(CollectionError, match=problem):
        names.server_name(server)


def test_server_names_and_usernames_that_are_accepted() -> None:
    assert names.server_name("DC01.Corp.Example.") == "DC01.Corp.Example"
    assert names.account_name("CORP\\auditor") == "CORP\\auditor"
    assert names.account_name("auditor@corp.example") == "corp.example\\auditor"
    assert names.account_name(None) is None


@pytest.mark.parametrize(
    "username", ["auditor", "\\auditor", "CORP\\", "@corp.example", "C\\a:b", "C\\u\n"]
)
def test_a_username_needs_a_domain(username: str) -> None:
    with pytest.raises(CollectionError, match="must be DOMAIN"):
        names.account_name(username)


# --- transport settings -----------------------------------------------------------------


def test_https_always_verifies_the_certificate(tmp_path: Path) -> None:
    values = settings(TARGET)
    assert (values["ssl"], values["port"], values["cert_validation"], values["encryption"]) == (
        True, 5986, True, "auto",
    )  # fmt: skip
    ca = tmp_path / "corp-ca.pem"
    with_ca = settings(replace(TARGET, ca_file=ca, port=443))
    assert (with_ca["cert_validation"], with_ca["port"]) == (str(ca), 443)


@pytest.mark.parametrize("auth", remote.AUTHS)
def test_http_is_used_only_with_message_encryption(auth: str) -> None:
    values = settings(replace(TARGET, auth=auth, transport="http"))
    assert (values["ssl"], values["port"], values["encryption"]) == (False, 5985, "always")


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"auth": "basic"}, "--auth must be one of"),
        ({"auth": "credssp"}, "--auth must be one of"),
        ({"transport": "ftp"}, "--auth must be one of"),
        ({"transport": "http", "ca_file": "x.pem"}, "--ca-file applies to https only"),
    ],
)
def test_insecure_combinations_are_refused(changes: dict[str, Any], problem: str) -> None:
    with pytest.raises(CollectionError, match=problem):
        settings(replace(TARGET, **changes))


@pytest.mark.parametrize(("transport", "wrapped"), [("https", False), ("http", True)])
def test_the_settings_reach_the_real_transport(transport: str, *, wrapped: bool) -> None:
    """The real pypsrp transport keeps verification on and wraps plain HTTP."""
    wsman_module = pytest.importorskip("pypsrp.wsman")
    wsman = wsman_module.WSMan(**settings(replace(TARGET, transport=transport, auth="ntlm")))
    transport_object = wsman.transport
    assert transport_object.cert_validation is True
    assert transport_object.ssl is (transport == "https")
    assert transport_object.wrap_required is wrapped
    assert transport_object.endpoint.startswith(f"{transport}://{SERVER}:")


def test_script_parameters() -> None:
    values = parameters(at(0), at(60), 7, ["Security"], every_event=True)
    assert values == {
        "ToPipeline": True, "Method": "psrp", "Channel": ["Security"],
        "Since": "2026-11-03T14:00:00.0000000Z", "Until": "2026-11-03T14:01:00.0000000Z", "All": True,
    }  # fmt: skip
    assert parameters(None, None, 30, ["System"], every_event=False) == {
        "ToPipeline": True, "Method": "psrp", "Channel": ["System"], "Days": 30,
    }  # fmt: skip


# --- a stand-in for pypsrp --------------------------------------------------------------


class Remote:
    """The parts of pypsrp toledot uses, replaying chosen output in chosen batches."""

    def __init__(self, batches: Sequence[Sequence[object]], *, end: int = COMPLETED) -> None:
        self.batches: list[Sequence[object]] = list(batches)
        self.end = end
        self.settings: dict[str, Any] = {}
        self.script = ""
        self.parameters: dict[str, Any] = {}
        self.error: Exception | None = None
        self.errors: list[str] = []
        self.stopped = False

    def classes(self) -> tuple[Any, Any, Any, int]:  # noqa: C901 - one small class per pypsrp part
        remote_side = self

        class WSMan:
            def __init__(self, **values: Any) -> None:
                remote_side.settings = values
                if remote_side.error is not None:
                    raise remote_side.error

            def __enter__(self) -> WSMan:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        class Pool:
            def __init__(self, _: object) -> None:
                pass

            def __enter__(self) -> Pool:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        class Streams:
            error = remote_side.errors

        class Shell:
            def __init__(self, _: object) -> None:
                self.state = RUNNING
                self.output: list[object] = []
                self.had_errors = False
                self.streams = Streams()

            def add_script(self, text: str) -> None:
                remote_side.script = text

            def add_parameters(self, values: dict[str, Any]) -> None:
                remote_side.parameters = values

            def begin_invoke(self) -> None:
                pass

            def poll_invoke(self, timeout: int) -> None:
                assert timeout == remote.POLL_SECONDS
                if remote_side.batches:
                    self.output.extend(remote_side.batches.pop(0))
                if not remote_side.batches:
                    self.state = remote_side.end
                    self.had_errors = remote_side.end == FAILED

            def stop(self) -> None:
                remote_side.stopped = True
                msg = "stop is best effort"
                raise RuntimeError(msg)

        return WSMan, Pool, Shell, RUNNING


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Remote:
    side = Remote([LINES[:2], [], LINES[2:]])
    monkeypatch.setattr(remote, "_client", side.classes)
    return side


def run(destination: Path, **options: Any) -> remote.Result:
    return collect(
        TARGET,
        "script text",
        {"ToPipeline": True},
        destination,
        force=options.pop("force", False),
        **options,
    )


def leftovers(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.name.endswith(".part"))


def test_a_collection_streams_into_a_checked_file(tmp_path: Path, fake: Remote) -> None:
    out = tmp_path / "dc01-events.jsonl"
    result = run(out)
    assert (result.path, result.events, result.gaps) == (out, 2, ())
    assert out.read_bytes() == GOOD
    items = list(read_bundle(out, ReadOptions()))
    assert not [item for item in items if isinstance(item, Problem)]
    assert len([item for item in items if isinstance(item, Event)]) == 2
    assert fake.settings["password"] == SECRET
    assert (fake.script, fake.parameters) == ("script text", {"ToPipeline": True})
    assert leftovers(tmp_path) == []


def test_gaps_the_collector_recorded_are_returned(tmp_path: Path, fake: Remote) -> None:
    data = encode(
        header(), [member_added()], [{"area": "the System log", "reason": "Access is denied."}]
    )
    fake.batches = [data.decode().splitlines()]
    assert run(tmp_path / "e.jsonl").gaps == ("the System log: Access is denied.",)


def damaged(lines: list[str]) -> list[Sequence[object]]:
    return [list(lines)]


@pytest.mark.parametrize(
    ("batches", "problem"),
    [
        (damaged(LINES[:-1]), "ended without its end line"),
        (damaged([LINES[0], LINES[2], LINES[3]]), "does not match what arrived"),
        (
            damaged([*LINES[:2], LINES[2].replace("Domain Admins", "Domain Guests"), LINES[3]]),
            "does not match",
        ),
        (damaged([*LINES, LINES[1]]), "output after its end line"),
        ([[LINES[0], 42]], "not one line of text"),
        ([[LINES[0], "a\nb"]], "not one line of text"),
        ([[LINES[0], "ü"]], "not one line of text"),
        ([[LINES[1]]], "first line is not a toledot header"),
    ],
)
def test_a_damaged_collection_leaves_no_file(
    tmp_path: Path, fake: Remote, batches: list[Sequence[object]], problem: str
) -> None:
    fake.batches = batches
    out = tmp_path / "e.jsonl"
    with pytest.raises(CollectionError, match=problem):
        run(out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


@pytest.mark.usefixtures("fake")
def test_an_overlong_line_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle, "MAX_LINE", 50)
    with pytest.raises(CollectionError, match="line 1 from the collector is too long"):
        run(tmp_path / "e.jsonl")


def test_a_script_that_fails_reports_its_own_error(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES[:2]]
    fake.end = FAILED
    fake.errors.append(f"Access is denied for {SECRET}")
    with pytest.raises(CollectionError) as exc:
        run(tmp_path / "e.jsonl")
    assert "the collector failed on dc01.corp.example: Access is denied for [redacted]" in str(
        exc.value
    )
    fake.errors.clear()
    fake.batches = [LINES[:2]]
    with pytest.raises(CollectionError, match="the script stopped with an error"):
        run(tmp_path / "e.jsonl")


def test_a_stalled_collection_is_stopped(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES[:1], [], [], [], LINES[1:]]
    ticks = iter(range(0, 10_000, 400))
    with pytest.raises(CollectionError, match="sent nothing for 600 seconds and was stopped"):
        collect(TARGET, "s", {}, tmp_path / "e.jsonl", force=False, clock=lambda: next(ticks))
    assert fake.stopped
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize(
    "error", [OSError(f"connection refused, password={SECRET}"), ValueError("")]
)
def test_library_errors_never_show_the_secret(
    tmp_path: Path, fake: Remote, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(secrets, "_resolved", {SECRET})
    fake.error = error
    with pytest.raises(CollectionError) as exc:
        run(tmp_path / "e.jsonl")
    assert SECRET not in str(exc.value)
    assert str(exc.value).startswith("remote collection from dc01.corp.example failed: ")
    assert leftovers(tmp_path) == []


def test_an_existing_file_is_kept_unless_forced(tmp_path: Path, fake: Remote) -> None:
    out = tmp_path / "e.jsonl"
    out.write_text("keep", encoding="utf-8")
    with pytest.raises(CollectionError, match="already exists; pass --force"):
        run(out)
    assert fake.settings == {}  # refused before connecting
    run(out, force=True)
    assert out.read_bytes() == GOOD


@pytest.mark.usefixtures("fake")
def test_a_file_that_appears_during_collection_is_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "e.jsonl"
    real = remote._Sink.finish  # noqa: SLF001 - the moment between check and publish

    def appear(sink: Any) -> Any:
        out.write_text("arrived", encoding="utf-8")
        return real(sink)

    monkeypatch.setattr(remote._Sink, "finish", appear)  # noqa: SLF001
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    assert out.read_text(encoding="utf-8") == "arrived"
    assert leftovers(tmp_path) == []


def no_hard_links(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Make ``os.link`` fail as on FAT; the count says how often it was tried."""
    calls = {"link": 0}

    def refuse(*_: object, **__: object) -> None:
        calls["link"] += 1
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", refuse)
    return calls


@pytest.mark.usefixtures("fake")
def test_a_file_system_without_hard_links_still_gets_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"
    result = run(out)
    assert calls["link"] == 1
    assert (result.path, result.events) == (out, 2)
    assert out.read_bytes() == GOOD
    assert sorted(path.name for path in tmp_path.iterdir()) == ["e.jsonl"]


@pytest.mark.usefixtures("fake")
def test_a_failed_copy_removes_the_partly_written_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_hard_links(monkeypatch)
    real = os.fsync
    out = tmp_path / "e.jsonl"

    def full(fd: int) -> None:
        if out.exists():  # only the copy into the destination fails
            raise OSError(errno.ENOSPC, "No space left on device")
        real(fd)

    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(CollectionError, match=r"cannot write .*e\.jsonl: No space left"):
        run(out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


@pytest.mark.usefixtures("fake")
def test_a_file_that_appears_when_links_are_unavailable_is_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"
    real = remote._Sink.finish  # noqa: SLF001 - the moment between check and publish

    def appear(sink: Any) -> Any:
        out.write_text("arrived", encoding="utf-8")
        return real(sink)

    monkeypatch.setattr(remote._Sink, "finish", appear)  # noqa: SLF001
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    assert out.read_text(encoding="utf-8") == "arrived"
    assert leftovers(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges on Windows")
def test_a_link_at_the_destination_is_never_followed(tmp_path: Path, fake: Remote) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("precious", encoding="utf-8")
    out = tmp_path / "e.jsonl"
    out.symlink_to(outside)
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    fake.batches = [LINES]
    run(out, force=True)
    assert outside.read_text(encoding="utf-8") == "precious"
    assert not out.is_symlink()
    assert out.read_bytes() == GOOD


@pytest.mark.usefixtures("fake")
def test_an_unwritable_folder_is_reported(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match="cannot write to"):
        run(tmp_path / "missing" / "e.jsonl")


def test_pypsrp_missing_says_how_to_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "pypsrp.wsman", None)
    with pytest.raises(CollectionError, match=r'pip install "faithful-toledot\[live\]"'):
        remote._client()  # noqa: SLF001 - the import boundary itself


def test_the_real_client_classes_load() -> None:
    pytest.importorskip("pypsrp")
    wsman, pool, shell, running = remote._client()  # noqa: SLF001
    assert (wsman.__name__, pool.__name__, shell.__name__, running) == (
        "WSMan", "RunspacePool", "PowerShell", RUNNING,
    )  # fmt: skip


# --- the commands -----------------------------------------------------------------------


def collect_args(out: Path, *extra: str) -> list[str]:
    return ["collect", "--server", SERVER, "-o", str(out), *extra]


@pytest.fixture
def fetched(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def resolve(reference: str) -> str:
        calls.append(reference)
        return SECRET

    monkeypatch.setattr(secrets, "resolve", resolve)
    return calls


@pytest.mark.parametrize(
    ("extra", "problem"),
    [
        (["--server", "10.0.0.5"], "is an IP address"),
        (["--username", "auditor", "--secret", "env:X"], "must be DOMAIN"),
        (["--secret", "env:X"], "--secret needs --username"),
        (["--username", "CORP\\auditor"], "--username needs --secret"),
        (
            ["--since", "2026-11-03T00:00:00Z", "--until", "2026-11-02T00:00:00Z"],
            "--since must be earlier",
        ),
        (["--auth", "ntlm"], "--auth ntlm needs --username and --secret"),
        (
            [
                "--transport",
                "http",
                "--ca-file",
                "ca.pem",
                "--username",
                "CORP\\a",
                "--secret",
                "env:X",
            ],
            "https only",
        ),
    ],
)
def test_collect_checks_everything_before_reading_the_secret(
    tmp_path: Path,
    fetched: list[str],
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    problem: str,
) -> None:
    expected = (
        ExitCode.USAGE if "needs" in problem or "earlier" in problem else ExitCode.INPUT_ERROR
    )
    assert main(collect_args(tmp_path / "e.jsonl", *extra)) == expected
    assert problem in capsys.readouterr().err
    assert fetched == []


def test_collect_runs_and_says_what_to_do_next(
    tmp_path: Path,
    fetched: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: dict[str, Any] = {}

    def fake_collect(
        target: Target, text: str, values: dict[str, Any], out: Path, *, force: bool
    ) -> remote.Result:
        seen.update(target=target, text=text, values=values, force=force)
        return remote.Result(out, 12, ("the System log: Access is denied.",))

    monkeypatch.setattr(remote, "collect", fake_collect)
    out = tmp_path / "my events.jsonl"
    args = collect_args(
        out,
        "--username",
        "auditor@corp.example",
        "--secret",
        "env:PW",
        "--all",
        "--channel",
        "Security",
    )
    assert main(args) == ExitCode.OK
    assert fetched == ["env:PW"]
    assert seen["target"].username == "corp.example\\auditor"
    assert seen["target"].secret == SECRET
    assert seen["text"] == script.text()
    assert seen["values"] == {
        "ToPipeline": True,
        "Method": "psrp",
        "Channel": ["Security"],
        "Days": 7,
        "All": True,
    }
    printed = capsys.readouterr().out
    assert f"Collected 12 events from {SERVER}" in printed
    assert "not read: the System log: Access is denied." in printed
    assert "toledot report" in printed
    assert "'" in printed or '"' in printed  # the path with a space is quoted


def test_collect_with_the_current_kerberos_ticket(
    tmp_path: Path, fetched: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets: list[Target] = []

    def record(target: Target, *_: object, **__: object) -> remote.Result:
        targets.append(target)
        return remote.Result(tmp_path, 0, ())

    monkeypatch.setattr(remote, "collect", record)
    assert main(collect_args(tmp_path / "e.jsonl")) == ExitCode.OK
    assert (targets[0].username, targets[0].secret, fetched) == (None, None, [])


@pytest.mark.parametrize(
    "extra",
    [
        ["--days", "0"],
        ["--days", "x"],
        ["--timeout", "0"],
        ["--port", "70000"],
        ["--since", "2026-11-03"],
        ["--since", "9999-12-31T23:59:59-14:00"],
        ["--since", "0001-01-01T00:00:00+14:00"],
    ],
)
def test_collect_option_values_are_checked(tmp_path: Path, extra: list[str]) -> None:
    assert main(collect_args(tmp_path / "e.jsonl", *extra)) == ExitCode.USAGE


def test_in_range_option_values_are_accepted() -> None:
    from faithful_toledot.arguments import bounded  # noqa: PLC0415 - used by this test only

    assert bounded(1, 10, "a number")("10") == 10


@pytest.mark.usefixtures("fake")
def test_a_collection_without_a_secret_still_publishes(tmp_path: Path) -> None:
    out = tmp_path / "e.jsonl"
    result = collect(replace(TARGET, secret=None), "s", {}, out, force=False)
    assert result.path == out
    assert out.read_bytes() == GOOD


def test_collect_out_of_range_since_says_why(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = collect_args(tmp_path / "e.jsonl", "--since", "9999-12-31T23:59:59-14:00")
    assert main(args) == ExitCode.USAGE
    assert "outside the years toledot can handle" in capsys.readouterr().err


def test_collector_writes_the_script(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / script.NAME
    assert main(["collector", "-o", str(out)]) == ExitCode.OK
    assert out.read_text(encoding="ascii") == script.text()
    assert "-OutFile dc01-events.jsonl" in capsys.readouterr().out
    assert main(["collector", "-o", str(out)]) == ExitCode.INPUT_ERROR
    assert main(["collector", "-o", str(out), "--force"]) == ExitCode.OK
