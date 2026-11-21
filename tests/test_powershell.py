# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - embedded PowerShell and event XML keep their own line layout
"""The PowerShell collector.

The text checks run everywhere. Where PowerShell is installed, the script's own
functions also run: its JSON writer is compared with Python's JSON parser, its
reading of event XML with toledot's XML reader, and a whole collection, with only
the Windows event log replaced by synthetic records, is read back by toledot's
collection reader. Set ``TOLEDOT_REQUIRE_PWSH=1`` to fail instead of skipping when
PowerShell is missing.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from faithful_toledot import catalog
from faithful_toledot.collect import script
from faithful_toledot.events import Event, LogFacts, Problem, ReadOptions
from faithful_toledot.formats.bundle import read_bundle
from faithful_toledot.formats.xml import read_xml

if TYPE_CHECKING:
    from pathlib import Path

TEXT = script.text()

# Commands the script may call. Anything else, such as Set-, New-Item, Remove-,
# Clear-, Invoke-Expression, or Start-Process, would make the test fail.
ALLOWED = {
    "Set-StrictMode", "New-Object", "Write-Output", "Get-Date", "Sort-Object",
    "ForEach-Object", "Where-Object",
}  # fmt: skip
_FUNCTION = re.compile(r"^function ([A-Za-z]+-[A-Za-z]+)", re.MULTILINE)
_COMMAND = re.compile(r"(?<![\w$.-])([A-Z][a-z]+-[A-Z][A-Za-z]+)\b")


def code() -> str:
    """The script without comments, so help text cannot hide or fake a command."""
    without_blocks = re.sub(r"<#.*?#>", "", TEXT, flags=re.DOTALL)
    without_blocks = re.sub(r"'[^'\n]*'", "''", without_blocks)
    return "\n".join(
        line.split(" #")[0]
        for line in without_blocks.splitlines()
        if not line.lstrip().startswith("#")
    )


def test_the_script_is_pure_ascii_for_windows_powershell() -> None:
    """Windows PowerShell 5.1 reads a file without a BOM in the system code page."""
    assert TEXT.isascii()
    assert "\r" not in TEXT


def test_the_script_states_the_version_it_writes() -> None:
    assert script.version() == "0.1.1"
    assert "$CollectorVersion = '0.1.1'" in TEXT


def test_the_script_asks_for_exactly_the_events_toledot_reads() -> None:
    found: dict[str, set[int]] = {}
    for channel, block in re.findall(r"'(Security|System)'\s*=\s*@\(([^)]*)\)", TEXT):
        found[channel] = {int(number) for number in re.findall(r"\d+", block)}
    expected: dict[str, set[int]] = {}
    for channel, number in catalog.load().wanted_ids:
        expected.setdefault(channel, set()).add(number)
    assert found == expected


def test_the_script_only_reads() -> None:
    body = code()
    defined = set(_FUNCTION.findall(body))
    called = set(_COMMAND.findall(body)) - defined
    assert called <= ALLOWED, called - ALLOWED
    for forbidden in (
        "Invoke-Expression",
        "Start-Process",
        "Remove-Item",
        "Set-Content",
        "Out-File",
    ):
        assert forbidden not in body
    assert "Set-StrictMode -Version 3.0" in TEXT
    assert "\n$ErrorActionPreference = 'Stop'\n" in TEXT


def test_the_output_file_is_never_overwritten_without_force() -> None:
    assert "[System.IO.FileMode]::CreateNew" in TEXT
    assert "[System.IO.FileMode]::Create " not in TEXT  # the file is never opened in place
    assert "[System.IO.File]::Move($Writer.TempPath, $Path)" in TEXT


def test_gaps_are_added_only_through_the_capped_helper() -> None:
    assert code().count("$Gaps.Add(") == 1  # inside Add-Gap, which stops at $MaxGaps
    assert "$MaxGaps = 1000" in TEXT
    assert "Get-GapText $gaps" in TEXT


def test_event_xml_is_parsed_with_dtds_refused() -> None:
    assert "[System.Xml.DtdProcessing]::Prohibit" in TEXT
    assert "XmlResolver = $null" in TEXT


# --- running the script's functions -----------------------------------------------------

_PWSH = shutil.which("pwsh") or shutil.which("powershell")
if _PWSH is None and os.environ.get("TOLEDOT_REQUIRE_PWSH") == "1":  # pragma: no cover
    msg = "TOLEDOT_REQUIRE_PWSH is set but PowerShell is not installed"
    raise RuntimeError(msg)
needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="PowerShell is not installed")

PARAMETERS = """
$OutFile = $null; $ToPipeline = $false; $Since = $null; $Until = $null; $Days = 7
$Channel = @('Security'); $All = $false; $Force = $false; $Method = 'powershell'
"""


def functions() -> str:
    """The script's definitions, without its parameter block or its call to run."""
    start = TEXT.index("Set-StrictMode")
    end = TEXT.index("if ($MyInvocation.InvocationName")
    return PARAMETERS + TEXT[start:end]


def run_pwsh(folder: Path, body: str) -> subprocess.CompletedProcess[str]:
    assert _PWSH is not None
    path = folder / "run.ps1"
    path.write_text(functions() + "\n" + body, encoding="utf-8")
    return subprocess.run(  # noqa: S603 - a fixed interpreter and a script built here
        [_PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        check=False,
    )


def encoded(value: str) -> str:
    """Pass any text into PowerShell untouched, as base64 of UTF-16."""
    raw = value.encode("utf-16-le", "surrogatepass")
    return f"[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{base64.b64encode(raw).decode()}'))"


HOSTILE = [
    "",
    "plain",
    'quote " and backslash \\',
    "controls \x00\x01\x08\t\n\r\x1f\x7f",
    "line separators \u2028\u2029",
    "accents é ü and CJK 漢字",
    "astral 😀 𝄞",
    "%%1794",
    "S-1-5-21-1111111111-2222222222-3333333333-500",
    "</Data><Data Name='x'>",
]


@needs_pwsh
def test_the_json_writer_agrees_with_python(tmp_path: Path) -> None:
    lines = "\n".join(f"ConvertTo-JsonText ({encoded(value)})" for value in HOSTILE)
    result = run_pwsh(tmp_path, lines + "\nConvertTo-JsonText $null")
    assert result.returncode == 0, result.stderr
    out = result.stdout.splitlines()
    assert all(line.isascii() for line in out)
    assert [json.loads(line) for line in out] == [*HOSTILE, None]


@needs_pwsh
def test_an_unpaired_surrogate_stays_visible(tmp_path: Path) -> None:
    result = run_pwsh(tmp_path, "ConvertTo-JsonText ('a' + [char] 0xD800 + 'b')")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == '"a\\ud800b"'


@needs_pwsh
def test_times_are_utc_with_seven_fraction_digits(tmp_path: Path) -> None:
    body = (
        "$t = [datetime]::new(2026, 11, 3, 14, 0, 5, [System.DateTimeKind]::Utc).AddTicks(1234567)\n"
        "Format-UtcTime $t\n"
        "Format-UtcTime ([datetime]::new(2026, 11, 3, 8, 0, 0, [System.DateTimeKind]::Utc).ToLocalTime())\n"
        "ConvertTo-JsonTimeOrNull $null\nConvertTo-JsonNumberOrNull $null\nConvertTo-JsonNumberOrNull 42"
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        "2026-11-03T14:00:05.1234567Z", "2026-11-03T08:00:00.0000000Z", "null", "null", "42",
    ]  # fmt: skip


EVENT_XML = [
    """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
<EventID>4728</EventID><Version>0</Version><Level>0</Level><Task>13826</Task><Opcode>0</Opcode>
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-11-03T14:00:00.1234567Z"/>
<EventRecordID>48231</EventRecordID><Correlation ActivityID="{AAAAAAAA-0000-0000-0000-000000000001}"/>
<Execution ProcessID="716" ThreadID="1288"/><Channel>Security</Channel><Computer>DC01.corp.example</Computer>
<Security/></System><EventData>
<Data Name="MemberName">CN=Dana,OU=Staff,DC=corp,DC=example</Data><Data Name="MemberSid">S-1-5-21-1-2-3-1207</Data>
<Data Name="TargetUserName">Domain Admins</Data><Data Name="Empty"></Data><Data Name="Empty">again</Data>
<Data>unnamed &amp; escaped &lt;x&gt;</Data><Data Name="Multi">line one
	line two</Data><Binary>0A0B</Binary></EventData></Event>""",
    """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><Version>0</Version>
<TimeCreated SystemTime="2026-11-03T14:00:00Z"/><EventRecordID>9</EventRecordID>
<Channel>Security</Channel><Computer>DC01.corp.example</Computer></System>
<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
<SubjectUserSid>S-1-5-21-1-2-3-1104</SubjectUserSid><SubjectUserName>alice</SubjectUserName>
<Nested><A>one</A><B> </B><C>two</C></Nested></LogFileCleared></UserData></Event>""",
]


@needs_pwsh
def test_event_fields_match_toledots_xml_reader(tmp_path: Path) -> None:
    """The collector and the XML reader name and read every field the same way."""
    body = "\n".join(
        f"$f = Get-EventFields ({encoded(xml)}); ConvertTo-JsonObject $f.Data; ConvertTo-JsonObject $f.System"
        for xml in EVENT_XML
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    out = [json.loads(line) for line in result.stdout.splitlines()]
    source = tmp_path / "events.xml"
    source.write_text("<Events>" + "".join(EVENT_XML) + "</Events>", encoding="utf-8")
    events = [item for item in read_xml(source, ReadOptions()) if isinstance(item, Event)]
    assert [out[0], out[2]] == [dict(event.data) for event in events]
    assert out[0]["Empty#2"] == "again"
    assert out[0]["param6"] == "unnamed & escaped <x>"
    assert out[2]["Nested"] == "one two"
    assert out[1] == {
        "Level": "0", "Task": "13826", "Opcode": "0", "Keywords": "0x8020000000000000",
        "ActivityID": "{AAAAAAAA-0000-0000-0000-000000000001}", "ProcessID": "716",
        "ThreadID": "1288", "UserID": "",
    }  # fmt: skip


@needs_pwsh
def test_event_xml_with_a_dtd_is_refused(tmp_path: Path) -> None:
    xml = '<!DOCTYPE Event [<!ENTITY x "boom">]><Event><EventData><Data>&x;</Data></EventData></Event>'
    result = run_pwsh(tmp_path, f"try {{ Get-EventFields ({encoded(xml)}) }} catch {{ 'refused' }}")
    assert result.stdout.strip() == "refused"


@needs_pwsh
def test_id_ranges_and_queries(tmp_path: Path) -> None:
    body = (
        "(Get-IdRanges @(4728, 4720, 4722, 4721, 104, 4720)) -join ' | '\n"
        "$from = [datetime]::new(2026, 11, 1, 0, 0, 0, [System.DateTimeKind]::Utc)\n"
        "Get-QueryText @('EventID=104') $from $null\n"
        "Get-QueryText @() $from $from.AddDays(1)"
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "EventID=104 | (EventID>=4720 and EventID<=4722) | EventID=4728",
        "*[System[(EventID=104) and TimeCreated[@SystemTime>='2026-11-01T00:00:00.0000000Z']]]",
        (
            "*[System[TimeCreated[@SystemTime>='2026-11-01T00:00:00.0000000Z' and "
            "@SystemTime<'2026-11-02T00:00:00.0000000Z']]]"
        ),
    ]


# A stand-in for the Windows event log: the script's real header, line, hash, and end
# line writers run; only reading records is replaced.
STUB = r"""
function Get-LogFacts([string] $Name, $Gaps) {
    [ordered] @{ channel = $Name; oldest_record_id = 100; oldest_time = [datetime]::new(2026, 10, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
        newest_record_id = 900; record_count = 801; max_size_bytes = 134217728; mode = 'circular' }
}
function Read-Channel($Writer, [string] $Name, [datetime] $From, [Nullable[datetime]] $To, $Gaps) {
    $time = [datetime]::new(2026, 11, 3, 14, 0, 0, [System.DateTimeKind]::Utc)
    foreach ($i in 1..3) {
        $xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Level>0</Level></System><EventData>' +
            '<Data Name="TargetUserName">Group ' + $i + '</Data><Data Name="Note">caf' + [char]0xE9 + ' "q" \ </Data></EventData></Event>'
        Write-Line $Writer (Format-EventLine (200 + $i) 4728 0 $time.AddSeconds($i) 'DC01.corp.example' $Name 'Microsoft-Windows-Security-Auditing' $xml)
        $Writer.Count++
    }
    $Gaps.Add([ordered] @{ area = 'record 299 of the Security log'; reason = 'The data is invalid.' })
}
"""


@needs_pwsh
@pytest.mark.parametrize("pipeline", [False, True])
def test_a_whole_collection_reads_back_cleanly(tmp_path: Path, *, pipeline: bool) -> None:
    out = tmp_path / "events.jsonl"
    setup = f"$OutFile = '{out}'" if not pipeline else "$ToPipeline = $true; $Method = 'psrp'"
    body = (
        STUB
        + setup
        + "\n$Since = [datetime]::new(2026, 11, 1, 0, 0, 0, [System.DateTimeKind]::Utc)\nInvoke-Collection"
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    if pipeline:
        out.write_bytes(result.stdout.encode("ascii").replace(b"\r\n", b"\n"))
    raw = out.read_bytes()
    assert raw.isascii()
    assert raw.endswith(b"\n")
    assert b"\r" not in raw
    items = list(read_bundle(out, ReadOptions()))
    facts = items[0]
    assert isinstance(facts, LogFacts)
    assert (facts.oldest_record, facts.newest_record, facts.filtered) == (100, 900, True)
    events = [item for item in items if isinstance(item, Event)]
    assert [event.record_id for event in events] == [201, 202, 203]
    assert events[0].data == {"TargetUserName": "Group 1", "Note": 'café "q" \\ '}
    problems = [item for item in items if isinstance(item, Problem)]
    assert [problem.reason for problem in problems] == [
        "The collector could not read record 299 of the Security log: The data is invalid."
    ]
    header = json.loads(raw.splitlines()[0])
    assert header["collector"]["method"] == ("psrp" if pipeline else "powershell")
    assert header["query"]["since"] == "2026-11-01T00:00:00.0000000Z"


MANY_GAPS = (
    STUB
    + """
function Read-Channel($Writer, [string] $Name, [datetime] $From, [Nullable[datetime]] $To, $Gaps) {
    foreach ($i in 1..2500) { Add-Gap $Gaps "record $i of the $Name log" ('x' * 5000) }
    Add-Gap $Gaps '' ''
}
"""
)


@needs_pwsh
def test_more_than_a_thousand_gaps_still_make_a_valid_end_line(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    result = collect_over(tmp_path, out, stub=MANY_GAPS, force=False)
    assert result.returncode == 0, result.stderr
    items = list(read_bundle(out, ReadOptions()))
    reasons = [item.reason for item in items if isinstance(item, Problem)]
    assert len(reasons) == 1000
    assert (
        reasons[-1]
        == "The collector could not read further gaps: 1502 further gaps are not listed here"
    )
    assert not any("end line is not valid" in reason or "hash" in reason for reason in reasons)
    trailer = json.loads(out.read_bytes().splitlines()[-1])
    assert len(trailer["gaps"]) == 1000
    assert all(len(gap["reason"]) <= 4096 for gap in trailer["gaps"])


FAILING = (
    STUB
    + """
function Read-Channel($Writer, [string] $Name, [datetime] $From, [Nullable[datetime]] $To, $Gaps) {
    Write-Line $Writer '{"half":"written"}'
    throw 'the log went away'
}
"""
)


def collect_over(
    folder: Path, out: Path, *, stub: str, force: bool
) -> subprocess.CompletedProcess[str]:
    setting = "$Force = $true\n" if force else ""
    return run_pwsh(folder, stub + f"$OutFile = '{out}'\n{setting}Invoke-Collection")


def only_the_file(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.name != "run.ps1")


@needs_pwsh
def test_an_existing_file_is_not_overwritten(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    out.write_text("keep", encoding="utf-8")
    result = collect_over(tmp_path, out, stub=STUB, force=False)
    assert result.returncode != 0
    assert "already exists" in result.stderr
    assert out.read_text(encoding="utf-8") == "keep"
    assert only_the_file(tmp_path) == ["events.jsonl"]


@needs_pwsh
def test_a_failed_run_without_force_keeps_the_existing_file_and_leaves_nothing(
    tmp_path: Path,
) -> None:
    out = tmp_path / "events.jsonl"
    out.write_text("keep", encoding="utf-8")
    result = collect_over(tmp_path, out, stub=FAILING, force=False)
    assert result.returncode != 0
    assert out.read_text(encoding="utf-8") == "keep"
    assert only_the_file(tmp_path) == ["events.jsonl"]


@needs_pwsh
def test_a_failed_run_with_force_keeps_the_existing_file_and_leaves_nothing(
    tmp_path: Path,
) -> None:
    out = tmp_path / "events.jsonl"
    out.write_text("keep", encoding="utf-8")
    result = collect_over(tmp_path, out, stub=FAILING, force=True)
    assert result.returncode != 0
    assert "the log went away" in result.stderr
    assert out.read_text(encoding="utf-8") == "keep"
    assert only_the_file(tmp_path) == ["events.jsonl"]


@needs_pwsh
def test_a_failed_run_with_nothing_before_it_leaves_no_file(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    assert collect_over(tmp_path, out, stub=FAILING, force=False).returncode != 0
    assert only_the_file(tmp_path) == []


@needs_pwsh
def test_a_successful_run_with_force_replaces_the_existing_file(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    out.write_text("old", encoding="utf-8")
    result = collect_over(tmp_path, out, stub=STUB, force=True)
    assert result.returncode == 0, result.stderr
    assert only_the_file(tmp_path) == ["events.jsonl"]
    items = list(read_bundle(out, ReadOptions()))
    assert [item.record_id for item in items if isinstance(item, Event)] == [201, 202, 203]


@needs_pwsh
def test_a_successful_run_without_force_creates_the_file_and_leaves_nothing_else(
    tmp_path: Path,
) -> None:
    out = tmp_path / "events.jsonl"
    result = collect_over(tmp_path, out, stub=STUB, force=False)
    assert result.returncode == 0, result.stderr
    assert only_the_file(tmp_path) == ["events.jsonl"]


@needs_pwsh
def test_a_relative_out_file_is_relative_to_the_powershell_location(tmp_path: Path) -> None:
    place = tmp_path / "here"
    place.mkdir()
    # The process directory stays elsewhere; only PowerShell's location moves.
    body = (
        STUB + f"Set-Location -LiteralPath '{place}'\n$OutFile = 'events.jsonl'\nInvoke-Collection"
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    assert only_the_file(place) == ["events.jsonl"]


@pytest.mark.skipif(sys.platform != "win32" or _PWSH is None, reason="needs Windows")
def test_the_real_script_reads_a_real_log(tmp_path: Path) -> None:  # pragma: no cover
    """Application is readable without elevation; every event in a short window."""
    assert _PWSH is not None
    out = tmp_path / "events.jsonl"
    path = tmp_path / script.NAME
    path.write_text(TEXT, encoding="ascii")
    result = subprocess.run(  # noqa: S603
        [_PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path),
         "-OutFile", str(out), "-Channel", "Application", "-All", "-Days", "1"],
        capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    items = list(read_bundle(out, ReadOptions()))
    assert isinstance(items[0], LogFacts)
    assert not [item for item in items if isinstance(item, Problem)]
