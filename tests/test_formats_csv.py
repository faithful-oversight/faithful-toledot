# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CSV (message text) event reader."""

from __future__ import annotations

import csv
import io
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from faithful_toledot import catalog
from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, ReadOptions
from faithful_toledot.formats import _text
from faithful_toledot.formats import csv as csv_reader
from faithful_toledot.formats.csv import MAX_COLUMNS, read_csv

if TYPE_CHECKING:
    from collections.abc import Mapping

ADMIN = "S-1-5-21-1111111111-2222222222-3333333333-500"
USER = "S-1-5-21-1111111111-2222222222-3333333333-1105"
CST = timedelta(hours=-6)
POWERSHELL_HEADER = [
    "Message", "Id", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
    "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId",
    "TimeCreated", "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds",
    "Bookmark", "LevelDisplayName", "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames",
    "Properties",
]  # fmt: skip
VIEWER_HEADER = ["Level", "Date and Time", "Source", "Event ID", "Task Category"]


def message(title: str, *sections: tuple[str, list[tuple[str, str]]], eol: str = "\r\n") -> str:
    """Render a message the way Windows does: sections, then tab-indented ``Label:`` lines."""
    lines = [title, ""]
    for name, fields in sections:
        lines.append(f"{name}:")
        lines.extend(f"\t{label}:\t\t{value}" for label, value in fields)
        lines.append("")
    return eol.join(lines)


MESSAGE_4720 = message(
    "A user account was created.",
    (
        "Subject",
        [
            ("Security ID", ADMIN),
            ("Account Name", "admin"),
            ("Account Domain", "CORP"),
            ("Logon ID", "0x3e7"),
        ],
    ),
    ("New Account", [("Security ID", USER), ("Account Name", "jdoe"), ("Account Domain", "CORP")]),
    ("Attributes", [("SAM Account Name", "jdoe"), ("Display Name", "<value not set>")]),
)
LABELS_4720 = {
    "Subject/Security ID": "SubjectUserSid",
    "Subject/Account Name": "SubjectUserName",
    "Subject/Account Domain": "SubjectDomainName",
    "Subject/Logon ID": "SubjectLogonId",
    "New Account/Security ID": "TargetSid",
    "New Account/Account Name": "TargetUserName",
    "New Account/Account Domain": "TargetDomainName",
}


def labels_for(event_id: int) -> Mapping[str, str] | None:
    return LABELS_4720 if event_id == 4720 else None


OPTIONS = ReadOptions(local_offset=CST, day_first=False, labels_for=labels_for)


def ps_row(**changes: str) -> list[str]:
    base = {
        "Message": MESSAGE_4720,
        "Id": "4720",
        "Version": "0",
        "Level": "0",
        "Task": "13824",
        "Opcode": "0",
        "Keywords": "-9214364837600034816",
        "RecordId": "4120",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "LogName": "Security",
        "ProcessId": "612",
        "ThreadId": "700",
        "MachineName": "dc01.corp.example",
        "UserId": "",
        "TimeCreated": "2026-11-10T02:15:03.1234567+00:00",
        "ActivityId": "aaaaaaaa-0000-0000-0000-000000000001",
        "LevelDisplayName": "Information",
        "TaskDisplayName": "User Account Management",
        "Properties": "System.Collections.Generic.List`1[...]",
    }
    base.update(changes)
    return [base.get(column, "") for column in POWERSHELL_HEADER]


def viewer_row(**changes: str) -> list[str]:
    base = {
        "Level": "Audit Success",
        "Date and Time": "11/9/2026 8:15:03 PM",
        "Source": "Microsoft Windows security auditing.",
        "Event ID": "4720",
        "Task Category": "User Account Management",
        "Message": MESSAGE_4720,
    }
    base.update(changes)
    return [base[c] for c in [*VIEWER_HEADER, "Message"]]


def to_csv(header: list[str], rows: list[list[str]], eol: str = "\r\n") -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=eol, quoting=csv.QUOTE_ALL)
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue()


def ps_csv(*rows: list[str]) -> str:
    return to_csv(POWERSHELL_HEADER, list(rows))


def viewer_csv(*rows: list[str], trailing_header: bool = False) -> str:
    return to_csv([*VIEWER_HEADER, *([""] if trailing_header else [])], list(rows))


def read(
    tmp_path: Path, content: str | bytes, options: ReadOptions = OPTIONS
) -> list[Event | Problem]:
    path = tmp_path / "export.csv"
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return list(read_csv(path, options))


def only_event(items: list[Event | Problem]) -> Event:
    assert len(items) == 1
    assert isinstance(items[0], Event), items[0]
    return items[0]


def only_problem(items: list[Event | Problem]) -> Problem:
    assert len(items) == 1
    assert isinstance(items[0], Problem), items[0]
    return items[0]


# --- Get-WinEvent | Export-Csv ------------------------------------------------------


def test_powershell_export_with_mapped_labels(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, ps_csv(ps_row())))
    assert found.event_id == 4720
    assert found.time == datetime(2026, 11, 10, 2, 15, 3, 123456, tzinfo=UTC)
    assert found.computer == "dc01.corp.example"
    assert found.channel == "Security"
    assert found.provider == "Microsoft-Windows-Security-Auditing"
    assert found.record_id == 4120
    assert found.version == 0
    assert found.source.position == "row 1 (line 2)"
    assert found.data == {
        "SubjectUserSid": ADMIN,
        "SubjectUserName": "admin",
        "SubjectDomainName": "CORP",
        "SubjectLogonId": "0x3e7",
        "TargetSid": USER,
        "TargetUserName": "jdoe",
        "TargetDomainName": "CORP",
        "Attributes/SAM Account Name": "jdoe",
        "Attributes/Display Name": "<value not set>",
    }
    assert found.system == {
        "Keywords": "0x8020000000000000",
        "Level": "0",
        "Task": "13824",
        "Opcode": "0",
        "ActivityID": "{AAAAAAAA-0000-0000-0000-000000000001}",
        "ProcessID": "612",
        "ThreadID": "700",
        "LevelDisplayName": "Information",
        "TaskDisplayName": "User Account Management",
    }


def test_without_labels_every_key_is_section_slash_label(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, ps_csv(ps_row(Id="4738")), OPTIONS))
    assert list(found.data)[:3] == [
        "Subject/Security ID",
        "Subject/Account Name",
        "Subject/Account Domain",
    ]
    assert found.data["New Account/Security ID"] == USER
    bare = only_event(read(tmp_path, ps_csv(ps_row()), ReadOptions(local_offset=CST)))
    assert bare.data["Subject/Security ID"] == ADMIN


def test_labels_for_is_asked_once_per_event_id(tmp_path: Path) -> None:
    asked: list[int] = []

    def counting(event_id: int) -> Mapping[str, str] | None:
        asked.append(event_id)
        return None

    options = ReadOptions(local_offset=CST, labels_for=counting)
    read(tmp_path, ps_csv(ps_row(), ps_row(), ps_row(Id="4738"), ps_row()), options)
    assert asked == [4720, 4738]


def test_powershell_5_type_line_is_skipped(tmp_path: Path) -> None:
    text = "#TYPE System.Diagnostics.Eventing.Reader.EventLogRecord\r\n" + ps_csv(ps_row())
    assert only_event(read(tmp_path, text)).source.position == "row 1 (line 3)"


@pytest.mark.parametrize(
    "encode",
    [
        lambda t: t.encode("utf-8"),
        lambda t: b"\xef\xbb\xbf" + t.encode("utf-8"),
        lambda t: b"\xff\xfe" + t.encode("utf-16-le"),
        lambda t: b"\xfe\xff" + t.encode("utf-16-be"),
    ],
    ids=["utf-8", "utf-8-bom", "utf-16-le", "utf-16-be"],
)
@pytest.mark.parametrize("chunk", [4, 7, 64 * 1024])
@pytest.mark.parametrize("eol", ["\r\n", "\n"])
def test_encodings_chunking_and_line_endings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encode: object, chunk: int, eol: str
) -> None:
    monkeypatch.setattr(_text, "READ_CHUNK", chunk)
    message_text = MESSAGE_4720.replace("jdoe", "Zoë ☃ 😀", 1).replace("\r\n", eol)
    text = to_csv(POWERSHELL_HEADER, [ps_row(Message=message_text), ps_row(RecordId="4121")], eol)
    path = tmp_path / "e.csv"
    path.write_bytes(encode(text))  # type: ignore[operator]
    items = list(read_csv(path, OPTIONS))
    assert [i.source.position for i in items] == [
        "row 1 (line 2)",
        f"row 2 (line {message_text.count(eol) + 3})",
    ]
    assert isinstance(items[0], Event)
    assert items[0].data["TargetUserName"] == "Zoë ☃ 😀"
    assert items[0].data["Attributes/SAM Account Name"] == "jdoe"


def test_positions_count_rows_not_lines_and_blank_lines_are_skipped(tmp_path: Path) -> None:
    text = ps_csv(ps_row(), ps_row(RecordId="2"))
    lines = text.split("\r\n")
    text_with_blanks = "\r\n".join(lines[:1]) + "\r\n\r\n" + "\r\n".join(lines[1:])
    items = read(tmp_path, text_with_blanks)
    assert items[0].source.position.startswith("row 1 (line 3")
    assert items[1].source.position.startswith("row 2 (line ")


def test_unused_columns_and_missing_optional_columns(tmp_path: Path) -> None:
    header = ["Message", "Id", "ProviderName", "LogName", "MachineName", "TimeCreated", "Extra"]
    row = [MESSAGE_4720, "4720", "P", "Security", "dc01", "2026-11-10T02:15:03Z", "ignored"]
    found = only_event(read(tmp_path, to_csv(header, [row])))
    assert found.record_id is None
    assert found.version == 0
    assert found.system == {}


def test_empty_optional_cells(tmp_path: Path) -> None:
    found = only_event(
        read(
            tmp_path,
            ps_csv(
                ps_row(Version="", RecordId="", Keywords="", ActivityId="", LevelDisplayName="")
            ),
        )
    )
    assert found.record_id is None
    assert found.version == 0
    assert "Keywords" not in found.system
    assert "LevelDisplayName" not in found.system


@pytest.mark.parametrize(
    ("changes", "text"),
    [
        ({"Id": "x"}, "event ID"),
        ({"Id": "70000"}, "event ID"),
        ({"Version": "300"}, "Version"),
        ({"RecordId": "x"}, "RecordId"),
        ({"ProviderName": ""}, "ProviderName column is empty"),
        ({"LogName": ""}, "LogName column is empty"),
        ({"MachineName": ""}, "MachineName column is empty"),
        ({"Keywords": "zzz"}, "Keywords"),
        ({"ActivityId": "nope"}, "ActivityID"),
        ({"Level": "high"}, "Level"),
        ({"TimeCreated": "last tuesday"}, "time cannot be used"),
        ({"TimeCreated": "2026-02-30T00:00:00Z"}, "not a real date"),
        ({"Message": ""}, "no 'Label: value' lines"),
        ({"Message": "A user account was created."}, "no 'Label: value' lines"),
    ],
)
def test_bad_rows_are_problems_and_reading_continues(
    tmp_path: Path, changes: dict[str, str], text: str
) -> None:
    items = read(tmp_path, ps_csv(ps_row(**changes), ps_row(RecordId="9")))
    assert isinstance(items[0], Problem)
    assert text in items[0].reason
    assert items[0].source.position == "row 1 (line 2)" or "row 1" in items[0].source.position
    assert isinstance(items[1], Event)


def test_problem_keeps_the_record_id_when_it_can_be_read(tmp_path: Path) -> None:
    assert only_problem(read(tmp_path, ps_csv(ps_row(Id="x")))).record_id == 4120
    assert only_problem(read(tmp_path, ps_csv(ps_row(Id="x", RecordId="")))).record_id is None


def test_rows_with_the_wrong_number_of_fields(tmp_path: Path) -> None:
    short = ps_row()[:-3]
    items = read(tmp_path, to_csv(POWERSHELL_HEADER, [short, ps_row()]))
    assert "fields but the header has 27" in items[0].reason  # type: ignore[union-attr]
    assert isinstance(items[1], Event)


def test_field_over_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(csv_reader, "MAX_FIELD_CHARS", 500)
    items = read(tmp_path, ps_csv(ps_row(Properties="x" * 501), ps_row(Properties="x" * 500)))
    assert "field is longer than 500" in items[0].reason  # type: ignore[union-attr]
    assert isinstance(items[1], Event)


# --- times --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("11/10/2026 8:15:03 PM", datetime(2026, 11, 11, 2, 15, 3, tzinfo=UTC)),
        ("11/10/2026 12:15:03 AM", datetime(2026, 11, 10, 6, 15, 3, tzinfo=UTC)),
        ("11/10/2026 12:15:03 PM", datetime(2026, 11, 10, 18, 15, 3, tzinfo=UTC)),
        ("11/10/2026 1:00:00 am", datetime(2026, 11, 10, 7, 0, 0, tzinfo=UTC)),
        ("11/10/2026 8:15:03\u202fPM", datetime(2026, 11, 11, 2, 15, 3, tzinfo=UTC)),
        ("11/10/2026 20:15:03", datetime(2026, 11, 11, 2, 15, 3, tzinfo=UTC)),
        ("11/10/2026 8:15 PM", datetime(2026, 11, 11, 2, 15, 0, tzinfo=UTC)),
        ("11/10/2026 8:15:03.5 PM", datetime(2026, 11, 11, 2, 15, 3, 500000, tzinfo=UTC)),
        ("11.10.2026 20:15:03", datetime(2026, 11, 11, 2, 15, 3, tzinfo=UTC)),
        ("2026-11-10 20:15:03", datetime(2026, 11, 11, 2, 15, 3, tzinfo=UTC)),
        ("2026-11-10T02:15:03Z", datetime(2026, 11, 10, 2, 15, 3, tzinfo=UTC)),
        ("2026-11-09T20:15:03-06:00", datetime(2026, 11, 10, 2, 15, 3, tzinfo=UTC)),
        ("2026-11-10T08:15:03+0600", datetime(2026, 11, 10, 2, 15, 3, tzinfo=UTC)),
        ("2026-11-10T08:15:03+06", datetime(2026, 11, 10, 2, 15, 3, tzinfo=UTC)),
        ("2026-11-10T02:15:03,25 Z", datetime(2026, 11, 10, 2, 15, 3, 250000, tzinfo=UTC)),
    ],
)
def test_time_shapes_with_month_first_and_a_local_offset(
    tmp_path: Path, stamp: str, expected: datetime
) -> None:
    assert only_event(read(tmp_path, ps_csv(ps_row(TimeCreated=stamp)))).time == expected


def test_iso_times_with_an_offset_need_no_options(tmp_path: Path) -> None:
    found = only_event(
        read(tmp_path, ps_csv(ps_row(TimeCreated="2026-11-10T02:15:03Z")), ReadOptions())
    )
    assert found.time == datetime(2026, 11, 10, 2, 15, 3, tzinfo=UTC)


def test_naive_time_without_local_offset_explains_the_option(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="local_offset") as caught:
        read(tmp_path, ps_csv(ps_row(TimeCreated="11/13/2026 8:15:03 PM")), ReadOptions())
    text = str(caught.value)
    assert "daylight saving" in text
    assert "ToString('o')" in text
    assert "11/13/2026" in text


def test_naive_iso_time_needs_local_offset_too(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="local_offset"):
        read(tmp_path, ps_csv(ps_row(TimeCreated="2026-11-10T02:15:03")), ReadOptions())
    options = ReadOptions(local_offset=timedelta(hours=1))
    assert (
        only_event(
            read(tmp_path, ps_csv(ps_row(TimeCreated="2026-11-10T02:15:03")), options)
        ).time.hour
        == 1
    )


def test_ambiguous_day_and_month_needs_day_first(tmp_path: Path) -> None:
    only_offset = ReadOptions(local_offset=CST)
    with pytest.raises(InputError, match="day_first") as caught:
        read(tmp_path, ps_csv(ps_row(TimeCreated="11/10/2026 8:15:03 PM")), only_offset)
    assert "either way round" in str(caught.value)
    day_first = ReadOptions(local_offset=CST, day_first=True)
    assert (
        only_event(
            read(tmp_path, ps_csv(ps_row(TimeCreated="11/10/2026 8:15:03 PM")), day_first)
        ).time.month
        == 10
    )


def test_unambiguous_dates_need_no_day_first(tmp_path: Path) -> None:
    only_offset = ReadOptions(local_offset=CST)
    month_first = only_event(
        read(tmp_path, ps_csv(ps_row(TimeCreated="11/13/2026 8:15:03 PM")), only_offset)
    )
    assert (month_first.time.month, month_first.time.day) == (11, 14)
    day_first = only_event(
        read(tmp_path, ps_csv(ps_row(TimeCreated="13/11/2026 20:15:03")), only_offset)
    )
    assert (day_first.time.month, day_first.time.day) == (11, 14)
    same = only_event(
        read(tmp_path, ps_csv(ps_row(TimeCreated="05/05/2026 20:15:03")), only_offset)
    )
    assert (same.time.month, same.time.day) == (5, 6)


def test_option_errors_are_raised_even_after_good_rows(tmp_path: Path) -> None:
    text = ps_csv(
        ps_row(TimeCreated="11/13/2026 8:15:03 PM"), ps_row(TimeCreated="11/10/2026 8:15:03 PM")
    )
    path = tmp_path / "late.csv"
    path.write_text(text, encoding="utf-8")
    reader = read_csv(path, ReadOptions(local_offset=CST))
    assert isinstance(next(reader), Event)
    with pytest.raises(InputError, match="day_first"):
        next(reader)


@pytest.mark.parametrize(
    ("stamp", "options"),
    [
        ("13/13/2026 8:15:03 PM", ReadOptions(local_offset=CST)),
        ("14/13/2026 8:15:03 PM", ReadOptions(local_offset=CST)),
        ("02/30/2026 8:15:03 PM", ReadOptions(local_offset=CST, day_first=False)),
        ("30/02/2026 8:15:03 PM", ReadOptions(local_offset=CST, day_first=True)),
        ("11/10/2026 13:15:03 PM", ReadOptions(local_offset=CST, day_first=False)),
        ("11/10/2026 0:15:03 AM", ReadOptions(local_offset=CST, day_first=False)),
        ("11/10/2026 25:15:03", ReadOptions(local_offset=CST, day_first=False)),
        ("11/10/2026 8:15:61", ReadOptions(local_offset=CST, day_first=False)),
        ("11-10-2026 8:15:03", ReadOptions(local_offset=CST, day_first=False)),
        ("2026-11-10T02:15:03+24:00", ReadOptions()),
        ("2026-11-10T02:15:03+05:60", ReadOptions()),
        ("0001-01-01T00:00:00+05:00", ReadOptions()),
        ("9999-12-31T23:59:59-05:00", ReadOptions()),
    ],
)
def test_impossible_times_are_problems(tmp_path: Path, stamp: str, options: ReadOptions) -> None:
    problem = only_problem(read(tmp_path, ps_csv(ps_row(TimeCreated=stamp)), options))
    assert "time cannot be used" in problem.reason


def test_unusable_local_offset_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="local_offset"):
        read(tmp_path, ps_csv(ps_row()), ReadOptions(local_offset=timedelta(hours=24)))


# --- message parsing ----------------------------------------------------------------


def parse(tmp_path: Path, text: str, options: ReadOptions | None = None) -> dict[str, str]:
    found = only_event(
        read(tmp_path, ps_csv(ps_row(Message=text)), options or ReadOptions(local_offset=CST))
    )
    return dict(found.data)


def test_same_label_in_two_sections_is_two_fields_and_repeats_are_numbered(tmp_path: Path) -> None:
    text = (
        "Title\n\nSubject:\n\tSecurity ID:\t\tA\n\tSecurity ID:\t\tB\n"
        "Member:\n\tSecurity ID:\t\tC\nSubject:\n\tSecurity ID:\t\tD"
    )
    assert parse(tmp_path, text) == {
        "Subject/Security ID": "A",
        "Subject/Security ID#2": "B",
        "Member/Security ID": "C",
        "Subject/Security ID#3": "D",
    }


def test_4728_member_message(tmp_path: Path) -> None:
    text = message(
        "A member was added to a security-enabled global group.",
        ("Subject", [("Security ID", ADMIN), ("Account Name", "admin"), ("Logon ID", "0x3e7")]),
        (
            "Member",
            [("Security ID", USER), ("Account Name", "CN=jdoe,OU=Staff,DC=corp,DC=example")],
        ),
        (
            "Group",
            [
                ("Security ID", f"{USER[:-4]}512"),
                ("Group Name", "Domain Admins"),
                ("Group Domain", "CORP"),
            ],
        ),
        ("Additional Information", [("Privileges", "-")]),
    )
    data = parse(tmp_path, text)
    assert data["Member/Account Name"] == "CN=jdoe,OU=Staff,DC=corp,DC=example"
    assert data["Group/Group Name"] == "Domain Admins"
    assert data["Additional Information/Privileges"] == "-"


def test_4624_values_with_colons_and_blank_values(tmp_path: Path) -> None:
    text = message(
        "An account was successfully logged on.",
        ("Logon Information", [("Logon Type", "3"), ("Restricted Admin Mode", "-")]),
        (
            "Network Information",
            [
                ("Workstation Name", "WS01"),
                ("Source Network Address", "::1"),
                ("Source Port", "49152"),
            ],
        ),
        ("Process Information", [("Process Name", "C:\\Windows\\System32\\lsass.exe")]),
        ("Detailed Authentication Information", [("Package Name (NTLM only)", "-")]),
    )
    data = parse(tmp_path, text)
    assert data["Network Information/Source Network Address"] == "::1"
    assert data["Process Information/Process Name"] == "C:\\Windows\\System32\\lsass.exe"
    assert data["Detailed Authentication Information/Package Name (NTLM only)"] == "-"


def test_5136_value_may_contain_colons_and_dn(tmp_path: Path) -> None:
    text = message(
        "A directory service object was modified.",
        (
            "Object",
            [
                ("DN", "CN=jdoe,OU=Staff,DC=corp,DC=example"),
                ("GUID", "CN=jdoe,OU=Staff,DC=corp,DC=example"),
            ],
        ),
        (
            "Attribute",
            [("LDAP Display Name", "description"), ("Value", "reviewed: yes; ticket: INC-1")],
        ),
        (
            "Operation",
            [("Type", "Value Added"), ("Correlation ID", "{AAAAAAAA-0000-0000-0000-000000000003}")],
        ),
    )
    data = parse(tmp_path, text)
    assert data["Attribute/Value"] == "reviewed: yes; ticket: INC-1"
    assert data["Operation/Correlation ID"] == "{AAAAAAAA-0000-0000-0000-000000000003}"


def test_multi_line_values_join_with_newlines(tmp_path: Path) -> None:
    text = (
        "A user account was changed.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\r\n"
        "Privileges:\r\n\tPrivileges:\t\tSeSecurityPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n"
        "\tNext:\t\tafter\r\n"
        "Changed Attributes:\r\n\tUser Account Control:\r\n\t\tAccount Disabled\r\n"
        "\t\t'Password Not Required' - Enabled\r\n"
        "\tSAM Account Name:\t-\r\n"
    )
    data = parse(tmp_path, text)
    assert (
        data["Privileges/Privileges"]
        == "SeSecurityPrivilege\nSeBackupPrivilege\nSeRestorePrivilege"
    )
    assert data["Privileges/Next"] == "after"
    assert (
        data["Changed Attributes/User Account Control"]
        == "Account Disabled\n'Password Not Required' - Enabled"
    )
    assert data["Changed Attributes/SAM Account Name"] == "-"


def test_a_blank_line_ends_a_continuation(tmp_path: Path) -> None:
    text = "T\n\nS:\n\tA:\t\t1\n\n\t\tstray\n"
    problem = only_problem(
        read(tmp_path, ps_csv(ps_row(Message=text)), ReadOptions(local_offset=CST))
    )
    assert "not 'Label: value'" in problem.reason


def test_continuation_lines_that_look_like_fields_are_still_continuations(tmp_path: Path) -> None:
    text = "T\n\nS:\n\tA:\t\t1\n\t\tB: 2\n\tC:\t\t3\n"
    assert parse(tmp_path, text) == {"S/A": "1\nB: 2", "S/C": "3"}


def test_free_text_and_unindented_lines_are_ignored(tmp_path: Path) -> None:
    text = (
        "Opening sentence.\n\nS:\n\tA:\t\t1\n\nToken Elevation Type indicates the type of token.\n"
        "Type 1 is a full token with no privileges removed.\n"
    )
    assert parse(tmp_path, text) == {"S/A": "1"}


def test_tab_first_label_spaces_and_fields_before_a_section(tmp_path: Path) -> None:
    text = (
        "\tLoose Label\t\tvalue one\n\tSpaced:   value two  \n"
        "Section:\n\tPrivileges\t\t-\n\tOther : x\n"
    )
    assert parse(tmp_path, text) == {
        "Loose Label": "value one",
        "Spaced": "value two  ",
        "Section/Privileges": "-",
        "Section/Other": "x",
    }
    assert parse(tmp_path, "S:\n  A: 1\n  B: 2\n") == {"S/A": "1", "S/B": "2"}


def test_labels_for_may_map_only_some_keys(tmp_path: Path) -> None:
    options = ReadOptions(
        local_offset=CST, labels_for=lambda _id: {"Subject/Security ID": "SubjectUserSid"}
    )
    data = parse(tmp_path, MESSAGE_4720, options)
    assert list(data)[:2] == ["SubjectUserSid", "Subject/Account Name"]


def test_mapped_names_that_collide_are_numbered(tmp_path: Path) -> None:
    options = ReadOptions(local_offset=CST, labels_for=lambda _id: {"S/A": "X", "S/B": "X"})
    assert parse(tmp_path, "T\n\nS:\n\tA:\t1\n\tB:\t2\n", options) == {"X": "1", "X#2": "2"}


def test_bare_cr_line_endings_in_a_message(tmp_path: Path) -> None:
    assert parse(tmp_path, "T\r\rS:\r\tA:\t\t1\r\tB:\t\t2") == {"S/A": "1", "S/B": "2"}


@pytest.mark.parametrize(
    "text",
    ["T\n\nS:\n\tno separator here\n", "T\n\nS:\n\t: value\n", "T\n\nS:\n\t   \tonly:\n\tx\n:\n"],
)
def test_indented_lines_that_are_not_fields_are_problems(tmp_path: Path, text: str) -> None:
    problem = only_problem(
        read(tmp_path, ps_csv(ps_row(Message=text)), ReadOptions(local_offset=CST))
    )
    assert "not 'Label: value'" in problem.reason


def test_message_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(csv_reader, "MAX_MESSAGE_LINES", 6)
    problem = only_problem(read(tmp_path, ps_csv(ps_row(Message="S:\n" + "\tA:\t1\n" * 10))))
    assert "more than 6 lines" in problem.reason
    monkeypatch.setattr(csv_reader, "MAX_MESSAGE_LINES", 100)
    monkeypatch.setattr(csv_reader, "MAX_FIELDS", 3)
    problem = only_problem(read(tmp_path, ps_csv(ps_row(Message="S:\n" + "\tA:\t1\n" * 4))))
    assert "more than 3 fields" in problem.reason


# --- Event Viewer export ------------------------------------------------------------


def test_event_viewer_export(tmp_path: Path) -> None:
    items = read(
        tmp_path,
        viewer_csv(viewer_row(), viewer_row(**{"Event ID": "4728", "Level": "Audit Failure"})),
    )
    first, second = items
    assert isinstance(first, Event)
    assert isinstance(second, Event)
    assert first.event_id == 4720
    assert first.time == datetime(2026, 11, 10, 2, 15, 3, tzinfo=UTC)
    assert first.provider == "Microsoft Windows security auditing."
    assert first.record_id is None
    assert first.computer == ""
    assert first.channel == ""
    assert first.version == 0
    assert first.system == {
        "LevelDisplayName": "Audit Success",
        "TaskDisplayName": "User Account Management",
    }
    assert first.data["TargetUserName"] == "jdoe"
    assert first.source.position == "row 1 (line 2)"
    assert second.system["LevelDisplayName"] == "Audit Failure"


def test_event_viewer_header_with_an_unnamed_last_column(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, viewer_csv(viewer_row(), trailing_header=True)))
    assert found.event_id == 4720


def test_event_viewer_empty_level_and_category(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, viewer_csv(viewer_row(Level="", **{"Task Category": ""}))))
    assert found.system == {}


def test_event_viewer_row_without_a_message_column(tmp_path: Path) -> None:
    problem = only_problem(read(tmp_path, viewer_csv(viewer_row()[:5])))
    assert "5 fields but the header has 6" in problem.reason


def test_event_viewer_bad_values(tmp_path: Path) -> None:
    items = read(
        tmp_path,
        viewer_csv(
            viewer_row(**{"Event ID": "x"}), viewer_row(**{"Date and Time": "soon"}), viewer_row()
        ),
    )
    assert [type(i).__name__ for i in items] == ["Problem", "Problem", "Event"]


def test_event_viewer_times_need_the_options(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="local_offset"):
        read(tmp_path, viewer_csv(viewer_row()), ReadOptions())


# --- headers and file level ---------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        ["Foo", "Bar"],
        ["Niveau", "Date et heure", "Source", "ID de l'événement", "Catégorie de la tâche"],
        ["Level", "Date and Time", "Source", "Event ID"],
        ["Level", "Date and Time", "Source", "Event ID", "Task Category", "Extra"],
        ["Message", "Id", "ProviderName"],
        [""],
    ],
)
def test_unknown_headers_are_refused(tmp_path: Path, header: list[str]) -> None:
    with pytest.raises(InputError, match="header toledot knows"):
        read(tmp_path, to_csv(header, [["x"] * len(header)]))


def test_localized_header_message_names_english_only(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="English"):
        read(tmp_path, to_csv(["Niveau", "Date"], []))


def test_duplicate_header_names_are_refused(tmp_path: Path) -> None:
    header = [*POWERSHELL_HEADER, "Id"]
    with pytest.raises(InputError, match="more than once"):
        read(tmp_path, to_csv(header, [[*ps_row(), "1"]]))
    with pytest.raises(InputError, match="more than once"):
        read(tmp_path, to_csv([*VIEWER_HEADER, "", ""], []))


def test_too_many_columns(tmp_path: Path) -> None:
    header = [f"c{i}" for i in range(MAX_COLUMNS + 1)]
    with pytest.raises(InputError, match="more than 256 columns"):
        read(tmp_path, to_csv(header, []))


@pytest.mark.parametrize(
    "content", [b"", b"\xef\xbb\xbf", b"\r\n\r\n", b"#TYPE x\r\n", b"\xff\xfe"]
)
def test_files_without_a_header_are_refused(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(InputError):
        read(tmp_path, content)


def test_header_without_rows_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="no event rows"):
        read(tmp_path, ps_csv())
    with pytest.raises(InputError, match="no event rows"):
        read(tmp_path, ps_csv() + "\r\n\r\n")


def test_header_error_is_raised_by_the_call(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(InputError, match=r"bad\.csv"):
        read_csv(path, ReadOptions())


def test_missing_file_and_directory(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read"):
        read_csv(tmp_path / "nope.csv", ReadOptions())
    with pytest.raises(InputError, match="cannot read"):
        read_csv(tmp_path, ReadOptions())


# --- hostile input ------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        b"Message,Id\x00\r\n",
        b"\xff\xfe\x00\x00M\x00\x00\x00",
        b"M\x00e\x00",
        b"Message,Id\r\n\xff",
        b"\xff\xfeM\x00\x00\xd8",
        b"\xff\xfeM\x00e",
    ],
)
def test_bad_encodings_and_nul_in_the_header_are_refused(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(InputError):
        read(tmp_path, content)


def test_nul_or_bad_bytes_after_good_rows_keep_the_rows_and_report_the_stop(tmp_path: Path) -> None:
    good = ps_csv(ps_row(), ps_row(RecordId="2")).encode("utf-8")
    for tail, text in [(b"\x00", "NUL"), (b"\xff", "not valid UTF-8")]:
        items = read(tmp_path, good + b'"abc' + tail)
        assert [type(i).__name__ for i in items] == ["Event", "Event", "Problem"], tail
        assert text in items[2].reason  # type: ignore[union-attr]
        assert "rest of the file was not read" in items[2].reason  # type: ignore[union-attr]


def test_bytes_before_a_bad_byte_in_the_same_chunk_are_not_lost(tmp_path: Path) -> None:
    items = read(tmp_path, ps_csv(ps_row(), ps_row(RecordId="2")).encode() + b"\xff")
    assert [type(i).__name__ for i in items] == ["Event", "Event", "Problem"]


def test_broken_quoting_stops_the_read(tmp_path: Path) -> None:
    good = ps_csv(ps_row())
    items = read(tmp_path, good + '"abc"def,1\r\n' + ps_csv(ps_row())[len(ps_csv()) :])
    assert [type(i).__name__ for i in items] == ["Event", "Problem"]
    assert "stopped being readable" in items[1].reason  # type: ignore[union-attr]
    assert items[1].source.position == "after row 1"


def test_unterminated_quote_at_the_end(tmp_path: Path) -> None:
    items = read(tmp_path, ps_csv(ps_row()) + '"never closed\r\nmore\r\n')
    assert [type(i).__name__ for i in items] == ["Event", "Problem"]


def test_broken_quoting_before_any_row_is_a_file_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="not readable CSV"):
        read(tmp_path, '"Message"x,Id\r\n')


def test_a_field_over_the_csv_limit_stops_the_read(tmp_path: Path) -> None:
    huge = "x" * 200_000
    items = read(tmp_path, ps_csv(ps_row()) + ps_csv(ps_row(Properties=huge))[len(ps_csv()) :])
    assert [type(i).__name__ for i in items] == ["Event", "Problem"]
    assert "field larger than field limit" in items[1].reason  # type: ignore[union-attr]


def test_a_line_over_the_limit_stops_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(csv_reader, "MAX_LINE_CHARS", 3000)
    long_row = ps_row(Properties="y" * 4000)
    items = read(tmp_path, to_csv(POWERSHELL_HEADER, [ps_row(), long_row, ps_row()]))
    assert [type(i).__name__ for i in items] == ["Event", "Problem"]
    assert "longer than 3000" in items[1].reason  # type: ignore[union-attr]
    with pytest.raises(InputError, match="longer than 3000"):
        read(tmp_path, "x" * 4000 + "\r\n")


def test_generator_closes_its_file_when_abandoned(tmp_path: Path) -> None:
    path = tmp_path / "many.csv"
    path.write_text(ps_csv(*[ps_row() for _ in range(20)]), encoding="utf-8")
    reader = read_csv(path, OPTIONS)
    assert isinstance(next(reader), Event)
    reader.close()  # type: ignore[attr-defined]


# --- property tests -----------------------------------------------------------------


def _read_bytes(content: bytes) -> list[Event | Problem]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fuzz.csv"
        path.write_bytes(content)
        return list(read_csv(path, OPTIONS))


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=300))
def test_arbitrary_bytes_only_raise_input_error(content: bytes) -> None:
    try:
        items = _read_bytes(content)
    except InputError:
        return
    assert all(isinstance(i, (Event, Problem)) for i in items)


_SOUP = st.lists(
    st.sampled_from(
        [
            '"',
            ",",
            "\r\n",
            "\n",
            "\r",
            "Message",
            "Id",
            "ProviderName",
            "LogName",
            "MachineName",
            "TimeCreated",
            "4720",
            "11/13/2026 8:15:03 PM",
            "x",
            "\t",
            ":",
            "S:",
            "\tA:\t1",
            "\x00",
            "é",
        ]
    ),
    max_size=40,
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(parts=_SOUP, with_header=st.booleans())
def test_csv_like_soup_only_raises_input_error(parts: list[str], *, with_header: bool) -> None:
    header = ",".join(POWERSHELL_HEADER) + "\r\n" if with_header else ""
    try:
        items = _read_bytes((header + "".join(parts)).encode("utf-8"))
    except InputError:
        return
    assert all(isinstance(i, (Event, Problem)) for i in items)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.text(alphabet=st.sampled_from(["\t", " ", ":", "\n", "\r", "a", "S", "-", "é"]), max_size=60)
)
def test_any_message_text_gives_an_event_or_a_problem(text: str) -> None:
    content = ps_csv(ps_row(Message=text)).encode("utf-8")
    try:
        items = _read_bytes(content)
    except InputError:
        return
    assert len(items) == 1
    assert isinstance(items[0], (Event, Problem))


def test_nul_at_the_start_of_a_later_chunk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_text, "READ_CHUNK", 4)
    with pytest.raises(InputError, match="NUL"):
        read(tmp_path, b"Mess\x00age,Id\r\n")


def test_packaged_catalog_labels_work_as_labels_for(tmp_path: Path) -> None:
    labels = catalog.labels_for(4720)
    assert labels, "the catalog has no labels for event 4720"
    sections: dict[str, list[tuple[str, str]]] = {}
    for index, key in enumerate(labels):
        section, _, label = key.rpartition("/")
        sections.setdefault(section, []).append((label, f"value{index}"))
    text = message("A user account was created.", *sections.items())
    options = ReadOptions(local_offset=CST, labels_for=catalog.labels_for)
    found = only_event(read(tmp_path, ps_csv(ps_row(Message=text)), options))
    assert list(found.data.values()) == [f"value{i}" for i in range(len(labels))]
    assert list(found.data) == list(labels.values())


# --- forged message text -----------------------------------------------------------------------

REAL_OPTIONS = ReadOptions(local_offset=CST, day_first=False, labels_for=catalog.labels_for)
DS_SECTIONS = (
    ("Subject", [("Security ID", ADMIN), ("Account Name", "admin"), ("Account Domain", "CORP")]),
    ("Directory Service", [("Name", "corp.example"), ("Type", "Active Directory Domain Services")]),
    ("Object", [("DN", "CN=Group,DC=corp,DC=example"), ("Class", "group")]),
)


def ds_message(value: str, operation: str = "Value Added") -> str:
    """A 5136 message as Windows writes it: the attribute value comes before the operation."""
    return message(
        "A directory service object was modified.",
        *DS_SECTIONS,
        ("Attribute", [("LDAP Display Name", "member"), ("Value", value)]),
        ("Operation", [("Type", operation), ("Correlation ID", "{1}")]),
    )


def test_an_honest_directory_message_still_reads_with_its_real_operation(tmp_path: Path) -> None:
    row = ps_row(Message=ds_message("CN=Mallory,DC=corp,DC=example"), Id="5136")
    data = only_event(read(tmp_path, ps_csv(row), REAL_OPTIONS)).data
    assert data["OperationType"] == "Value Added"
    assert data["AttributeValue"] == "CN=Mallory,DC=corp,DC=example"


@pytest.mark.parametrize("layout", ["powershell", "viewer"])
def test_a_value_that_forges_a_section_makes_the_row_a_problem(tmp_path: Path, layout: str) -> None:
    forged = ds_message("CN=Mallory,DC=corp,DC=example\r\n\r\nOperation:\r\n\tType:\tValue Deleted")
    if layout == "powershell":
        content = ps_csv(ps_row(Message=forged, Id="5136"))
    else:
        content = viewer_csv(viewer_row(Message=forged, **{"Event ID": "5136"}))
    problem = only_problem(read(tmp_path, content, REAL_OPTIONS))
    assert "ambiguous" in problem.reason
    assert "'Operation'" in problem.reason


def test_a_value_that_forges_a_label_makes_the_row_a_problem(tmp_path: Path) -> None:
    text = message(
        "A user account was changed.",
        ("Subject", [("Security ID", ADMIN), ("Account Name", "admin")]),
        ("Target Account", [("Security ID", USER)]),
        (
            "Changed Attributes",
            [
                ("Display Name", "Eve\r\n\tOld UAC Value:\t\t0x15\r\n\tNew UAC Value:\t\t0x14"),
                ("Old UAC Value", "0x15"),
                ("New UAC Value", "0x10"),
            ],
        ),
    )
    problem = only_problem(read(tmp_path, ps_csv(ps_row(Message=text, Id="4738")), REAL_OPTIONS))
    assert "ambiguous" in problem.reason
    assert "Old UAC Value" in problem.reason


def test_a_repeat_in_an_event_toledot_has_no_labels_for_is_not_refused(tmp_path: Path) -> None:
    text = "T\n\nS:\n\tA:\t1\nS:\n\tA:\t2\n"
    options = ReadOptions(local_offset=CST, labels_for=lambda _id: None)
    assert parse(tmp_path, text, options) == {"S/A": "1", "S/A#2": "2"}
