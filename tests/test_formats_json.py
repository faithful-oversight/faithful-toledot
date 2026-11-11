# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the JSON and JSON Lines event reader."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from faithful_toledot import catalog
from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, ReadOptions
from faithful_toledot.formats import _text
from faithful_toledot.formats import json as json_reader
from faithful_toledot.formats.json import MAX_DEPTH, read_json

ADMIN = "S-1-5-21-1111111111-2222222222-3333333333-500"
USER = "S-1-5-21-1111111111-2222222222-3333333333-1105"
WHEN = datetime(2026, 11, 10, 2, 15, 3, 123000, tzinfo=UTC)
MILLIS = int(WHEN.timestamp() * 1000)
DATE = f"/Date({MILLIS})/"  # what ConvertTo-Json in Windows PowerShell 5.1 writes, once decoded
NAMES = {
    4720: ("TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectLogonId"),
    4624: ("SubjectUserSid", "LogonType", "IpAddress", "IpPort", "WorkstationName"),
}


def names_for(event_id: int, _version: int, count: int) -> tuple[str, ...] | None:
    names = NAMES.get(event_id)
    return names if names is not None and len(names) == count else None


OPTIONS = ReadOptions(names_for=names_for)


def sid(value: str) -> dict[str, Any]:
    return {
        "BinaryLength": 28,
        "AccountDomainSid": {"BinaryLength": 24, "Value": value[:-5]},
        "Value": value,
    }


def record(**changes: Any) -> dict[str, Any]:
    """A synthetic ``EventLogRecord`` as ``ConvertTo-Json`` writes it."""
    base: dict[str, Any] = {
        "Id": 4720,
        "Version": 0,
        "Qualifiers": None,
        "Level": 0,
        "Task": 13824,
        "Opcode": 0,
        "Keywords": -9214364837600034816,
        "RecordId": 4120,
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "ProviderId": "54849625-5478-4994-a5ba-3e3b0328c30d",
        "LogName": "Security",
        "ProcessId": 612,
        "ThreadId": 700,
        "MachineName": "dc01.corp.example",
        "UserId": None,
        "TimeCreated": DATE,
        "ActivityId": "aaaaaaaa-0000-0000-0000-000000000001",
        "Message": "A user account was created.",
        "Properties": [
            {"Value": "jdoe"},
            {"Value": "CORP"},
            {"Value": sid(USER)},
            {"Value": sid(ADMIN)},
            {"Value": 999},
        ],
    }
    base.update(changes)
    return {k: v for k, v in base.items() if v is not _GONE}


_GONE = object()


def named(**changes: Any) -> dict[str, Any]:
    """A synthetic custom-exporter record with named data."""
    base: dict[str, Any] = {
        "EventID": 4728,
        "TimeCreated": "2026-11-10T02:15:03.123Z",
        "Computer": "dc01.corp.example",
        "Channel": "Security",
        "EventData": {"MemberSid": USER, "TargetUserName": "Domain Admins"},
    }
    base.update(changes)
    return {k: v for k, v in base.items() if v is not _GONE}


def write(tmp_path: Path, content: str | bytes | object, *, name: str = "export.json") -> Path:
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    elif isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_text(json.dumps(content), encoding="utf-8")
    return path


def read(tmp_path: Path, content: object, options: ReadOptions = OPTIONS) -> list[Event | Problem]:
    return list(read_json(write(tmp_path, content), options))


def only_event(items: list[Event | Problem]) -> Event:
    assert len(items) == 1
    assert isinstance(items[0], Event), items[0]
    return items[0]


def only_problem(items: list[Event | Problem]) -> Problem:
    assert len(items) == 1
    assert isinstance(items[0], Problem), items[0]
    return items[0]


# --- PowerShell records -------------------------------------------------------------


def test_array_of_records_from_get_winevent(tmp_path: Path) -> None:
    items = read(
        tmp_path,
        [
            record(),
            record(
                Id=4624,
                RecordId=4121,
                Properties=[
                    {"Value": sid(ADMIN)},
                    {"Value": 3},
                    {"Value": "192.0.2.10"},
                    {"Value": "49152"},
                    {"Value": "-"},
                ],
            ),
        ],
    )
    first, second = items
    assert isinstance(first, Event)
    assert isinstance(second, Event)
    assert first.event_id == 4720
    assert first.time == WHEN
    assert first.computer == "dc01.corp.example"
    assert first.channel == "Security"
    assert first.provider == "Microsoft-Windows-Security-Auditing"
    assert first.record_id == 4120
    assert first.version == 0
    assert first.source.position == "element 1"
    assert first.data == {
        "TargetUserName": "jdoe",
        "TargetDomainName": "CORP",
        "TargetSid": USER,
        "SubjectUserSid": ADMIN,
        "SubjectLogonId": "999",
    }
    assert first.system == {
        "Keywords": "0x8020000000000000",
        "Level": "0",
        "Task": "13824",
        "Opcode": "0",
        "ActivityID": "{AAAAAAAA-0000-0000-0000-000000000001}",
        "ProcessID": "612",
        "ThreadID": "700",
    }
    assert second.data["LogonType"] == "3"
    assert second.data["IpAddress"] == "192.0.2.10"
    assert second.source.position == "element 2"


def test_single_object_compact_and_pretty_printed(tmp_path: Path) -> None:
    assert only_event(read(tmp_path, record())).event_id == 4720
    pretty = write(tmp_path, json.dumps(record(), indent=2), name="pretty.json")
    found = only_event(list(read_json(pretty, OPTIONS)))
    assert found.source.position == "element 1"


def test_pretty_printed_array_with_surrounding_whitespace(tmp_path: Path) -> None:
    path = write(tmp_path, "\n\n  " + json.dumps([record(), record(RecordId=2)], indent=4) + "\n\n")
    assert [getattr(i, "record_id", None) for i in read_json(path, OPTIONS)] == [4120, 2]


def test_names_for_is_called_with_id_version_and_count(tmp_path: Path) -> None:
    seen: list[tuple[int, int, int]] = []

    def recorder(event_id: int, version: int, count: int) -> tuple[str, ...] | None:
        seen.append((event_id, version, count))
        return None

    found = only_event(read(tmp_path, record(Version=2), ReadOptions(names_for=recorder)))
    assert seen == [(4720, 2, 5)]
    assert found.version == 2
    assert list(found.data) == ["param1", "param2", "param3", "param4", "param5"]


def test_names_unavailable_means_param_names_and_nothing_else(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, record(Id=9999), ReadOptions()))
    assert found.data == {
        "param1": "jdoe",
        "param2": "CORP",
        "param3": USER,
        "param4": ADMIN,
        "param5": "999",
    }


def test_no_properties_never_asks_for_names(tmp_path: Path) -> None:
    def boom(*_args: object) -> tuple[str, ...]:
        raise AssertionError

    assert only_event(read(tmp_path, record(Properties=[]), ReadOptions(names_for=boom))).data == {}


def test_duplicate_and_unusable_names(tmp_path: Path) -> None:
    dup = ReadOptions(names_for=lambda *_: ("A", "A", "B", "A", "A#2"))
    assert list(only_event(read(tmp_path, record(), dup)).data) == ["A", "A#2", "B", "A#3", "A#2#2"]
    for bad in [("A", "B"), ("A", "B", "C", "D", ""), ("A", "B", "C", "D", "n" * 300)]:
        problem = only_problem(read(tmp_path, record(), ReadOptions(names_for=lambda *_, b=bad: b)))
        assert "names_for" in problem.reason
        assert problem.record_id == 4120


def test_a_name_that_collides_with_a_later_repeat(tmp_path: Path) -> None:
    options = ReadOptions(names_for=lambda *_: ("A", "A#2", "A", "B", "C"))
    assert list(only_event(read(tmp_path, record(), options)).data) == ["A", "A#2", "A#3", "B", "C"]


def test_property_values_are_written_as_event_xml_text_where_known(tmp_path: Path) -> None:
    props = [
        {"Value": "text"},
        {"Value": sid(USER)},
        {"Value": 2147483648},
        {"Value": -5},
        {"Value": True},
        {"Value": False},
        {"Value": None},
        {"Value": [0, 15, 255, 171]},
        {"Value": []},
        {"Value": DATE},
        {"Value": 1.5},
        {"Value": {"Value": 7}},
        {"Value": "%%1794"},
        {"Value": "0x3e7"},
        {"Value": "2026-11-09T20:15:03.123-06:00"},
        USER,
        7,
    ]
    options = ReadOptions()
    found = only_event(read(tmp_path, record(Properties=props), options))
    assert list(found.data.values()) == [
        "text",
        USER,
        "2147483648",
        "-5",
        "true",
        "false",
        "",
        "000FFFAB",
        "",
        "2026-11-10T02:15:03.1230000Z",
        "1.5",
        "7",
        "%%1794",
        "0x3e7",
        "2026-11-09T20:15:03.123-06:00",
        USER,
        "7",
    ]


def test_hex_integers_arrive_as_decimal_and_stay_decimal(tmp_path: Path) -> None:
    """The documented divergence: a logon ID of 0x3e7 is the number 999 in JSON."""
    found = only_event(read(tmp_path, record(Properties=[{"Value": 0x3E7}] * 5)))
    assert found.data["SubjectLogonId"] == "999"


@pytest.mark.parametrize(
    "value",
    [
        {"Value": "x", "Other": 1},
        {"a": 1},
        ["a", "b"],
        [256],
        [-1],
        [True],
        [1.5],
        {"Value": {"b": 1}},
    ],
)
def test_unsupported_property_values_are_problems(tmp_path: Path, value: object) -> None:
    problem = only_problem(read(tmp_path, record(Properties=[{"Value": value}] * 5)))
    assert "not supported" in problem.reason or "byte array" in problem.reason


def test_date_property_out_of_range(tmp_path: Path) -> None:
    problem = only_problem(
        read(tmp_path, record(Properties=[{"Value": "/Date(999999999999999)/"}] * 5))
    )
    assert "date out of range" in problem.reason


def test_a_property_list_over_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json_reader, "MAX_FIELDS", 4)
    assert "more than 4 properties" in only_problem(read(tmp_path, record())).reason


@pytest.mark.parametrize(
    "stamp",
    [
        DATE,
        f"/Date({MILLIS}+0000)/",
        f"/Date({MILLIS}-0600)/",
        "2026-11-10T02:15:03.123Z",
        "2026-11-10T02:15:03.1230000Z",
        "2026-11-09T20:15:03.123-06:00",
        "2026-11-10T04:15:03.123+0200",
        {"value": DATE, "DisplayHint": 2, "DateTime": "Tuesday, November 10, 2026 2:15:03 AM"},
        {"Value": "2026-11-10T02:15:03.123Z"},
    ],
)
def test_every_time_shape(tmp_path: Path, stamp: object) -> None:
    assert only_event(read(tmp_path, record(TimeCreated=stamp))).time == WHEN


def test_epoch_and_pre_epoch_dates(tmp_path: Path) -> None:
    assert only_event(read(tmp_path, record(TimeCreated="/Date(0)/"))).time == datetime(
        1970, 1, 1, tzinfo=UTC
    )
    assert only_event(read(tmp_path, record(TimeCreated="/Date(-1000)/"))).time.year == 1969


@pytest.mark.parametrize(
    ("stamp", "text"),
    [
        ("2026-11-10T02:15:03", "no UTC offset"),
        ("yesterday", "not an ISO 8601"),
        ("/Date(999999999999999)/", "out of range"),
        (1762740903, "must be a string"),
        (None, "must be a string"),
        ({"DisplayHint": 2}, "no 'value'"),
        ({"value": DATE, "Value": DATE}, "ambiguous"),
        ({"value": 5}, "must be a string"),
    ],
)
def test_bad_times_are_problems(tmp_path: Path, stamp: object, text: str) -> None:
    problem = only_problem(read(tmp_path, record(TimeCreated=stamp)))
    assert text in problem.reason
    assert problem.record_id == 4120


def test_time_without_offset_uses_local_offset(tmp_path: Path) -> None:
    options = ReadOptions(names_for=names_for, local_offset=timedelta(hours=-6))
    assert (
        only_event(read(tmp_path, record(TimeCreated="2026-11-09T20:15:03.123"), options)).time
        == WHEN
    )


def test_unusable_local_offset_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="local_offset"):
        read(tmp_path, record(), ReadOptions(local_offset=timedelta(hours=30)))


def test_user_id_shapes(tmp_path: Path) -> None:
    as_object = only_event(
        read(
            tmp_path,
            record(UserId={"BinaryLength": 12, "AccountDomainSid": None, "Value": "S-1-5-18"}),
        )
    )
    assert as_object.system["UserID"] == "S-1-5-18"
    assert only_event(read(tmp_path, record(UserId="S-1-5-18"))).system["UserID"] == "S-1-5-18"
    assert "UserID" not in only_event(read(tmp_path, record(UserId=None))).system
    assert "UserID" not in only_event(read(tmp_path, record(UserId=_GONE))).system
    assert "UserID" not in only_event(read(tmp_path, record(UserId={"Value": None}))).system


@pytest.mark.parametrize(
    "changes",
    [
        {"UserId": 5},
        {"Keywords": "abc"},
        {"Keywords": 1 << 70},
        {"Keywords": 20000000000000000000},
        {"Keywords": True},
        {"Keywords": 1.5},
        {"ActivityId": "not-a-guid"},
        {"Level": "x"},
        {"Level": -1},
        {"ProcessId": [1]},
        {"UserId": "S" * 300},
    ],
)
def test_bad_system_values_are_problems(tmp_path: Path, changes: dict[str, object]) -> None:
    assert isinstance(only_problem(read(tmp_path, record(**changes))), Problem)


def test_system_values_accept_numbers_and_numeric_text(tmp_path: Path) -> None:
    found = only_event(
        read(
            tmp_path,
            record(
                Keywords="0X8020000000000000",
                Level="4",
                Task=None,
                ActivityId="{AAAAAAAA-0000-0000-0000-000000000009}",
                RelatedActivityId="bbbbbbbb-0000-0000-0000-000000000009",
            ),
        )
    )
    assert found.system["Keywords"] == "0x8020000000000000"
    assert found.system["Level"] == "4"
    assert "Task" not in found.system
    assert found.system["RelatedActivityID"] == "{BBBBBBBB-0000-0000-0000-000000000009}"


@pytest.mark.parametrize("missing", ["Id", "TimeCreated", "MachineName", "LogName", "ProviderName"])
def test_missing_required_keys(tmp_path: Path, missing: str) -> None:
    items = read(tmp_path, [record(**{missing: _GONE}), record()])
    assert isinstance(items[0], Problem)
    assert missing in items[0].reason
    assert isinstance(items[1], Event)


@pytest.mark.parametrize(
    "changes",
    [
        {"Id": 70000},
        {"Id": "abc"},
        {"Id": True},
        {"Id": 1.5},
        {"MachineName": ""},
        {"LogName": 5},
        {"ProviderName": None},
        {"Version": 300},
        {"Version": "x"},
        {"RecordId": -1},
        {"RecordId": "x"},
        {"Properties": "x"},
        {"Properties": None},
    ],
)
def test_bad_field_values_are_problems(tmp_path: Path, changes: dict[str, object]) -> None:
    assert isinstance(only_problem(read(tmp_path, record(**changes))), Problem)


def test_numeric_text_is_accepted_for_whole_numbers(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, record(Id="4720", Version=None, RecordId=None)))
    assert found.event_id == 4720
    assert found.version == 0
    assert found.record_id is None


def test_properties_with_named_shape_keys_is_ambiguous(tmp_path: Path) -> None:
    for extra in (
        {"EventID": 4720},
        {"Computer": "x"},
        {"Channel": "x"},
        {"SystemTime": "x"},
        {"Provider": "x"},
    ):
        assert "ambiguous" in only_problem(read(tmp_path, {**record(), **extra})).reason


# --- named data ---------------------------------------------------------------------


def test_named_shape_with_all_primary_spellings(tmp_path: Path) -> None:
    found = only_event(
        read(
            tmp_path,
            named(
                Provider="Microsoft-Windows-Security-Auditing",
                Version=1,
                RecordId=77,
                Level=0,
                Keywords="0x8020000000000000",
            ),
        )
    )
    assert found.event_id == 4728
    assert found.time == WHEN
    assert found.computer == "dc01.corp.example"
    assert found.channel == "Security"
    assert found.provider == "Microsoft-Windows-Security-Auditing"
    assert found.record_id == 77
    assert found.version == 1
    assert list(found.data.items()) == [("MemberSid", USER), ("TargetUserName", "Domain Admins")]
    assert found.system == {"Keywords": "0x8020000000000000", "Level": "0"}


def test_named_shape_with_the_other_spellings(tmp_path: Path) -> None:
    obj = {
        "Id": "4738",
        "SystemTime": "2026-11-10T02:15:03.123Z",
        "MachineName": "dc02",
        "LogName": "Security",
        "ProviderName": "P",
        "EventRecordID": 5,
        "ActivityID": "aaaaaaaa-0000-0000-0000-000000000001",
        "RelatedActivityID": "aaaaaaaa-0000-0000-0000-000000000002",
        "ProcessID": 1,
        "ThreadID": 2,
        "UserID": "S-1-5-18",
        "data": {"a": 1, "b": True, "c": None, "d": [1, 2], "e": sid(USER), "f": "x"},
    }
    found = only_event(read(tmp_path, obj))
    assert found.event_id == 4738
    assert found.record_id == 5
    assert found.provider == "P"
    assert found.data == {"a": "1", "b": "true", "c": "", "d": "0102", "e": USER, "f": "x"}
    assert found.system["UserID"] == "S-1-5-18"
    assert found.system["ThreadID"] == "2"


def test_named_shape_without_provider_has_empty_provider_and_null_data_is_empty(
    tmp_path: Path,
) -> None:
    found = only_event(read(tmp_path, named(EventData=None)))
    assert found.provider == ""
    assert found.data == {}
    assert only_event(read(tmp_path, named(EventData={}))).data == {}


VALID = {
    "EventID": 4728,
    "Id": 4728,
    "TimeCreated": "2026-11-10T02:15:03Z",
    "SystemTime": "2026-11-10T02:15:03Z",
    "Computer": "h",
    "MachineName": "h",
    "Channel": "c",
    "LogName": "c",
    "EventData": {},
    "data": {},
    "Provider": "p",
    "ProviderName": "p",
    "RecordId": 1,
    "EventRecordID": 1,
    "ActivityId": "aaaaaaaa-0000-0000-0000-000000000001",
    "ActivityID": "aaaaaaaa-0000-0000-0000-000000000001",
    "RelatedActivityId": "aaaaaaaa-0000-0000-0000-000000000001",
    "RelatedActivityID": "aaaaaaaa-0000-0000-0000-000000000001",
    "ProcessId": 1,
    "ProcessID": 1,
    "ThreadId": 1,
    "ThreadID": 1,
    "UserId": "S-1-5-18",
    "UserID": "S-1-5-18",
}


@pytest.mark.parametrize(
    "pair",
    [
        ("EventID", "Id"),
        ("TimeCreated", "SystemTime"),
        ("Computer", "MachineName"),
        ("Channel", "LogName"),
        ("EventData", "data"),
        ("Provider", "ProviderName"),
        ("RecordId", "EventRecordID"),
        ("ActivityId", "ActivityID"),
        ("RelatedActivityId", "RelatedActivityID"),
        ("ProcessId", "ProcessID"),
        ("ThreadId", "ThreadID"),
        ("UserId", "UserID"),
    ],
)
def test_two_spellings_of_one_field_are_ambiguous(tmp_path: Path, pair: tuple[str, str]) -> None:
    obj = named(**{pair[0]: _GONE, pair[1]: _GONE, "EventData": {}})
    if "EventData" in pair:
        del obj["EventData"]
    obj |= {pair[0]: VALID[pair[0]], pair[1]: VALID[pair[1]]}
    assert "ambiguous" in only_problem(read(tmp_path, [obj])).reason


@pytest.mark.parametrize("missing", ["EventID", "TimeCreated", "Computer", "Channel"])
def test_named_shape_missing_required(tmp_path: Path, missing: str) -> None:
    items = read(tmp_path, [named(**{missing: _GONE}), named()])
    assert isinstance(items[0], Problem)
    assert missing in items[0].reason
    assert isinstance(items[1], Event)


@pytest.mark.parametrize(
    "changes",
    [
        {"EventData": [1]},
        {"EventData": "x"},
        {"EventData": {"": "x"}},
        {"EventData": {"a": {"b": 1}}},
        {"Provider": 5},
        {"Version": "x"},
        {"Computer": ""},
    ],
)
def test_named_shape_bad_values(tmp_path: Path, changes: dict[str, object]) -> None:
    assert isinstance(only_problem(read(tmp_path, named(**changes))), Problem)


def test_named_data_over_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json_reader, "MAX_FIELDS", 1)
    assert "more than 1 data fields" in only_problem(read(tmp_path, named())).reason


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    assert only_event(read(tmp_path, named(Message="x", Anything={"deep": [1]}))).event_id == 4728


# --- shape detection ----------------------------------------------------------------


def test_both_shapes_in_one_record_is_a_problem(tmp_path: Path) -> None:
    items = read(tmp_path, [record(), {**record(), "EventData": {}}, record()])
    assert [type(i) for i in items] == [Event, Problem, Event]
    assert "ambiguous" in items[1].reason  # type: ignore[union-attr]


def test_a_later_record_of_neither_shape_is_a_problem(tmp_path: Path) -> None:
    items = read(tmp_path, [record(), {"hello": 1}, 5, "text", None, [1], record()])
    assert [type(i).__name__ for i in items] == ["Event", *["Problem"] * 5, "Event"]
    assert "neither Properties" in items[1].reason  # type: ignore[union-attr]
    assert "not a JSON object" in items[2].reason  # type: ignore[union-attr]
    assert items[4].source.position == "element 5"


@pytest.mark.parametrize("first", [{"hello": 1}, 5, "text", [1], None])
def test_first_record_of_neither_shape_refuses_the_file(tmp_path: Path, first: object) -> None:
    with pytest.raises(InputError, match="not a Windows event export"):
        read(tmp_path, [first, record()])


# --- JSON Lines ---------------------------------------------------------------------


def lines(*objects: object, sep: str = "\n") -> str:
    return sep.join(json.dumps(o) for o in objects) + sep


def test_json_lines_with_blank_lines_and_crlf(tmp_path: Path) -> None:
    text = json.dumps(record()) + "\r\n\r\n" + json.dumps(named()) + "\r\n\r\n\r\n"
    items = read(tmp_path, text.encode())
    assert [(type(i).__name__, i.source.position) for i in items] == [
        ("Event", "line 1"),
        ("Event", "line 3"),
    ]


@pytest.mark.parametrize("chunk", [4, 5, 7, 13, 100])
@pytest.mark.parametrize("sep", ["\n", "\r\n", "\r"])
def test_json_lines_positions_survive_chunk_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chunk: int, sep: str
) -> None:
    monkeypatch.setattr(_text, "READ_CHUNK", chunk)
    objs = [named(EventID=4700 + i, EventData={"n": "é" * i}) for i in range(8)]
    path = write(
        tmp_path,
        ("" + sep).join(json.dumps(o, ensure_ascii=False) for o in objs).encode("utf-8"),
        name="l.jsonl",
    )
    items = list(read_json(path, OPTIONS))
    assert [i.source.position for i in items] == [f"line {n}" for n in range(1, 9)]
    assert [i.event_id for i in items if isinstance(i, Event)] == [4700 + i for i in range(8)]


def test_json_lines_bad_lines_are_problems_and_reading_continues(tmp_path: Path) -> None:
    text = (
        lines(named())
        + "{not json\n"
        + lines(named())
        + '{"a":1} {"b":2}\n'
        + "[1]\n"
        + lines(named())
    )
    items = read(tmp_path, text)
    assert [type(i).__name__ for i in items] == [
        "Event",
        "Problem",
        "Event",
        "Problem",
        "Problem",
        "Event",
    ]
    assert items[1].source.position == "line 2"
    assert "not valid JSON" in items[1].reason  # type: ignore[union-attr]
    assert "more than one JSON value" in items[3].reason  # type: ignore[union-attr]


def test_json_lines_line_over_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json_reader, "MAX_LINE_CHARS", 300)
    short = json.dumps(named())
    assert len(short) < 300
    big = json.dumps(named(EventData={"a": "x" * 400}))
    items = read(tmp_path, f"{short}\n{big}\n{short}\n")
    assert [type(i).__name__ for i in items] == ["Event", "Problem", "Event"]
    assert "longer than 300" in items[1].reason  # type: ignore[union-attr]
    assert items[2].source.position == "line 3"


def test_json_lines_invalid_text_after_good_lines(tmp_path: Path) -> None:
    content = lines(named(), named()).encode() + b'{"a":"\xff"}\n'
    items = read(tmp_path, content)
    assert [type(i).__name__ for i in items] == ["Event", "Event", "Problem"]
    assert "not valid UTF-8" in items[2].reason  # type: ignore[union-attr]
    assert items[2].source.position == "after line 2"


def test_json_lines_first_line_must_be_an_event(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="first record"):
        read(tmp_path, lines({"hello": 1}, named()))


# --- encodings ----------------------------------------------------------------------


@pytest.mark.parametrize("layout", ["array", "lines", "object"])
@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_encodings(tmp_path: Path, layout: str, encoding: str) -> None:
    obj = named(EventData={"n": "Zoë ☃ 😀"})
    text = {
        "array": json.dumps([obj, obj]),
        "lines": lines(obj, obj),
        "object": json.dumps(obj, indent=1),
    }[layout]
    items = list(read_json(write(tmp_path, text.encode(encoding)), OPTIONS))
    assert len(items) == (1 if layout == "object" else 2)
    assert all(isinstance(i, Event) and i.data == {"n": "Zoë ☃ 😀"} for i in items)


def test_utf_16_big_endian_with_mark(tmp_path: Path) -> None:
    content = b"\xfe\xff" + json.dumps([named()]).encode("utf-16-be")
    assert only_event(list(read_json(write(tmp_path, content), OPTIONS))).event_id == 4728


@pytest.mark.parametrize(
    "content",
    [
        b"\xff\xfe\x00\x00[\x00\x00\x00",
        b"[\x00{\x00",
        b"\xff\xfe[\x00\x00\xd8]\x00",
        b"\xff\xfe[\x00",
        b'[{"a":"\xff"}]',
        b"[\x00]",
    ],
)
def test_bad_encodings_are_refused(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(InputError):
        read(tmp_path, content)


# --- strict decoding ----------------------------------------------------------------


def test_duplicate_keys_make_that_record_a_problem(tmp_path: Path) -> None:
    text = '[{"Id":1,"Id":2,"Properties":[]},' + json.dumps(record()) + "]"
    items = read(tmp_path, text)
    assert "repeats a property name" in items[0].reason  # type: ignore[union-attr]
    assert isinstance(items[1], Event)


def test_duplicate_keys_deep_inside_a_record(tmp_path: Path) -> None:
    text = json.dumps(record()).replace('"Value": "jdoe"', '"Value": "jdoe", "Value": "x"')
    assert "repeats" in only_problem(read(tmp_path, f"[{text}]")).reason


def test_nesting_over_the_limit_is_a_problem(tmp_path: Path) -> None:
    deep: Any = "x"
    for _ in range(MAX_DEPTH + 2):
        deep = {"a": deep}
    items = read(tmp_path, [record(Extra=deep), record()])
    assert "nested more than" in items[0].reason  # type: ignore[union-attr]
    assert isinstance(items[1], Event)


def test_nesting_in_arrays_counts_too(tmp_path: Path) -> None:
    deep: Any = 1
    for _ in range(MAX_DEPTH + 2):
        deep = [deep]
    assert "nested more than" in only_problem(read(tmp_path, [record(Extra=deep)])).reason


def test_absurd_nesting_is_a_syntax_stop(tmp_path: Path) -> None:
    deep = "[" * 200000
    with pytest.raises(InputError, match="nested too deeply"):
        read(tmp_path, "[" + deep)
    text = "[" + json.dumps(record()) + "," + deep
    items = read(tmp_path, text)
    assert isinstance(items[0], Event)
    assert isinstance(items[1], Problem)
    assert "nested too deeply" in items[1].reason


@pytest.mark.parametrize(
    ("literal", "text"),
    [
        ("1" * 25, "more than 20 digits"),
        ("-" + "9" * 25, "more than 20 digits"),
        ("NaN", "NaN and Infinity"),
        ("Infinity", "NaN and Infinity"),
        ("-Infinity", "NaN and Infinity"),
        ("1." + "0" * 80, "too long"),
    ],
)
def test_number_limits_make_the_record_a_problem(tmp_path: Path, literal: str, text: str) -> None:
    raw = '[{"Id":4720,"Extra":' + literal + ',"Properties":[]},' + json.dumps(record()) + "]"
    items = read(tmp_path, raw)
    assert text in items[0].reason  # type: ignore[union-attr]
    assert isinstance(items[1], Event)


def test_a_twenty_digit_number_is_fine(tmp_path: Path) -> None:
    raw = json.dumps(record()).replace('"RecordId": 4120', '"RecordId": 18446744073709551615')
    assert only_event(read(tmp_path, raw)).record_id == 2**64 - 1


def test_lone_surrogates_make_the_record_a_problem(tmp_path: Path) -> None:
    value = '"\\ud800"'
    for raw in (
        '[{"Id":1,"Extra":' + value + ',"Properties":[]}]',
        '[{"Id":1,"Extra":["a",{"b":' + value + '}],"Properties":[]}]',
        '[{"Id":1,"\\udc00":1,"Properties":[]}]',
    ):
        assert "unpaired surrogate" in only_problem(read(tmp_path, raw)).reason


def test_lone_surrogate_in_a_later_record(tmp_path: Path) -> None:
    raw = (
        "["
        + json.dumps(record())
        + ',{"Id":1,"Extra":"\\ud800","Properties":[]},{"Id":1,"\\udc00":1,"Properties":[]}]'
    )
    items = read(tmp_path, raw)
    assert [type(i).__name__ for i in items] == ["Event", "Problem", "Problem"]
    assert "unpaired surrogate" in items[1].reason  # type: ignore[union-attr]
    assert "property name" in items[2].reason  # type: ignore[union-attr]


def test_paired_surrogate_escapes_are_fine(tmp_path: Path) -> None:
    raw = json.dumps(named(EventData={"n": "😀"}), ensure_ascii=True)
    assert only_event(read(tmp_path, raw)).data == {"n": "😀"}


def test_value_and_name_length_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json_reader, "MAX_VALUE_CHARS", 30)
    items = read(
        tmp_path,
        [
            named(EventData={"a": "x" * 31}),
            named(EventData={"n" * 300: "1"}),
            named(EventData={"a": "x" * 30}),
        ],
    )
    assert "value is longer than 30" in items[0].reason  # type: ignore[union-attr]
    assert "property name is longer" in items[1].reason  # type: ignore[union-attr]
    assert isinstance(items[2], Event)


def test_record_size_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json_reader, "MAX_EVENT_CHARS", 200)
    items = read(tmp_path, [named(), named(EventData={"a": "x" * 150, "b": "y" * 150})])
    assert isinstance(items[0], Event)
    assert "more than 200 characters" in items[1].reason  # type: ignore[union-attr]


# --- file level ---------------------------------------------------------------------


@pytest.mark.parametrize("content", ["", "   \n\t ", "[]", "  [ ]  ", "﻿"])
def test_files_with_no_records_are_refused(tmp_path: Path, content: str) -> None:
    with pytest.raises(InputError):
        read(tmp_path, content.encode("utf-8"))


@pytest.mark.parametrize("content", ["abc", "123", '"text"', "null", "true", "<xml/>", "# hi"])
def test_files_that_are_not_json_objects_or_arrays(tmp_path: Path, content: str) -> None:
    with pytest.raises(InputError, match="does not start with"):
        read(tmp_path, content)


def test_error_is_raised_by_the_call(tmp_path: Path) -> None:
    path = write(tmp_path, "abc")
    with pytest.raises(InputError):
        read_json(path, OPTIONS)


@pytest.mark.parametrize("raw", ["[{", "[1 2]", "[{},]", "[,]", '{"a":1', "[", '[{"a"', "[ "])
def test_broken_syntax_before_any_record_is_refused(tmp_path: Path, raw: str) -> None:
    with pytest.raises(InputError):
        read(tmp_path, raw)


@pytest.mark.parametrize("raw", ["[{", '{"a":1', "[", '[{"a"', "[,]"])
def test_syntax_error_message_says_not_valid_json(tmp_path: Path, raw: str) -> None:
    with pytest.raises(InputError, match="not valid JSON"):
        read(tmp_path, raw)


def test_broken_syntax_after_records_keeps_them_and_reports_the_stop(tmp_path: Path) -> None:
    one = json.dumps(named())
    for tail, text in [
        (",", "Expecting value"),
        (", {", "Expecting property name"),
        ("  oops", "expected a comma"),
        ("] extra", "more after the array"),
    ]:
        items = read(tmp_path, f"[{one}{tail}")
        assert isinstance(items[0], Event)
        assert isinstance(items[1], Problem), tail
        assert text in items[1].reason or "not valid" in items[1].reason
        assert items[1].source.position == "after element 1"
        assert "rest of the file was not read" in items[1].reason


def test_extra_data_after_a_single_object(tmp_path: Path) -> None:
    pretty = json.dumps(named(), indent=2)
    with pytest.raises(InputError, match="more after the object"):
        read(tmp_path, pretty + "\n" + pretty)


def test_extra_data_after_an_array_is_reported_after_its_records(tmp_path: Path) -> None:
    arr = "[" + json.dumps(named()) + "]"
    items = read(tmp_path, arr + " " + arr)
    assert [type(i) for i in items] == [Event, Problem]
    assert "more after the array" in items[1].reason  # type: ignore[union-attr]


def test_jsonl_of_arrays_is_not_accepted(tmp_path: Path) -> None:
    arr = "[" + json.dumps(named()) + "]"
    items = read(tmp_path, arr + "\n" + arr + "\n")
    assert [type(i) for i in items] == [Event, Problem]
    assert "one object per line" in items[1].reason  # type: ignore[union-attr]


def test_pretty_printed_object_is_not_mistaken_for_json_lines(tmp_path: Path) -> None:
    assert len(read(tmp_path, json.dumps(named(), indent=4))) == 1


def test_large_document_is_refused_with_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(json_reader, "MAX_JSON_BYTES", 100)
    path = write(tmp_path, json.dumps([named(), named()]))
    with pytest.raises(InputError, match="JSON Lines"):
        read_json(path, OPTIONS)
    # JSON Lines of any size is not subject to the limit
    big = write(tmp_path, lines(named(), named(), named()), name="big.jsonl")
    assert len(list(read_json(big, OPTIONS))) == 3


def test_first_line_over_the_line_limit_falls_back_to_document_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(json_reader, "MAX_LINE_CHARS", 30)
    assert len(read(tmp_path, json.dumps([named(), named()]))) == 2
    with pytest.raises(InputError, match="does not start with"):
        read(tmp_path, "x" * 100)


def test_missing_file_and_directory(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read"):
        read_json(tmp_path / "nope.json", OPTIONS)
    with pytest.raises(InputError, match="cannot read"):
        read_json(tmp_path, OPTIONS)


def test_stat_failure_is_an_input_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path, json.dumps([named()]))
    real = json_reader._first_line  # noqa: SLF001 - tests the module's own helper

    def vanish(p: Path) -> str | None:
        result = real(p)
        p.unlink()
        return result

    monkeypatch.setattr(json_reader, "_first_line", vanish)
    with pytest.raises(InputError, match="cannot read"):
        read_json(path, OPTIONS)


def test_abandoned_reader_closes_the_file(tmp_path: Path) -> None:
    path = write(tmp_path, lines(*[named() for _ in range(20)]), name="many.jsonl")
    reader = read_json(path, OPTIONS)
    assert isinstance(next(reader), Event)
    reader.close()  # type: ignore[attr-defined]


# --- property tests -----------------------------------------------------------------


def _read_bytes(content: bytes) -> list[Event | Problem]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fuzz.json"
        path.write_bytes(content)
        return list(read_json(path, OPTIONS))


_JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**30), max_value=10**30)
    | st.floats(allow_nan=False)
    | st.text(max_size=12),
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=12,
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=300))
def test_arbitrary_bytes_only_raise_input_error(content: bytes) -> None:
    try:
        items = _read_bytes(content)
    except InputError:
        return
    assert all(isinstance(i, (Event, Problem)) for i in items)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_JSON, max_size=5), st.sampled_from(["array", "lines"]))
def test_arbitrary_json_values_only_raise_input_error(values: list[object], layout: str) -> None:
    text = json.dumps(values) if layout == "array" else "\n".join(json.dumps(v) for v in values)
    try:
        items = _read_bytes(text.encode("utf-8"))
    except InputError:
        return
    assert all(isinstance(i, (Event, Problem)) for i in items)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.dictionaries(
        st.sampled_from(
            [
                "Id",
                "EventID",
                "TimeCreated",
                "Computer",
                "MachineName",
                "Channel",
                "LogName",
                "ProviderName",
                "Properties",
                "EventData",
                "data",
                "Version",
                "RecordId",
                "Keywords",
                "UserId",
                "ActivityId",
            ]
        ),
        _JSON | st.just(DATE) | st.just("2026-11-10T02:15:03Z") | st.integers(0, 70000),
        max_size=10,
    )
)
def test_mutated_records_only_raise_input_error_or_become_problems(obj: dict[str, object]) -> None:
    try:
        items = _read_bytes(json.dumps([named(), obj]).encode("utf-8"))
    except InputError:
        return
    assert isinstance(items[0], Event)
    assert all(isinstance(i, (Event, Problem)) for i in items)


@settings(max_examples=150, deadline=None)
@given(
    st.dictionaries(
        st.text(min_size=1, max_size=10).filter(lambda s: s.isprintable()),
        st.text(max_size=20),
        min_size=1,
        max_size=8,
    )
)
def test_named_data_round_trips_in_order(data: dict[str, str]) -> None:
    items = _read_bytes(json.dumps([named(EventData=data)]).encode("utf-8"))
    (found,) = items
    assert isinstance(found, Event)
    assert dict(found.data) == data
    assert list(found.data) == list(data)


def test_packaged_catalog_names_work_as_names_for(tmp_path: Path) -> None:
    counts = [n for n in range(1, 60) if catalog.names_for(4720, 0, n) is not None]
    assert counts, "the catalog names no layout of event 4720"
    count = counts[0]
    expected = catalog.names_for(4720, 0, count)
    assert expected is not None
    props = [{"Value": f"v{i}"} for i in range(count)]
    options = ReadOptions(names_for=catalog.names_for)
    found = only_event(read(tmp_path, record(Properties=props), options))
    assert list(found.data) == list(expected)
    assert list(found.data.values()) == [f"v{i}" for i in range(count)]
