# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the native Windows Event Log (.evtx) reader.

Every file here is built by :mod:`tests.evtx_builder`; no real log is needed. The
tests go through :func:`read_evtx` only.
"""

from __future__ import annotations

import struct
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, ReadOptions
from faithful_toledot.formats import evtx
from faithful_toledot.formats.evtx import read_evtx
from tests import evtx_builder as b

if TYPE_CHECKING:
    from collections.abc import Sequence

OPTIONS = ReadOptions()
WHEN = datetime(2026, 11, 10, 2, 15, 3, 123456, tzinfo=UTC)


def read(tmp_path: Path, data: bytes, name: str = "log.evtx") -> list[Event | Problem]:
    """Write ``data`` to a file and read it all."""
    path = tmp_path / name
    path.write_bytes(data)
    return list(read_evtx(path, OPTIONS))


def events_of(items: Sequence[Event | Problem]) -> list[Event]:
    return [item for item in items if isinstance(item, Event)]


def problems_of(items: Sequence[Event | Problem]) -> list[Problem]:
    return [item for item in items if isinstance(item, Problem)]


def file_of(*contents: b.Instance | b.El, first_id: int = 1, **kwargs: object) -> bytes:
    """Return a one-chunk file holding the records."""
    return b.build_evtx([b.make_chunk(list(contents), first_id=first_id)], **kwargs)  # type: ignore[arg-type]


def one_event(tmp_path: Path, content: b.Instance | b.El) -> Event:
    items = read(tmp_path, file_of(content))
    assert len(items) == 1, items
    event = items[0]
    assert isinstance(event, Event), event
    return event


def one_problem(tmp_path: Path, content: b.Instance | b.El) -> Problem:
    items = read(tmp_path, file_of(content))
    assert len(items) == 1, items
    problem = items[0]
    assert isinstance(problem, Problem), problem
    return problem


def data_event(*pairs: tuple[str | None, str | b.Value], **kwargs: object) -> b.Instance:
    return b.security_event(1, 4624, data=list(pairs), **kwargs)  # type: ignore[arg-type]


def sections_event(
    sections: Sequence[object], extra: Sequence[b.Value] = (), **kwargs: object
) -> b.Instance:
    """An event whose part after ``System`` is ``sections`` (slots from 14)."""
    root = b.event_root(sections, **kwargs)  # type: ignore[arg-type]
    return b.Instance(root, b.event_values(1) + list(extra))


# --- A whole event, end to end ---


def test_reads_an_event_with_every_system_field(tmp_path: Path) -> None:
    activity = uuid.UUID("12345678-1234-5678-1234-567812345678")
    event = one_event(
        tmp_path,
        b.security_event(
            4728,
            4728,
            data=[("MemberSid", "S-1-5-21-1"), ("TargetUserName", "Domain Admins")],
            when=WHEN,
            activity=activity,
            user_sid="S-1-5-21-1111111111-2222222222-3333333333-1105",
            qualifiers=16384,
            version=2,
        ),
    )
    assert event.event_id == 4728
    assert event.time == WHEN
    assert event.computer == "dc01.corp.example"
    assert event.channel == "Security"
    assert event.provider == "Microsoft-Windows-Security-Auditing"
    assert event.record_id == 4728
    assert event.version == 2
    assert dict(event.data) == {"MemberSid": "S-1-5-21-1", "TargetUserName": "Domain Admins"}
    assert list(event.data) == ["MemberSid", "TargetUserName"]
    assert event.source.file == "log.evtx"
    assert event.source.position == "record 1"
    assert dict(event.system) == {
        "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "Level": "0",
        "Task": "13824",
        "Opcode": "0",
        "Keywords": "0x8020000000000000",
        "ActivityID": "{12345678-1234-5678-1234-567812345678}",
        "ProcessID": "572",
        "ThreadID": "3068",
        "UserID": "S-1-5-21-1111111111-2222222222-3333333333-1105",
    }


def test_event_time_is_utc_and_drops_the_hundred_nanosecond_digit(tmp_path: Path) -> None:
    # The builder adds 7 ticks (700 ns) past the microsecond; a datetime keeps microseconds.
    event = one_event(tmp_path, b.security_event(1, when=WHEN + timedelta(microseconds=1)))
    assert event.time == WHEN + timedelta(microseconds=1)
    assert event.time.utcoffset() == timedelta(0)


def test_optional_null_values_leave_out_their_elements_and_attributes(tmp_path: Path) -> None:
    event = one_event(tmp_path, b.security_event(1, user_sid=None))
    assert "UserID" not in event.system
    assert "ActivityID" not in event.system


def test_embedded_event_data_reads_like_inline_event_data(tmp_path: Path) -> None:
    pairs = [("A", "1"), (None, "x"), ("B", "2")]
    inline = one_event(tmp_path, b.security_event(1, data=pairs, mode="inline"))
    embedded = one_event(tmp_path, b.security_event(1, data=pairs, mode="embedded"))
    assert dict(inline.data) == dict(embedded.data) == {"A": "1", "param1": "x", "B": "2"}


def test_event_without_event_data_has_empty_data(tmp_path: Path) -> None:
    assert dict(one_event(tmp_path, b.security_event(1, mode="none")).data) == {}


def test_computer_name_can_be_a_substitution_and_can_be_empty(tmp_path: Path) -> None:
    assert one_event(tmp_path, b.security_event(1, computer="srv.corp.example")).computer == (
        "srv.corp.example"
    )


def test_unnamed_and_duplicate_data_names(tmp_path: Path) -> None:
    event = one_event(
        tmp_path,
        data_event(
            ("X", "1"),
            (None, "a"),
            ("X", "2"),
            (None, "b"),
            ("X", "3"),
            ("param1", "c"),
            ("X#2", "d"),
        ),
    )
    assert list(event.data.items()) == [
        ("X", "1"),
        ("param1", "a"),
        ("X#2", "2"),
        ("param2", "b"),
        ("X#3", "3"),
        ("param1#2", "c"),
        ("X#2#2", "d"),
    ]


def test_many_records_share_names_and_templates(tmp_path: Path) -> None:
    contents = [b.security_event(i + 1, 4000 + i, data=[("N", str(i))]) for i in range(50)]
    items = read(tmp_path, file_of(*contents))
    assert [e.event_id for e in events_of(items)] == list(range(4000, 4050))
    assert [e.data["N"] for e in events_of(items)] == [str(i) for i in range(50)]
    assert [e.record_id for e in events_of(items)] == list(range(1, 51))


def test_forced_inline_definitions_and_pointers(tmp_path: Path) -> None:
    template = b.event_root([b.data_section(["N"], 14)])
    values = [*b.event_values(1), b.string("v")]
    inline_again = b.Instance(template, values, inline=True)
    pointer = b.Instance(template, values, inline=False)
    items = read(tmp_path, file_of(b.Instance(template, values), inline_again, pointer))
    assert len(events_of(items)) == 3


def test_records_in_several_chunks(tmp_path: Path) -> None:
    one = b.make_chunk([b.security_event(1)], first_id=1)
    two = b.make_chunk([b.security_event(2), b.security_event(3)], first_id=2)
    items = read(tmp_path, b.build_evtx([one, two]))
    assert [e.record_id for e in events_of(items)] == [1, 2, 3]
    assert problems_of(items) == []


def test_forwarded_event_keeps_its_own_record_number(tmp_path: Path) -> None:
    # The record header says 7; the event inside says 90, as a forwarded event does.
    chunk = b.make_chunk([b.security_event(90)], first_id=7)
    items = read(tmp_path, b.build_evtx([chunk]))
    (event,) = events_of(items)
    assert event.record_id == 90
    assert event.source.position == "record 7"


def test_empty_file_with_only_a_header(tmp_path: Path) -> None:
    assert read(tmp_path, b.build_evtx([])) == []


def test_options_are_accepted_and_unused(tmp_path: Path) -> None:
    path = tmp_path / "a.evtx"
    path.write_bytes(file_of(b.security_event(1)))
    custom = ReadOptions(local_offset=timedelta(hours=-5), day_first=True)
    assert len(list(read_evtx(path, custom))) == 1


# --- Value rendering ---

GUID = uuid.UUID("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9")
STAMP = datetime(2026, 11, 10, 2, 15, 3, 123456, tzinfo=UTC)

RENDERED = [
    (b.string("héllo wörld"), "héllo wörld"),
    (b.string("no terminator", terminated=False), "no terminator"),
    (b.string(""), ""),
    (b.Value(b.T_STRING, b""), ""),
    (b.ansi("café"), "café"),
    (b.integer(b.T_INT8, -5), "-5"),
    (b.integer(b.T_UINT8, 200), "200"),
    (b.integer(b.T_INT16, -2), "-2"),
    (b.integer(b.T_UINT16, 65535), "65535"),
    (b.integer(b.T_INT32, -7), "-7"),
    (b.integer(b.T_UINT32, 4294967295), "4294967295"),
    (b.integer(b.T_INT64, -1), "-1"),
    (b.integer(b.T_UINT64, 2**64 - 1), "18446744073709551615"),
    (b.real(1.5), "1.5"),
    (b.real(0.1, double=True), "0.1"),
    (b.real(float("inf")), "1.#INF"),
    (b.real(float("-inf")), "-1.#INF"),
    (b.real(float("nan")), "-1.#IND"),
    (b.integer(b.T_BOOL, 1), "true"),
    (b.integer(b.T_BOOL, 0), "false"),
    (b.integer(b.T_BOOL, 5), "5"),
    (b.Value(b.T_BOOL, b"\x01"), "true"),
    (b.Value(b.T_BOOL, b"\x00\x00"), "false"),
    (b.binary(b"\x00\xab\xff"), "00ABFF"),
    (b.binary(b""), ""),
    (b.guid(GUID), "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}"),
    (b.size_t(0x1F), "0x1f"),
    (b.size_t(0x1F, wide=False), "0x1f"),
    (b.filetime(STAMP), "2026-11-10T02:15:03.1234560Z"),
    (b.Value(b.T_FILETIME, struct.pack("<Q", 0)), "1601-01-01T00:00:00.0000000Z"),
    (b.systemtime(STAMP), "2026-11-10T02:15:03.123Z"),
    (
        b.sid("S-1-5-21-1111111111-2222222222-3333333333-1105"),
        "S-1-5-21-1111111111-2222222222-3333333333-1105",
    ),
    (b.sid("S-1-5-18"), "S-1-5-18"),
    (b.sid("S-1-0x1234567890ab"), "S-1-0x1234567890ab"),
    (b.integer(b.T_HEX32, 255), "0xff"),
    (b.integer(b.T_HEX64, 0), "0x0"),
    (b.integer(b.T_HEX64, 0x3E7), "0x3e7"),
    (b.Value(b.T_UINT32, b""), ""),
    (b.null(), ""),
]


@pytest.mark.parametrize(("value", "expected"), RENDERED)
def test_values_render_as_windows_shows_them(tmp_path: Path, value: b.Value, expected: str) -> None:
    event = one_event(tmp_path, data_event(("V", value)))
    assert dict(event.data) == {"V": expected}


def test_a_null_value_in_an_optional_slot_omits_the_element(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", b.Slot(14, optional=True), Name="V")])
    event = one_event(tmp_path, sections_event([section], [b.null()]))
    assert dict(event.data) == {}


ARRAYS = [
    (b.array(b.T_UINT16, [b.integer(b.T_UINT16, 1), b.integer(b.T_UINT16, 2)]), ["1", "2"]),
    (b.array(b.T_INT8, [b.integer(b.T_INT8, -1)]), ["-1"]),
    (b.array(b.T_BOOL, [b.integer(b.T_BOOL, 1), b.integer(b.T_BOOL, 0)]), ["true", "false"]),
    (b.array(b.T_HEX64, [b.integer(b.T_HEX64, 255)]), ["0xff"]),
    (b.array(b.T_GUID, [b.guid(GUID)]), ["{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}"]),
    (b.array(b.T_FILETIME, [b.filetime(STAMP)]), ["2026-11-10T02:15:03.1234560Z"]),
    (b.array(b.T_SYSTEMTIME, [b.systemtime(STAMP)]), ["2026-11-10T02:15:03.123Z"]),
    (b.array(b.T_REAL64, [b.real(0.5, double=True)]), ["0.5"]),
    (
        b.array(b.T_SID, [b.sid("S-1-5-18"), b.sid("S-1-5-32-544")]),
        ["S-1-5-18", "S-1-5-32-544"],
    ),
    (b.Value(b.T_STRING | b.ARRAY, "ab\x00cd\x00".encode("utf-16-le")), ["ab", "cd"]),
    (b.Value(b.T_STRING | b.ARRAY, "ab\x00\x00cd".encode("utf-16-le")), ["ab", "", "cd"]),
    (b.Value(b.T_STRING | b.ARRAY, b""), [""]),
    (b.Value(b.T_ANSI | b.ARRAY, b"ab\x00cd\x00"), ["ab", "cd"]),
    (
        b.array(b.T_SIZE, [b.integer(b.T_HEX32, 7), b.integer(b.T_HEX32, 8)], hint=b.T_HEX32),
        ["0x7", "0x8"],
    ),
    (b.array(b.T_SIZE, [b.integer(b.T_HEX64, 7)], hint=b.T_HEX64), ["0x7"]),
    (b.array(b.T_SIZE, [b.integer(b.T_HEX32, 7)], hint=b.T_HEX32 | b.ARRAY), ["0x7"]),
    (b.array(b.T_UINT8, []), [""]),
]


@pytest.mark.parametrize(("value", "items"), ARRAYS)
def test_array_values_repeat_their_element(
    tmp_path: Path, value: b.Value, items: list[str]
) -> None:
    event = one_event(tmp_path, data_event(("V", value)))
    expected: dict[str, str] = {}
    for n, item in enumerate(items, start=1):
        expected["V" if n == 1 else f"V#{n}"] = item
    assert dict(event.data) == expected


BAD_VALUES = [
    (b.Value(b.T_STRING, b"\x00"), "odd number of bytes"),
    (b.Value(b.T_STRING, b"\x00\xd8"), "not valid UTF-16"),
    (b.string("a\x00b"), "NUL"),
    (b.Value(b.T_ANSI, b"\x81"), "Windows-1252"),
    (b.Value(b.T_ANSI, b"a\x00b"), "NUL"),
    (b.Value(b.T_UINT32, b"\x01\x02"), "2 bytes, not 4"),
    (b.Value(0x20, b"\x00"), "not supported"),
    (b.Value(0x23, b"\x00"), "not supported"),
    (b.Value(b.T_BOOL, b"\x00\x00\x00"), "unexpected size"),
    (b.Value(b.T_SIZE, b"\x00\x00\x00"), "neither 4 nor 8"),
    (b.Value(b.T_SID, b"\x01\x01\x00\x00\x00\x00\x00\x05"), "cut short"),
    (b.Value(b.T_SID, b"\x01"), "cut short"),
    (b.Value(b.T_SID, b"\x02\x00\x00\x00\x00\x00\x00\x05"), "unknown revision"),
    (b.Value(b.T_SID, b"\x01\x10" + bytes(6) + bytes(64)), "too many sub-authorities"),
    (b.Value(b.T_SID, b"\x01\x00\x00\x00\x00\x00\x00\x05\x00"), "extra bytes"),
    (b.Value(b.T_FILETIME, struct.pack("<Q", 2**64 - 1)), "year 9999"),
    (b.Value(b.T_UINT16 | b.ARRAY, b"\x01\x02\x03"), "whole number"),
    (b.Value(b.T_UINT8 | b.ARRAY, bytes(4097)), "too many items"),
    (b.Value(b.T_SIZE | b.ARRAY, bytes(8)), "4 or 8 bytes"),
    (b.Value(b.T_BINARY | b.ARRAY, b"\x00"), "not supported"),
    (b.Value(b.T_SID | b.ARRAY, b"\x01\x00\x00\x00\x00\x00\x00"), "cut short"),
    (b.Value(b.T_STRING | b.ARRAY, b"\x00"), "odd number of bytes"),
    (b.Value(b.T_ANSI | b.ARRAY, b"\x81\x00"), "Windows-1252"),
    (b.Value(b.T_STRING | b.ARRAY, "a\x00".encode("utf-16-le")[:1]), "odd"),
]


@pytest.mark.parametrize(("value", "why"), BAD_VALUES)
def test_unreadable_values_become_a_problem_for_that_record(
    tmp_path: Path, value: b.Value, why: str
) -> None:
    problem = one_problem(tmp_path, data_event(("V", value)))
    assert why in problem.reason
    assert problem.record_id == 1
    assert problem.source.position == "record 1"


def test_a_sid_array_stops_at_too_many_items(tmp_path: Path) -> None:
    sid = b.sid_bytes("S-1-5-18")
    problem = one_problem(tmp_path, data_event(("V", b.Value(b.T_SID | b.ARRAY, sid * 4097))))
    assert "too many items" in problem.reason


def test_arrays_of_different_lengths_in_one_element_are_refused(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", b.Slot(14), b.Slot(15), Name="V")])
    values = [
        b.array(b.T_UINT8, [b.integer(b.T_UINT8, 1), b.integer(b.T_UINT8, 2)]),
        b.array(b.T_UINT8, [b.integer(b.T_UINT8, 3)]),
    ]
    assert "different lengths" in one_problem(tmp_path, sections_event([section], values)).reason


def test_arrays_of_equal_length_in_one_element_advance_together(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", b.Slot(14), "-", b.Slot(15), Name="V")])
    two = [b.integer(b.T_UINT8, 1), b.integer(b.T_UINT8, 2)]
    values = [b.array(b.T_UINT8, two), b.array(b.T_UINT8, two)]
    event = one_event(tmp_path, sections_event([section], values))
    assert dict(event.data) == {"V": "1-1", "V#2": "2-2"}


def test_an_array_cannot_be_an_attribute(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", "x", Name=b.Slot(14))])
    values = [b.array(b.T_UINT8, [b.integer(b.T_UINT8, 1)])]
    assert (
        "attribute holds an array"
        in one_problem(tmp_path, sections_event([section], values)).reason
    )


def test_binary_xml_cannot_be_an_attribute(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", "x", Name=b.Slot(14))])
    values = [b.embedded(b.el("Y"))]
    assert (
        "attribute holds an array"
        in one_problem(tmp_path, sections_event([section], values)).reason
    )


def test_attribute_values_join_text_and_substitutions(tmp_path: Path) -> None:
    section = b.El(
        "EventData",
        [b.el("Data", "x", Name=["pre-", b.Slot(14), b.CharRef(33), b.EntityRef("amp")])],
    )
    event = one_event(tmp_path, sections_event([section], [b.string("mid")]))
    assert dict(event.data) == {"pre-mid!&": "x"}


def test_an_optional_null_attribute_and_an_empty_attribute_are_left_out(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", "x", Name=b.Slot(14, optional=True), Other="")])
    event = one_event(tmp_path, sections_event([section], [b.null()]))
    assert dict(event.data) == {"param1": "x"}


def test_a_normal_null_attribute_value_is_empty_so_the_attribute_is_left_out(
    tmp_path: Path,
) -> None:
    section = b.El("EventData", [b.el("Data", "x", Name=b.Slot(14))])
    event = one_event(tmp_path, sections_event([section], [b.null()]))
    assert dict(event.data) == {"param1": "x"}


# --- Binary XML constructs ---


def test_text_pieces_join_in_element_content(tmp_path: Path) -> None:
    section = b.El(
        "EventData",
        [
            b.el(
                "Data",
                "a",
                b.CharRef(38),
                b.EntityRef("lt"),
                b.EntityRef("gt"),
                b.EntityRef("quot"),
                b.EntityRef("apos"),
                b.CData("<x>"),
                "b",
                b.Slot(14),
                Name="n",
            )
        ],
    )
    event = one_event(tmp_path, sections_event([section], [b.string("!")]))
    assert dict(event.data) == {"n": "a&<>\"'<x>b!"}


def test_processing_instructions_in_content_carry_nothing(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", "a", b.PI("note", "ignored"), "b", Name="n")])
    assert dict(one_event(tmp_path, sections_event([section])).data) == {"n": "ab"}


def test_a_prologue_processing_instruction_is_skipped(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, b.security_event(1), prologue=b.PI("xml", "version"))
    (event,) = events_of(read(tmp_path, b.build_evtx([chunk.finish()])))
    assert event.event_id == 4624


def test_a_processing_instruction_without_data_is_refused(tmp_path: Path) -> None:
    section = b.El("EventData", [b.PI("note", None)])
    assert "processing instruction" in one_problem(tmp_path, sections_event([section])).reason


def test_a_record_may_hold_a_plain_element_instead_of_a_template(tmp_path: Path) -> None:
    system = b.el(
        "System",
        b.el("Provider", Name="P"),
        b.el("EventID", "4720"),
        b.el("TimeCreated", SystemTime="2026-11-10T02:15:03.1234567Z"),
        b.el("Channel", "Security"),
        b.el("Computer", "dc01.corp.example"),
    )
    event = one_event(
        tmp_path, b.el("Event", system, b.el("EventData", b.el("Data", "v", Name="N")))
    )
    assert event.event_id == 4720
    assert event.time == WHEN
    assert event.record_id == 1  # no EventRecordID: the record header's number
    assert dict(event.data) == {"N": "v"}


def test_embedded_binary_xml_variants(tmp_path: Path) -> None:
    inner = b.data_section(["A"], 0)
    for with_header in (True, False):
        for with_end in (True, False):
            value = b.embedded(
                b.Instance(inner, [b.string("1")]), fragment_header=with_header, end_token=with_end
            )
            event = one_event(tmp_path, sections_event([b.Slot(14, vtype=b.T_BINXML)], [value]))
            assert dict(event.data) == {"A": "1"}


def test_embedded_plain_element_and_empty_embedded_value(tmp_path: Path) -> None:
    section = b.Slot(14, vtype=b.T_BINXML)
    plain = b.embedded(b.el("EventData", b.el("Data", "v", Name="N")))
    assert dict(one_event(tmp_path, sections_event([section], [plain])).data) == {"N": "v"}
    nothing = b.Value(b.T_BINXML)
    assert dict(one_event(tmp_path, sections_event([section], [nothing])).data) == {}


def test_templates_nest_through_embedded_values(tmp_path: Path) -> None:
    leaf = b.el("Data", b.Slot(0, vtype=b.T_STRING), Name="Deep")
    wrapper = b.El("EventData", [b.Slot(0, vtype=b.T_BINXML)])
    value = b.embedded(b.Instance(wrapper, [b.embedded(b.Instance(leaf, [b.string("x")]))]))
    event = one_event(tmp_path, sections_event([b.Slot(14, vtype=b.T_BINXML)], [value]))
    assert dict(event.data) == {"Deep": "x"}


def test_user_data_is_flattened_by_element_name(tmp_path: Path) -> None:
    user = b.el(
        "UserData",
        b.el(
            "LogCleared",
            b.el("SubjectUserName", "admin"),
            b.el("Details", b.el("Code", "5", Level="high"), b.el("Name", "n")),
            b.el("SubjectUserName", "again"),
            b.el("Empty"),
            b.el("Tagged", "t", xmlns="urn:x", Kind="k"),
            xmlns="urn:example",
            Version="2",
        ),
    )
    event = one_event(tmp_path, sections_event([user]))
    assert dict(event.data) == {
        "Version": "2",
        "SubjectUserName": "admin",
        "Details/Code": "5",
        "Details/Code@Level": "high",
        "Details/Name": "n",
        "SubjectUserName#2": "again",
        "Empty": "",
        "Tagged": "t",
        "Tagged@Kind": "k",
    }


def test_user_data_with_xmlns_prefix_and_no_children(tmp_path: Path) -> None:
    user = b.el("UserData", b.el("Thing", **{"xmlns:p": "urn:p"}))
    assert dict(one_event(tmp_path, sections_event([user])).data) == {}
    empty = b.el("UserData")
    assert dict(one_event(tmp_path, sections_event([empty])).data) == {}


def test_user_data_with_two_children_is_refused(tmp_path: Path) -> None:
    user = b.el("UserData", b.el("A"), b.el("B"))
    assert "more than one element" in one_problem(tmp_path, sections_event([user])).reason


def test_event_data_binary_and_other_elements(tmp_path: Path) -> None:
    section = b.El(
        "EventData",
        [
            b.el("Data", "d", Name="N"),
            b.el("Binary", "00FF"),
            b.el("Complex", "c"),
            b.el("Binary", "11"),
        ],
    )
    event = one_event(tmp_path, sections_event([section]))
    assert dict(event.data) == {"N": "d", "Binary": "00FF", "Complex": "c", "Binary#2": "11"}


def test_event_data_and_user_data_together_keep_both(tmp_path: Path) -> None:
    sections = [
        b.el("EventData", b.el("Data", "1", Name="N")),
        b.el("UserData", b.el("U", b.el("N", "2"))),
    ]
    assert dict(one_event(tmp_path, sections_event(sections)).data) == {"N": "1", "N#2": "2"}


def test_unknown_sections_are_ignored(tmp_path: Path) -> None:
    sections = [b.el("RenderingInfo", b.el("Message", "text"))]
    assert dict(one_event(tmp_path, sections_event(sections)).data) == {}


def test_text_where_an_element_holds_children_is_refused(tmp_path: Path) -> None:
    section = b.el("EventData", b.el("Data", b.el("Inner", "x"), Name="N"))
    assert (
        "holds an element where text was expected"
        in one_problem(tmp_path, sections_event([section])).reason
    )


# --- Records that are not events ---


def literal_event(system_children: list[b.El], *sections: b.El) -> b.El:
    return b.el("Event", b.el("System", *system_children), *sections)


def good_system() -> list[b.El]:
    return [
        b.el("Provider", Name="P"),
        b.el("EventID", "4720"),
        b.el("TimeCreated", SystemTime="2026-11-10T02:15:03.1234567Z"),
        b.el("Channel", "Security"),
        b.el("Computer", "dc01.corp.example"),
    ]


def test_literal_events_read_the_same_way(tmp_path: Path) -> None:
    event = one_event(tmp_path, literal_event(good_system()))
    assert (event.event_id, event.provider, event.channel, event.computer) == (
        4720,
        "P",
        "Security",
        "dc01.corp.example",
    )
    assert event.version == 0
    assert dict(event.system) == {}


def test_an_empty_computer_name_is_allowed(tmp_path: Path) -> None:
    system = [c for c in good_system() if c.name != "Computer"] + [b.el("Computer")]
    assert one_event(tmp_path, literal_event(system)).computer == ""


def test_system_fields_keep_unknown_elements_and_attributes(tmp_path: Path) -> None:
    system = [
        *good_system(),
        b.el("Execution", ProcessID="4", ProcessorID="1"),
        b.el("Correlation", RelatedActivityID="{X}"),
        b.el("Custom", "text", Flag="1"),
        b.el("Version", "3"),
        b.el("EventRecordID", "99"),
    ]
    event = one_event(tmp_path, literal_event(system))
    assert event.version == 3
    assert event.record_id == 99
    assert dict(event.system) == {
        "ProcessID": "4",
        "Execution@ProcessorID": "1",
        "RelatedActivityID": "{X}",
        "Custom": "text",
        "Custom@Flag": "1",
    }


@pytest.mark.parametrize(
    ("mutate", "why"),
    [
        (lambda s: [c for c in s if c.name != "EventID"], "no EventID"),
        (lambda s: [c for c in s if c.name != "TimeCreated"], "no TimeCreated@SystemTime"),
        (lambda s: [c for c in s if c.name != "Provider"], "no Provider@Name"),
        (lambda s: [c for c in s if c.name != "Channel"], "no Channel"),
        (lambda s: [c for c in s if c.name != "Computer"], "no Computer"),
        (lambda s: [*s, b.el("EventID", "1")], "EventID twice"),
        (lambda s: [*s, b.el("Provider", Name="Q")], "Provider@Name twice"),
        (
            lambda s: [c if c.name != "EventID" else b.el("EventID", "47x") for c in s],
            "EventID is not a whole number",
        ),
        (
            lambda s: [c if c.name != "EventID" else b.el("EventID", "") for c in s],
            "EventID is not a whole number",
        ),
        (lambda s: [*s, b.el("Version", "-1")], "Version is not a whole number"),
        (lambda s: [*s, b.el("EventRecordID", "x")], "EventRecordID is not a whole number"),
        (
            lambda s: [
                c if c.name != "TimeCreated" else b.el("TimeCreated", SystemTime="yesterday")
                for c in s
            ],
            "not a date and time",
        ),
        (
            lambda s: [
                c
                if c.name != "TimeCreated"
                else b.el("TimeCreated", SystemTime="2026-13-40T00:00:00Z")
                for c in s
            ],
            "not a real date",
        ),
        (lambda s: [*s, b.el("Level", b.el("Inner"))], "element where text was expected"),
    ],
)
def test_events_that_lack_what_an_event_needs_become_problems(
    tmp_path: Path, mutate: object, why: str
) -> None:
    system = mutate(good_system())  # type: ignore[operator]
    problem = one_problem(tmp_path, literal_event(system))
    assert why in problem.reason


def test_a_provider_without_a_name_is_known_by_its_guid(tmp_path: Path) -> None:
    system = [c for c in good_system() if c.name != "Provider"] + [b.el("Provider", Guid="{G}")]
    assert one_event(tmp_path, literal_event(system)).provider == "{G}"


def test_time_without_fraction_and_with_short_fraction(tmp_path: Path) -> None:
    for text, micros in (("2026-11-10T02:15:03Z", 0), ("2026-11-10T02:15:03.5Z", 500000)):
        system = [c for c in good_system() if c.name != "TimeCreated"]
        system.append(b.el("TimeCreated", SystemTime=text))
        event = one_event(tmp_path, literal_event(system))
        assert event.time == datetime(2026, 11, 10, 2, 15, 3, micros, tzinfo=UTC)


def test_the_element_must_be_event_with_one_system(tmp_path: Path) -> None:
    assert "not <Event>" in one_problem(tmp_path, b.el("Other", b.el("System"))).reason
    assert "exactly one <System>" in one_problem(tmp_path, b.el("Event")).reason
    two = b.el("Event", b.el("System"), b.el("System"))
    assert "exactly one <System>" in one_problem(tmp_path, two).reason


def raw_record_file(*bodies: bytes) -> bytes:
    chunk = b.ChunkBuilder()
    for i, body in enumerate(bodies, start=1):
        chunk.add_raw_record(i, body)
    return b.build_evtx([chunk.finish()])


@pytest.mark.parametrize(
    ("body", "why"),
    [
        (b"\x0f\x01\x01\x00\x00", "exactly one element"),
        (b"\x00", "exactly one element"),
        (b"", "exactly one element"),
        (b"\x0f\x02\x01\x00", "not version 1.1"),
        (b"\x0f\x01", "not version 1.1"),
        (b"\x0f\x01\x01\x00\x63", "unexpected token 0x63"),
        (b"\x0f\x01\x01\x00\x0a", "points into the chunk header"),
        (b"\x00" + bytes(8), "data follows the end"),
        (b"\x0f\x01\x01\x00\x01", "data ends"),
        (b"\x0f\x01\x01\x00\x0c\x01", "data ends"),
    ],
)
def test_malformed_binary_xml_streams(tmp_path: Path, body: bytes, why: str) -> None:
    items = read(tmp_path, raw_record_file(body))
    assert [type(i) for i in items] == [Problem]
    assert why in problems_of(items)[0].reason


def test_two_roots_in_one_record_are_refused(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, [b.security_event(1), b.security_event(1)])
    items = read(tmp_path, b.build_evtx([chunk.finish()]))
    assert "exactly one element" in problems_of(items)[0].reason


# --- Template and token damage ---


def damaged(tmp_path: Path, content: b.Instance | b.El, *more: b.Instance | b.El) -> list[Problem]:
    return problems_of(read(tmp_path, file_of(content, *more)))


def test_template_definition_pointing_outside_the_chunk(tmp_path: Path) -> None:
    for offset in (0, 100, 70000, 0xFFFFFFFF, 65536 - 20):
        content = b.security_event(1)
        content.def_offset = offset
        content.inline = False
        (problem,) = damaged(tmp_path, content)
        assert "points outside the chunk" in problem.reason


def test_template_pointer_to_garbage_is_refused_and_remembered(tmp_path: Path) -> None:
    good = b.security_event(1, data=[("A", "1")])
    bad = b.Instance(good.template, list(good.values), inline=False, def_offset=600)
    items = read(
        tmp_path,
        file_of(
            good, bad, b.Instance(good.template, list(good.values), inline=False, def_offset=600)
        ),
    )
    assert len(events_of(items)) == 1
    reasons = [p.reason for p in problems_of(items)]
    assert len(reasons) == 2
    assert reasons[0].split(": ", 1)[1] == reasons[1].split(": ", 1)[1]


def test_template_definition_that_does_not_fit(tmp_path: Path) -> None:
    template = b.event_root([])
    template.size_delta = 1000
    (problem,) = damaged(tmp_path, b.Instance(template, b.event_values(1)))
    assert "extends beyond its parent" in problem.reason or "does not end" in problem.reason


def test_element_size_that_does_not_match_its_content(tmp_path: Path) -> None:
    # A child's size that stops short of its real end, or runs past it, inside a parent.
    for delta, why in ((-2, "data ends inside text"), (2, "size does not match its content")):
        child = b.el("Data", "x", Name="N")
        child.size_delta = delta
        section = b.El("EventData", [child, b.el("Data", "y", Name="M")])
        (problem,) = damaged(tmp_path, sections_event([section]))
        assert why in problem.reason


def test_element_start_that_is_not_closed(tmp_path: Path) -> None:
    raw = bytes([0x41]) + struct.pack("<H", 0xFFFF) + struct.pack("<I", 0)
    section = b.El("EventData", [b.Raw(raw)])
    assert damaged(tmp_path, sections_event([section]))


def test_definition_not_starting_with_an_element(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    info = chunk.add_record(1, b.security_event(1))
    chunk_bytes = bytearray(chunk.finish())
    # Replace the first byte of the template's element (after the 4 byte fragment header).
    marker = b"\x0f\x01\x01\x00\x41\xff\xff"
    at = chunk_bytes.index(marker, info.offset)
    chunk_bytes[at + 4] = 0x63
    b.seal_chunk(chunk_bytes)
    items = read(tmp_path, b.build_evtx([bytes(chunk_bytes)]))
    assert "does not start with an element" in problems_of(items)[0].reason


def test_definition_with_bad_end(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    info = chunk.add_record(1, b.security_event(1))
    data = bytearray(chunk.finish())
    start = info.offset + 24 + 4
    # token(1) unknown(1) id(4) offset(4) then the 24 byte header; its size is the last 4 bytes.
    size_at = start + 10 + 20
    size = struct.unpack_from("<I", data, size_at)[0]
    struct.pack_into("<I", data, size_at, size - 1)
    b.seal_chunk(data)
    items = read(tmp_path, b.build_evtx([bytes(data)]))
    assert problems_of(items)


def test_definition_longer_than_its_record(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    info = chunk.add_record(1, b.security_event(1))
    data = bytearray(chunk.finish())
    size_at = info.offset + 24 + 4 + 10 + 20
    struct.pack_into("<I", data, size_at, 60000)
    b.seal_chunk(data)
    items = read(tmp_path, b.build_evtx([bytes(data)]))
    assert "extends beyond its record" in problems_of(items)[0].reason


def test_substitution_naming_a_missing_value(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", b.Slot(40), Name="N")])
    (problem,) = damaged(tmp_path, sections_event([section]))
    assert "does not have" in problem.reason


def test_value_list_damage(tmp_path: Path) -> None:
    template = b.event_root([])
    cases = {
        "too many values": struct.pack("<I", 5000),
        "value list is cut short": struct.pack("<I", 1000) + bytes(8),
        "extends beyond the record": struct.pack("<I", 1) + struct.pack("<HBx", 60000, 1),
    }
    for why, raw in cases.items():
        (problem,) = damaged(tmp_path, b.Instance(template, values_raw=raw))
        assert why in problem.reason


@pytest.mark.parametrize(
    ("part", "why"),
    [
        (b.EntityRef("nbsp"), "unknown entity"),
        (b.CharRef(0), "not a character"),
        (b.CharRef(0xD800), "not a character"),
        (b.Raw(b"\x05\x02\x00\x00"), "not a string"),
        (b.Raw(b"\x05\x01\x05\x00ab"), "data ends inside text"),
        (b.Raw(b"\x05\x01\x01\x00\x00\xd8"), "not valid UTF-16"),
        (b.Raw(b"\x05\x01\x01\x00\x00\x00"), "NUL"),
        (b.Raw(b"\x63"), "unexpected token 0x63"),
        (b.Raw(b"\x0d\x00"), "data ends"),
        (b.Raw(b"\x0a\x00\x00\x00\x00"), "name"),
    ],
)
def test_damaged_content_tokens(tmp_path: Path, part: object, why: str) -> None:
    section = b.El("EventData", [b.el("Data", part, Name="N")])
    (problem,) = damaged(tmp_path, sections_event([section]))
    assert why in problem.reason


def test_cdata_in_an_attribute_is_refused(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", "x", Name=b.CData("n"))])
    (problem,) = damaged(tmp_path, sections_event([section]))
    assert "attribute holds a CDATA" in problem.reason


def test_attribute_lists_that_lie(tmp_path: Path) -> None:
    def with_raw(attr_bytes: bytes) -> b.Instance:
        # An element start with attributes whose list is written by hand.
        body = bytes([0x41]) + struct.pack("<I", 0)
        return sections_event([b.El("EventData", [b.Raw(body + attr_bytes)])])

    for attr_bytes in (
        struct.pack("<I", 9999),
        struct.pack("<I", 1) + b"\x63",
        struct.pack("<I", 0),
    ):
        assert damaged(tmp_path, with_raw(attr_bytes))


def test_attribute_flags_that_disagree_with_the_list(tmp_path: Path) -> None:
    # "More attributes follow" flag on the last attribute.
    chunk = b.ChunkBuilder()
    info = chunk.add_record(1, literal_event(good_system()))
    data = bytearray(chunk.finish())
    name = "Provider\x00".encode("utf-16-le")
    at = data.index(name, info.offset) + len(name) + 4  # the only attribute's token
    assert data[at] == 0x06
    data[at] = 0x46
    b.seal_chunk(data)
    assert problems_of(read(tmp_path, b.build_evtx([bytes(data)])))


def test_an_attribute_list_holding_a_non_attribute_is_refused(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    info = chunk.add_record(1, literal_event(good_system()))
    data = bytearray(chunk.finish())
    name = "Provider\x00".encode("utf-16-le")
    token_at = data.index(name, info.offset) + len(name) + 4  # after the list's size field
    assert data[token_at] == 0x06
    data[token_at] = 0x63
    b.seal_chunk(data)
    reasons = [p.reason for p in problems_of(read(tmp_path, b.build_evtx([bytes(data)])))]
    assert any("not an attribute" in r for r in reasons)


def test_an_inline_name_longer_than_its_element_is_refused(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, literal_event(good_system()))
    data = bytearray(chunk.finish())
    at = data.index("Computer".encode("utf-16-le"), 512) - 2
    struct.pack_into("<H", data, at, 256)
    b.seal_chunk(data)
    reasons = [p.reason for p in problems_of(read(tmp_path, b.build_evtx([bytes(data)])))]
    assert any("data ends inside a name" in r for r in reasons)


def test_name_damage(tmp_path: Path) -> None:
    def named(raw: bytes) -> b.Instance:
        return sections_event([b.El("EventData", [b.Raw(b"\x01" + struct.pack("<I", 8) + raw)])])

    cases = [
        struct.pack("<I", 100),  # into the chunk header
        struct.pack("<I", 70000),  # past the chunk
    ]
    for raw in cases:
        assert damaged(tmp_path, named(raw))


def test_names_with_impossible_lengths_or_missing_terminators(tmp_path: Path) -> None:
    for name_bytes, why in (
        (b"\x00\x00\x00\x00\x00\x00\x00\x00", "impossible length"),
        (b"\x00\x00\x00\x00\x00\x00\xff\xff", "impossible length"),
        (b"\x00\x00\x00\x00\x00\x00\x01\x00\x41\x00\x42\x00", "not terminated"),
        (b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00", "NUL"),
        (b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\xd8\x00\x00", "not valid UTF-16"),
    ):
        chunk = b.ChunkBuilder()
        chunk.add_garbage(b"")
        record = literal_event(good_system())
        chunk.add_record(1, record)
        data = bytearray(chunk.finish())
        # The name "Event" is inline at the start of the first element; rewrite its name record.
        at = data.index("Event".encode("utf-16-le"), 512) - 8
        data[at : at + len(name_bytes)] = name_bytes
        b.seal_chunk(data)
        items = read(tmp_path, b.build_evtx([bytes(data)]))
        assert any(why in p.reason for p in problems_of(items)), (why, items)


def test_a_name_that_runs_past_its_element(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, literal_event(good_system()))
    data = bytearray(chunk.finish())
    at = data.index("Event".encode("utf-16-le"), 512) - 2
    struct.pack_into("<H", data, at, 200)  # claims 200 characters
    b.seal_chunk(data)
    assert problems_of(read(tmp_path, b.build_evtx([bytes(data)])))


def test_names_may_be_referenced_before_they_are_written(tmp_path: Path) -> None:
    # An element whose name points ahead into the records area is still bounds-checked.
    chunk = b.ChunkBuilder()
    chunk.add_record(1, literal_event(good_system()))
    data = bytearray(chunk.finish())
    # Point the root element's name at the System name's record (later in the chunk).
    system_name = data.index("System".encode("utf-16-le"), 512) - 8
    root_ref = data.index("Event".encode("utf-16-le"), 512) - 8 - 4
    struct.pack_into("<I", data, root_ref, system_name)
    b.seal_chunk(data)
    items = read(tmp_path, b.build_evtx([bytes(data)]))
    assert problems_of(items)  # the root is now <System>, not <Event>


# --- Limits ---


def deep(levels: int) -> b.El:
    node = b.el("Leaf", "x")
    for _ in range(levels):
        node = b.el("Wrap", node)
    return node


def test_deeply_nested_elements_are_refused(tmp_path: Path) -> None:
    (problem,) = damaged(tmp_path, sections_event([deep(40)]))
    assert "nested too deeply" in problem.reason


def test_nested_elements_below_the_limit_are_read(tmp_path: Path) -> None:
    items = read(tmp_path, file_of(sections_event([deep(5)])))
    assert len(events_of(items)) == 1


def test_templates_nested_too_deep_are_refused(tmp_path: Path) -> None:
    leaf = b.data_section(["A"], 0)
    wrapper = b.El("EventData", [b.Slot(0, vtype=b.T_BINXML)])
    value = b.embedded(b.Instance(leaf, [b.string("x")]))
    for _ in range(12):
        value = b.embedded(b.Instance(wrapper, [value]))
    (problem,) = damaged(tmp_path, sections_event([b.Slot(14, vtype=b.T_BINXML)], [value]))
    assert "templates are nested too deeply" in problem.reason


def test_too_many_elements_are_refused(tmp_path: Path) -> None:
    two_arrays = [b.array(b.T_UINT8, [b.integer(b.T_UINT8, 1)] * 3000)] * 2
    section = b.El(
        "EventData", [b.el("Data", b.Slot(14), Name="A"), b.el("Data", b.Slot(15), Name="B")]
    )
    (problem,) = damaged(tmp_path, sections_event([section], two_arrays))
    assert "too many elements" in problem.reason


def test_too_much_text_is_refused(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", b.Slot(14), Name=f"d{i}") for i in range(20)])
    (problem,) = damaged(tmp_path, sections_event([section], [b.string("x" * 30000)]))
    assert "too much text" in problem.reason


def test_too_much_array_text_is_refused(tmp_path: Path) -> None:
    section = b.El("EventData", [b.el("Data", b.Slot(14), Name=f"d{i}") for i in range(40)])
    text = b.Value(b.T_STRING | b.ARRAY, ("x" * 4000 + "\x00").encode("utf-16-le") * 4)
    (problem,) = damaged(tmp_path, sections_event([section], [text]))
    assert "too much text" in problem.reason


def test_too_much_template_data_in_a_chunk_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evtx, "_MAX_DEFINITION_BYTES", 100)
    (problem,) = damaged(tmp_path, b.security_event(1))
    assert "too much template data" in problem.reason


# --- The container ---


def test_wrong_signature_is_refused_before_anything_is_read(tmp_path: Path) -> None:
    path = tmp_path / "x.evtx"
    path.write_bytes(b"MZ" + bytes(5000))
    with pytest.raises(InputError, match=r"x\.evtx is not a Windows event log"):
        read_evtx(path, OPTIONS)


def test_a_cut_off_header_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "x.evtx"
    path.write_bytes(b"ElfFile\x00" + bytes(100))
    with pytest.raises(InputError, match="cut off"):
        read_evtx(path, OPTIONS)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"header_size": 64}, "not the EVTX layout"),
        ({"block_size": 8192}, "not the EVTX layout"),
        ({"major": 2}, "format version 2.1"),
        ({"minor": 9}, "format version 3.9"),
    ],
)
def test_impossible_headers_are_refused(
    tmp_path: Path, kwargs: dict[str, int], message: str
) -> None:
    path = tmp_path / "x.evtx"
    path.write_bytes(b.build_evtx([], **kwargs))  # type: ignore[arg-type]
    with pytest.raises(InputError, match=message):
        read_evtx(path, OPTIONS)


@pytest.mark.parametrize("minor", [0, 1, 2])
def test_supported_versions(tmp_path: Path, minor: int) -> None:
    assert read(tmp_path, b.build_evtx([b.make_chunk([b.security_event(1)])], minor=minor))


def test_missing_and_unreadable_paths_are_input_errors(tmp_path: Path) -> None:
    with pytest.raises(InputError, match=r"cannot read nothing\.evtx"):
        read_evtx(tmp_path / "nothing.evtx", OPTIONS)
    with pytest.raises(InputError, match="cannot read"):
        read_evtx(tmp_path, OPTIONS)


def test_file_header_checksum_mismatch_is_reported_and_chunks_are_still_read(
    tmp_path: Path,
) -> None:
    items = read(tmp_path, b.build_evtx([b.make_chunk([b.security_event(1)])], bad_crc=True))
    (problem,) = problems_of(items)
    assert "file header checksum does not match" in problem.reason
    assert problem.source.position == "file header"
    assert len(events_of(items)) == 1


def test_a_file_that_stores_no_checksums_says_so_once(tmp_path: Path) -> None:
    chunk = b.make_chunk([b.security_event(1)], no_crc=True)
    items = read(tmp_path, b.build_evtx([chunk], no_crc=True))
    (problem,) = problems_of(items)
    assert "stores no checksums" in problem.reason
    assert len(events_of(items)) == 1


def test_a_chunk_that_stores_no_checksums_in_a_file_that_does(tmp_path: Path) -> None:
    chunk = b.make_chunk([b.security_event(1)], no_crc=True)
    items = read(tmp_path, b.build_evtx([chunk]))
    (problem,) = problems_of(items)
    assert "chunk 0" in problem.reason
    assert "stores no checksums" in problem.reason
    assert len(events_of(items)) == 1


def test_a_dirty_file_is_reported_once_and_chunks_past_the_header_count_are_read(
    tmp_path: Path,
) -> None:
    chunks = [b.make_chunk([b.security_event(i)], first_id=i) for i in (1, 2, 3)]
    items = read(tmp_path, b.build_evtx(chunks, dirty=True, chunk_count=1))
    (problem,) = problems_of(items)
    assert "not closed cleanly" in problem.reason
    assert "(1)" in problem.reason
    assert [e.record_id for e in events_of(items)] == [1, 2, 3]


def test_a_clean_file_whose_chunk_count_is_wrong_is_reported(tmp_path: Path) -> None:
    chunks = [b.make_chunk([b.security_event(i)], first_id=i) for i in (1, 2)]
    for wrong in (1, 5):
        items = read(tmp_path, b.build_evtx(chunks, chunk_count=wrong))
        (problem,) = problems_of(items)
        assert f"counts {wrong} chunks but the file holds 2" in problem.reason
        assert len(events_of(items)) == 2


def test_a_file_cut_in_the_middle_of_a_chunk_is_reported(tmp_path: Path) -> None:
    whole = b.build_evtx(
        [b.make_chunk([b.security_event(1)]), b.make_chunk([b.security_event(2)], first_id=2)]
    )
    items = read(tmp_path, whole[:-1000])
    reasons = [p.reason for p in problems_of(items)]
    assert any("64536 bytes that do not make a whole chunk" in r for r in reasons)
    assert any("counts 2 chunks but the file holds 1" in r for r in reasons)
    assert [e.record_id for e in events_of(items)] == [1]


def test_zeroed_chunks_at_the_end_are_normal_and_silent(tmp_path: Path) -> None:
    chunks = [b.make_chunk([b.security_event(1)]), bytes(b.CHUNK_SIZE), bytes(b.CHUNK_SIZE)]
    items = read(tmp_path, b.build_evtx(chunks))
    assert problems_of(items) == []
    assert len(events_of(items)) == 1


def test_zeroed_chunks_in_the_middle_are_reported(tmp_path: Path) -> None:
    one = b.make_chunk([b.security_event(1)])
    three = b.make_chunk([b.security_event(4)], first_id=4)
    items = read(tmp_path, b.build_evtx([one, bytes(b.CHUNK_SIZE), three]))
    (problem,) = problems_of(items)
    assert "chunk 1 is all zeros" in problem.reason
    items = read(tmp_path, b.build_evtx([one, bytes(b.CHUNK_SIZE), bytes(b.CHUNK_SIZE), three]))
    (problem,) = problems_of(items)
    assert "chunks 1 to 2 is all zeros" in problem.reason
    assert [e.record_id for e in events_of(items)] == [1, 4]


def patched_chunk(edit: object, *, events: int = 2, seal: bool = True) -> bytes:
    data = bytearray(b.make_chunk([b.security_event(i + 1) for i in range(events)]))
    edit(data)  # type: ignore[operator]
    if seal:
        b.seal_chunk(data)
    return bytes(data)


def test_a_chunk_without_the_chunk_signature_is_skipped_with_one_problem(tmp_path: Path) -> None:
    bad = patched_chunk(lambda d: d.__setitem__(slice(0, 8), b"NotAChnk"))
    good = b.make_chunk([b.security_event(3)], first_id=3)
    items = read(tmp_path, b.build_evtx([bad, good]))
    (problem,) = problems_of(items)
    assert "chunk 0 does not start with the chunk signature" in problem.reason
    assert [e.record_id for e in events_of(items)] == [3]


def test_a_chunk_header_with_a_bad_checksum_is_skipped_and_names_its_record_range(
    tmp_path: Path,
) -> None:
    chunk = b.make_chunk(
        [b.security_event(10), b.security_event(11)], first_id=10, bad_header_crc=True
    )
    items = read(tmp_path, b.build_evtx([chunk]))
    (problem,) = problems_of(items)
    assert "chunk 0, records 10 to 11" in problem.reason
    assert "header checksum" in problem.reason
    assert events_of(items) == []


def test_a_chunk_header_with_a_wrong_size_is_skipped(tmp_path: Path) -> None:
    bad = patched_chunk(lambda d: struct.pack_into("<I", d, 40, 64))
    (problem,) = problems_of(read(tmp_path, b.build_evtx([bad])))
    assert "unknown header size" in problem.reason


@pytest.mark.parametrize("free", [0, 511, 65537, 0xFFFFFFFF])
def test_a_free_space_offset_outside_the_chunk_skips_the_chunk(tmp_path: Path, free: int) -> None:
    bad = patched_chunk(lambda d: struct.pack_into("<I", d, 48, free))
    (problem,) = problems_of(read(tmp_path, b.build_evtx([bad])))
    assert "free-space offset outside the chunk" in problem.reason


def test_a_records_checksum_mismatch_is_reported_but_records_are_still_read(tmp_path: Path) -> None:
    chunk = b.make_chunk([b.security_event(1), b.security_event(2)], bad_records_crc=True)
    items = read(tmp_path, b.build_evtx([chunk]))
    (problem,) = problems_of(items)
    assert "records checksum" in problem.reason
    assert "chunk 0, records 1 to 2" in problem.reason
    assert len(events_of(items)) == 2


def test_a_record_count_that_disagrees_with_the_header_is_reported(tmp_path: Path) -> None:
    chunk = b.make_chunk([b.security_event(1), b.security_event(2)], last_id=5)
    items = read(tmp_path, b.build_evtx([chunk]))
    (problem,) = problems_of(items)
    assert "should hold 5 records by its header, but 2 were found" in problem.reason
    assert len(events_of(items)) == 2


def test_a_header_range_that_runs_backwards_is_not_a_count_claim(tmp_path: Path) -> None:
    chunk = b.make_chunk([b.security_event(1)], first_id=5, last_id=1)
    items = read(tmp_path, b.build_evtx([chunk]))
    assert problems_of(items) == []


def test_an_empty_chunk_has_no_records(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder().finish()
    assert read(tmp_path, b.build_evtx([chunk])) == []


# --- Records inside a chunk ---


def three_records() -> tuple[b.ChunkBuilder, list[b.RecordInfo]]:
    chunk = b.ChunkBuilder()
    infos = [chunk.add_record(i, b.security_event(i, 4000 + i)) for i in (1, 2, 3)]
    return chunk, infos


def test_a_wrong_size_copy_loses_that_record_only(tmp_path: Path) -> None:
    chunk, infos = three_records()
    data = bytearray(chunk.finish())
    struct.pack_into("<I", data, infos[1].offset + infos[1].size - 4, 12345)
    b.seal_chunk(data)
    items = read(tmp_path, b.build_evtx([bytes(data)]))
    (problem,) = problems_of(items)
    assert problem.record_id == 2
    assert "does not match its copy" in problem.reason
    assert [e.record_id for e in events_of(items)] == [1, 3]


@pytest.mark.parametrize("size", [0, 10, 27, 0xFFFFFFFF, 60000])
def test_an_impossible_record_size_is_reported_and_reading_resumes(
    tmp_path: Path, size: int
) -> None:
    chunk, infos = three_records()
    data = bytearray(chunk.finish())
    struct.pack_into("<I", data, infos[1].offset + 4, size)
    b.seal_chunk(data)
    items = read(tmp_path, b.build_evtx([bytes(data)]))
    assert [e.record_id for e in events_of(items)] == [1, 3]
    assert len(problems_of(items)) == 1


def test_bytes_that_are_not_a_record_are_reported_then_the_next_record_is_found(
    tmp_path: Path,
) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, b.security_event(1))
    chunk.add_garbage(b"\xde\xad\xbe\xef" * 7)
    chunk.add_record(2, b.security_event(2))
    items = read(tmp_path, b.build_evtx([chunk.finish()]))
    (problem,) = problems_of(items)
    assert "bytes at offset" in problem.reason
    assert [e.record_id for e in events_of(items)] == [1, 2]


def test_garbage_to_the_end_of_the_records_is_one_problem(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, b.security_event(1))
    chunk.add_garbage(b"\xde\xad\xbe\xef" * 7)
    items = read(tmp_path, b.build_evtx([chunk.finish()]))
    assert len(problems_of(items)) == 1
    assert len(events_of(items)) == 1


def test_zero_padding_up_to_the_free_space_offset_is_normal(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, b.security_event(1))
    chunk.add_garbage(bytes(200))
    items = read(tmp_path, b.build_evtx([chunk.finish()]))
    assert problems_of(items) == []


def test_a_record_cut_off_by_the_free_space_offset(tmp_path: Path) -> None:
    chunk, infos = three_records()
    data = bytearray(chunk.finish(free_offset=infos[2].offset + 10))
    items = read(tmp_path, b.build_evtx([bytes(data)]))
    reasons = [p.reason for p in problems_of(items)]
    assert any("does not match its copy" in r for r in reasons)
    assert [e.record_id for e in events_of(items)] == [1, 2]


def test_a_record_signature_in_the_last_few_bytes(tmp_path: Path) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, b.security_event(1))
    chunk.add_garbage(b"\x2a\x2a\x00\x00" + b"\x01" * 4)
    problems = problems_of(read(tmp_path, b.build_evtx([chunk.finish()])))
    assert any(p.record_id is None and "does not match its copy" in p.reason for p in problems)


def test_data_after_the_end_of_the_xml_is_refused_but_a_missing_end_token_is_not(
    tmp_path: Path,
) -> None:
    chunk = b.ChunkBuilder()
    chunk.add_record(1, b.security_event(1), trailer=b"\x00" + b"\xff" * 16)
    chunk.add_record(2, b.security_event(2), trailer=b"")
    chunk.add_record(3, b.security_event(3), trailer=b"\x00\x01\x02")
    items = read(tmp_path, b.build_evtx([chunk.finish()]))
    assert [p.record_id for p in problems_of(items)] == [1]
    assert [e.record_id for e in events_of(items)] == [2, 3]


def test_a_problem_never_quotes_record_content(tmp_path: Path) -> None:
    marker = "UNIQUE-VALUE-MARKER"
    section = b.El("EventData", [b.el("Data", b.Slot(14), Name="N")])
    bad = b.Value(b.T_UINT32, marker.encode())
    (problem,) = damaged(tmp_path, sections_event([section], [bad]))
    assert marker not in problem.reason


# --- Laziness and robustness ---


def test_reading_is_lazy_one_chunk_at_a_time(tmp_path: Path) -> None:
    chunks = [b.make_chunk([b.security_event(i)], first_id=i) for i in (1, 2, 3)]
    path = tmp_path / "x.evtx"
    path.write_bytes(b.build_evtx(chunks))
    iterator = read_evtx(path, OPTIONS)
    first = next(iterator)
    assert isinstance(first, Event)
    iterator.close()  # type: ignore[attr-defined]


def test_the_reader_only_reads_the_file_in_chunk_sized_pieces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "x.evtx"
    path.write_bytes(b.build_evtx([b.make_chunk([b.security_event(1)])] * 3))
    sizes: list[int] = []
    real_open = Path.open

    def spying_open(self: Path, *args: object, **kwargs: object) -> object:
        handle = real_open(self, *args, **kwargs)  # type: ignore[call-overload]
        real_read = handle.read

        def read_spy(size: int = -1) -> bytes:
            sizes.append(size)
            return real_read(size)  # type: ignore[no-any-return]

        handle.read = read_spy
        return handle

    monkeypatch.setattr(Path, "open", spying_open)
    list(read_evtx(path, OPTIONS))
    assert sizes
    assert -1 not in sizes
    assert max(sizes) <= b.CHUNK_SIZE


def base_file() -> bytes:
    contents: list[b.Instance | b.El] = [
        b.security_event(1, 4728, data=[("MemberSid", "S-1-5-21-1"), (None, "x")]),
        b.security_event(
            2, 4729, data=[("A", b.sid("S-1-5-18")), ("B", b.filetime(STAMP))], mode="embedded"
        ),
        b.security_event(
            3, 4730, data=[("L", b.array(b.T_UINT16, [b.integer(b.T_UINT16, 1)] * 3))]
        ),
        b.security_event(4, 4731, activity=GUID),
    ]
    return b.build_evtx(
        [
            b.make_chunk(contents),
            b.make_chunk([b.security_event(5), b.security_event(6, mode="embedded")], first_id=5),
        ]
    )


BASE = base_file()
USED = b.FILE_HEADER_SIZE + b.CHUNK_SIZE + 4000


def consume(data: bytes) -> list[Event | Problem]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fuzz.evtx"
        path.write_bytes(data)
        try:
            return list(read_evtx(path, OPTIONS))
        except InputError:
            return []


@settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(
    edits=st.lists(st.tuples(st.integers(0, USED), st.integers(0, 255)), min_size=1, max_size=12),
    cut=st.one_of(st.none(), st.integers(0, len(BASE))),
)
def test_flipping_and_cutting_bytes_never_escapes_as_an_exception(
    edits: list[tuple[int, int]], cut: int | None
) -> None:
    data = bytearray(BASE)
    for position, value in edits:
        data[position] = value
    if cut is not None:
        del data[cut:]
    for item in consume(bytes(data)):
        assert isinstance(item, (Event, Problem))


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    start=st.integers(b.FILE_HEADER_SIZE + b.CHUNK_HEADER_SIZE, b.FILE_HEADER_SIZE + 4200),
    chunk_of=st.binary(min_size=1, max_size=64),
)
def test_overwriting_stretches_of_records_never_escapes(start: int, chunk_of: bytes) -> None:
    data = bytearray(BASE)
    data[start : start + len(chunk_of)] = chunk_of
    for item in consume(bytes(data)):
        assert isinstance(item, (Event, Problem))


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(blob=st.binary(max_size=3000))
def test_arbitrary_bytes_after_a_valid_header_never_escape(blob: bytes) -> None:
    header = b.build_evtx([])
    for item in consume(header + blob):
        assert isinstance(item, (Event, Problem))
    for item in consume(blob):
        assert isinstance(item, (Event, Problem))


def test_the_base_file_for_fuzzing_is_itself_clean(tmp_path: Path) -> None:
    items = read(tmp_path, BASE)
    assert problems_of(items) == []
    assert [e.record_id for e in events_of(items)] == [1, 2, 3, 4, 5, 6]
