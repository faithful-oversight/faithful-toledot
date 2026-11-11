# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Windows event XML reader."""

from __future__ import annotations  # noqa: I001 - reviewed

import tempfile
from xml.sax.saxutils import escape
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, ReadOptions
from faithful_toledot.formats import _text
from faithful_toledot.formats import xml as xml_reader
from faithful_toledot.formats.xml import MAX_DEPTH, read_xml

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"
ADMIN = "S-1-5-21-1111111111-2222222222-3333333333-500"


def event(  # noqa: PLR0913 - one knob per part of a synthetic event
    event_id: object = 4720,
    *,
    data: str = "",
    body: str | None = None,
    record: str | None = "4120",
    namespace: str | None = NS,
    time: str | None = "2026-11-10T02:15:03.1230000Z",
    computer: str | None = "dc01.corp.example",
    channel: str | None = "Security",
    provider: str | None = "Microsoft-Windows-Security-Auditing",
    system_extra: str = "",
    tail: str = "",
) -> str:
    """Build one synthetic ``Event``. ``None`` leaves a part out."""
    parts = []
    if provider is not None:
        parts.append(
            f"<Provider Name='{provider}' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
        )
    if event_id is not None:
        parts.append(f"<EventID Qualifiers='0'>{event_id}</EventID><Version>0</Version>")
    parts.append("<Level>0</Level><Task>13824</Task><Opcode>0</Opcode>")
    parts.append("<Keywords>0x8020000000000000</Keywords>")
    if time is not None:
        parts.append(f"<TimeCreated SystemTime='{time}'/>")
    if record is not None:
        parts.append(f"<EventRecordID>{record}</EventRecordID>")
    parts.append("<Correlation ActivityID='{AAAAAAAA-0000-0000-0000-000000000001}'/>")
    parts.append("<Execution ProcessID='612' ThreadID='700'/>")
    if channel is not None:
        parts.append(f"<Channel>{channel}</Channel>")
    if computer is not None:
        parts.append(f"<Computer>{computer}</Computer>")
    parts.append(f"<Security UserID='{SID}'/>{system_extra}")
    inner = f"<System>{''.join(parts)}</System>" + (body if body is not None else data)
    xmlns = f" xmlns='{namespace}'" if namespace else ""
    return f"<Event{xmlns}>{inner}{tail}</Event>"


def event_data(**pairs: str) -> str:
    return (
        "<EventData>"
        + "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in pairs.items())
        + "</EventData>"
    )


def read(
    tmp_path: Path, content: str | bytes, options: ReadOptions | None = None
) -> list[Event | Problem]:
    path = tmp_path / "export.xml"
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return list(read_xml(path, options or ReadOptions()))


def only_event(items: list[Event | Problem]) -> Event:
    assert len(items) == 1
    item = items[0]
    assert isinstance(item, Event), item
    return item


def only_problem(items: list[Event | Problem]) -> Problem:
    assert len(items) == 1
    item = items[0]
    assert isinstance(item, Problem), item
    return item


# --- accepted shapes ----------------------------------------------------------------


def test_wevtutil_bare_sequence_has_no_root(tmp_path: Path) -> None:
    text = event(4720, data=event_data(TargetUserName="jdoe")) + "\n" + event(4728) + "\n"
    items = read(tmp_path, text)
    assert [i.event_id for i in items if isinstance(i, Event)] == [4720, 4728]
    first = items[0]
    assert isinstance(first, Event)
    assert first.data == {"TargetUserName": "jdoe"}
    assert first.source.position == "event 1 (line 1)"
    assert str(items[1].source) == "export.xml, event 2 (line 2)"


def test_wevtutil_with_events_root(tmp_path: Path) -> None:
    text = f"<Events>\n{event(4624)}\n{event(4672)}\n</Events>\n"
    items = read(tmp_path, text)
    assert [i.source.position for i in items] == ["event 1 (line 2)", "event 2 (line 3)"]


def test_event_viewer_save_all_with_declaration_and_rendering_info(tmp_path: Path) -> None:
    rendering = (
        "<RenderingInfo Culture='en-US'><Message>A user account was created.</Message>"
        "<Level>Information</Level><Keywords><Keyword>Audit Success</Keyword></Keywords>"
        "</RenderingInfo>"
    )
    text = (
        '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>\n'
        + event(4720, data=event_data(TargetUserName="jdoe"), tail=rendering)
        + "\n</Events>"
    )
    found = only_event(read(tmp_path, text))
    assert found.data == {"TargetUserName": "jdoe"}
    assert found.source.position == "event 1 (line 3)"


def test_get_winevent_toxml_concatenated_without_whitespace(tmp_path: Path) -> None:
    text = event(4720) + event(4738) + event(5136)
    items = read(tmp_path, text)
    assert [i.event_id for i in items if isinstance(i, Event)] == [4720, 4738, 5136]
    assert [i.source.position for i in items] == [f"event {n} (line 1)" for n in (1, 2, 3)]


def test_pretty_printed_events_keep_value_text_exact(tmp_path: Path) -> None:
    text = (
        "<Events>\n  <Event>\n    <System>\n      <Provider Name='P'/>\n"
        "      <EventID>4720</EventID>\n      <TimeCreated SystemTime='2026-11-10T02:15:03Z'/>\n"
        "      <Channel>Security</Channel>\n      <Computer>dc01</Computer>\n    </System>\n"
        "    <EventData>\n      <Data Name='A'>1</Data>\n    </EventData>\n  </Event>\n</Events>\n"
    )
    assert only_event(read(tmp_path, text)).data == {"A": "1"}


def test_xml_declaration_with_newline_inside_keeps_line_numbers(tmp_path: Path) -> None:
    text = "<?xml version='1.0'\n encoding='UTF-16'?>" + event(4720)
    assert only_event(read(tmp_path, text)).source.position == "event 1 (line 2)"


def test_events_without_a_namespace(tmp_path: Path) -> None:
    assert only_event(read(tmp_path, event(4720, namespace=None))).event_id == 4720


@pytest.mark.parametrize(
    "encode",
    [
        lambda text: text.encode("utf-8"),
        lambda text: b"\xef\xbb\xbf" + text.encode("utf-8"),
        lambda text: b"\xff\xfe" + text.encode("utf-16-le"),
        lambda text: b"\xfe\xff" + text.encode("utf-16-be"),
    ],
    ids=["utf-8", "utf-8-bom", "utf-16-le-bom", "utf-16-be-bom"],
)
@pytest.mark.parametrize("chunk", [1, 5, 64 * 1024])
def test_encodings_and_chunk_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encode: object, chunk: int
) -> None:
    monkeypatch.setattr(_text, "READ_CHUNK", max(chunk, 4))
    text = (
        "<?xml version='1.0'?>\n" + event(4720, data=event_data(TargetUserName="Zoë ☃ 😀")) + "\n"
    )
    path = tmp_path / "e.xml"
    path.write_bytes(encode(text))  # type: ignore[operator]
    found = only_event(list(read_xml(path, ReadOptions())))
    assert found.data == {"TargetUserName": "Zoë ☃ 😀"}


# --- mapping ------------------------------------------------------------------------


def test_system_fields_are_mapped(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, event(4720)))
    assert found.event_id == 4720
    assert found.time == datetime(2026, 11, 10, 2, 15, 3, 123000, tzinfo=UTC)
    assert found.computer == "dc01.corp.example"
    assert found.channel == "Security"
    assert found.provider == "Microsoft-Windows-Security-Auditing"
    assert found.record_id == 4120
    assert found.version == 0
    assert list(found.system.items()) == [
        ("Keywords", "0x8020000000000000"),
        ("Level", "0"),
        ("Task", "13824"),
        ("Opcode", "0"),
        ("ActivityID", "{AAAAAAAA-0000-0000-0000-000000000001}"),
        ("ProcessID", "612"),
        ("ThreadID", "700"),
        ("UserID", SID),
    ]


def test_seven_digit_ticks_are_cut_to_microseconds(tmp_path: Path) -> None:
    found = only_event(read(tmp_path, event(time="2026-11-10T02:15:03.1234567Z")))
    assert found.time.microsecond == 123456


def test_optional_parts_may_be_absent(tmp_path: Path) -> None:
    text = (
        "<Event><System><Provider Name='P'/><EventID>4720</EventID>"
        "<TimeCreated SystemTime='2026-11-10T02:15:03Z'/><Channel>Security</Channel>"
        "<Computer>dc01</Computer>"
        "<Correlation RelatedActivityID='{AAAAAAAA-0000-0000-0000-000000000002}'/>"
        "<Execution/></System></Event>"
    )
    found = only_event(read(tmp_path, text))
    assert found.record_id is None
    assert found.version == 0
    assert found.data == {}
    assert found.system == {"RelatedActivityID": "{AAAAAAAA-0000-0000-0000-000000000002}"}


def test_realistic_4720_4728_4738_5136_4624_data_keep_order_and_text(tmp_path: Path) -> None:
    cases = {
        4720: {
            "TargetUserName": "jdoe",
            "TargetDomainName": "CORP",
            "TargetSid": SID,
            "SubjectUserSid": ADMIN,
            "SubjectLogonId": "0x3e7",
            "UserAccountControl": "%%2080 %%2050",
        },
        4728: {
            "MemberName": "CN=jdoe,OU=Staff,DC=corp,DC=example",
            "MemberSid": SID,
            "TargetUserName": "Domain Admins",
            "PrivilegeList": "-",
        },
        4738: {
            "TargetUserName": "jdoe",
            "DisplayName": "%%1793",
            "UserAccountControl": "-",
            "PasswordLastSet": "11/9/2026 8:15:03 PM",
        },
        5136: {
            "OpType": "%%14674",
            "ObjectDN": "CN=jdoe,OU=Staff,DC=corp,DC=example",
            "AttributeLDAPDisplayName": "description",
            "AttributeValue": "a &amp; b &lt;c&gt;",
        },
        4624: {
            "LogonType": "3",
            "IpAddress": "192.0.2.10",
            "IpPort": "49152",
            "WorkstationName": "-",
        },
    }
    text = "".join(event(i, data=event_data(**d)) for i, d in cases.items())
    items = read(tmp_path, text)
    for item, (event_id, expected) in zip(items, cases.items(), strict=True):
        assert isinstance(item, Event)
        assert item.event_id == event_id
        want = {
            k: v.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            for k, v in expected.items()
        }
        assert list(item.data.items()) == list(want.items())


def test_empty_data_is_an_empty_string_and_text_is_not_stripped(tmp_path: Path) -> None:
    body = (
        "<EventData><Data Name='A'/><Data Name='B'>  x  </Data><Data Name='C'>-</Data></EventData>"
    )
    assert only_event(read(tmp_path, event(body=body))).data == {"A": "", "B": "  x  ", "C": "-"}


def test_unnamed_data_use_their_position_and_binary_has_its_own_key(tmp_path: Path) -> None:
    body = (
        "<EventData><Data>one</Data><Data Name='N'>two</Data><Data Name=''>three</Data>"
        "<Binary>0A0B</Binary></EventData>"
    )
    assert only_event(read(tmp_path, event(body=body))).data == {
        "param1": "one",
        "N": "two",
        "param3": "three",
        "Binary": "0A0B",
    }


def test_repeated_names_keep_the_first_and_number_the_rest(tmp_path: Path) -> None:
    body = (
        "<EventData><Data Name='A'>1</Data><Data Name='A'>2</Data><Data Name='A'>3</Data>"
        "<Data Name='A#2'>4</Data><Data Name='B'>5</Data><Data Name='param2'>6</Data></EventData>"
    )
    data = only_event(read(tmp_path, event(body=body))).data
    assert list(data.items()) == [
        ("A", "1"),
        ("A#2", "2"),
        ("A#3", "3"),
        ("A#2#2", "4"),
        ("B", "5"),
        ("param2", "6"),
    ]


def test_cdata_comments_and_processing_instructions_inside_values(tmp_path: Path) -> None:
    body = (
        "<EventData><Data Name='A'>x<!-- c -->y<![CDATA[<z>]]>&#65;<?pi data?></Data></EventData>"
    )
    assert only_event(read(tmp_path, event(body=body))).data == {"A": "xy<z>A"}


def test_user_data_is_flattened_from_its_single_wrapper(tmp_path: Path) -> None:
    body = (
        "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
        "<SubjectUserName>admin</SubjectUserName><SubjectDomainName>CORP</SubjectDomainName>"
        "<Nested><A>1</A>\n  <B>2</B><C><D>deep</D></C></Nested><Empty/>"
        "</LogFileCleared></UserData>"
    )
    data = only_event(read(tmp_path, event(body=body))).data
    assert data == {
        "SubjectUserName": "admin",
        "SubjectDomainName": "CORP",
        "Nested": "1 2 deep",
        "Empty": "",
    }


def test_user_data_with_no_children_is_empty(tmp_path: Path) -> None:
    assert only_event(read(tmp_path, event(body="<UserData/>"))).data == {}


def test_user_data_with_two_wrappers_is_ambiguous(tmp_path: Path) -> None:
    body = "<UserData><A><X>1</X></A><B><Y>2</Y></B></UserData>"
    problem = only_problem(read(tmp_path, event(body=body)))
    assert "more than one child" in problem.reason
    assert problem.record_id == 4120
    assert problem.source.position == "event 1 (line 1)"


def test_both_event_data_and_user_data_is_a_problem(tmp_path: Path) -> None:
    for body in ("<EventData/><UserData/>", "<UserData/><EventData/>"):
        assert (
            "both EventData and UserData" in only_problem(read(tmp_path, event(body=body))).reason
        )


def test_repeated_sections_are_a_problem(tmp_path: Path) -> None:
    body = (
        "<EventData><Data Name='A'>1</Data></EventData>"
        "<EventData><Data Name='A'>2</Data></EventData>"
    )
    assert "more than once" in only_problem(read(tmp_path, event(body=body))).reason


def test_unknown_elements_are_ignored(tmp_path: Path) -> None:
    body = (
        "<ProcessingErrorData><ErrorCode>1</ErrorCode></ProcessingErrorData>"
        "<EventData><Other><Data Name='X'>no</Data></Other>"
        "<Data Name='A'>yes<Deep><Data Name='Z'>z</Data></Deep></Data>"
        "</EventData>"
    )
    extra = "<Extension>1</Extension><Provider2 Name='x'/>"
    found = only_event(read(tmp_path, event(body=body, system_extra=extra)))
    assert found.data == {"A": "yes z"}


def test_children_in_another_namespace_are_ignored_in_system_and_event_data(tmp_path: Path) -> None:
    text = (
        f"<Event xmlns='{NS}'><System><Provider Name='P'/><EventID>1</EventID>"
        "<TimeCreated SystemTime='2026-11-10T02:15:03Z'/><Channel>C</Channel><Computer>h</Computer>"
        "<x:Foreign xmlns:x='urn:other'>1</x:Foreign></System>"
        "<EventData><x:Data xmlns:x='urn:other' Name='B'>no</x:Data>"
        "<Data Name='A'>yes</Data></EventData></Event>"
    )
    assert only_event(read(tmp_path, text)).data == {"A": "yes"}


def test_prefixed_event_namespace_is_accepted(tmp_path: Path) -> None:
    text = (
        f"<e:Event xmlns:e='{NS}'><e:System><e:Provider Name='P'/><e:EventID>1</e:EventID>"
        "<e:TimeCreated SystemTime='2026-11-10T02:15:03Z'/><e:Channel>C</e:Channel>"
        "<e:Computer>h</e:Computer></e:System></e:Event>"
    )
    assert only_event(read(tmp_path, text)).computer == "h"


def test_event_in_another_namespace_is_a_problem_and_reading_continues(tmp_path: Path) -> None:
    text = event(4720, namespace="urn:other") + event(4728)
    items = read(tmp_path, text)
    assert isinstance(items[0], Problem)
    assert "namespace" in items[0].reason
    assert items[0].source.position == "event 1 (line 1)"
    assert isinstance(items[1], Event)
    assert items[1].source.position == "event 2 (line 1)"


def test_events_container_in_another_namespace_is_not_event_xml(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="first element is <Events>"):
        read(tmp_path, f"<Events xmlns='urn:other'>{event(1)}</Events>")


# --- problems for one event ---------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "text"),
    [
        ({"event_id": None}, "System/EventID"),
        ({"time": None}, "SystemTime"),
        ({"computer": None}, "System/Computer"),
        ({"channel": None}, "System/Channel"),
        ({"provider": None}, "Provider/@Name"),
        ({"computer": ""}, "System/Computer"),
        ({"event_id": 70000}, "EventID is not a whole number"),
        ({"event_id": "abc"}, "EventID is not a whole number"),
        ({"event_id": -1}, "EventID is not a whole number"),
        ({"time": "yesterday"}, "cannot be used: it is not an ISO 8601 timestamp"),
        ({"time": "2026-13-40T02:15:03Z"}, "not a real date"),
        ({"time": "2026-11-10T02:15:03"}, "no UTC offset"),
        ({"time": "2026-11-10T02:15:03+25:00"}, "UTC offset is not valid"),
        ({"time": "0001-01-01T00:00:00+05:00"}, "not a real date"),
    ],
)
def test_one_bad_event_is_a_problem_and_the_next_is_read(
    tmp_path: Path, kwargs: dict[str, object], text: str
) -> None:
    items = read(tmp_path, event(**kwargs) + "\n" + event(4728))  # type: ignore[arg-type]
    assert len(items) == 2
    problem = items[0]
    assert isinstance(problem, Problem)
    assert text in problem.reason
    assert problem.source.position == "event 1 (line 1)"
    assert problem.record_id == 4120
    assert isinstance(items[1], Event)


def test_bad_version_and_record_id(tmp_path: Path) -> None:
    text = event().replace("<Version>0</Version>", "<Version>300</Version>")
    assert "Version" in only_problem(read(tmp_path, text)).reason
    problem = only_problem(read(tmp_path, event(record="12x")))
    assert "EventRecordID" in problem.reason
    assert problem.record_id is None


def test_repeated_system_element_is_a_problem(tmp_path: Path) -> None:
    problem = only_problem(read(tmp_path, event(system_extra="<EventID>5</EventID>")))
    assert "System/EventID appears more than once" in problem.reason


def test_time_without_offset_uses_local_offset_when_given(tmp_path: Path) -> None:
    options = ReadOptions(local_offset=timedelta(hours=-6))
    found = only_event(read(tmp_path, event(time="2026-11-10T02:15:03"), options))
    assert found.time == datetime(2026, 11, 10, 8, 15, 3, tzinfo=UTC)


def test_an_unusable_local_offset_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="local_offset"):
        read(tmp_path, event(), ReadOptions(local_offset=timedelta(hours=24)))


# --- limits -------------------------------------------------------------------------


def test_nesting_over_the_limit_is_a_problem_for_that_event(tmp_path: Path) -> None:
    deep = "<A>" * (MAX_DEPTH + 2) + "x" + "</A>" * (MAX_DEPTH + 2)
    body = f"<UserData><W><Field>{deep}</Field></W></UserData>"
    items = read(tmp_path, event(body=body) + event(4728))
    assert isinstance(items[0], Problem)
    assert "nested more than" in items[0].reason
    assert isinstance(items[1], Event)


def test_deep_nesting_in_ignored_elements_is_harmless(tmp_path: Path) -> None:
    deep = "<A>" * 5000 + "</A>" * 5000
    found = only_event(read(tmp_path, event(tail=f"<RenderingInfo>{deep}</RenderingInfo>")))
    assert found.event_id == 4720


def test_too_many_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xml_reader, "MAX_FIELDS", 3)
    body = "<EventData>" + "<Data>x</Data>" * 4 + "</EventData>"
    items = read(
        tmp_path,
        event(body=body) + event(body="<EventData>" + "<Data>x</Data>" * 3 + "</EventData>"),
    )
    assert isinstance(items[0], Problem)
    assert "more than 3 data fields" in items[0].reason
    assert isinstance(items[1], Event)


def test_value_over_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xml_reader, "MAX_VALUE_CHARS", 40)
    items = read(tmp_path, event(data=event_data(A="x" * 41)) + event(data=event_data(A="x" * 40)))
    assert isinstance(items[0], Problem)
    assert "value is longer than 40" in items[0].reason
    assert isinstance(items[1], Event)


def test_event_text_over_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xml_reader, "MAX_EVENT_CHARS", 30)
    problem = only_problem(
        read(tmp_path, event(data=event_data(A="x" * 10, B="y" * 10, C="z" * 10)))
    )
    assert "more than 30 characters" in problem.reason


def test_attribute_and_name_over_the_limit(tmp_path: Path) -> None:
    long = "n" * 300
    items = read(tmp_path, event(provider=long) + event(data=event_data(**{long: "1"})) + event())
    assert "longer than 256" in items[0].reason  # type: ignore[union-attr]
    assert isinstance(items[1], Problem)
    assert "Data name is longer" in items[1].reason
    assert isinstance(items[2], Event)


def test_only_the_first_reason_is_reported(tmp_path: Path) -> None:
    long = "g" * 300
    text = (
        "<Event><System><Provider Name='P'/><EventID>1</EventID>"
        "<TimeCreated SystemTime='2026-11-10T02:15:03Z'/><Channel>C</Channel><Computer>h</Computer>"
        f"<Correlation ActivityID='{long}' RelatedActivityID='{long}'/></System></Event>"
    )
    problem = only_problem(read(tmp_path, text))
    assert "ActivityID" in problem.reason
    assert "RelatedActivityID" not in problem.reason


def test_a_single_huge_token_stops_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_text, "READ_CHUNK", 64)
    monkeypatch.setattr(xml_reader, "MAX_IDLE_CHARS", 200)
    huge = "<!--" + "x" * 1000 + "-->"
    with pytest.raises(InputError, match="single XML token"):
        read(tmp_path, huge + event())
    items = read(tmp_path, event() + huge + event(4728))
    assert isinstance(items[0], Event)
    assert isinstance(items[-1], Problem)
    assert "single XML token" in items[-1].reason
    assert "rest of the file was not read" in items[-1].reason


# --- hostile and malformed files ----------------------------------------------------


DOCTYPES = [
    "<!DOCTYPE Events>",
    '<!DOCTYPE Events [<!ENTITY x "y">]>',
    '<!DOCTYPE Events SYSTEM "http://example.com/evil.dtd">',
    '<!DOCTYPE Events [<!ENTITY % p SYSTEM "http://example.com/p">%p;]>',
    '<!DOCTYPE Events [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>',
]


@pytest.mark.parametrize("doctype", DOCTYPES)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_dtd_and_entities_are_refused_in_any_encoding(
    tmp_path: Path, doctype: str, encoding: str
) -> None:
    text = f"<?xml version='1.0'?>{doctype}<Events>{event(4720)}</Events>"
    with pytest.raises(InputError, match="declares a DTD or entity"):
        read(tmp_path, text.encode(encoding))


def test_a_dtd_after_good_events_still_stops_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = event(4720)
    monkeypatch.setattr(_text, "READ_CHUNK", len(first))
    path = tmp_path / "late.xml"
    path.write_text(first + "<!DOCTYPE x>" + event(4728), encoding="utf-8")
    reader = read_xml(path, ReadOptions())
    assert isinstance(next(reader), Event)
    with pytest.raises(InputError, match="declares a DTD or entity"):
        next(reader)


def test_a_dtd_in_the_only_chunk_is_refused_by_the_call(tmp_path: Path) -> None:
    path = tmp_path / "late.xml"
    path.write_text(event(4720) + "<!ENTITY a 'b'>" + event(4728), encoding="utf-8")
    with pytest.raises(InputError, match="declares a DTD or entity"):
        read_xml(path, ReadOptions())


def test_undefined_entity_reference_is_not_expanded(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="not well-formed"):
        read(tmp_path, event(data=event_data(A="&xxe;")))


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\xef\xbb\xbf",
        b"\xff\xfe",
        b"   \n",
        b"hello",
        b"<html><body/></html>",
        b"<Events/>",
        b"<Events></Events>",
    ],
)
def test_files_that_are_not_event_xml_are_refused(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(InputError):
        read(tmp_path, content)


def test_error_is_raised_by_the_call_not_by_the_first_next(tmp_path: Path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text("<html/>", encoding="utf-8")
    with pytest.raises(InputError, match=r"bad\.xml is not Windows event XML"):
        read_xml(path, ReadOptions())


def test_text_before_the_first_element_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="text before the first element"):
        read(tmp_path, "hello " + event())


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read"):
        list(read_xml(tmp_path / "nope.xml", ReadOptions()))
    with pytest.raises(InputError, match="cannot read"):
        list(read_xml(tmp_path, ReadOptions()))


@pytest.mark.parametrize(
    "content",
    [
        b"\xff\xfe\x00\x00<\x00\x00\x00",
        b"\x00\x00\xfe\xff\x00\x00\x00<",
        "<Events/>".encode("utf-16-le"),
        "<Events/>".encode("utf-16-be"),
        b"<Event>\x00</Event>",
        b"<Events>\xff\xfe</Events>",
        b"\xff\xfe<\x00\x00\xd8",
        b"\xff\xfe<\x00E",
    ],
)
def test_bad_encodings_are_refused(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(InputError):
        read(tmp_path, content)


def test_invalid_text_after_good_events_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_text, "READ_CHUNK", 4096)
    good = event(4720) + "\n"
    items = read(tmp_path, (good * 100).encode() + b"\xff\xfe")
    assert isinstance(items[-1], Problem)
    assert "not valid UTF-8" in items[-1].reason
    assert items[-1].source.position == "after event 100"
    assert sum(isinstance(i, Event) for i in items) == 100


def test_truncated_file_keeps_earlier_events_and_reports_the_cut(tmp_path: Path) -> None:
    text = f"<Events>{event(4720)}\n{event(4728)}\n<Event><System><Prov"
    items = read(tmp_path, text)
    assert [type(i) for i in items] == [Event, Event, Problem]
    problem = items[2]
    assert isinstance(problem, Problem)
    assert "not well-formed" in problem.reason
    assert "rest of the file was not read" in problem.reason
    assert problem.source.position == "event 3 (line 3)"


def test_unclosed_events_root_after_complete_events(tmp_path: Path) -> None:
    items = read(tmp_path, f"<Events>{event(4720)}")
    assert [type(i) for i in items] == [Event, Problem]
    assert items[1].source.position.startswith("line ")


def test_truncated_before_any_event_is_a_file_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="not well-formed"):
        read(tmp_path, "<Events><Event><System><Prov")
    with pytest.raises(InputError, match="not well-formed"):
        read(tmp_path, "<Event>")


def test_mismatched_tags_after_events_stop_the_read(tmp_path: Path) -> None:
    items = read(tmp_path, event(4720) + "</oops>" + event(4728))
    assert [type(i) for i in items] == [Event, Problem]


def test_second_xml_declaration_stops_the_read(tmp_path: Path) -> None:
    text = "<?xml version='1.0'?>" + event(4720) + "<?xml version='1.0'?>" + event(4728)
    items = read(tmp_path, text)
    assert [type(i) for i in items] == [Event, Problem]


def test_unknown_top_level_elements_and_text_are_problems_after_a_valid_event(
    tmp_path: Path,
) -> None:
    text = (
        event(4720)
        + "<Other/>\nstray text\nmore stray\n"
        + f"<Events>{event(4728)}<Weird><Event/></Weird>junk</Events>"
    )
    items = read(tmp_path, text)
    kinds = [type(i).__name__ for i in items]
    assert kinds == ["Event", "Problem", "Problem", "Event", "Problem", "Problem"]
    assert "<Other>" in items[1].reason  # type: ignore[union-attr]
    assert "text outside any event" in items[2].reason  # type: ignore[union-attr]
    assert "<Weird>" in items[4].reason  # type: ignore[union-attr]


def test_nested_events_container_is_skipped(tmp_path: Path) -> None:
    items = read(tmp_path, f"<Events>{event(4720)}<Events>{event(4728)}</Events></Events>")
    assert [type(i) for i in items] == [Event, Problem]


def test_generator_closes_its_file_when_abandoned(tmp_path: Path) -> None:
    path = tmp_path / "many.xml"
    path.write_text(event(4720) * 50, encoding="utf-8")
    reader = read_xml(path, ReadOptions())
    assert isinstance(next(reader), Event)
    reader.close()  # type: ignore[attr-defined]


def test_malformed_leading_whitespace_before_declaration_is_tolerated(tmp_path: Path) -> None:
    assert only_event(read(tmp_path, "\n  <?xml version='1.0'?>\n" + event())).event_id == 4720


# --- property tests -----------------------------------------------------------------

_FRAGMENTS = [
    b"<Event>",
    b"</Event>",
    b"<System>",
    b"</System>",
    b"<EventData>",
    b"</EventData>",
    b"<Data Name='A'>",
    b"</Data>",
    b"<UserData>",
    b"</UserData>",
    b"<Events>",
    b"</Events>",
    b"<EventID>4720</EventID>",
    b"<Provider Name='P'/>",
    b"<Computer>c</Computer>",
    b"<Channel>Security</Channel>",
    b"<TimeCreated SystemTime='2026-11-10T02:15:03Z'/>",
    b"<!DOCTYPE x>",
    b"<!--",
    b"-->",
    b"&amp;",
    b"&#0;",
    b"\x00",
    b"\xff",
    b"x",
]


def _read_bytes(content: bytes) -> list[Event | Problem]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fuzz.xml"
        path.write_bytes(content)
        return list(read_xml(path, ReadOptions()))


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=300))
def test_arbitrary_bytes_only_raise_input_error(content: bytes) -> None:
    try:
        items = _read_bytes(content)
    except InputError:
        return
    assert all(isinstance(i, (Event, Problem)) for i in items)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.sampled_from(_FRAGMENTS), max_size=30), st.sampled_from(["utf-8", "utf-16"]))
def test_xml_like_soup_only_raises_input_error(parts: list[bytes], encoding: str) -> None:
    joined = b"".join(parts)
    content = (
        joined
        if encoding == "utf-8"
        else b"\xff\xfe" + joined.decode("latin-1").encode("utf-16-le")
    )
    try:
        items = _read_bytes(content)
    except InputError:
        return
    assert all(isinstance(i, (Event, Problem)) for i in items)


@settings(max_examples=100, deadline=None)
@given(
    st.lists(
        st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), max_size=20), max_size=8
    )
)
def test_any_text_value_round_trips(values: list[str]) -> None:
    names = [f"F{i}" for i in range(len(values))]
    body = (
        "<EventData>"
        + "".join(
            f"<Data Name='{n}'>{escape(v)}</Data>" for n, v in zip(names, values, strict=True)
        )
        + "</EventData>"
    )
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "t.xml"
        path.write_text(event(body=body), encoding="utf-16")
        (found,) = list(read_xml(path, ReadOptions()))
    assert isinstance(found, Event)
    # expat normalises \r, so compare against the same normalisation
    assert list(found.data.values()) == [
        v.replace("\r\n", "\n").replace("\r", "\n") for v in values
    ]
