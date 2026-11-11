# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The collection file written by toledot's collectors, and the format detector."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from importlib.resources import files
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema.validators import validator_for

from faithful_toledot import formats
from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, LogFacts, Problem, ReadOptions
from faithful_toledot.formats import bundle
from faithful_toledot.formats.bundle import encode, format_time, read_bundle
from tests.helpers import DC, at, logon, member_added

if TYPE_CHECKING:
    from pathlib import Path

OPTIONS = ReadOptions()


def header(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "toledot_events": 1,
        "collector": {
            "name": "Collect-ToledotEvents.ps1",
            "version": "0.1.0",
            "method": "powershell",
        },
        "collected_at": "2026-11-03T15:00:00.0000000Z",
        "computer": DC,
        "operator": "CORP\\auditor",
        "query": {
            "channels": ["Security"],
            "event_ids": [4624, 4728],
            "since": "2026-11-01T00:00:00.0000000Z",
            "until": None,
        },
        "logs": [
            {
                "channel": "Security",
                "oldest_record_id": 12,
                "oldest_time": "2026-11-02T00:00:00.5000000Z",
                "newest_record_id": 99999,
                "record_count": 99988,
                "max_size_bytes": 134217728,
                "mode": "circular",
            }
        ],
    }
    document.update(overrides)
    return document


def write(tmp_path: Path, data: bytes, name: str = "events.jsonl") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def read(path: Path) -> list[Event | Problem | LogFacts]:
    return list(read_bundle(path, OPTIONS))


def lines_of(data: bytes) -> list[bytes]:
    return data.splitlines(keepends=True)


EVENTS = [logon(), member_added()]


def test_a_collection_reads_back_as_the_events_written(tmp_path: Path) -> None:
    path = write(tmp_path, encode(header(), EVENTS))
    facts, *events = read(path)
    assert isinstance(facts, LogFacts)
    assert (facts.computer, facts.channel, facts.filtered) == (DC, "Security", True)
    assert facts.oldest_time == datetime(2026, 11, 2, 0, 0, 0, 500000, tzinfo=UTC)
    assert facts.asked_since == datetime(2026, 11, 1, tzinfo=UTC)
    assert (facts.oldest_record, facts.newest_record) == (12, 99999)
    assert [e.data for e in events if isinstance(e, Event)] == [e.data for e in EVENTS]
    first = events[0]
    assert isinstance(first, Event)
    assert (first.time, first.record_id, first.event_id) == (
        EVENTS[0].time, EVENTS[0].record_id, 4624,
    )  # fmt: skip
    assert str(first.source) == "events.jsonl, line 2"
    assert formats.detect(path) == "collection"
    assert len(list(formats.read(path, OPTIONS))) == 3


def test_every_line_matches_the_published_schema() -> None:
    text = files("faithful_toledot").joinpath("schema/events-v1.schema.json").read_text("utf-8")
    schema = json.loads(text)
    validator = validator_for(schema)(schema)
    data = encode(header(), EVENTS, [{"area": "System", "reason": "Access is denied."}])
    for line in data.splitlines():
        validator.validate(json.loads(line))
    assert data.startswith(bundle.MARKER)


def test_a_collection_of_every_event_says_it_is_unfiltered(tmp_path: Path) -> None:
    query = {"channels": ["Security"], "event_ids": [], "since": None, "until": None}
    facts = read(write(tmp_path, encode(header(query=query, logs=header()["logs"]), [])))[0]
    assert isinstance(facts, LogFacts)
    assert (facts.filtered, facts.asked_since) == (False, None)


def test_gaps_the_collector_recorded_become_problems(tmp_path: Path) -> None:
    data = encode(header(), EVENTS, [{"area": "the System log", "reason": "Access is denied."}])
    problems = [item for item in read(write(tmp_path, data)) if isinstance(item, Problem)]
    assert [p.reason for p in problems] == [
        "The collector could not read the System log: Access is denied."
    ]


def test_a_file_cut_short_is_read_and_reported(tmp_path: Path) -> None:
    data = b"".join(lines_of(encode(header(), EVENTS))[:-1])
    *rest, last = read(write(tmp_path, data))
    assert len([item for item in rest if isinstance(item, Event)]) == 2
    assert isinstance(last, Problem)
    assert "ends without the collector's end line" in last.reason


def test_a_removed_event_is_caught_by_the_count_and_the_hash(tmp_path: Path) -> None:
    lines = lines_of(encode(header(), EVENTS))
    del lines[1]
    reasons = [
        item.reason for item in read(write(tmp_path, b"".join(lines))) if isinstance(item, Problem)
    ]
    assert any("counts 2 events but 1 were read" in reason for reason in reasons)
    assert any("do not match the hash" in reason for reason in reasons)


def test_an_altered_event_is_caught_by_the_hash(tmp_path: Path) -> None:
    data = encode(header(), EVENTS).replace(b"Domain Admins", b"Domain Guests")
    reasons = [item.reason for item in read(write(tmp_path, data)) if isinstance(item, Problem)]
    assert reasons == ["The file's contents do not match the hash in its end line."]


def test_content_after_the_end_line_is_reported(tmp_path: Path) -> None:
    data = encode(header(), EVENTS) + lines_of(encode(header(), EVENTS))[1]
    last = read(write(tmp_path, data))[-1]
    assert isinstance(last, Problem)
    assert last.reason == "The file continues after its end line."


def event_line(**changes: Any) -> bytes:
    document = json.loads(lines_of(encode(header(), EVENTS))[2])
    for name, value in changes.items():
        if value is ...:
            del document[name]
        else:
            document[name] = value
    return json.dumps(document).encode("utf-8") + b"\n"


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (b"not json\n", "the line is not valid JSON"),
        (b"[1]\n", "the line is not a JSON object"),
        (b"\xff\xfe\n", "the line is not UTF-8"),
        (b'{"a":1,"a":2}\n', "the property 'a' is repeated"),
        (b'{"a":NaN}\n', "NaN is not JSON"),
        (b'{"a":"\\ud800"}\n', "unpaired surrogate"),
        (b'{"a":' + b"[" * 20 + b"]" * 20 + b"}\n", "nested too deeply"),
        (b'{"a":' + b"[" * 100000 + b"]" * 100000 + b"}\n", "nested too deeply"),
        (b'{"a":' + b"9" * 5000 + b"}\n", "the line is not valid JSON"),
        (event_line(extra=1), "unknown property 'extra'"),
        (event_line(data=...), "no 'data'"),
        (event_line(record_id=-1), "record_id is not a whole number"),
        (event_line(record_id=True), "record_id is not a whole number"),
        (event_line(event_id=70000), "event_id is not a whole number"),
        (event_line(version="1"), "version is not a whole number"),
        (event_line(time="2026-11-03 14:00:00"), "time is not a UTC time"),
        (event_line(time="2026-02-30T00:00:00Z"), "time is not a real date"),
        (event_line(time=5), "time is not a UTC time"),
        (event_line(computer=""), "computer is not text"),
        (event_line(channel="x" * 300), "channel is not text"),
        (event_line(data=[]), "data is not an object"),
        (event_line(data={"A": 1}), "data.A is not text"),
        (event_line(system={"": "x"}), "a name in system is not text"),
        (event_line(data={f"f{i}": "" for i in range(300)}), "data is not an object of at most"),
    ],
)
def test_a_bad_line_is_a_problem_and_reading_goes_on(
    tmp_path: Path, line: bytes, reason: str
) -> None:
    lines = lines_of(encode(header(), EVENTS))
    lines.insert(2, line)
    items = read(write(tmp_path, b"".join(lines)))
    assert len([item for item in items if isinstance(item, Event)]) == 2
    bad = [item for item in items if isinstance(item, Problem)]
    assert reason in bad[0].reason
    assert bad[0].source.position == "line 3"


def test_a_bad_event_keeps_its_record_number_when_readable(tmp_path: Path) -> None:
    lines = lines_of(encode(header(), EVENTS))
    lines.insert(1, event_line(record_id=77, time="never"))
    problem = next(
        item for item in read(write(tmp_path, b"".join(lines))) if isinstance(item, Problem)
    )
    assert problem.record_id == 77


@pytest.mark.parametrize(
    ("trailer", "reason"),
    [
        ({"end": True, "events": 2, "sha256": "0" * 64}, "the line has no 'gaps'"),
        ({"end": False, "events": 2, "sha256": "0" * 64, "gaps": []}, "not what the schema says"),
        (
            {"end": True, "events": "2", "sha256": "0" * 64, "gaps": []},
            "events is not a whole number",
        ),
        (
            {"end": True, "events": 2, "sha256": "0" * 64, "gaps": [1]},
            "an entry in gaps is not an object",
        ),
        (
            {"end": True, "events": 2, "sha256": "0" * 64, "gaps": [{"area": "x"}]},
            "gaps.reason is not text",
        ),
    ],
)
def test_a_bad_end_line_is_a_problem(tmp_path: Path, trailer: dict[str, Any], reason: str) -> None:
    lines = lines_of(encode(header(), EVENTS))[:-1]
    lines.append(json.dumps(trailer).encode() + b"\n")
    problems = [
        item for item in read(write(tmp_path, b"".join(lines))) if isinstance(item, Problem)
    ]
    assert any(reason in problem.reason for problem in problems)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"computer": ""}, "computer is not text"),
        ({"collected_at": "yesterday"}, "collected_at is not a UTC time"),
        ({"query": []}, "query or logs are not what the schema says"),
        ({"logs": [1]}, "an entry in logs is not an object"),
        (
            {"logs": [{"channel": "Security", "oldest_time": 7}]},
            "logs.oldest_time is not a UTC time",
        ),
        ({"logs": [{"channel": "Security", "oldest_record_id": "1"}]}, "oldest_record_id is not"),
        ({"query": {"event_ids": 5}}, "query.event_ids is not a list"),
        ({"query": {"event_ids": [], "since": "x"}}, "query.since is not a UTC time"),
        ({"surprise": 1}, "unknown property 'surprise'"),
        ({"logs": [{}] * 17}, "query or logs are not what the schema says"),
    ],
)
def test_a_bad_header_is_an_input_error(
    tmp_path: Path, changes: dict[str, Any], reason: str
) -> None:
    path = write(tmp_path, encode(header(**changes), []))
    with pytest.raises(InputError, match="events.jsonl is not a toledot collection: .*" + reason):
        read_bundle(path, OPTIONS).__next__()


def test_unreadable_and_oversized_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(InputError, match=r"cannot read missing\.jsonl"):
        next(read_bundle(tmp_path / "missing.jsonl", OPTIONS))
    monkeypatch.setattr(bundle, "MAX_LINE", 2000)
    long_event = replace(member_added(), data={"A": "x" * 5000})
    data = encode(header(), [*EVENTS, long_event, member_added()])
    items = read(write(tmp_path, data))
    assert len([item for item in items if isinstance(item, Event)]) == 2
    last = items[-1]
    assert isinstance(last, Problem)
    assert "longer than 2000 bytes; the rest is not read" in last.reason
    monkeypatch.setattr(bundle, "MAX_LINE", 100)
    with pytest.raises(InputError, match="the first line is too long"):
        next(read_bundle(write(tmp_path, data, "big.jsonl"), OPTIONS))


def test_times_keep_seven_fraction_digits_as_written() -> None:
    assert format_time(at(0.123456)) == "2026-11-03T14:00:00.1234560Z"
    assert format_time(at(0)) == "2026-11-03T14:00:00.0000000Z"


@settings(max_examples=150, deadline=None)
@given(st.binary(max_size=400), st.integers(min_value=0, max_value=1200))
def test_damage_anywhere_never_raises_anything_but_an_input_error(
    tmp_path_factory: pytest.TempPathFactory, junk: bytes, where: int
) -> None:
    data = bytearray(encode(header(), EVENTS))
    spot = where % (len(data) + 1)
    data[spot : spot + len(junk)] = junk
    path = tmp_path_factory.mktemp("damage") / "events.jsonl"
    path.write_bytes(bytes(data))
    try:
        items = list(read_bundle(path, OPTIONS))
    except InputError:
        return
    assert all(isinstance(item, Event | Problem | LogFacts) for item in items)


# --- format detection -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start", "kind"),
    [
        (b"ElfFile\x00" + bytes(100), "evtx"),
        (b'{"toledot_events":1,"x":1}', "collection"),
        (b"<Events><Event/></Events>", "xml"),
        (b"\xef\xbb\xbf  \r\n<Event", "xml"),
        ("<Event".encode("utf-16"), "xml"),
        ("\ufeff<Event".encode("utf-16-be"), "xml"),
        ("<Event".encode("utf-16-le"), "xml"),
        (b'[{"Id": 4728}]', "json"),
        (b'{"Id": 4728}\n{"Id": 4729}', "json"),
        ('{"Id": 1}'.encode("utf-16"), "json"),
        (b'"Message","Id","Version"\r\n', "csv"),
        (b"Level,Date and Time,Source,Event ID,Task Category\r\n", "csv"),
        (b"Level\tDate and Time\r\n", "csv"),
    ],
)
def test_the_format_is_decided_from_the_first_bytes(
    tmp_path: Path, start: bytes, kind: str
) -> None:
    assert formats.detect(write(tmp_path, start, "misnamed.txt")) == kind


@pytest.mark.parametrize(
    ("data", "reason"),
    [(b"", "is empty"), (b"hello world", "is not an event log toledot can read")],
)
def test_files_in_no_known_format_are_refused(tmp_path: Path, data: bytes, reason: str) -> None:
    with pytest.raises(InputError, match=reason):
        formats.detect(write(tmp_path, data, "odd.bin"))
    with pytest.raises(InputError, match=r"cannot read gone\.evtx"):
        formats.detect(tmp_path / "gone.evtx")
