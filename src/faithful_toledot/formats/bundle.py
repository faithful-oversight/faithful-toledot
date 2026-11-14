# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read the JSON Lines file written by toledot's own collectors.

The first line is a header, each following line is one event, and the last line is
a trailer holding the event count and the SHA-256 of every byte before it. The file
is read line by line, so its size is not limited by memory. See
``schema/events-v1.schema.json`` for the exact shape.

A file that ends without its trailer was cut short: every event in it is still
read, and one problem says the end is missing. A trailer whose hash or count does
not match is a problem too. Neither is hidden, and neither stops the reading.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NamedTuple

from faithful_toledot.clock import date_and_time
from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, LogFacts, Problem, Source

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from faithful_toledot.events import ReadOptions

MARKER = b'{"toledot_events":'
"""How every collection file starts, byte for byte."""
MAX_LINE = 8 * 1024 * 1024
"""The longest line accepted, in bytes. A line is one event."""
MAX_FIELDS = 256
MAX_VALUE = 1024 * 1024
MAX_NAME = 255
MAX_DEPTH = 8

_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,7}))?Z"
)
_EVENT_KEYS = frozenset(
    {
        "record_id",
        "event_id",
        "version",
        "time",
        "computer",
        "channel",
        "provider",
        "system",
        "data",
    }
)
_HEADER_KEYS = frozenset(
    {"toledot_events", "collector", "collected_at", "computer", "operator", "query", "logs"}
)
_TRAILER_KEYS = frozenset({"end", "events", "sha256", "gaps"})
_GAP_KEYS = frozenset({"area", "reason"})
_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_GAPS = 1000


class BadLineError(ValueError):
    """A line that is not what the schema says."""


class Trailer(NamedTuple):
    """The checked contents of an end line.

    Attributes:
        events: The event count the collector states.
        sha256: The hash it states, 64 lower-case hex digits.
        gaps: What the collector could not read, as ``(area, reason)`` pairs. At most
            ``MAX_GAPS`` are kept.
        unlisted_gaps: How many entries beyond ``MAX_GAPS`` the end line held. The schema
            allows 1000, so a line with more is not what a toledot collector writes, but
            its count and hash still decide whether the events arrived whole.
    """

    events: int
    sha256: str
    gaps: tuple[tuple[str, str], ...]
    unlisted_gaps: int = 0


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            msg = f"the property {name!r} is repeated"
            raise BadLineError(msg)
        out[name] = value
    return out


def _constant(text: str) -> Any:
    msg = f"{text} is not JSON"
    raise BadLineError(msg)


def _decode(line: bytes) -> dict[str, Any]:
    """Parse one line strictly: UTF-8, one object, no repeated names, valid Unicode."""
    try:
        text = line.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except UnicodeDecodeError:
        msg = "the line is not UTF-8"
        raise BadLineError(msg) from None
    except RecursionError:
        msg = "the line is nested too deeply"
        raise BadLineError(msg) from None
    except ValueError as exc:
        msg = str(exc) if isinstance(exc, BadLineError) else "the line is not valid JSON"
        raise BadLineError(msg) from None
    if not isinstance(value, dict):
        msg = "the line is not a JSON object"
        raise BadLineError(msg)
    _check(value, 0)
    return value


def _check(value: object, depth: int) -> None:
    """Refuse deep nesting and text that is not valid Unicode."""
    if depth > MAX_DEPTH:
        msg = "the line is nested too deeply"
        raise BadLineError(msg)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            msg = "the line holds an unpaired surrogate"
            raise BadLineError(msg) from None
    elif isinstance(value, dict):
        for name, item in value.items():
            _check(name, depth + 1)
            _check(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check(item, depth + 1)


def _time(value: object, what: str) -> datetime:
    match = _TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        msg = f"{what} is not a UTC time such as 2026-11-03T14:00:00.1234567Z"
        raise BadLineError(msg)
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fraction = (match.group(7) or "").ljust(7, "0")
    try:
        base = datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        msg = f"{what} is not a real date and time"
        raise BadLineError(msg) from None
    return base + timedelta(microseconds=int(fraction[:6]))


def _optional_time(value: object, what: str) -> datetime | None:
    return None if value is None else _time(value, what)


def _integer(value: object, what: str, *, high: int, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= high:
        msg = f"{what} is not a whole number from 0 to {high}"
        raise BadLineError(msg)
    return value


def _string(value: object, what: str, *, limit: int = MAX_NAME, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not value and not empty):
        msg = f"{what} is not text of at most {limit} characters"
        raise BadLineError(msg)
    return value


def _strings(value: object, what: str, *, limit: int) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_FIELDS:
        msg = f"{what} is not an object of at most {MAX_FIELDS} text values"
        raise BadLineError(msg)
    for name, item in value.items():
        _string(name, f"a name in {what}")
        _string(item, f"{what}.{name}", limit=limit, empty=True)
    return value


def _keys(value: dict[str, Any], allowed: frozenset[str], required: frozenset[str]) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown or missing:
        problem = f"unknown property {unknown[0]!r}" if unknown else f"no {missing[0]!r}"
        msg = f"the line has {problem}"
        raise BadLineError(msg)


def _event(value: dict[str, Any], source: Source) -> Event:
    _keys(value, _EVENT_KEYS, _EVENT_KEYS)
    record = _integer(value["record_id"], "record_id", high=2**63 - 1)
    event_id = _integer(value["event_id"], "event_id", high=65535)
    version = _integer(value["version"], "version", high=255)
    if record is None or event_id is None or version is None:  # pragma: no cover - not optional
        raise BadLineError
    return Event(
        event_id=event_id,
        time=_time(value["time"], "time"),
        computer=_string(value["computer"], "computer"),
        channel=_string(value["channel"], "channel"),
        provider=_string(value["provider"], "provider", empty=True),
        record_id=record,
        version=version,
        data=_strings(value["data"], "data", limit=MAX_VALUE),
        system=_strings(value["system"], "system", limit=1024),
        source=source,
    )


def _facts(header: dict[str, Any], name: str) -> list[LogFacts]:
    """Read the header's facts about each log. A header that breaks the schema raises."""
    _keys(header, _HEADER_KEYS, _HEADER_KEYS - {"operator"})
    computer = _string(header["computer"], "computer")
    _time(header["collected_at"], "collected_at")
    query = header["query"]
    logs = header["logs"]
    if not isinstance(query, dict) or not isinstance(logs, list) or len(logs) > 16:  # noqa: PLR2004
        msg = "the header's query or logs are not what the schema says"
        raise BadLineError(msg)
    since = _optional_time(query.get("since"), "query.since")
    _optional_time(query.get("until"), "query.until")
    ids = query.get("event_ids")
    if not isinstance(ids, list):
        msg = "query.event_ids is not a list"
        raise BadLineError(msg)
    out = []
    for log in logs:
        if not isinstance(log, dict):
            msg = "an entry in logs is not an object"
            raise BadLineError(msg)
        out.append(
            LogFacts(
                computer=computer,
                channel=_string(log.get("channel"), "logs.channel"),
                source=Source(name, "line 1"),
                oldest_time=_optional_time(log.get("oldest_time"), "logs.oldest_time"),
                oldest_record=_integer(
                    log.get("oldest_record_id"),
                    "logs.oldest_record_id",
                    high=2**63 - 1,
                    optional=True,
                ),
                newest_record=_integer(
                    log.get("newest_record_id"),
                    "logs.newest_record_id",
                    high=2**63 - 1,
                    optional=True,
                ),
                asked_since=since,
                filtered=bool(ids),
            )
        )
    return out


def check_header(line: bytes, name: str) -> list[LogFacts]:
    """Check a header line against the schema, as the file reader does.

    Both the file reader and the remote collector call this, so a stream is published
    only if the reader will accept its first line.

    Args:
        line: The line's bytes, with or without its newline.
        name: The file's name, for the source of the facts.

    Returns:
        The header's facts about each log.

    Raises:
        BadLineError: The line is too long or is not a header the schema allows.
    """
    if len(line) > MAX_LINE:
        msg = "the first line is too long"
        raise BadLineError(msg)
    return _facts(_decode(line), name)


def decode_line(line: bytes) -> dict[str, Any]:
    """Parse one line strictly (UTF-8, one object, no repeated names).

    Raises:
        BadLineError: The line is not that.
    """
    return _decode(line)


def check_end(value: dict[str, Any]) -> Trailer:
    """Check a decoded end line against the schema, as the file reader does.

    The checks are the schema's: exactly the keys ``end``, ``events``, ``sha256`` and
    ``gaps``; ``end`` is ``true``; ``events`` is a whole number; ``sha256`` is 64 lower-case
    hex digits; ``gaps`` is a list of at most 1000 objects with non-empty ``area`` and
    ``reason`` text. Whether the count and hash match the events is for the caller. A list
    of more than 1000 gaps breaks the schema, but it is not refused here: the first 1000
    are kept and the rest are counted in ``unlisted_gaps``, so the event count and the hash
    are still checked and the gaps are not lost.

    Raises:
        BadLineError: The line breaks one of those rules.
    """
    _keys(value, _TRAILER_KEYS, _TRAILER_KEYS)
    gaps = value["gaps"]
    if value["end"] is not True or not isinstance(gaps, list):
        msg = "the end line is not what the schema says"
        raise BadLineError(msg)
    stated = _integer(value["events"], "events", high=2**63 - 1)
    digest = value["sha256"]
    if stated is None or not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        msg = "sha256 is not 64 lower-case hex digits"
        raise BadLineError(msg)
    pairs = []
    for gap in gaps[:MAX_GAPS]:
        if not isinstance(gap, dict):
            msg = "an entry in gaps is not an object"
            raise BadLineError(msg)
        _keys(gap, _GAP_KEYS, _GAP_KEYS)
        pairs.append(
            (
                _string(gap["area"], "gaps.area"),
                _string(gap["reason"], "gaps.reason", limit=4096),
            )
        )
    return Trailer(stated, digest, tuple(pairs), max(len(gaps) - MAX_GAPS, 0))


def is_bundle(start: bytes) -> bool:
    """Whether a file's first bytes are those of a toledot collection."""
    return start.startswith(MARKER)


def read_bundle(path: Path, options: ReadOptions) -> Iterator[Event | Problem | LogFacts]:  # noqa: ARG001
    """Read a collection file written by a toledot collector.

    Args:
        path: The file.
        options: Not used; the file says everything about itself.

    Yields:
        The header's facts about each log, then every event, and a problem for each
        line that breaks the schema, for a missing trailer, and for a trailer whose
        count or hash does not match.

    Raises:
        InputError: The file cannot be opened, or its first line is not a header.
    """
    name = path.name
    try:
        handle = path.open("rb")
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror or exc}"
        raise InputError(msg) from None
    with handle:
        first = handle.readline(MAX_LINE + 1)
        try:
            facts = check_header(first, name)
        except BadLineError as exc:
            msg = f"{name} is not a toledot collection: {exc}"
            raise InputError(msg) from None
        yield from facts
        yield from _lines(handle, name, hashlib.sha256(first))


def _lines(handle: Any, name: str, digest: Any) -> Iterator[Event | Problem]:
    count = 0
    number = 1
    ended = False
    while True:
        line = handle.readline(MAX_LINE + 1)
        if not line:
            break
        number += 1
        source = Source(name, f"line {number}")
        if ended:
            yield Problem(source, "The file continues after its end line.")
            return
        if len(line) > MAX_LINE:
            yield Problem(
                source, f"The line is longer than {MAX_LINE} bytes; the rest is not read."
            )
            return
        try:
            value = _decode(line)
        except BadLineError as exc:
            digest.update(line)
            yield Problem(source, f"The line is not a valid event: {exc}.")
            continue
        if "end" in value:
            ended = True
            try:
                yield from _trailer(value, source, count, digest.hexdigest())
            except BadLineError as exc:
                yield Problem(source, f"The end line is not valid: {exc}.")
            continue
        digest.update(line)
        try:
            event = _event(value, source)
        except BadLineError as exc:
            yield Problem(source, f"The line is not a valid event: {exc}.", _record(value))
            continue
        count += 1
        yield event
    if not ended:
        text = (
            "The file ends without the collector's end line, so it was cut short or the "
            "collection did not finish. Events may be missing."
        )
        yield Problem(Source(name, f"line {number}"), text)


def _record(value: dict[str, Any]) -> int | None:
    number = value.get("record_id")
    return number if isinstance(number, int) and not isinstance(number, bool) else None


def _trailer(value: dict[str, Any], source: Source, count: int, digest: str) -> Iterator[Problem]:
    trailer = check_end(value)
    if trailer.events != count:
        text = (
            f"The end line counts {trailer.events} events but {count} were read. "
            "Events are missing or the file was altered."
        )
        yield Problem(source, text)
    if trailer.sha256 != digest:
        yield Problem(source, "The file's contents do not match the hash in its end line.")
    for area, reason in trailer.gaps:
        yield Problem(source, f"The collector could not read {area}: {reason}")
    if trailer.unlisted_gaps:
        text = (
            f"The end line lists {trailer.unlisted_gaps} more gaps than the {MAX_GAPS} a "
            "collector may write. They are not listed here. Events may be missing."
        )
        yield Problem(source, text)


def format_time(moment: datetime) -> str:
    """Write a time the way a collection file holds it: UTC with seven fraction digits."""
    utc = moment.astimezone(UTC)
    return f"{date_and_time(utc)}.{utc.microsecond:06d}0Z"


def encode(
    header: dict[str, Any], events: list[Event], gaps: list[dict[str, str]] | None = None
) -> bytes:
    """Build a collection file's bytes from a header and events.

    The collectors write this format themselves, in PowerShell. This writer exists
    for the bundled example and for tests, and is the reference for what they emit.

    Args:
        header: The header line's object, whose first key must be ``toledot_events``.
        events: The events, in the order to write them.
        gaps: What could not be read, as ``area`` and ``reason`` pairs.
    """
    lines = [json.dumps(header, ensure_ascii=False, separators=(",", ":"))]
    lines += [
        json.dumps(
            {
                "record_id": event.record_id,
                "event_id": event.event_id,
                "version": event.version,
                "time": format_time(event.time),
                "computer": event.computer,
                "channel": event.channel,
                "provider": event.provider,
                "system": dict(event.system),
                "data": dict(event.data),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        for event in events
    ]
    body = "".join(line + "\n" for line in lines).encode("utf-8")
    trailer = {
        "end": True,
        "events": len(events),
        "sha256": hashlib.sha256(body).hexdigest(),
        "gaps": gaps or [],
    }
    return body + json.dumps(trailer, separators=(",", ":")).encode("utf-8") + b"\n"
