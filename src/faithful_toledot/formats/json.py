# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""Reader for JSON and JSON Lines event exports.

Module name: this is ``faithful_toledot.formats.json``. Imports are absolute, so it does
not shadow the standard library's ``json``; it must never be run as a script from its own
directory, as with any module named like a standard one.

Accepted layouts
----------------
* A JSON array of event objects, or a single event object (``Get-WinEvent ... |
  ConvertTo-Json -Depth 4`` writes an array, or one object when there is one event).
* JSON Lines: one event object per line, blank lines ignored. A file whose first
  non-blank line is a complete JSON object is read as JSON Lines; a file that starts with
  ``[``, or whose first line is only the start of an object, is read as one document.
* UTF-8 with or without a byte order mark, and UTF-16 with a byte order mark.

Two object shapes are accepted, told apart by key. Key spellings are exact and case
sensitive. Unlisted keys (such as ``Message``) are ignored.

**PowerShell record** (an ``EventLogRecord`` serialized by ``ConvertTo-Json``). Present
when the object has ``Properties`` and none of the named-shape keys. Required:
``Id``, ``TimeCreated``, ``MachineName``, ``LogName``, ``ProviderName``, and
``Properties`` (an array). Optional: ``Version`` (0 if absent or null), ``RecordId``,
``Keywords``, ``Level``, ``Task``, ``Opcode``, ``ActivityId``, ``RelatedActivityId``,
``ProcessId``, ``ThreadId``, ``UserId``.

**Named data** (custom exporters). Present when the object has ``EventData`` or ``data``
and no ``Properties``. Exactly one spelling of each of these must be present:
``EventID`` or ``Id``; ``TimeCreated`` or ``SystemTime``; ``Computer`` or
``MachineName``; ``Channel`` or ``LogName``; ``EventData`` or ``data`` (an object of
name to value, or ``null`` for none). Optional, again at most one spelling each:
``Provider`` or ``ProviderName`` (empty text if absent, because this shape often has no
provider); ``Version``; ``RecordId`` or ``EventRecordID``; ``Keywords``; ``Level``;
``Task``; ``Opcode``; ``ActivityId`` or ``ActivityID``; ``RelatedActivityId`` or
``RelatedActivityID``; ``ProcessId`` or ``ProcessID``; ``ThreadId`` or ``ThreadID``;
``UserId`` or ``UserID``.

An object that has two spellings of one field, both ``Properties`` and a named-data key, or
neither shape's keys, is a problem for that record, never a guess. If the very first
record in the file matches neither shape, the file is refused.

Timestamps
----------
``TimeCreated`` and ``SystemTime`` accept three shapes: the Windows PowerShell 5.1 form
``"\/Date(1762740903123)\/"`` (milliseconds since 1970 in UTC; an optional ``+HHMM``
suffix is ignored because the milliseconds are already UTC); an ISO 8601 string, as
PowerShell 7 writes (``2026-11-10T02:15:03.123Z`` or with an offset); and an object
with a ``value`` (or ``Value``) property holding either string, as ``ConvertTo-Json``
writes a ``DateTime`` that carries extra properties. Milliseconds are the finest
precision PowerShell 5.1 keeps; the 100 ns ticks of the original event are lost. An ISO
time with no offset needs ``options.local_offset``, otherwise that record is a problem.

Values and names
----------------
``Properties`` are positional and have no names in the JSON. Names come from
``options.names_for(event_id, version, count)``. If it returns ``None``, the values are
named ``param1``, ``param2`` and so on, and nothing else is added: **field names are
unavailable for that event.** A returned tuple of the wrong length makes the event a
problem. Duplicate names are written ``name#2``, ``name#3``.

Each value is written as the text Windows event XML would show, where JSON keeps enough
to know it:

* A SID object (``BinaryLength``, ``AccountDomainSid``, ``Value``) becomes its ``Value``.
  ``{"Value": x}`` wrappers (``EventProperty``) are removed.
* Numbers are decimal. ``true`` and ``false`` are ``true`` and ``false``. ``null`` is empty.
* ``/Date()/`` strings become ``2026-11-10T02:15:03.1230000Z``.
* An array of whole numbers from 0 to 255 (a ``byte[]``) becomes upper-case hex.
* ``Keywords`` (a signed 64-bit number) becomes ``0x`` hex as in XML. ``ActivityId`` becomes
  an upper-case GUID in braces.

**These values differ from the XML text, and the correlation layer must normalise them.**
JSON does not keep what Windows rendered, only the value. A ``HexInt64`` such as the
logon ID ``0x3e7`` arrives as the number ``999`` and stays ``"999"``; a ``HexInt32``
such as a process ID the same. ``%%1794``-style placeholders are strings and survive. A
PS7 ``DateTime`` property arrives as an ISO string and is kept as that string. A
string-typed property survives exactly. With too little ``-Depth``, PowerShell replaces
nested objects with their ``ToString()`` text, which is kept as is.

Limits
------
A whole-file document must fit in ``MAX_JSON_BYTES``; larger exports are refused with
advice to use JSON Lines or EVTX. JSON Lines streams, with a limit of ``MAX_LINE_CHARS``
per line. Decoding is strict: repeated property names, nesting past ``MAX_DEPTH``, a
whole number of more than ``MAX_INT_DIGITS`` digits, ``NaN``/``Infinity``, and lone
surrogates are rejected. In a record they make that record a problem.

A file-level error (``InputError``) is raised before the first record when the file is
unreadable, is not JSON, or its first record is not an event. Later syntax errors in a
document stop the read with one problem; in JSON Lines a bad line is a problem and the
next line is read. Positions are ``element N``, ``line N`` (JSON Lines), and so on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from json import JSONDecodeError, JSONDecoder
from typing import TYPE_CHECKING, Any

from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, Source
from faithful_toledot.formats._text import (
    MAX_EVENT_CHARS,
    MAX_FIELDS,
    MAX_NAME_CHARS,
    MAX_VALUE_CHARS,
    TimestampError,
    add_data,
    check_options,
    eager,
    iso_utc,
    parse_iso,
    parse_unsigned,
    read_chunks,
    split_lines,
    system_from_export,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator
    from pathlib import Path

    from faithful_toledot.events import ReadOptions

MAX_JSON_BYTES = 256 * 1024 * 1024
"""Largest whole-file JSON document read. It is loaded into memory; use JSON Lines above it."""
MAX_LINE_CHARS = 16 * 1024 * 1024
"""Longest JSON Lines line. A longer one is a problem, and the next line is read."""
MAX_DEPTH = 32
"""Deepest nesting inside one record. A real record, SID objects included, uses 5."""
MAX_INT_DIGITS = 20
"""Most digits in a whole number. A 64-bit value has at most 20."""
_MAX_FLOAT_CHARS = 64
_WHITESPACE = " \t\n\r"
_DATE = re.compile(r"/Date\((-?[0-9]{1,15})(?:[+-][0-9]{4})?\)/", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MISSING = object()
_NAMED_ONLY = frozenset(
    ("EventID", "Computer", "Channel", "SystemTime", "EventData", "data", "Provider")
)


class _Object(dict[str, Any]):
    """A decoded JSON object that remembers whether a property name repeated."""

    repeated: bool = False


@dataclass(frozen=True)
class _Invalid:
    """A value the strict decoder refused, held until its record can be reported."""

    reason: str


@dataclass(frozen=True)
class _Float:
    """A JSON number with a fraction or exponent, kept as written."""

    text: str


class _Reject(Exception):  # noqa: N818 - a signal, not an error type
    """A record cannot be turned into an event; the message says why."""


class _Syntax(Exception):  # noqa: N818 - a signal, not an error type
    """The document's syntax is broken at a point it cannot be read past."""


def _pairs(pairs: list[tuple[str, Any]]) -> _Object:
    result = _Object()
    for key, value in pairs:
        if key in result:
            result.repeated = True
        else:
            result[key] = value
    return result


def _parse_int(text: str) -> int | _Invalid:
    if len(text) > MAX_INT_DIGITS + 1:  # the sign
        return _Invalid(f"a number has more than {MAX_INT_DIGITS} digits")
    return int(text)


def _parse_float(text: str) -> _Float | _Invalid:
    if len(text) > _MAX_FLOAT_CHARS:
        return _Invalid("a number is too long")
    return _Float(text)


def _parse_constant(_name: str) -> _Invalid:
    return _Invalid("NaN and Infinity are not valid JSON numbers")


_DECODER = JSONDecoder(
    object_pairs_hook=_pairs,
    parse_int=_parse_int,
    parse_float=_parse_float,
    parse_constant=_parse_constant,
    strict=True,
)


def read_json(path: Path, options: ReadOptions) -> Iterator[Event | Problem]:
    """Read a JSON or JSON Lines event export. See the module documentation.

    Args:
        path: The file.
        options: Read options. ``names_for`` names ``Properties``; ``local_offset``
            covers an ISO time with no offset.

    Returns:
        An iterator of events and problems in file order. Errors that make the whole file
        unusable are raised by this call, before any record is returned.

    Raises:
        InputError: The file cannot be read, is too large, is not JSON, has no records,
            or its first record is not an event.
    """
    check_options(options)
    return eager(
        _read(path, options),
        empty=f"{path.name} contains no event records; there is nothing to read",
    )


# --- strict scan --------------------------------------------------------------------


def _scan(root: object) -> str | None:
    """Return why a decoded record is unusable, or ``None``. Iterative, so depth is safe."""
    pending: list[tuple[object, int]] = [(root, 0)]
    budget = MAX_EVENT_CHARS
    while pending:
        value, depth = pending.pop()
        reason, cost = _scan_node(value, depth, pending)
        budget -= cost + 1
        if reason is not None:
            return reason
        if budget < 0:
            return f"the record holds more than {MAX_EVENT_CHARS} characters"
    return None


def _scan_node(  # noqa: PLR0911 - one exit per kind of value
    value: object, depth: int, pending: list[tuple[object, int]]
) -> tuple[str | None, int]:
    """Check one value; queue its children. Returns a reason (or ``None``) and its size."""
    if isinstance(value, _Invalid):
        return value.reason, 0
    if isinstance(value, (_Object, list)) and depth >= MAX_DEPTH:
        return f"the record is nested more than {MAX_DEPTH} levels deep", 0
    if isinstance(value, _Object):
        if value.repeated:
            return "an object repeats a property name", 0
        cost = 0
        for key, item in value.items():
            bad = _bad_text(key, MAX_NAME_CHARS)
            if bad:
                return f"a property name {bad}", 0
            cost += len(key)
            pending.append((item, depth + 1))
        return None, cost
    if isinstance(value, list):
        pending.extend((item, depth + 1) for item in value)
    elif isinstance(value, str):
        bad = _bad_text(value, MAX_VALUE_CHARS)
        return (f"a value {bad}" if bad else None), len(value)
    return None, 0


def _bad_text(text: str, limit: int) -> str | None:
    if len(text) > limit:
        return f"is longer than {limit} characters"
    if not text.isascii():
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            return "contains an unpaired surrogate, which is not valid Unicode"
    return None


# --- converting a record ------------------------------------------------------------


def _one(obj: dict[str, Any], *names: str) -> object:
    """Return the value under whichever of ``names`` is present, or ``_MISSING``."""
    present = [name for name in names if name in obj]
    if len(present) > 1:
        msg = f"it has both {present[0]!r} and {present[1]!r}, which is ambiguous"
        raise _Reject(msg)
    return obj[present[0]] if present else _MISSING


def _required(obj: dict[str, Any], *names: str) -> object:
    value = _one(obj, *names)
    if value is _MISSING:
        msg = f"it lacks {' or '.join(repr(n) for n in names)}"
        raise _Reject(msg)
    return value


def _text_value(value: object, label: str) -> str:
    """A string field. Anything but a non-empty string is refused."""
    if not isinstance(value, str) or not value:
        msg = f"{label} must be a non-empty string"
        raise _Reject(msg)
    return value


def _whole(value: object, maximum: int, label: str) -> int:
    """A whole number given as a JSON number or as digits in a string."""
    if type(value) is int and 0 <= value <= maximum:
        return value
    if isinstance(value, str):
        parsed = parse_unsigned(value, maximum)
        if parsed is not None:
            return parsed
    msg = f"{label} must be a whole number from 0 to {maximum}"
    raise _Reject(msg)


def _moment(value: object, options: ReadOptions) -> datetime:
    if isinstance(value, _Object):
        inner = _one(value, "value", "Value")
        if inner is _MISSING:
            msg = "the time is an object with no 'value'"
            raise _Reject(msg)
        value = inner
    if not isinstance(value, str):
        msg = "the time must be a string"
        raise _Reject(msg)
    match = _DATE.fullmatch(value)
    try:
        if match is not None:
            return _EPOCH + timedelta(milliseconds=int(match.group(1)))
        return parse_iso(value.strip(), local_offset=options.local_offset)
    except OverflowError:
        msg = "the time is out of range"
        raise _Reject(msg) from None
    except TimestampError as exc:
        msg = f"the time cannot be used: {exc}"
        raise _Reject(msg) from None


def _render(value: object) -> str:  # noqa: PLR0911 - one exit per kind of value
    """Write one property value as the text Windows event XML would show, where known."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, _Float):
        return value.text
    if isinstance(value, str):
        return _render_string(value)
    if isinstance(value, list):
        return _render_bytes(value)
    if isinstance(value, _Object):  # pragma: no branch - the decoder makes no other type
        inner = value.get("Value", _MISSING)
        if isinstance(inner, str) and value.keys() <= {"Value", "BinaryLength", "AccountDomainSid"}:
            return inner  # a SID
        if value.keys() == {"Value"}:
            return _render(inner)
    msg = "a property has a value of a kind that is not supported"
    raise _Reject(msg)


def _render_string(value: str) -> str:
    match = _DATE.fullmatch(value)
    if match is None:
        return value
    try:
        return iso_utc(_EPOCH + timedelta(milliseconds=int(match.group(1))))
    except OverflowError:
        msg = "a property is a date out of range"
        raise _Reject(msg) from None


def _render_bytes(value: list[object]) -> str:
    numbers = [item for item in value if type(item) is int and 0 <= item <= 255]  # noqa: PLR2004 - fixed limits of the format
    if len(numbers) == len(value):
        return "".join(f"{number:02X}" for number in numbers)
    msg = "a property is an array that is not a byte array"
    raise _Reject(msg)


def _user_id(value: object) -> str:
    if isinstance(value, _Object):
        value = value.get("Value")
    if value is None or value is _MISSING:
        return ""
    if not isinstance(value, str):
        msg = "UserId must be a SID string or an object with a 'Value'"
        raise _Reject(msg)
    return value


def _plain(value: object, label: str) -> str:
    """Text for a ``System`` value: a number, a string, or null (nothing)."""
    if value is None or value is _MISSING:
        return ""
    if type(value) is int:
        return str(value)
    if isinstance(value, str):
        return value
    msg = f"{label} must be a number or a string"
    raise _Reject(msg)


_SYSTEM_SPELLINGS = (
    ("Keywords", ("Keywords",)),
    ("Level", ("Level",)),
    ("Task", ("Task",)),
    ("Opcode", ("Opcode",)),
    ("ActivityID", ("ActivityId", "ActivityID")),
    ("RelatedActivityID", ("RelatedActivityId", "RelatedActivityID")),
    ("ProcessID", ("ProcessId", "ProcessID")),
    ("ThreadID", ("ThreadId", "ThreadID")),
    ("UserID", ("UserId", "UserID")),
)


def _system(obj: dict[str, Any]) -> dict[str, str]:
    raw: dict[str, str] = {}
    for key, spellings in _SYSTEM_SPELLINGS:
        value = _one(obj, *spellings)
        raw[key] = _user_id(value) if key == "UserID" else _plain(value, key)
    try:
        return system_from_export(raw)
    except ValueError as exc:
        raise _Reject(str(exc)) from None


def _record_id(obj: dict[str, Any], *spellings: str) -> int | None:
    value = _one(obj, *spellings)
    if value is _MISSING or value is None:
        return None
    return _whole(value, (1 << 64) - 1, "RecordId")


def _safe_record_id(obj: dict[str, Any]) -> int | None:
    """The record number for a problem report, or ``None`` if it cannot be read."""
    for name in ("RecordId", "EventRecordID"):
        value = obj.get(name)
        if type(value) is int and 0 <= value < 1 << 64:
            return value
    return None


def _powershell(obj: dict[str, Any], source: Source, options: ReadOptions) -> Event:
    if _NAMED_ONLY & obj.keys():
        msg = "it has Properties and also keys of the named-data shape, which is ambiguous"
        raise _Reject(msg)
    event_id = _whole(_required(obj, "Id"), 65535, "Id")
    moment = _moment(_required(obj, "TimeCreated"), options)
    computer = _text_value(_required(obj, "MachineName"), "MachineName")
    channel = _text_value(_required(obj, "LogName"), "LogName")
    provider = _text_value(_required(obj, "ProviderName"), "ProviderName")
    properties = obj["Properties"]
    if not isinstance(properties, list):
        msg = "Properties must be an array"
        raise _Reject(msg)
    version_value = obj.get("Version")
    version = 0 if version_value is None else _whole(version_value, 255, "Version")
    values = [_render(item.get("Value") if _is_wrapper(item) else item) for item in properties]
    return Event(
        event_id=event_id,
        time=moment,
        computer=computer,
        channel=channel,
        provider=provider,
        record_id=_record_id(obj, "RecordId"),
        data=_positional(values, event_id, version, options),
        source=source,
        version=version,
        system=_system(obj),
    )


def _is_wrapper(item: object) -> bool:
    return isinstance(item, _Object) and item.keys() == {"Value"}


def _positional(
    values: list[str], event_id: int, version: int, options: ReadOptions
) -> dict[str, str]:
    """Name positional values with ``options.names_for``, or ``param1``... if it knows none."""
    if len(values) > MAX_FIELDS:
        msg = f"it has more than {MAX_FIELDS} properties"
        raise _Reject(msg)
    names = options.names_for(event_id, version, len(values)) if values else None
    if names is None:
        names = tuple(f"param{index}" for index in range(1, len(values) + 1))
    elif len(names) != len(values):
        msg = f"names_for gave {len(names)} names for {len(values)} properties"
        raise _Reject(msg)
    data: dict[str, str] = {}
    counts: dict[str, int] = {}
    for name, value in zip(names, values, strict=True):
        if not name or len(name) > MAX_NAME_CHARS:
            msg = "names_for gave a name that is not usable"
            raise _Reject(msg)
        add_data(data, counts, name, value)
    return data


def _named(obj: dict[str, Any], source: Source, options: ReadOptions) -> Event:
    event_id = _whole(_required(obj, "EventID", "Id"), 65535, "the event ID")
    moment = _moment(_required(obj, "TimeCreated", "SystemTime"), options)
    computer = _text_value(_required(obj, "Computer", "MachineName"), "the computer")
    channel = _text_value(_required(obj, "Channel", "LogName"), "the channel")
    provider_value = _one(obj, "Provider", "ProviderName")
    provider = "" if provider_value is _MISSING else _text_value(provider_value, "the provider")
    raw = _required(obj, "EventData", "data")
    if raw is None:
        raw = _Object()
    if not isinstance(raw, _Object):
        msg = "EventData must be an object of names and values"
        raise _Reject(msg)
    if len(raw) > MAX_FIELDS:
        msg = f"it has more than {MAX_FIELDS} data fields"
        raise _Reject(msg)
    data: dict[str, str] = {}
    counts: dict[str, int] = {}
    for name, value in raw.items():
        if not name:
            msg = "EventData has an empty name"
            raise _Reject(msg)
        add_data(data, counts, name, _render(value))
    version_value = obj.get("Version")
    version = 0 if version_value is None else _whole(version_value, 255, "Version")
    return Event(
        event_id=event_id,
        time=moment,
        computer=computer,
        channel=channel,
        provider=provider,
        record_id=_record_id(obj, "RecordId", "EventRecordID"),
        data=data,
        source=source,
        version=version,
        system=_system(obj),
    )


def _convert(  # noqa: PLR0911 - one exit per kind of value
    value: object, name: str, position: str, options: ReadOptions, *, first: bool
) -> Event | Problem:
    """Turn one decoded record into an event or a problem.

    Only the first record of a file may refuse the whole file: if it is not an event of
    either shape, the file is not an event export.
    """
    source = Source(name, position)
    if not isinstance(value, _Object):
        return _unusable(name, source, "the record is not a JSON object", first=first)
    reason = _scan(value)
    if reason is not None:
        return Problem(source, reason)
    has_properties = "Properties" in value
    has_named = "EventData" in value or "data" in value
    if has_properties and has_named:
        return Problem(source, "it has both Properties and EventData or data, which is ambiguous")
    if not has_properties and not has_named:
        return _unusable(
            name, source, "it has neither Properties nor EventData or data", first=first
        )
    try:
        if has_properties:
            return _powershell(value, source, options)
        return _named(value, source, options)
    except _Reject as exc:
        return Problem(source, str(exc), _safe_record_id(value))


def _unusable(name: str, source: Source, reason: str, *, first: bool) -> Problem:
    if first:
        msg = f"{name} is not a Windows event export: the first record fails: {reason}"
        raise InputError(msg)
    return Problem(source, reason)


# --- reading the file ---------------------------------------------------------------


def _skip(text: str, index: int) -> int:
    while index < len(text) and text[index] in _WHITESPACE:
        index += 1
    return index


def _decode_at(text: str, index: int) -> tuple[object, int]:
    try:
        return _DECODER.raw_decode(text, index)
    except JSONDecodeError as exc:
        msg = f"{exc.msg} at line {exc.lineno}, column {exc.colno}"
        raise _Syntax(msg) from None
    except RecursionError:
        msg = "the JSON is nested too deeply"
        raise _Syntax(msg) from None


def _document_values(text: str) -> Iterator[tuple[str, object]]:
    """Yield ``(position, value)`` for each record of a whole-file document."""
    index = _skip(text, 0)
    if text[index : index + 1] == "{":
        value, end = _decode_at(text, index)
        if _skip(text, end) != len(text):
            msg = (
                "there is more after the object. For several events, use a JSON array "
                "or JSON Lines (one object per line)"
            )
            raise _Syntax(msg)
        yield "element 1", value
        return
    index = _skip(text, index + 1)  # past "["
    number = 0
    if text[index : index + 1] == "]":
        index += 1
    else:
        while True:
            number += 1
            value, index = _decode_at(text, index)
            yield f"element {number}", value
            index = _skip(text, index)
            separator = text[index : index + 1]
            index += 1
            if separator == "]":
                break
            if separator != ",":
                msg = "expected a comma or ] after an element"
                raise _Syntax(msg)
            index = _skip(text, index)
    if _skip(text, index) != len(text):
        msg = "there is more after the array. A JSON Lines file has one object per line"
        raise _Syntax(msg)


def _first_line(path: Path) -> str | None:
    """Return the first non-blank line (``None`` if there is none or it is over the limit)."""
    lines = split_lines(read_chunks(path), max_chars=MAX_LINE_CHARS, keepends=False)
    try:
        for _number, line in lines:
            if line is None:
                return None
            if line.strip(_WHITESPACE):
                return line
        return ""
    finally:
        lines.close()


def _is_lines(first: str) -> bool:
    """Whether the first line is a complete JSON object, so the file is JSON Lines."""
    index = _skip(first, 0)
    try:
        _value, end = _DECODER.raw_decode(first, index)
    except (JSONDecodeError, RecursionError):
        return False
    return _skip(first, end) == len(first)


def _load(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        msg = f"cannot read {path.name}: {exc.strerror or exc}"
        raise InputError(msg) from None
    too_big = (
        f"{path.name} is larger than {MAX_JSON_BYTES} bytes and a JSON document must be "
        "loaded whole; export JSON Lines (one event per line) or use the EVTX file instead"
    )
    if size > MAX_JSON_BYTES:
        raise InputError(too_big)
    return "".join(read_chunks(path))


def _read(path: Path, options: ReadOptions) -> Generator[Event | Problem, None, None]:
    name = path.name
    first_line = _first_line(path)
    if first_line == "":
        return  # nothing but whitespace: no records
    if first_line is not None and not first_line.lstrip(_WHITESPACE).startswith(("[", "{")):
        msg = f"{name} is not a Windows event export: it does not start with [ or {{"
        raise InputError(msg)
    if (
        first_line is not None
        and first_line.lstrip(_WHITESPACE).startswith("{")
        and _is_lines(first_line)
    ):
        yield from _read_lines(path, options)
    else:
        yield from _read_document(path, options)


def _read_document(path: Path, options: ReadOptions) -> Iterator[Event | Problem]:
    name = path.name
    text = _load(path)
    if text[_skip(text, 0)] not in "[{":
        msg = f"{name} is not a Windows event export: it does not start with [ or {{"
        raise InputError(msg)
    produced = 0
    values = _document_values(text)
    while True:
        try:
            position, value = next(values)
        except StopIteration:
            return
        except _Syntax as exc:
            if produced == 0:
                msg = f"{name} is not valid JSON: {exc}"
                raise InputError(msg) from None
            yield Problem(
                Source(name, f"after element {produced}"),
                f"the JSON is not valid ({exc}); the rest of the file was not read",
            )
            return
        yield _convert(value, name, position, options, first=produced == 0)
        produced += 1


def _line_value(line: str) -> object:
    """Decode a JSON Lines line, which must hold exactly one value."""
    value, end = _decode_at(line, _skip(line, 0))
    if _skip(line, end) != len(line):
        msg = "there is more than one JSON value on the line"
        raise _Syntax(msg)
    return value


def _read_lines(path: Path, options: ReadOptions) -> Iterator[Event | Problem]:
    """Read JSON Lines. The first non-blank line was already checked to be a whole object."""
    name = path.name
    produced = 0
    last = 0
    lines = split_lines(read_chunks(path), max_chars=MAX_LINE_CHARS, keepends=False)
    try:
        while True:
            try:
                number, line = next(lines)
            except StopIteration:
                return
            except InputError as exc:
                yield Problem(
                    Source(name, f"after line {last}"),
                    f"{exc}; the rest of the file was not read",
                )
                return
            last = number
            position = f"line {number}"
            if line is not None and not line.strip(_WHITESPACE):
                continue
            if line is None:
                item: Event | Problem = Problem(
                    Source(name, position), f"the line is longer than {MAX_LINE_CHARS} characters"
                )
            else:
                try:
                    item = _convert(_line_value(line), name, position, options, first=produced == 0)
                except _Syntax as exc:
                    item = Problem(Source(name, position), f"the line is not valid JSON ({exc})")
            produced += 1
            yield item
    finally:
        lines.close()
