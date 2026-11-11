# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""Reader for CSV exports that keep the rendered English message, not the fields.

Module name: this is ``faithful_toledot.formats.csv``. Imports are absolute, so it does
not shadow the standard library's ``csv``; never run it as a script from its own
directory.

Two layouts are accepted, told apart by the header row. Header names are English and
exact; an export from a machine with another display language is refused with a message
that says so.

**``Get-WinEvent ... | Export-Csv``**: the header must have ``Message``, ``Id``,
``ProviderName``, ``LogName``, ``MachineName`` and ``TimeCreated``. ``Version``,
``RecordId``, ``Level``, ``Task``, ``Opcode``, ``Keywords``, ``ActivityId``,
``RelatedActivityId``, ``ProcessId``, ``ThreadId``, ``UserId``, ``LevelDisplayName`` and
``TaskDisplayName`` are used when present. A first line starting ``#TYPE`` (Windows
PowerShell 5.1 writes one) is skipped. Other columns are ignored.

**Event Viewer, "Save All Events As... CSV"**: the header is ``Level``, ``Date and
Time``, ``Source``, ``Event ID``, ``Task Category``, then optionally one unnamed column;
each row has those five fields followed by the message as a sixth. This layout has no
computer name, channel, or record number: ``computer`` and ``channel`` are empty text and
``record_id`` is ``None``. ``provider`` is the ``Source`` column, which is the provider's
display text (for example ``Microsoft Windows security auditing.``), not the provider
name that XML carries; the correlation layer must normalise it. ``Level`` and ``Task
Category`` are kept as text in ``system`` under ``LevelDisplayName`` and
``TaskDisplayName``.

Fields are recovered from the message
-------------------------------------
Windows security messages look like this (tabs shown as ``->``)::

    A user account was created.

    Subject:
    ->Security ID:->->S-1-5-21-...
    ->Account Name:->->admin

    New Account:
    ->Security ID:->->S-1-5-21-...

The rules, applied line by line:

* A line with no indentation that ends in ``:`` starts a *section* (``Subject``). Any other
  unindented line (the opening sentence, the explanatory paragraph that follows some
  events) is free text and is ignored.
* An indented line is a field: the label is the text before the first ``:`` (or, if a tab
  comes first, before that tab), and the value is the rest with the separating tabs and
  spaces removed. Trailing text is kept exactly.
* The key is ``Section/Label`` (``Subject/Security ID``). The same label in two sections
  is two fields. ``options.labels_for(event_id)`` maps that key to the field name used in
  event XML. **A key it has no mapping for is kept under the ``Section/Label`` text**, so
  nothing is lost; if ``labels_for`` returns ``None`` every key is kept that way.
  A repeated name becomes ``name#2``, ``name#3``.
* **Multi-line values**: a line indented deeper than the section's field lines, directly
  after a field with no blank line between, continues that field. Its text, with
  indentation removed, is joined to the value with ``\n``. So ``Privileges:`` followed by
  one privilege per line is one value, one privilege per line, and a ``User Account
  Control:`` label with no value followed by indented flag names has those names as its
  value. Windows XML writes such values with ``\r\n`` and tabs; the correlation layer
  must normalise whitespace. A blank line ends any continuation.
* A message with no field lines at all (for example because tabs were lost in the export
  or the provider's message file was missing) is a problem for that row, as is an
  indented line that is neither a field nor a continuation.

Times
-----
An ISO 8601 time with an offset is used as it is. The two layouts normally write local
times with no offset, such as ``11/10/2026 8:15:03 PM``; the English 12 hour and a 24 hour
form with ``/`` or ``.`` between day, month, and year are read. Without an offset the time
is ambiguous, so ``options.local_offset`` is required, and for a date whose first two
numbers are both 12 or less and differ, ``options.day_first`` is required. When a needed
option is missing the read stops with an :class:`InputError` that says which option to
pass or how to re-export. **A fixed offset is wrong across a daylight saving change**: if
the export spans one, re-export with ISO 8601 times (``$_.TimeCreated.ToString('o')``).
Seconds are kept; Windows' PowerShell CSV export drops fractions of a second.

Limits
------
A field is at most ``MAX_FIELD_CHARS`` characters (the ``csv`` module's own default, and
this module checks it as well), a physical line at most ``MAX_LINE_CHARS``, a header
``MAX_COLUMNS`` columns, and a message ``MAX_MESSAGE_LINES`` lines and ``MAX_FIELDS``
fields. NUL characters are refused. A duplicate header name is an :class:`InputError`. The
reader makes one pass and never rescans.

File errors and problems
------------------------
Before the first row, an unreadable or empty file, an unknown header, or a repeated
header name raises :class:`InputError`. A bad row (wrong number of fields, an unreadable
ID or time, a message that cannot be parsed) is a problem and the next row is read.
Broken CSV quoting, an over-long line or field, or invalid text stops the read with one
problem, because the rows after it cannot be told apart. Positions are ``row N (line L)``
with ``N`` counting data rows from 1 and ``L`` the line the row starts on.
"""

from __future__ import annotations

import csv
import re
from typing import TYPE_CHECKING

from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, Source
from faithful_toledot.formats._text import (
    MAX_FIELDS,
    MAX_NAME_CHARS,
    AmbiguousDateError,
    NaiveTimestampError,
    TimestampError,
    add_data,
    check_options,
    eager,
    parse_timestamp,
    parse_unsigned,
    read_chunks,
    split_lines,
    system_from_export,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator, Mapping
    from datetime import datetime
    from pathlib import Path

    from faithful_toledot.events import ReadOptions

MAX_COLUMNS = 256
"""Most columns in the header. Get-WinEvent writes about 27."""
MAX_FIELD_CHARS = 131072
"""Longest field. This is also the ``csv`` module's default limit."""
MAX_LINE_CHARS = 4 << 20
"""Longest physical line. A message is many short lines; one very long line is not real."""
MAX_MESSAGE_LINES = 4096
"""Most lines in one message. Real messages have under 100."""

_POWERSHELL_REQUIRED = ("Message", "Id", "ProviderName", "LogName", "MachineName", "TimeCreated")
_VIEWER_HEADER = ("Level", "Date and Time", "Source", "Event ID", "Task Category")
_EXPORT_NAMES = (
    ("Keywords", "Keywords"),
    ("Level", "Level"),
    ("Task", "Task"),
    ("Opcode", "Opcode"),
    ("ActivityID", "ActivityId"),
    ("RelatedActivityID", "RelatedActivityId"),
    ("ProcessID", "ProcessId"),
    ("ThreadID", "ThreadId"),
    ("UserID", "UserId"),
)
_NEWLINE = re.compile(r"\r\n|\r|\n")
_MAX_RECORD_ID = (1 << 64) - 1


def read_csv(path: Path, options: ReadOptions) -> Iterator[Event | Problem]:
    """Read a ``Get-WinEvent | Export-Csv`` or Event Viewer CSV export.

    Args:
        path: The CSV file.
        options: Read options. ``labels_for`` names the fields recovered from messages;
            ``local_offset`` and ``day_first`` interpret times that have no offset.

    Returns:
        An iterator of events and problems in file order. Header errors are raised by
        this call, before any row is returned.

    Raises:
        InputError: The file cannot be read, has an unknown or repeated header, holds no
            rows, or has times that need ``local_offset`` or ``day_first``.
    """
    check_options(options)
    return eager(
        _read(path, options),
        empty=f"{path.name} contains a header but no event rows; there is nothing to read",
    )


class _OptionError(InputError):
    """The file needs ``local_offset`` or ``day_first``; this is never downgraded to a problem."""


class _RowError(Exception):
    """A row cannot be turned into an event; the message says why."""


class _LineTooLong(Exception):  # noqa: N818 - a signal, not an error type
    """A physical line is over the limit."""


class _Feed:
    """The file's lines for ``csv.reader``, counting how many it has handed over."""

    def __init__(self, lines: Iterator[tuple[int, str | None]]) -> None:
        self._lines = lines
        self.consumed = 0

    def __iter__(self) -> _Feed:
        return self

    def __next__(self) -> str:
        number, line = next(self._lines)
        self.consumed = number
        if line is None:
            msg = f"line {number} is longer than {MAX_LINE_CHARS} characters"
            raise _LineTooLong(msg)
        if number == 1 and line.startswith("#TYPE"):
            return self.__next__()
        return line


def _header(reader: Iterator[list[str]], name: str) -> list[str]:
    for row in reader:
        if row:
            return row
    msg = f"{name} has no header row"
    raise InputError(msg)


def _read(path: Path, options: ReadOptions) -> Generator[Event | Problem, None, None]:
    name = path.name
    chunks = read_chunks(path)
    lines = split_lines(chunks, max_chars=MAX_LINE_CHARS, keepends=True)
    feed = _Feed(lines)
    reader = csv.reader(feed, strict=True)
    produced = 0
    try:
        layout = _layout(_header(reader, name), name)
        converter = _Converter(name, options, layout)
        number = 0
        while True:
            start = feed.consumed + 1
            row = next(reader)
            if not row:
                continue  # a blank line
            number += 1
            position = f"row {number} (line {start})"
            yield converter.convert(row, position)
            produced += 1
    except StopIteration:
        return
    except _OptionError:
        raise
    except (InputError, csv.Error, _LineTooLong) as exc:
        reason = str(exc)
        if produced == 0:
            if isinstance(exc, InputError):
                raise
            msg = f"{name} is not readable CSV: {reason}"
            raise InputError(msg) from None
        yield Problem(
            Source(name, f"after row {produced}"),
            f"the file stopped being readable ({reason}); the rest of the file was not read",
        )
    finally:
        lines.close()
        chunks.close()


class _Layout:
    """Which columns hold what."""

    def __init__(self, kind: str, width: int, columns: dict[str, int]) -> None:
        self.kind = kind  # "powershell" or "viewer"
        self.width = width
        self.columns = columns


def _layout(header: list[str], name: str) -> _Layout:
    if len(header) > MAX_COLUMNS:
        msg = f"{name} has more than {MAX_COLUMNS} columns"
        raise InputError(msg)
    seen: set[str] = set()
    for column in header:
        if column in seen:
            msg = f"{name} has the column name {column[:MAX_NAME_CHARS]!r} more than once"
            raise InputError(msg)
        seen.add(column)
    columns = {column: index for index, column in enumerate(header)}
    if tuple(header) in {_VIEWER_HEADER, (*_VIEWER_HEADER, "")}:
        return _Layout("viewer", len(_VIEWER_HEADER) + 1, columns)
    if all(column in columns for column in _POWERSHELL_REQUIRED):
        return _Layout("powershell", len(header), columns)
    msg = (
        f"{name} does not have a header toledot knows. Expected Get-WinEvent columns "
        f"({', '.join(_POWERSHELL_REQUIRED)}) or the Event Viewer columns "
        f"({', '.join(_VIEWER_HEADER)}). Only English headers are read; re-export "
        "with Get-WinEvent | Export-Csv, or from Event Viewer set to English"
    )
    raise InputError(msg)


class _Converter:
    """Turns rows into events for one file."""

    def __init__(self, name: str, options: ReadOptions, layout: _Layout) -> None:
        self.name = name
        self.options = options
        self.layout = layout
        self._labels: dict[int, Mapping[str, str] | None] = {}

    def convert(self, row: list[str], position: str) -> Event | Problem:
        """Turn one row into an event, or say why it cannot be."""
        source = Source(self.name, position)
        record_id: int | None = None
        try:
            if len(row) != self.layout.width:
                msg = f"the row has {len(row)} fields but the header has {self.layout.width}"
                raise _RowError(msg)  # noqa: TRY301 - handled just below
            if any(len(field) > MAX_FIELD_CHARS for field in row):
                msg = f"a field is longer than {MAX_FIELD_CHARS} characters"
                raise _RowError(msg)  # noqa: TRY301 - handled just below
            if self.layout.kind == "viewer":
                return self._viewer(row, source)
            record_id = self._record_id(row)
            return self._powershell(row, source, record_id)
        except _RowError as exc:
            return Problem(source, str(exc), record_id)

    # --- the two layouts -----------------------------------------------------------

    def _viewer(self, row: list[str], source: Source) -> Event:
        level, stamp, provider, event_id_text, category, message = row
        event_id = _event_id(event_id_text)
        moment = self._time(stamp)
        system = {"LevelDisplayName": level, "TaskDisplayName": category}
        return Event(
            event_id=event_id,
            time=moment,
            computer="",
            channel="",
            provider=provider,
            record_id=None,
            data=self._fields(message, event_id),
            source=source,
            version=0,
            system={key: value for key, value in system.items() if value},
        )

    def _powershell(self, row: list[str], source: Source, record_id: int | None) -> Event:
        columns = self.layout.columns

        def cell(column: str) -> str:
            index = columns.get(column)
            return row[index] if index is not None else ""

        for column in ("ProviderName", "LogName", "MachineName"):
            if not cell(column):
                msg = f"the {column} column is empty"
                raise _RowError(msg)
        if cell("RecordId") and record_id is None:
            msg = "RecordId is not a whole number"
            raise _RowError(msg)
        event_id = _event_id(cell("Id"))
        moment = self._time(cell("TimeCreated"))
        version = 0
        if cell("Version"):
            parsed = parse_unsigned(cell("Version"), 255)
            if parsed is None:
                msg = "Version is not a whole number from 0 to 255"
                raise _RowError(msg)
            version = parsed
        try:
            system = system_from_export({key: cell(column) for key, column in _EXPORT_NAMES})
        except ValueError as exc:
            raise _RowError(str(exc)) from None
        for key in ("LevelDisplayName", "TaskDisplayName"):
            if cell(key):
                system[key] = cell(key)
        return Event(
            event_id=event_id,
            time=moment,
            computer=cell("MachineName"),
            channel=cell("LogName"),
            provider=cell("ProviderName"),
            record_id=record_id,
            data=self._fields(cell("Message"), event_id),
            source=source,
            version=version,
            system=system,
        )

    def _record_id(self, row: list[str]) -> int | None:
        index = self.layout.columns.get("RecordId")
        text = row[index] if index is not None and index < len(row) else ""
        if not text:
            return None
        return parse_unsigned(text, _MAX_RECORD_ID)

    # --- values --------------------------------------------------------------------

    def _time(self, text: str) -> datetime:
        options = self.options
        try:
            return parse_timestamp(
                text.strip(),
                local_offset=options.local_offset,
                day_first=options.day_first,
                allow_clock=True,
            )
        except NaiveTimestampError:
            msg = (
                f"{self.name} has times with no UTC offset, such as {text.strip()[:40]!r}. "
                "Pass the UTC offset those local times use (the local_offset option, for "
                "example -05:00; note that one fixed offset is wrong across a daylight "
                "saving change), or re-export with ISO 8601 times that carry an offset, "
                "for example $_.TimeCreated.ToString('o')"
            )
            raise _OptionError(msg) from None
        except AmbiguousDateError:
            msg = (
                f"{self.name} has dates such as {text.strip()[:40]!r} where the day and "
                "month could be either way round. Pass the day_first option (true if "
                "the day comes first, as in 10/11/2026 for 10 November), or re-export "
                "with ISO 8601 times"
            )
            raise _OptionError(msg) from None
        except TimestampError as exc:
            msg = f"the time cannot be used: {exc}"
            raise _RowError(msg) from None

    def _fields(self, message: str, event_id: int) -> dict[str, str]:
        if event_id not in self._labels:
            self._labels[event_id] = self.options.labels_for(event_id)
        return _parse_message(message, self._labels[event_id])


def _event_id(text: str) -> int:
    event_id = parse_unsigned(text, 65535)
    if event_id is None:
        msg = "the event ID is not a whole number from 0 to 65535"
        raise _RowError(msg)
    return event_id


def _split_field(body: str) -> tuple[str, str] | None:
    """Split an indented line into label and value, or ``None`` if it has neither."""
    colon = body.find(":")
    tab = body.find("\t")
    if colon >= 0 and (tab < 0 or colon < tab):
        label, value = body[:colon], body[colon + 1 :].lstrip(" \t")
    elif tab >= 0:
        label, value = body[:tab], body[tab:].lstrip("\t")
    else:
        return None
    label = label.strip()
    return (label, value) if label else None


def _parse_message(message: str, labels: Mapping[str, str] | None) -> dict[str, str]:
    """Recover ``Section/Label`` fields from a rendered message. See the module documentation."""
    lines = _NEWLINE.split(message)
    if len(lines) > MAX_MESSAGE_LINES:
        msg = f"the message has more than {MAX_MESSAGE_LINES} lines"
        raise _RowError(msg)
    fields: list[tuple[str, list[str]]] = []
    section = ""
    field_indent = 0
    open_field = False  # whether the previous line was a field, so a deeper line continues it
    for line in lines:
        body = line.lstrip(" \t")
        if not body:
            open_field = False
            continue
        indent = len(line) - len(body)
        if indent == 0:
            open_field = False
            if body.endswith(":"):
                section = body[:-1].strip()
                field_indent = 0
            continue  # a section header, or free text
        if open_field and indent > field_indent:
            fields[-1][1].append(body)
            continue
        split = _split_field(body)
        if split is None:
            msg = "the message has an indented line that is not 'Label: value'"
            raise _RowError(msg)
        field_indent = field_indent or indent
        label, value = split
        fields.append((f"{section}/{label}" if section else label, [value]))
        open_field = True
    if not fields:
        msg = (
            "the message has no 'Label: value' lines; the export may have lost its tabs "
            "or the message text may be missing"
        )
        raise _RowError(msg)
    if len(fields) > MAX_FIELDS:
        msg = f"the message has more than {MAX_FIELDS} fields"
        raise _RowError(msg)
    return _name_fields(fields, labels)


def _name_fields(
    fields: list[tuple[str, list[str]]], labels: Mapping[str, str] | None
) -> dict[str, str]:
    """Join continuation lines and name each field through ``labels`` if it has a mapping."""
    data: dict[str, str] = {}
    counts: dict[str, int] = {}
    for key, parts in fields:
        values = parts if parts[0] else parts[1:]
        name = key if labels is None else labels.get(key, key)
        add_data(data, counts, name, "\n".join(values))
    return data
