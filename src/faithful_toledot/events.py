# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The one shape every input format is read into.

A reader turns a file into a stream of :class:`Event` and :class:`Problem` items.
Nothing after the readers knows which format an event came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping
    from datetime import datetime, timedelta
    from pathlib import Path
    from typing import Protocol

    class Reader(Protocol):
        """A function that reads one input file."""

        def __call__(
            self, path: Path, options: ReadOptions
        ) -> Iterator[Event | Problem | LogFacts]:
            """Yield every record in file order: an event, or why it could not be read."""
            ...


@dataclass(frozen=True)
class Source:
    """Where an event or a problem came from.

    Attributes:
        file: The input file's name as the user gave it.
        position: A place a person can find, such as ``record 4120`` or ``line 12``.
    """

    file: str
    position: str

    def __str__(self) -> str:
        """Return the file and position as one phrase."""
        return f"{self.file}, {self.position}"


@dataclass(frozen=True)
class Event:
    """One Windows event, as recorded.

    Values are kept as the text Windows writes in the event's XML, without
    interpretation: ``%%1794`` stays ``%%1794``, a SID stays a SID, and an empty
    field is an empty string. Meaning is added later, in one place.

    Attributes:
        event_id: The event identifier, such as ``4728``.
        time: When the event was recorded, timezone-aware, in UTC.
        computer: The computer that recorded it, as written.
        channel: The log, such as ``Security``.
        provider: The provider name, such as ``Microsoft-Windows-Security-Auditing``.
        record_id: The log's record number, or ``None`` if the export lost it.
        version: The event's schema version.
        data: The named ``EventData`` (or ``UserData``) fields, in order.
        system: Other ``System`` fields that were present, by element name, such as
            ``Keywords``, ``Level``, ``Task``, ``Opcode``, and ``ActivityID``.
        source: Where the event came from.
    """

    event_id: int
    time: datetime
    computer: str
    channel: str
    provider: str
    record_id: int | None
    data: Mapping[str, str]
    source: Source
    version: int = 0
    system: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Problem:
    """A record, or part of a file, that could not be read.

    A problem never stops the reading of the rest of the file. It is reported, so a
    reader of the narrative knows what is missing from it.

    Attributes:
        source: Where the unreadable record is.
        reason: A sentence saying what is wrong, without any of the record's content
            beyond what is needed to find it.
        record_id: The record number, when it could still be read.
    """

    source: Source
    reason: str
    record_id: int | None = None


@dataclass(frozen=True)
class LogFacts:
    """What a collector recorded about a log at the moment it read it.

    Only toledot's own collectors write these. They let the account say when a log
    no longer reached back as far as the collection asked for.

    Attributes:
        computer: The computer the log is on.
        channel: The log.
        source: Where the facts were read from.
        oldest_time: The time of the oldest record still in the log.
        oldest_record: Its record number.
        newest_record: The record number of the newest record.
        asked_since: The start of the period the collection asked for, if it had one.
        filtered: Whether the collection kept chosen events only.
    """

    computer: str
    channel: str
    source: Source
    oldest_time: datetime | None = None
    oldest_record: int | None = None
    newest_record: int | None = None
    asked_since: datetime | None = None
    filtered: bool = True


@dataclass(frozen=True)
class ReadOptions:
    """What a reader may need that the file itself does not say.

    Attributes:
        local_offset: The UTC offset of timestamps that carry none, as some CSV
            exports do. ``None`` means such a file is refused with an explanation.
        day_first: Whether an ambiguous date such as ``03/04/2026`` is day first.
            ``None`` means an ambiguous date is refused.
        names_for: Given an event ID, its version, and how many unnamed values a
            record has, the field names in order, or ``None`` when not known. Exports
            that lose field names, such as ``Get-WinEvent | ConvertTo-Json``, need it.
        labels_for: Given an event ID, the map from a label in the English message
            text (``Security ID`` under ``Subject``, written ``Subject/Security ID``)
            to its field name, or ``None`` when not known. Message-only exports need it.
    """

    local_offset: timedelta | None = None
    day_first: bool | None = None
    names_for: Callable[[int, int, int], tuple[str, ...] | None] = lambda *_: None
    labels_for: Callable[[int], Mapping[str, str] | None] = lambda _: None
