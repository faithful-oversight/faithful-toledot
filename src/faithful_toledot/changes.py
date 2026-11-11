# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""What toledot says about a set of events: changes, where they came from, and gaps.

These are plain records. :mod:`faithful_toledot.correlate` builds them, and the
output modules only read them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from faithful_toledot.events import Problem, Source


@dataclass(frozen=True)
class Party:
    r"""An account or object named in an event.

    Every part is what the event recorded, or ``None`` when it recorded nothing.
    ``known_as`` is a name toledot found for the SID in *another* event of the same
    input; it is shown apart from the recorded name, so a reader can tell them apart.

    Attributes:
        sid: The security identifier.
        name: The account name.
        domain: The account's domain.
        dn: The distinguished name.
        object_class: The directory object class, such as ``user``.
        guid: The directory object GUID.
        well_known: The name of a well-known SID or RID, such as ``Domain Admins``.
        known_as: ``DOMAIN\name`` seen with this SID elsewhere in the input.
    """

    sid: str | None = None
    name: str | None = None
    domain: str | None = None
    dn: str | None = None
    object_class: str | None = None
    guid: str | None = None
    well_known: str | None = None
    known_as: str | None = None

    @property
    def empty(self) -> bool:
        """Whether the event recorded nothing that identifies this party."""
        return not (self.sid or self.name or self.dn or self.guid)


@dataclass(frozen=True)
class Origin:
    """Where the actor's logon session came from.

    The link is the logon ID: the change event names the session, and a logon event
    on the same computer says where that session started. ``status`` says how far
    that link holds.

    Attributes:
        status: ``session`` when the logon event was found; ``local`` for a session
            of the computer itself, which has no logon event; ``not-in-input`` when
            the change names a session whose logon event is not in the input;
            ``ended`` when the input holds only a logoff of that session before the
            change, so the logon that was in use is not in the input;
            ``none`` when the change event names no session.
        logon_id: The session's logon ID, as recorded.
        address: The source network address of the logon, if it recorded one.
        port: The source port.
        workstation: The workstation name the logon recorded.
        logon_type: The logon type number.
        logon_type_name: The logon type in words.
        logon_time: When the session started.
        source: The logon event.
    """

    status: str
    logon_id: str | None = None
    address: str | None = None
    port: str | None = None
    workstation: str | None = None
    logon_type: str | None = None
    logon_type_name: str | None = None
    logon_time: datetime | None = None
    source: Source | None = None


@dataclass(frozen=True)
class Detail:
    """One thing a change did to its target.

    Attributes:
        label: What was changed, in plain words, such as ``display name``.
        kind: ``initial`` (a value given to a newly created object), ``set`` (a new
            value, old one not recorded), ``changed`` (old and new
            recorded), ``added`` or ``removed`` (one value of a list), or ``info``
            (a recorded fact that is not a value change).
        old: The earlier value, when recorded.
        new: The new value, when there is one.
        meaning: The value in words when toledot can decode it, such as the names of
            account-control flags. The recorded value stays in ``old`` and ``new``.
        attribute: The directory attribute or event field the detail comes from.
    """

    label: str
    kind: str
    old: str | None = None
    new: str | None = None
    meaning: str | None = None
    attribute: str | None = None


@dataclass(frozen=True)
class EventRef:
    """One event a change is built from."""

    event_id: int
    record_id: int | None
    time: datetime
    source: Source


@dataclass(frozen=True)
class Change:
    """One change: who did what to what, when, on which computer, and from where.

    Attributes:
        id: A stable identifier within one report, such as ``C0007``.
        time: When the first of its events was recorded, in UTC.
        computer: The computer that recorded it.
        category: The kind of target, such as ``user`` or ``group``.
        action: What happened, such as ``member-added``.
        title: The event's short title.
        actor: Who did it.
        target: What it was done to.
        member: The account added or removed, for membership changes.
        details: What changed, value by value.
        origin: Where the actor's session came from.
        events: The events it is built from, in order.
        related: Identifiers of other changes by the same session within moments of
            this one. They are likely parts of one administrative action.
        notes: Anything a reader needs in order not to over-read the change.
        sentence: The change as one plain sentence.
    """

    id: str
    time: datetime
    computer: str
    category: str
    action: str
    title: str
    actor: Party
    target: Party
    member: Party | None
    details: tuple[Detail, ...]
    origin: Origin
    events: tuple[EventRef, ...]
    related: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    sentence: str = ""


@dataclass(frozen=True)
class Notice:
    """An event that bears on how far the log itself can be trusted.

    A cleared log, dropped events, a changed audit policy, or a clock changed by a
    person mean the account may be incomplete: these are warnings. A log service that
    stopped at shutdown, an archived log, or a clock the system synchronised are
    routine: these are information.

    Attributes:
        time: When the event was recorded.
        computer: The computer that recorded it.
        kind: What happened, such as ``log-cleared``.
        text: The same in a sentence.
        actor: Who did it, as far as the event records.
        event: The event.
        severity: ``warning`` when it bears on completeness, else ``info``.
    """

    time: datetime
    computer: str
    kind: str
    text: str
    actor: Party
    event: EventRef
    severity: str = "warning"


@dataclass(frozen=True)
class Coverage:
    """What the input holds for one log on one computer, and what it cannot show.

    Attributes:
        computer: The computer.
        channel: The log.
        events: How many events were read. A collector may report a log it found no
            events in.
        first: The earliest event time, or ``None`` when no event was read.
        last: The latest event time.
        first_record: The lowest record number, when records are numbered.
        last_record: The highest record number.
        continuity: ``complete`` when every record number in the range is present;
            ``gaps`` when some are absent; ``unnumbered`` when the export kept no
            record numbers; ``empty`` when no event was read.
        missing: The absent record-number ranges, first and last inclusive.
        missing_count: How many record numbers are absent.
        scope: ``unfiltered`` when the user stated the input is the whole log,
            ``filtered`` when the input says it holds chosen events only, and
            ``unknown`` otherwise. Absent record numbers mean missing events only in
            an unfiltered log; in a filtered one they are expected.
        overwritten_before: Set when a collector asked for events from an earlier
            time than the log's oldest record: events before this time were already
            gone from the log when it was read.
        statement: What that means for a reader, in a sentence.
    """

    computer: str
    channel: str
    events: int
    first: datetime | None
    last: datetime | None
    first_record: int | None
    last_record: int | None
    continuity: str
    missing: tuple[tuple[int, int], ...]
    missing_count: int
    scope: str
    statement: str
    overwritten_before: datetime | None = None

    @property
    def missing_events(self) -> bool:
        """Whether this log is known to be missing events."""
        return (self.continuity == "gaps" and self.scope == "unfiltered") or bool(
            self.overwritten_before
        )

    @property
    def checked(self) -> bool:
        """Whether the input gives positive evidence about this log's completeness.

        Continuous record numbers show nothing between the first and the last is
        absent. A collection states what it asked the log for, so its expected gaps
        are accounted for. Absent numbers in an input of unknown scope, and an export
        with no record numbers, leave toledot unable to tell.
        """
        if self.continuity == "complete":
            return True
        return self.scope in {"filtered", "unfiltered"} and self.continuity in {"gaps", "empty"}


COMPLETENESS = ("complete", "unconfirmed", "incomplete")
"""``complete``: evidence that nothing is missing. ``unconfirmed``: nothing shows events
missing, but the input cannot show that they are not. ``incomplete``: events are known
or likely to be missing."""


@dataclass
class Account:
    """Everything toledot can say about the input.

    Attributes:
        changes: The changes, in time order.
        notices: Events that bear on the log's own completeness.
        coverage: Per computer and log, what was read and what is absent.
        problems: Records and files that could not be read, and conflicts.
        counts: How many events were read, by what became of them: ``changes``,
            ``context``, ``notices``, ``other`` (not a change toledot describes),
            ``duplicates``, and ``outside_window`` (before ``since`` or from ``until``).
            Every event read is in exactly one count. An audit policy change is both a
            change and a notice; its event is counted with the changes.
        other_ids: Event IDs read but not described, with their counts.
    """

    changes: list[Change] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    other_ids: dict[tuple[str, int], int] = field(default_factory=dict)

    @property
    def completeness(self) -> str:
        """One of ``COMPLETENESS``: whether the input shows the account is whole."""
        warned = any(notice.severity == "warning" for notice in self.notices)
        if self.problems or warned or any(c.missing_events for c in self.coverage):
            return "incomplete"
        if not self.coverage or not all(c.checked for c in self.coverage):
            return "unconfirmed"
        return "complete"

    @property
    def complete(self) -> bool:
        """Whether the input gives evidence that the account is whole."""
        return self.completeness == "complete"
