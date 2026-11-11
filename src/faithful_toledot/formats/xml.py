# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Reader for Windows event XML.

Accepted shapes (all are the Windows event schema,
``http://schemas.microsoft.com/win/2004/08/events/event``):

* ``wevtutil qe Security /f:xml``: a bare sequence of ``<Event>`` elements with no root.
* ``wevtutil qe ... /e:Events``: the same inside an ``<Events>`` root.
* Event Viewer, "Save All Events As... XML": an ``<Events>`` root, with an optional
  ``<RenderingInfo>`` inside each event, which is ignored.
* ``Get-WinEvent | ForEach-Object ToXml()``, one event per line or concatenated.
* UTF-8 (with or without a byte order mark) and UTF-16 with a byte order mark.

How it reads
------------
The file is decoded strictly, 64 KiB at a time, and fed to an incremental ``pyexpat``
parser, so memory use does not depend on the file's size and a whole-document tree is
never built. To accept a file with no root element, the parser is given a synthetic
wrapper element before the file's text and the closing tag after it. Any XML declaration
at the start of the file is blanked out first (declarations are only legal at the very
start, and the wrapper would make them an error). The declared encoding is ignored; the
byte order mark and strict UTF-8 decoding decide. A second declaration in the middle of
a file, as from two exports appended together, is not well-formed inside the wrapper and
stops the read there, which is reported as a problem.

Hostile input
-------------
A DOCTYPE or an entity declaration anywhere in the file raises :class:`InputError`, in
any encoding, even after events have been read. The file is decoded here, so the check does
not depend on the encoding. It works because the synthetic wrapper makes every DTD
declaration ill-formed (a DOCTYPE is only legal before the root element), so the parser
never accepts one, never declares or expands an entity, and never fetches anything; the
reader then recognises the cause (``<!`` followed by a capital letter near the failure)
and says so. Undefined entity references such as ``&xxe;`` are not well-formed either.
A single token (a comment, a tag, a run of
text) that grows past ``MAX_IDLE_CHARS`` without the parser finishing it stops the read.
Inside one event, ``MAX_DEPTH``, ``MAX_FIELDS``, ``MAX_VALUE_CHARS`` and
``MAX_EVENT_CHARS`` apply; an event over a limit becomes a :class:`Problem` and reading
continues with the next event.

What is a file-level error and what is a problem
------------------------------------------------
Before the first event has been read, anything that makes the file not Windows event XML
raises :class:`InputError`: it cannot be read, it is empty or has no events, it is not
well-formed, or its first element is neither ``Event`` nor ``Events``. After that, a
file that stops being well-formed (a truncated export, for example) yields one
:class:`Problem` saying where, and reading ends. The events before it are kept. Other
bad records, such as a missing ``EventID`` or an unusable timestamp, are problems for
that event only.

Mapping
-------
Each ``Event`` becomes one :class:`Event`:

* ``Provider/@Name``, ``EventID`` text (the ``Qualifiers`` attribute is ignored), ``Version``
  (0 if absent), ``TimeCreated/@SystemTime``, ``EventRecordID`` (``None`` if absent),
  ``Channel`` and ``Computer`` are the event's own fields. A missing or empty
  ``EventID``, ``SystemTime``, ``Computer``, ``Channel`` or ``Provider/@Name`` makes the
  event a problem. A time with no offset needs ``options.local_offset``.
* ``Keywords``, ``Level``, ``Task``, ``Opcode``, ``Correlation/@ActivityID`` and
  ``@RelatedActivityID``, ``Execution/@ProcessID`` and ``@ThreadID``, and
  ``Security/@UserID`` are kept as written in ``Event.system`` under ``Keywords``,
  ``Level``, ``Task``, ``Opcode``, ``ActivityID``, ``RelatedActivityID``, ``ProcessID``,
  ``ThreadID`` and ``UserID``.
* ``EventData/Data``: the ``Name`` attribute is the key, with the element's text, exactly
  as written. A ``Data`` with no name gets ``param`` and its 1-based position among all
  ``Data`` elements of the event (``param2`` is the second ``Data``). A repeated name
  keeps the first under its name and stores later ones as ``name#2``, ``name#3``.
  ``EventData/Binary`` is stored under ``Binary``.
* ``UserData``: it must have at most one child element (the provider's wrapper, whose
  name and namespace are ignored). Each child of that wrapper becomes a field named by
  its local element name. If a field has child elements of its own, the text of all its
  descendants is joined with single spaces, skipping whitespace-only text. Attributes
  and text directly inside the wrapper are not read.
* Other children of ``Event`` (``RenderingInfo``, ``ProcessingErrorData``) and unknown
  elements inside ``System`` and ``EventData`` are ignored.

Namespaces: an ``Event`` must be in the events namespace or in no namespace. An
``Event`` in any other namespace is a problem for that event. Inside an event, elements
of ``System`` and ``EventData`` must be in the same namespace as the ``Event``.
``UserData`` content may be in any namespace, as providers use their own.

Positions are ``event N (line L)``, where ``N`` counts ``Event`` elements from 1 and ``L``
is the line of the ``Event`` start tag.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from xml.parsers import expat

from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, Source
from faithful_toledot.formats._text import (
    MAX_EVENT_CHARS,
    MAX_FIELDS,
    MAX_NAME_CHARS,
    MAX_VALUE_CHARS,
    SYSTEM_ORDER,
    TimestampError,
    add_data,
    check_options,
    eager,
    parse_iso,
    parse_unsigned,
    read_chunks,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator
    from pathlib import Path

    from faithful_toledot.events import ReadOptions

EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
"""The namespace of Windows event XML."""
MAX_DEPTH = 16
"""Deepest element nesting inside one ``Event``. Real events use 4 and ``UserData`` 6."""
MAX_DECLARATION_CHARS = 4096
"""Longest XML declaration looked for. A real one is under 100 characters."""
MAX_IDLE_CHARS = 4 << 20
"""Most characters that may go by without the parser finishing one token or text run."""

_WRAPPER = "toledot-wrapper"
_SECTIONS = frozenset({"System", "EventData", "UserData"})
_SYSTEM_TEXT = frozenset(
    {
        "EventID",
        "Version",
        "Level",
        "Task",
        "Opcode",
        "Keywords",
        "EventRecordID",
        "Channel",
        "Computer",
    }
)
_SYSTEM_ATTRIBUTES = {
    "Provider": (("Name", "ProviderName"),),
    "TimeCreated": (("SystemTime", "SystemTime"),),
    "Correlation": (("ActivityID", "ActivityID"), ("RelatedActivityID", "RelatedActivityID")),
    "Execution": (("ProcessID", "ProcessID"), ("ThreadID", "ThreadID")),
    "Security": (("UserID", "UserID"),),
}
_DECLARATION = re.compile(r"[ \t\r\n]*<\?xml[ \t\r\n][^>]*\?>")
_DTD_DECLARATION = re.compile(r"<![A-Z]")
_DTD_TAIL = 8
_MAX_RECORD_ID = (1 << 64) - 1


def read_xml(path: Path, options: ReadOptions) -> Iterator[Event | Problem]:
    """Read Windows event XML. See the module documentation for the accepted shapes.

    Args:
        path: The XML file.
        options: Read options. Only ``local_offset`` is used, for a time with no offset.

    Returns:
        An iterator of events and problems in file order. Structural errors that occur
        before the first event are raised by this call, not by the first ``next``.

    Raises:
        InputError: The file cannot be read, is not Windows event XML, declares a DTD
            or entity, or holds no events.
    """
    check_options(options)
    return eager(
        _read(path, options),
        empty=f"{path.name} contains no Event elements; there is nothing to read",
    )


@dataclass
class _Collector:
    """Text being gathered for one value."""

    kind: str  # "system" or "field"
    key: str
    level: int  # absolute depth of the element the text belongs to
    current: list[str] = field(default_factory=list)
    pieces: list[str] = field(default_factory=list)
    nested: bool = False
    size: int = 0

    def flush(self) -> None:
        if self.current:
            self.pieces.append("".join(self.current))
            self.current.clear()

    def text(self) -> str:
        if not self.nested:
            return "".join(self.current)
        self.flush()
        return " ".join(piece for piece in self.pieces if piece.strip())


@dataclass
class _Builder:
    """One ``Event`` element as it is read."""

    number: int
    line: int
    namespace: str
    error: str | None = None
    system: dict[str, str] = field(default_factory=dict)
    system_seen: set[str] = field(default_factory=set)
    sections: set[str] = field(default_factory=set)
    data: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    path: list[str] = field(default_factory=list)
    position: int = 0
    user_children: int = 0
    fields: int = 0
    chars: int = 0

    def fail(self, reason: str) -> None:
        if self.error is None:
            self.error = reason


class _Stream:
    """The expat parser, its state, and the items it has produced but not yet handed on."""

    def __init__(self, name: str, options: ReadOptions) -> None:
        self.name = name
        self.options = options
        self.out: deque[Event | Problem] = deque()
        self.produced = 0
        self.stopped = False
        self.tick = 0
        self.tail = ""
        self.depth = 0
        self.skip_level = 0
        self.events_level = 0
        self.event_number = 0
        self.recognised = False
        self.junk_reported = False
        self.event: _Builder | None = None
        self.event_level = 0
        self.collector: _Collector | None = None
        parser = expat.ParserCreate(namespace_separator="}")
        parser.buffer_text = True
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = self._characters
        parser.CommentHandler = self._touch
        parser.ProcessingInstructionHandler = self._touch
        self.parser = parser

    # --- output --------------------------------------------------------------------

    def _emit(self, item: Event | Problem) -> None:
        self.produced += 1
        self.out.append(item)

    def _problem(self, where: str, reason: str, record_id: int | None = None) -> None:
        self._emit(Problem(Source(self.name, where), reason, record_id))

    def drain(self) -> Iterator[Event | Problem]:
        """Hand on everything produced so far."""
        while self.out:
            yield self.out.popleft()

    def stop(self, reason: str) -> None:
        """Stop reading: an error if nothing was produced, otherwise a problem."""
        if self.produced == 0:
            msg = f"{self.name}: {reason}"
            raise InputError(msg)
        ev = self.event
        where = (
            f"event {ev.number} (line {ev.line})"
            if ev is not None
            else f"line {self.parser.CurrentLineNumber}"
        )
        self._problem(where, f"{reason}; the rest of the file was not read")
        self.stopped = True

    # --- feeding -------------------------------------------------------------------

    def feed(self, text: str, *, final: bool = False) -> None:
        """Give the parser text. Parse failures end the read as described above."""
        window = self.tail + text
        self.tail = text[-_DTD_TAIL:]
        try:
            self.parser.Parse(text, final)
        except expat.ExpatError as exc:
            if _DTD_DECLARATION.search(window):
                msg = f"{self.name} declares a DTD or entity; refusing to parse it"
                raise InputError(msg) from None
            reason = expat.ErrorString(exc.code)
            self.stop(
                f"the XML is not well-formed ({reason}, line {exc.lineno}, column {exc.offset})"
            )

    # --- handlers ------------------------------------------------------------------

    def _touch(self, *_args: object) -> None:
        self.tick += 1

    def _start(self, name: str, attributes: dict[str, str]) -> None:
        self.tick += 1
        self.junk_reported = False
        self.depth += 1
        if self.skip_level or self.depth == 1:  # level 1 is the synthetic wrapper
            return
        namespace, _sep, local = name.rpartition("}")
        if self.event is None:
            self._start_outside(namespace, local)
        else:
            self._start_inside(namespace, local, attributes)

    def _start_outside(self, namespace: str, local: str) -> None:
        depth = self.depth
        known = namespace in {"", EVENT_NAMESPACE}
        in_events = self.events_level == 2  # noqa: PLR2004 - fixed limits of the format
        if local == "Event" and (depth == 2 or (depth == 3 and in_events)):  # noqa: PLR2004 - fixed limits of the format
            self.recognised = True
            self.event_number += 1
            self.event_level = depth
            self.event = _Builder(self.event_number, self.parser.CurrentLineNumber, namespace)
            if not known:
                self.event.fail("the Event is not in the Windows events namespace")
            return
        if known and local == "Events" and depth == 2 and not in_events:  # noqa: PLR2004 - fixed limits of the format
            self.recognised = True
            self.events_level = depth
            return
        if not self.recognised:
            msg = (
                f"{self.name} is not Windows event XML: its first element is "
                f"<{local[:40]}>, not <Event> or <Events>"
            )
            raise InputError(msg)
        self._problem(
            f"line {self.parser.CurrentLineNumber}",
            f"unexpected element <{local[:40]}> outside any event was skipped",
        )
        self.skip_level = depth

    def _start_inside(self, namespace: str, local: str, attributes: dict[str, str]) -> None:
        ev = self.event
        assert ev is not None  # noqa: S101 - narrowing for the type checker
        depth = self.depth
        if ev.error is not None:
            self.skip_level = depth
            return
        relative = depth - self.event_level
        if relative > MAX_DEPTH:
            ev.fail(f"elements are nested more than {MAX_DEPTH} levels deep")
            self.skip_level = depth
            return
        collector = self.collector
        if collector is not None:  # an element inside a value being collected
            collector.flush()
            collector.nested = True
            ev.path.append(local)
            return
        if relative == 1:
            self._start_section(ev, namespace, local)
            return
        section = ev.path[0]
        if section == "System" and relative == 2:  # noqa: PLR2004 - fixed limits of the format
            self._start_system(ev, namespace, local, attributes)
        elif section == "EventData" and relative == 2 and namespace == ev.namespace:  # noqa: PLR2004 - fixed limits of the format
            self._start_data(ev, local, attributes)
        elif section == "UserData":
            self._start_user(ev, local, relative)
        else:
            self.skip_level = depth

    def _start_section(self, ev: _Builder, namespace: str, local: str) -> None:
        if namespace != ev.namespace or local not in _SECTIONS:
            self.skip_level = self.depth  # RenderingInfo and anything unknown
            return
        if local in ev.sections:
            ev.fail(f"{local} appears more than once")
        elif {local, *ev.sections} >= {"EventData", "UserData"}:
            ev.fail("it has both EventData and UserData")
        if ev.error is not None:
            self.skip_level = self.depth
            return
        ev.sections.add(local)
        ev.path.append(local)

    def _start_system(
        self, ev: _Builder, namespace: str, local: str, attributes: dict[str, str]
    ) -> None:
        text = local in _SYSTEM_TEXT
        pairs = _SYSTEM_ATTRIBUTES.get(local, ())
        if namespace != ev.namespace or not (text or pairs):
            self.skip_level = self.depth
            return
        if local in ev.system_seen:
            ev.fail(f"System/{local} appears more than once")
            self.skip_level = self.depth
            return
        ev.system_seen.add(local)
        for attribute, key in pairs:
            value = attributes.get(attribute)
            if value is None:
                continue
            if len(value) > MAX_NAME_CHARS:
                ev.fail(f"System/{local}/@{attribute} is longer than {MAX_NAME_CHARS} characters")
            else:
                ev.system[key] = value
        ev.path.append(local)
        if text:
            self.collector = _Collector("system", local, self.depth)

    def _start_data(self, ev: _Builder, local: str, attributes: dict[str, str]) -> None:
        if local not in {"Data", "Binary"}:
            self.skip_level = self.depth
            return
        ev.position += 1
        key = attributes.get("Name") or f"param{ev.position}"
        if local == "Binary":
            key = "Binary"
        if len(key) > MAX_NAME_CHARS:
            ev.fail(f"a Data name is longer than {MAX_NAME_CHARS} characters")
            self.skip_level = self.depth
            return
        ev.path.append(local)
        self.collector = _Collector("field", key, self.depth)

    def _start_user(self, ev: _Builder, local: str, relative: int) -> None:
        if relative == 2:  # noqa: PLR2004 - fixed limits of the format
            ev.user_children += 1
            if ev.user_children > 1:
                ev.fail("UserData has more than one child element")
                self.skip_level = self.depth
                return
            ev.path.append(local)
            return
        # relative == 3: a field. Deeper elements are nested inside a collector.
        ev.path.append(local)
        self.collector = _Collector("field", local, self.depth)

    def _characters(self, text: str) -> None:
        self.tick += 1
        if self.skip_level:
            return
        ev = self.event
        if ev is None:
            if text.strip() and not self.junk_reported:
                self._junk()
            return
        collector = self.collector
        if collector is None or ev.error is not None:
            return
        collector.size += len(text)
        ev.chars += len(text)
        if collector.size > MAX_VALUE_CHARS:
            ev.fail(f"a value is longer than {MAX_VALUE_CHARS} characters")
        elif ev.chars > MAX_EVENT_CHARS:
            ev.fail(f"the event holds more than {MAX_EVENT_CHARS} characters of text")
        else:
            collector.current.append(text)

    def _junk(self) -> None:
        if not self.recognised:
            msg = f"{self.name} is not Windows event XML: it has text before the first element"
            raise InputError(msg)
        self.junk_reported = True
        self._problem(f"line {self.parser.CurrentLineNumber}", "text outside any event was skipped")

    def _end(self, _name: str) -> None:
        self.tick += 1
        depth = self.depth
        self.depth -= 1
        if self.skip_level:
            if depth == self.skip_level:
                self.skip_level = 0
            return
        ev = self.event
        if ev is None:
            if depth == self.events_level:
                self.events_level = 0
            return
        if depth == self.event_level:
            self._finish(ev)
            return
        collector = self.collector
        if collector is not None:
            if collector.nested:
                collector.flush()
            if collector.level == depth:
                self._store(ev, collector)
                self.collector = None
        ev.path.pop()

    def _store(self, ev: _Builder, collector: _Collector) -> None:
        if ev.error is not None:
            return
        text = collector.text()
        if collector.kind == "system":
            ev.system[collector.key] = text
            return
        ev.fields += 1
        if ev.fields > MAX_FIELDS:
            ev.fail(f"it has more than {MAX_FIELDS} data fields")
            return
        add_data(ev.data, ev.counts, collector.key, text)

    # --- building events -----------------------------------------------------------

    def _finish(self, ev: _Builder) -> None:
        self.event = None
        self.collector = None
        where = f"event {ev.number} (line {ev.line})"
        record = ev.system.get("EventRecordID")
        record_id = parse_unsigned(record, _MAX_RECORD_ID) if record is not None else None
        reason = ev.error or self._check_required(ev)
        if reason is None:
            built = self._build(ev, where, record_id)
            if isinstance(built, Event):
                self._emit(built)
                return
            reason = built
        self._problem(where, reason, record_id)

    @staticmethod
    def _check_required(ev: _Builder) -> str | None:
        for key, label in (
            ("EventID", "System/EventID"),
            ("SystemTime", "System/TimeCreated/@SystemTime"),
            ("Computer", "System/Computer"),
            ("Channel", "System/Channel"),
            ("ProviderName", "System/Provider/@Name"),
        ):
            if not ev.system.get(key, ""):
                return f"{label} is missing or empty"
        return None

    def _build(self, ev: _Builder, where: str, record_id: int | None) -> Event | str:
        system = ev.system
        event_id = parse_unsigned(system["EventID"], 65535)
        if event_id is None:
            return "System/EventID is not a whole number from 0 to 65535"
        version = 0
        if "Version" in system:
            parsed = parse_unsigned(system["Version"], 255)
            if parsed is None:
                return "System/Version is not a whole number from 0 to 255"
            version = parsed
        if "EventRecordID" in system and record_id is None:
            return "System/EventRecordID is not a whole number"
        try:
            moment = parse_iso(system["SystemTime"].strip(), local_offset=self.options.local_offset)
        except TimestampError as exc:
            return f"System/TimeCreated/@SystemTime cannot be used: {exc}"
        return Event(
            event_id=event_id,
            time=moment,
            computer=system["Computer"],
            channel=system["Channel"],
            provider=system["ProviderName"],
            record_id=record_id,
            data=ev.data,
            source=Source(self.name, where),
            version=version,
            system={key: system[key] for key in SYSTEM_ORDER if key in system},
        )


def _split_declaration(head: str, *, final: bool) -> str | None:
    """Blank out an XML declaration at the start of ``head``, keeping its line breaks.

    The declaration may arrive in pieces, so this returns ``None`` while the start of the
    file is not enough to decide, unless ``final`` says there is no more.
    """
    stripped = head.lstrip(" \t\r\n")
    if len(stripped) < len("<?xml ") and "<?xml".startswith(stripped[:5]):
        return head if final else None
    if not (stripped.startswith("<?xml") and stripped[5] in " \t\r\n"):
        return head
    match = _DECLARATION.match(head)
    if match is None:
        return head if final or len(head) >= MAX_DECLARATION_CHARS else None
    blanked = re.sub(r"[^\r\n]", " ", match.group())
    return blanked + head[match.end() :]


def _read(path: Path, options: ReadOptions) -> Generator[Event | Problem, None, None]:
    stream = _Stream(path.name, options)
    stream.feed(f"<{_WRAPPER}>")
    chunks = read_chunks(path)
    head: str | None = (
        ""  # the start of the file, held until it is known whether it has a declaration
    )
    idle = 0
    try:
        while not stream.stopped:
            try:
                chunk = next(chunks)
            except StopIteration:
                break
            except InputError as exc:
                if stream.produced == 0:
                    raise
                where = f"after event {stream.event_number}"
                stream.out.append(
                    Problem(Source(path.name, where), f"{exc}; the rest of the file was not read")
                )
                stream.stopped = True
                break
            if head is not None:
                head += chunk
                decided = _split_declaration(head, final=False)
                if decided is None:
                    continue
                chunk = decided
                head = None
            before = stream.tick
            stream.feed(chunk)
            idle = idle + len(chunk) if stream.tick == before else 0
            if idle > MAX_IDLE_CHARS and not stream.stopped:
                stream.stop(f"a single XML token is longer than {MAX_IDLE_CHARS} characters")
            yield from stream.drain()
        if head and not stream.stopped:  # the whole file was shorter than a declaration needs
            stream.feed(head)
        if not stream.stopped:
            stream.feed(f"</{_WRAPPER}>", final=True)
        yield from stream.drain()
    finally:
        chunks.close()
