# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""A small writer of synthetic ``.evtx`` bytes, for tests only.

Tests never need a real log: this module builds valid files (and, on request,
deliberately damaged ones) from a description. It writes the same structures the
reader parses:

- a 4096 byte file header ("ElfFile\\0", version 3.1, chunk count, flags, CRC32);
- 64 KiB chunks ("ElfChnk\\0", record id range, free-space offset, CRC32 of the
  records, CRC32 of the header);
- event records (``**\\0\\0``, size, record id, FILETIME, Binary XML, size copy,
  padded to 8 bytes);
- Binary XML: fragment header, elements with attributes, value text, character
  and entity references, CDATA, processing instructions, normal and optional
  substitutions, and template instances. A template definition is written inline
  the first time a chunk uses it and is pointed to afterwards, and a name is
  written inline the first time a chunk uses it and pointed to afterwards, which
  is what Windows does.

Typical use::

    chunk = ChunkBuilder()
    chunk.add_record(1, security_event(1, 4728, data=[("MemberSid", "S-1-5-21-1")]))
    data = build_evtx([chunk.finish()])

The format is described by the libevtx documentation ("Windows XML Event Log
(EVTX)") and [MS-EVEN6] 2.2.12. Nothing here copies real event data; every name,
address and SID is made up.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

CHUNK_SIZE = 65536
FILE_HEADER_SIZE = 4096
CHUNK_HEADER_SIZE = 512
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

# Value types
T_NULL, T_STRING, T_ANSI = 0x00, 0x01, 0x02
T_INT8, T_UINT8, T_INT16, T_UINT16, T_INT32, T_UINT32 = 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
T_INT64, T_UINT64, T_REAL32, T_REAL64, T_BOOL, T_BINARY = 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
T_GUID, T_SIZE, T_FILETIME, T_SYSTEMTIME, T_SID, T_HEX32, T_HEX64 = (
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
)
T_BINXML = 0x21
ARRAY = 0x80


def crc(*parts: bytes) -> int:
    """Return the CRC32 of the parts joined, as EVTX uses it."""
    value = 0
    for part in parts:
        value = zlib.crc32(part, value)
    return value


def filetime_of(when: datetime) -> int:
    """Return ``when`` as a FILETIME: 100 ns ticks since 1601-01-01 UTC."""
    delta = when - FILETIME_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


# --- Values ---


@dataclass(frozen=True)
class Value:
    """One template substitution value: its type and bytes.

    ``embedded`` makes the bytes Binary XML written in place, so it may use names
    and templates of the chunk.
    """

    vtype: int
    data: bytes = b""
    embedded: Instance | El | None = None
    fragment_header: bool = True
    end_token: bool = True
    hint: int | None = None  # the type a substitution token declares, when it is not a string


def null() -> Value:
    """Return a NULL value."""
    return Value(T_NULL)


def string(text: str, *, terminated: bool = True) -> Value:
    """Return a UTF-16 string value, NUL terminated as Windows writes it."""
    return Value(T_STRING, (text + ("\x00" if terminated else "")).encode("utf-16-le"))


def ansi(text: str, *, codec: str = "cp1252") -> Value:
    """Return an ANSI string value."""
    return Value(T_ANSI, text.encode(codec) + b"\x00")


def integer(vtype: int, number: int) -> Value:
    """Return an integer-like value of a fixed-width type."""
    formats = {
        T_INT8: "<b",
        T_UINT8: "<B",
        T_INT16: "<h",
        T_UINT16: "<H",
        T_INT32: "<i",
        T_UINT32: "<I",
        T_INT64: "<q",
        T_UINT64: "<Q",
        T_HEX32: "<I",
        T_HEX64: "<Q",
        T_BOOL: "<I",
    }
    return Value(vtype, struct.pack(formats[vtype], number))


def real(number: float, *, double: bool = False) -> Value:
    """Return a 32 or 64 bit floating point value."""
    return (
        Value(T_REAL64, struct.pack("<d", number))
        if double
        else Value(T_REAL32, struct.pack("<f", number))
    )


def binary(data: bytes) -> Value:
    """Return a binary value."""
    return Value(T_BINARY, data)


def guid(value: uuid.UUID) -> Value:
    """Return a GUID value (mixed-endian, as Windows stores it)."""
    return Value(T_GUID, value.bytes_le)


def filetime(when: datetime) -> Value:
    """Return a FILETIME value."""
    return Value(T_FILETIME, struct.pack("<Q", filetime_of(when)))


def systemtime(when: datetime) -> Value:
    """Return a SYSTEMTIME value."""
    fields = (
        when.year,
        when.month,
        (when.weekday() + 1) % 7,
        when.day,
        when.hour,
        when.minute,
        when.second,
        when.microsecond // 1000,
    )
    return Value(T_SYSTEMTIME, struct.pack("<8H", *fields))


def sid_bytes(text: str) -> bytes:
    """Return the binary form of a SID string such as ``S-1-5-18``."""
    parts = text.split("-")
    authority = int(parts[2], 0)
    subs = [int(p) for p in parts[3:]]
    head = bytes([int(parts[1]), len(subs)]) + authority.to_bytes(6, "big")
    return head + b"".join(struct.pack("<I", s) for s in subs)


def sid(text: str) -> Value:
    """Return a SID value."""
    return Value(T_SID, sid_bytes(text))


def size_t(number: int, *, wide: bool = True) -> Value:
    """Return a size_t value of 8 (or 4) bytes."""
    return Value(T_SIZE, struct.pack("<Q" if wide else "<I", number))


def embedded(
    content: Instance | El, *, fragment_header: bool = True, end_token: bool = True
) -> Value:
    """Return a Binary XML value holding a template instance or an element."""
    return Value(T_BINXML, embedded=content, fragment_header=fragment_header, end_token=end_token)


def array(vtype: int, items: Sequence[Value], *, hint: int | None = None) -> Value:
    """Return an array of values of one base type (fixed width types and SIDs).

    Strings are joined with NUL terminators, as an array of strings is stored.
    """
    return Value(vtype | ARRAY, b"".join(item.data for item in items), hint=hint)


# --- Binary XML trees ---


@dataclass(frozen=True)
class Slot:
    """A substitution in a template. ``vtype`` is the type the token declares."""

    index: int
    optional: bool = False
    vtype: int = 0


@dataclass(frozen=True)
class CharRef:
    """A character reference such as ``&#38;``."""

    code: int


@dataclass(frozen=True)
class EntityRef:
    """An entity reference such as ``&amp;``."""

    name: str


@dataclass(frozen=True)
class CData:
    """A CDATA section."""

    text: str


@dataclass(frozen=True)
class PI:
    """A processing instruction."""

    target: str
    data: str | None  # None writes the target alone, which is damaged


@dataclass(frozen=True)
class Raw:
    """Bytes written as they are, so a test can make a token the writer would not."""

    data: bytes


@dataclass
class El:
    """An element. ``attrs`` maps names to one value or a list of pieces."""

    name: str
    children: list[object] = field(default_factory=list)
    attrs: dict[str, object] = field(default_factory=dict)
    self_closing: bool | None = None  # None: self-closing when there are no children
    size_delta: int = 0  # added to the element's size field, to make a bad one


def el(name: str, *children: object, **attrs: object) -> El:
    """Build an element; keyword arguments are attributes."""
    return El(name, list(children), dict(attrs))


@dataclass
class Instance:
    """A template instance: a template (an element) and its values.

    Attributes:
        template: The template's root element. The same object is the same
            template, so a chunk writes it inline once and points to it after.
        values: The substitution values, in order.
        inline: Force the definition inline (``True``) or force a pointer to the
            earlier one (``False``); ``None`` does what Windows does.
        values_raw: Bytes to write instead of the value list, for hostile tests.
        def_offset: A definition offset to write instead of the real one.
    """

    template: El
    values: list[Value] = field(default_factory=list)
    inline: bool | None = None
    values_raw: bytes | None = None
    def_offset: int | None = None


# --- Writing ---


class _Writer:
    """A byte buffer that knows where in the chunk it will land."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.buf = bytearray()

    def pos(self) -> int:
        return self.base + len(self.buf)

    def u8(self, number: int) -> None:
        self.buf += struct.pack("<B", number)

    def u16(self, number: int) -> None:
        self.buf += struct.pack("<H", number)

    def u32(self, number: int) -> None:
        self.buf += struct.pack("<I", number)

    def patch32(self, at: int, number: int) -> None:
        self.buf[at : at + 4] = struct.pack("<I", number & 0xFFFFFFFF)

    def patch16(self, at: int, number: int) -> None:
        self.buf[at : at + 2] = struct.pack("<H", number)


@dataclass(frozen=True)
class RecordInfo:
    """Where a record was written, relative to the start of its chunk."""

    record_id: int
    offset: int
    size: int
    body_offset: int


class ChunkBuilder:
    """Builds one 64 KiB chunk of records.

    Names and template definitions are shared across the records added to one
    builder, the way a real chunk shares them.
    """

    def __init__(self) -> None:
        self.body = bytearray()
        self.names: dict[str, int] = {}
        self.definitions: dict[int, int] = {}
        self.records: list[RecordInfo] = []

    # Records

    def add_record(  # noqa: PLR0913 - every option is a keyword a test may damage
        self,
        record_id: int,
        content: Instance | El | Sequence[Instance | El],
        *,
        when: datetime | None = None,
        fragment_header: bool = True,
        prologue: PI | None = None,
        trailer: bytes = b"\x00",
    ) -> RecordInfo:
        """Add a record whose Binary XML is a template instance or a plain element.

        A list of contents writes them one after another, which is not a valid event
        record but is how a test makes a stream with two roots.
        """
        base = CHUNK_HEADER_SIZE + len(self.body)
        writer = _Writer(base + 24)
        if prologue is not None:
            self._parts(writer, [prologue], in_definition=False)
        if fragment_header:
            writer.buf += b"\x0f\x01\x01\x00"
        for item in [content] if isinstance(content, (Instance, El)) else content:
            if isinstance(item, Instance):
                self._instance(writer, item)
            else:
                self._element(writer, item, in_definition=False)
        writer.buf += trailer
        return self._finish_record(record_id, bytes(writer.buf), when)

    def add_raw_record(
        self, record_id: int, body: bytes, *, when: datetime | None = None
    ) -> RecordInfo:
        """Add a record around Binary XML bytes given as they are."""
        return self._finish_record(record_id, body, when)

    def _finish_record(self, record_id: int, body: bytes, when: datetime | None) -> RecordInfo:
        stamp = filetime_of(when or datetime(2026, 11, 10, 2, 15, 3, 123456, tzinfo=UTC))
        size = 24 + len(body) + 4
        size += -size % 8  # records are padded to 8 bytes
        record = struct.pack("<4sIQQ", b"\x2a\x2a\x00\x00", size, record_id, stamp)
        record += body + bytes(size - 4 - len(record) - len(body)) + struct.pack("<I", size)
        info = RecordInfo(record_id, CHUNK_HEADER_SIZE + len(self.body), size, 24)
        self.body += record
        self.records.append(info)
        return info

    def add_garbage(self, data: bytes) -> None:
        """Append bytes that are not a record, as they are."""
        self.body += data

    # Names and templates

    def _name_ref(self, w: _Writer, name: str) -> None:
        known = self.names.get(name)
        if known is not None:
            w.u32(known)
            return
        inline = w.pos() + 4
        self.names[name] = inline
        w.u32(inline)
        w.u32(0)  # next string in the hash bucket
        w.u16(0x1234)  # name hash; the reader does not check it
        w.u16(len(name))
        w.buf += (name + "\x00").encode("utf-16-le")

    def _text_piece(self, w: _Writer, text: str, *, more: bool) -> None:
        w.u8(0x45 if more else 0x05)
        w.u8(T_STRING)
        w.u16(len(text))
        w.buf += text.encode("utf-16-le")

    def _parts(self, w: _Writer, parts: list[object], *, in_definition: bool) -> None:
        for i, part in enumerate(parts):
            more = i < len(parts) - 1
            if isinstance(part, str):
                self._text_piece(w, part, more=more)
            elif isinstance(part, Slot):
                w.u8(0x0E if part.optional else 0x0D)
                w.u16(part.index)
                w.u8(part.vtype)
            elif isinstance(part, CharRef):
                w.u8(0x48 if more else 0x08)
                w.u16(part.code)
            elif isinstance(part, EntityRef):
                w.u8(0x49 if more else 0x09)
                self._name_ref(w, part.name)
            elif isinstance(part, CData):
                w.u8(0x47 if more else 0x07)
                w.u16(len(part.text))
                w.buf += part.text.encode("utf-16-le")
            elif isinstance(part, PI):
                w.u8(0x0A)
                self._name_ref(w, part.target)
                if part.data is not None:
                    w.u8(0x0B)
                    w.u16(len(part.data))
                    w.buf += part.data.encode("utf-16-le")
            elif isinstance(part, Raw):
                w.buf += part.data
            else:
                assert isinstance(part, El)
                self._element(w, part, in_definition=in_definition)

    def _element(self, w: _Writer, e: El, *, in_definition: bool) -> None:
        w.u8(0x41 if e.attrs else 0x01)
        if in_definition:
            w.u16(0xFFFF)
        size_at = len(w.buf)
        w.u32(0)
        start = len(w.buf)
        self._name_ref(w, e.name)
        if e.attrs:
            length_at = len(w.buf)
            w.u32(0)
            attrs_start = len(w.buf)
            items = list(e.attrs.items())
            for i, (name, value) in enumerate(items):
                w.u8(0x46 if i < len(items) - 1 else 0x06)
                self._name_ref(w, name)
                pieces = value if isinstance(value, list) else [value]
                self._parts(w, pieces, in_definition=in_definition)
            w.patch32(length_at, len(w.buf) - attrs_start)
        closing = e.self_closing if e.self_closing is not None else not e.children
        if closing:
            w.u8(0x03)
        else:
            w.u8(0x02)
            self._parts(w, e.children, in_definition=in_definition)
            w.u8(0x04)
        w.patch32(size_at, len(w.buf) - start + e.size_delta)

    def _instance(self, w: _Writer, inst: Instance) -> None:
        key = id(inst.template)
        known = self.definitions.get(key)
        w.u8(0x0C)
        w.u8(0x01)
        template_id = zlib.crc32(inst.template.name.encode()) ^ (key & 0xFFFF)
        w.u32(template_id & 0xFFFFFFFF)
        if known is not None and inst.inline is not True:
            w.u32(known if inst.def_offset is None else inst.def_offset)
        else:
            header = w.pos() + 4
            w.u32(header if inst.def_offset is None else inst.def_offset)
            self.definitions[key] = header
            self._definition(w, inst.template, key)
        if inst.values_raw is not None:
            w.buf += inst.values_raw
            return
        self._values(w, inst.values)

    def _definition(self, w: _Writer, template: El, key: int) -> None:
        w.u32(0)  # next definition in the hash bucket
        w.buf += uuid.UUID(int=key | (1 << 100)).bytes_le
        size_at = len(w.buf)
        w.u32(0)
        start = len(w.buf)
        w.buf += b"\x0f\x01\x01\x00"
        self._element(w, template, in_definition=True)
        w.u8(0x00)
        w.patch32(size_at, len(w.buf) - start)

    def _values(self, w: _Writer, values: list[Value]) -> None:
        w.u32(len(values))
        descriptors = len(w.buf)
        for value in values:
            w.u16(0)
            w.u8(value.vtype)
            w.u8(0)
        for i, value in enumerate(values):
            start = len(w.buf)
            if value.embedded is None:
                w.buf += value.data
            else:
                self._embedded(w, value)
            w.patch16(descriptors + 4 * i, len(w.buf) - start)

    def _embedded(self, w: _Writer, value: Value) -> None:
        if value.fragment_header:
            w.buf += b"\x0f\x01\x01\x00"
        if isinstance(value.embedded, Instance):
            self._instance(w, value.embedded)
        else:
            assert isinstance(value.embedded, El)
            self._element(w, value.embedded, in_definition=False)
        if value.end_token:
            w.u8(0x00)

    # Finishing

    def finish(  # noqa: PLR0913 - every option is a keyword a test may damage
        self,
        *,
        first_id: int | None = None,
        last_id: int | None = None,
        bad_header_crc: bool = False,
        bad_records_crc: bool = False,
        no_crc: bool = False,
        free_offset: int | None = None,
    ) -> bytes:
        """Return the chunk as 65536 bytes, with its header filled in.

        The keyword arguments damage the header on purpose: wrong CRC, ids that
        disagree with the records, a no-checksum flag, or a different free-space
        offset.
        """
        records = self.records
        first = first_id if first_id is not None else (records[0].record_id if records else 0)
        last = last_id if last_id is not None else (records[-1].record_id if records else 0)
        used = CHUNK_HEADER_SIZE + len(self.body)
        free = free_offset if free_offset is not None else used
        chunk = bytearray(CHUNK_SIZE)
        chunk[CHUNK_HEADER_SIZE : CHUNK_HEADER_SIZE + len(self.body)] = self.body
        last_offset = records[-1].offset if records else 0
        chunk[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQ", chunk, 8, first, last, first, last)
        struct.pack_into("<IIII", chunk, 40, 128, last_offset, free, 0)
        struct.pack_into("<I", chunk, 120, 0x4 if no_crc else 0)
        seal_chunk(chunk, bad_header_crc=bad_header_crc, bad_records_crc=bad_records_crc)
        if no_crc:  # such a chunk stores no checksums at all
            struct.pack_into("<I", chunk, 52, 0)
            struct.pack_into("<I", chunk, 124, 0)
        return bytes(chunk)


def seal_chunk(
    chunk: bytearray, *, bad_header_crc: bool = False, bad_records_crc: bool = False
) -> None:
    """Recompute a chunk's two CRC32 fields in place (after a test edited the chunk)."""
    free = struct.unpack_from("<I", chunk, 48)[0]
    records_crc = crc(bytes(chunk[CHUNK_HEADER_SIZE : max(free, CHUNK_HEADER_SIZE)]))
    struct.pack_into("<I", chunk, 52, records_crc ^ (1 if bad_records_crc else 0))
    header_crc = crc(bytes(chunk[:120]), bytes(chunk[128:CHUNK_HEADER_SIZE]))
    struct.pack_into("<I", chunk, 124, header_crc ^ (1 if bad_header_crc else 0))


def build_evtx(  # noqa: PLR0913 - every option is a keyword a test may damage
    chunks: Sequence[bytes],
    *,
    dirty: bool = False,
    chunk_count: int | None = None,
    no_crc: bool = False,
    bad_crc: bool = False,
    minor: int = 1,
    major: int = 3,
    header_size: int = 128,
    block_size: int = 4096,
    flags: int | None = None,
) -> bytes:
    """Return a whole ``.evtx`` file around chunks from :meth:`ChunkBuilder.finish`."""
    header = bytearray(FILE_HEADER_SIZE)
    header[0:8] = b"ElfFile\x00"
    count = len(chunks) if chunk_count is None else chunk_count
    struct.pack_into("<QQQ", header, 8, 0, max(len(chunks) - 1, 0), 1)
    struct.pack_into("<IHHHH", header, 32, header_size, minor, major, block_size, count)
    value = flags if flags is not None else (1 if dirty else 0) | (4 if no_crc else 0)
    struct.pack_into("<I", header, 120, value)
    checksum = 0 if no_crc else crc(bytes(header[:120]))
    struct.pack_into("<I", header, 124, checksum ^ (1 if bad_crc else 0))
    return bytes(header) + b"".join(chunks)


def refresh_file_crc(data: bytearray) -> None:
    """Recompute the file header CRC32 in place."""
    struct.pack_into("<I", data, 124, crc(bytes(data[:120])))


# --- Ready-made events ---

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
PROVIDER = "Microsoft-Windows-Security-Auditing"
PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"


def _system(*, computer: str | Slot, channel: str) -> El:
    return el(
        "System",
        el("Provider", Name=PROVIDER, Guid=PROVIDER_GUID),
        el(
            "EventID",
            Slot(0, optional=True, vtype=T_UINT16),
            Qualifiers=Slot(1, optional=True, vtype=T_UINT16),
        ),
        el("Version", Slot(2, optional=True, vtype=T_UINT8)),
        el("Level", Slot(3, optional=True, vtype=T_UINT8)),
        el("Task", Slot(4, optional=True, vtype=T_UINT16)),
        el("Opcode", Slot(5, optional=True, vtype=T_UINT8)),
        el("Keywords", Slot(6, optional=True, vtype=T_HEX64)),
        el("TimeCreated", SystemTime=Slot(7, optional=True, vtype=T_FILETIME)),
        el("EventRecordID", Slot(8, optional=True, vtype=T_UINT64)),
        el(
            "Correlation",
            ActivityID=Slot(9, optional=True, vtype=T_GUID),
        ),
        el(
            "Execution",
            ProcessID=Slot(10, optional=True, vtype=T_UINT32),
            ThreadID=Slot(11, optional=True, vtype=T_UINT32),
        ),
        el("Channel", channel),
        el("Computer", computer),
        el("Security", UserID=Slot(12, optional=True, vtype=T_SID)),
    )


def data_section(names: Sequence[str | None], first_slot: int, hints: Sequence[int] = ()) -> El:
    """Return an ``EventData`` element with one ``Data`` per name, substituting slots in order.

    A name of ``None`` makes an unnamed ``Data``. ``hints`` are the types the tokens declare.
    """
    children = []
    for i, name in enumerate(names):
        hint = hints[i] if i < len(hints) else T_STRING
        slot = Slot(first_slot + i, vtype=hint)
        children.append(el("Data", slot, Name=name) if name is not None else el("Data", slot))
    return El("EventData", list(children))


def event_root(
    sections: Sequence[object], *, channel: str = "Security", computer_slot: bool = False
) -> El:
    """Return an ``Event`` template with the standard ``System`` and then ``sections``.

    ``System`` uses slots 0 to 12, and slot 13 for the computer name when ``computer_slot``.
    """
    computer: str | Slot = Slot(13, vtype=T_STRING) if computer_slot else "dc01.corp.example"
    return El(
        "Event", [_system(computer=computer, channel=channel), *sections], {"xmlns": EVENT_NS}
    )


def event_values(  # noqa: PLR0913 - every option is a keyword a test may damage
    record_id: int,
    event_id: int = 4624,
    *,
    when: datetime | None = None,
    computer: str | None = None,
    version: int = 1,
    activity: uuid.UUID | None = None,
    user_sid: str | None = "S-1-5-18",
    qualifiers: int | None = None,
) -> list[Value]:
    """Return the values for the standard ``System`` slots; slot 13 is the computer name."""
    stamp = when or datetime(2026, 11, 10, 2, 15, 3, 123456, tzinfo=UTC)
    return [
        integer(T_UINT16, event_id),
        integer(T_UINT16, qualifiers) if qualifiers is not None else null(),
        integer(T_UINT8, version),
        integer(T_UINT8, 0),
        integer(T_UINT16, 13824),
        integer(T_UINT8, 0),
        integer(T_HEX64, 0x8020000000000000),
        # Keep the 100 ns digit the datetime cannot hold, so the reader's truncation shows.
        Value(T_FILETIME, struct.pack("<Q", filetime_of(stamp) + 7)),
        integer(T_UINT64, record_id),
        guid(activity) if activity else null(),
        integer(T_UINT32, 572),
        integer(T_UINT32, 3068),
        sid(user_sid) if user_sid else null(),
        string(computer or ""),
    ]


_TEMPLATES: dict[tuple[object, ...], El] = {}


def security_event(
    record_id: int,
    event_id: int = 4624,
    *,
    data: Sequence[tuple[str | None, str | Value]] = (),
    mode: str = "inline",
    channel: str = "Security",
    **system: object,
) -> Instance:
    """Return a template instance for a Security-style event with named data.

    ``mode`` is ``inline`` (EventData is part of the template), ``embedded`` (EventData
    arrives as a Binary XML value), or ``none`` (no EventData). Other keyword arguments
    go to :func:`event_values`.
    """
    names = [name for name, _ in data]
    items = [value if isinstance(value, Value) else string(value) for _, value in data]
    hints = [item.hint if item.hint is not None else T_STRING for item in items]
    use_computer = system.get("computer") is not None
    key = (tuple(names), tuple(hints), mode, channel, use_computer)
    if key not in _TEMPLATES:
        sections: list[object] = []
        if mode == "inline":
            sections.append(data_section(names, 14, hints))
        elif mode == "embedded":
            sections.append(Slot(14, vtype=T_BINXML))
        _TEMPLATES[key] = event_root(sections, channel=channel, computer_slot=use_computer)
    values = event_values(record_id, event_id, **system)  # type: ignore[arg-type]
    if mode == "inline":
        values += items
    elif mode == "embedded":
        values.append(embedded(Instance(data_section(names, 0, hints), items)))
    return Instance(_TEMPLATES[key], values)


def make_chunk(
    events: Sequence[Instance | El],
    *,
    first_id: int = 1,
    configure: Callable[[ChunkBuilder], None] | None = None,
    **finish: object,
) -> bytes:
    """Return a chunk holding ``events`` with consecutive record ids."""
    builder = ChunkBuilder()
    if configure:
        configure(builder)
    for i, content in enumerate(events):
        builder.add_record(first_id + i, content)
    return builder.finish(**finish)  # type: ignore[arg-type]
