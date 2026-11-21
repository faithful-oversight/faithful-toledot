# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read native Windows Event Log (``.evtx``) files with the standard library only.

An ``.evtx`` file comes from a machine the reader does not control, so every
number in it is treated as hostile: each offset and size is checked against the
chunk it points into before it is used, nesting and counts are capped, and the
file is read one 64 KiB chunk at a time, never whole.

What is read, and from where:

- The container: file header, 64 KiB chunks, and event records (libevtx format
  documentation, sections "File header", "Chunk header", "Event record").
- Binary XML inside each record ([MS-EVEN6] 2.2.12 and 3.1.4.7; libevtx
  "Binary XML"): tokens, name strings found by chunk offset, template
  definitions (inline on first use, then pointed to), substitution arrays with
  every documented value type, and embedded Binary XML (type 0x21).
- Recovery rules for dirty files and bad records (libevtx "Recovery" and
  "Corruption scenarios").

What the reader decides, so a reviewer does not have to guess:

- **Wrong file, impossible header.** Raised as :class:`InputError` when
  :func:`read_evtx` is called, before anything is yielded: wrong magic, a file
  shorter than the 4096 byte header, a header size or block size other than
  128 and 4096, or a format version other than 3.0 to 3.2.
- **File header checksum.** A mismatch yields a :class:`Problem` first. The
  fields that depend on it (chunk count, flags) are then not trusted, which
  costs nothing because chunks are always found by scanning to the end of the
  file.
- **Dirty flag, stale chunk count, truncated tail.** Each yields one
  :class:`Problem` before the records, saying the log was not closed cleanly,
  that the header count differs from the chunks present, or that the file ends
  in a partial chunk. Chunks past the header's count are read.
- **Empty chunks.** An all-zero chunk is normal at the end of a log and is
  silent. One followed by a chunk that holds data is reported, because
  something zeroed the middle of the log.
- **Chunk header checksum mismatch, bad magic, bad header size, bad free-space
  offset.** One :class:`Problem` naming the chunk and, where readable, its
  record-id range; the chunk is skipped, because nothing in a header that does
  not check out can be relied on to find the records.
- **Event-records checksum mismatch.** One :class:`Problem`, then the records
  are still decoded, each on its own merits. This is safe because every record
  is bounds-checked (size, size copy, and every offset inside it); a log being
  written when it was copied fails this checksum with intact records.
- **A bad record.** A :class:`Problem` with the record id when it is known;
  reading continues at the next record. If the record's size cannot be
  trusted, the reader scans forward for the next record signature.
- **Record count.** When a chunk finishes with a different number of records
  than its header range implies, one :class:`Problem` says so, so records lost
  without a trace cannot go unreported.

Values are rendered as Windows renders them in event XML. Integers are
decimal. Hex integers and size_t are ``0x`` plus lowercase digits. FILETIME is
``YYYY-MM-DDTHH:MM:SS.fffffffZ`` with seven digits (100 ns). SYSTEMTIME has
three digits. A GUID is uppercase in braces. A SID is ``S-1-5-...``. Binary is
uppercase hex without separators. A bool is ``true`` or ``false``. See the
notes beside each renderer for what was and was not confirmed against Windows.

Limits (module constants below) bound time and memory per record and per chunk.
"""

from __future__ import annotations

import math
import re
import struct
import uuid
import zlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn, TypeAlias, cast

from faithful_toledot.errors import InputError
from faithful_toledot.events import Event, Problem, Source

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from faithful_toledot.events import ReadOptions

__all__ = ["read_evtx"]

# --- Container layout (libevtx "File header", "Chunk header", "Event record") ---

_FILE_MAGIC = b"ElfFile\x00"
_CHUNK_MAGIC = b"ElfChnk\x00"
_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
_FILE_HEADER_SIZE = 4096
_CHUNK_SIZE = 65536
_CHUNK_HEADER_SIZE = 512
_RECORD_HEADER_SIZE = 24  # magic, size, record id, written FILETIME
_RECORD_MIN_SIZE = _RECORD_HEADER_SIZE + 4  # header and the trailing copy of the size
_RECORD_PADDING = 8  # records are padded to a multiple of this; padding is 0 to 7 bytes
_ZERO_CHUNK = bytes(_CHUNK_SIZE)
_DIRTY_FLAG = 0x0001
_NO_CRC32_FLAG = 0x0004  # in the file header and in chunk headers: no checksums are stored
_SUPPORTED_MINOR_VERSIONS = (0, 1, 2)

# --- Limits. Each bounds work done for hostile input; legitimate events are far below. ---

#: Deepest nesting of elements inside one template definition or element tree.
_MAX_ELEMENT_DEPTH = 32
#: Deepest nesting of template instances and embedded Binary XML values.
_MAX_TEMPLATE_DEPTH = 8
#: Most elements plus attributes built for one record, counting array repeats.
_MAX_NODES = 4096
#: Most characters of substituted text built for one record. Stops a template that
#: names one large value many times from multiplying it.
_MAX_TEXT_CHARS = 512 * 1024
#: Most substitution values in one template instance. Windows allows far fewer.
_MAX_SUBSTITUTIONS = 1024
#: Most items in one array value.
_MAX_ARRAY_ITEMS = 4096
#: Most characters in an element, attribute, or entity name.
_MAX_NAME_CHARS = 256
#: Most template definition bytes parsed for one chunk. A real chunk holds its
#: definitions once, so one chunk of definitions is the honest ceiling; sixteen
#: times that leaves room and stops overlapping fake definitions.
_MAX_DEFINITION_BYTES = 16 * _CHUNK_SIZE

# --- Binary XML tokens and value types ([MS-EVEN6] 2.2.12, libevtx "Token types") ---

_TOKEN_EOF = 0x00
_TOKEN_CLOSE_START = 0x02
_TOKEN_CLOSE_EMPTY = 0x03
_TOKEN_END_ELEMENT = 0x04
_TOKEN_ATTRIBUTE = (0x06, 0x46)
_TOKEN_OPEN_ELEMENT = (0x01, 0x41)
_TOKEN_PI_TARGET = 0x0A
_TOKEN_PI_DATA = 0x0B
_TOKEN_TEMPLATE = 0x0C
_TOKEN_FRAGMENT_HEADER = 0x0F
#: Tokens that carry one piece of text, by token byte (the 0x40 bit means "more follows").
_TEXT_TOKENS = {
    0x05: "text",
    0x45: "text",
    0x07: "cdata",
    0x47: "cdata",
    0x08: "charref",
    0x48: "charref",
    0x09: "entity",
    0x49: "entity",
    0x0D: "subst",
    0x0E: "subst",
}
_ATTRIBUTE_VALUE_KINDS = frozenset({"text", "charref", "entity", "subst"})
_ENTITIES = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}

_TOKEN_OPTIONAL_SUBST = 0x0E
_SUBST_TOKEN_SIZE = 3  # after the token byte: a 2 byte value number and a 1 byte declared type
_SURROGATES = range(0xD800, 0xE000)
_FILE_HEADER_FIELD = 128  # the header size both headers state
_MAJOR_VERSION = 3
_SID_HEADER = 8
_T_NULL = 0x00
_T_REAL32 = 0x0B
_T_REAL64 = 0x0C
_T_GUID = 0x0F
_T_FILETIME = 0x11
_T_STRING = 0x01
_T_ANSI = 0x02
_T_BOOL = 0x0D
_T_BINARY = 0x0E
_T_SIZE = 0x10
_T_SID = 0x13
_T_HEX32 = 0x14
_T_HEX64 = 0x15
_T_BINXML = 0x21
_T_ARRAY = 0x80
_INT_FORMATS = {
    0x03: "<b",
    0x04: "<B",
    0x05: "<h",
    0x06: "<H",
    0x07: "<i",
    0x08: "<I",
    0x09: "<q",
    0x0A: "<Q",
}
#: Byte width of each fixed-size type.
_WIDTHS = {
    0x03: 1,
    0x04: 1,
    0x05: 2,
    0x06: 2,
    0x07: 4,
    0x08: 4,
    0x09: 8,
    0x0A: 8,
    0x0B: 4,
    0x0C: 8,
    0x0D: 4,
    0x0F: 16,
    0x11: 8,
    0x12: 16,
    _T_HEX32: 4,
    _T_HEX64: 8,
}
_BOOL_WIDTHS = (1, 2, 4)
_MAX_SID_SUBAUTHORITIES = 15
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_TICKS_PER_SECOND = 10_000_000
_ANSI_CODEC = "cp1252"
_MAX_INTEGER = 2**64 - 1  # EventID, Version and record numbers are at most 64 bits
_MAX_INTEGER_DIGITS = len(str(_MAX_INTEGER))

_SYSTEM_TIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z",
    re.ASCII,
)

#: System fields kept in ``Event.system`` under these names; others keep ``Element@Attr``.
_SYSTEM_RENAMES = {
    "Level": "Level",
    "Task": "Task",
    "Opcode": "Opcode",
    "Keywords": "Keywords",
    "Correlation@ActivityID": "ActivityID",
    "Correlation@RelatedActivityID": "RelatedActivityID",
    "Execution@ProcessID": "ProcessID",
    "Execution@ThreadID": "ThreadID",
    "Security@UserID": "UserID",
    "Provider@Guid": "ProviderGuid",
    "Provider@EventSourceName": "EventSourceName",
}
#: System fields turned into typed ``Event`` attributes, so not repeated in ``system``.
_SYSTEM_CONSUMED = frozenset(
    {
        "EventID",
        "EventID@Qualifiers",
        "Version",
        "TimeCreated@SystemTime",
        "EventRecordID",
        "Channel",
        "Computer",
        "Provider@Name",
    }
)


class _DecodeError(Exception):
    """A record, or the part of a file being read, cannot be decoded; the message says why."""


def _fail(message: str) -> NoReturn:
    raise _DecodeError(message)


# --- Rendered and parsed trees ---


class _Subst(NamedTuple):
    """A substitution token in a template definition."""

    slot: int
    optional: bool
    hint: int  # the token's declared value type; only a size_t array needs it


_AttrPart: TypeAlias = "str | _Subst"
_Part: TypeAlias = "str | _Subst | _Elem"


class _Elem:
    """An element as written in a template definition, before values are filled in."""

    __slots__ = ("attrs", "children", "name")

    def __init__(self, name: str) -> None:
        self.name = name
        self.attrs: list[tuple[str, list[_AttrPart]]] = []
        self.children: list[_Part] = []


class _Node:
    """An element after substitution: the XML Windows would show."""

    __slots__ = ("attrs", "children", "name")

    def __init__(self, name: str, attrs: dict[str, str], children: list[_Node | str]) -> None:
        self.name = name
        self.attrs = attrs
        self.children = children

    def elements(self) -> list[_Node]:
        """Return the child elements, in order."""
        return [c for c in self.children if isinstance(c, _Node)]

    def text(self) -> str:
        """Return the text content; an element that has child elements has no plain text."""
        parts: list[str] = []
        for child in self.children:
            if isinstance(child, str):
                parts.append(child)
            else:
                _fail(f"<{self.name}> holds an element where text was expected")
        return "".join(parts)


class _Embedded(NamedTuple):
    """A value that is itself Binary XML, by position in the chunk."""

    start: int
    size: int


class _Instance:
    """The substitution values of one template instance."""

    __slots__ = ("cache", "slots")

    def __init__(self, slots: list[tuple[int, int, int]]) -> None:
        self.slots = slots  # (type, offset in chunk, size)
        self.cache: dict[tuple[int, int], str | list[str] | _Embedded | None] = {}


_NO_VALUES = _Instance([])


# --- Value rendering ---


def _utf16(raw: bytes, what: str) -> str:
    if len(raw) % 2:
        _fail(f"{what} has an odd number of bytes")
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        _fail(f"{what} is not valid UTF-16")
    return text


def _split_terminated(text: str) -> list[str]:
    """Split NUL-terminated strings; a last string without its NUL still counts."""
    parts = text.split("\x00")
    if parts[-1] == "":
        parts.pop()
    return parts


def _no_nul(text: str, what: str) -> str:
    if "\x00" in text:
        _fail(f"{what} contains a NUL character")
    return text


def _ansi(raw: bytes) -> str:
    try:
        return raw.decode(_ANSI_CODEC)
    except UnicodeDecodeError:
        _fail("an ANSI string has a byte with no character in Windows-1252")


def _sid_length(raw: bytes, pos: int) -> int:
    """Return the byte length of the SID at ``pos``, checking it is a SID."""
    if len(raw) - pos < _SID_HEADER:
        _fail("a SID is cut short")
    if raw[pos] != 1:
        _fail("a SID has an unknown revision")
    count = raw[pos + 1]
    if count > _MAX_SID_SUBAUTHORITIES:
        _fail("a SID has too many sub-authorities")
    length = 8 + 4 * count
    if len(raw) - pos < length:
        _fail("a SID is cut short")
    return length


def _sid_text(raw: bytes) -> str:
    """Render a SID the way ConvertSidToStringSid does, e.g. ``S-1-5-18``."""
    authority = int.from_bytes(raw[2:8], "big")
    # Windows writes an authority that does not fit 32 bits as 0x plus 12 hex digits.
    head = str(authority) if authority < 1 << 32 else f"0x{authority:012x}"
    subs = struct.unpack_from(f"<{raw[1]}I", raw, 8)
    return "-".join(["S", str(raw[0]), head, *map(str, subs)])


def _filetime(raw: bytes) -> str:
    seconds, ticks = divmod(struct.unpack("<Q", raw)[0], _TICKS_PER_SECOND)
    try:
        when = _FILETIME_EPOCH + timedelta(seconds=seconds)
    except OverflowError:
        _fail("a FILETIME is past the year 9999")
    return (
        f"{when.year:04d}-{when.month:02d}-{when.day:02d}"
        f"T{when.hour:02d}:{when.minute:02d}:{when.second:02d}.{ticks:07d}Z"
    )


def _systemtime(raw: bytes) -> str:
    year, month, _weekday, day, hour, minute, second, millis = struct.unpack("<8H", raw)
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{millis:03d}Z"


def _real(raw: bytes) -> str:
    # Windows spells the specials "1.#INF" and "-1.#IND". Other values are written
    # here with 7 (float) or 15 (double) significant digits, which was not compared
    # against Windows output.
    value = struct.unpack("<f" if len(raw) == _WIDTHS[_T_REAL32] else "<d", raw)[0]
    if math.isnan(value):
        return "-1.#IND"
    if math.isinf(value):
        return "1.#INF" if value > 0 else "-1.#INF"
    return f"{value:.7g}" if len(raw) == _WIDTHS[_T_REAL32] else f"{value:.15g}"


def _bool(raw: bytes) -> str:
    if len(raw) not in _BOOL_WIDTHS:
        _fail("a boolean value has an unexpected size")
    number = int.from_bytes(raw, "little")
    # Windows stores bit masks in some bool slots, so a value other than 0 or 1 is
    # kept as the number it is rather than being forced to "true".
    if number > 1:
        return str(number)
    return "true" if number else "false"


def _scalar(vtype: int, raw: bytes) -> str:
    """Render one non-array value of ``vtype`` from exactly its bytes."""
    if not raw:
        return ""  # A value with no bytes renders as empty text, whatever its type.
    if vtype in (_T_STRING, _T_ANSI):
        what = "a string" if vtype == _T_STRING else "an ANSI string"
        text = _utf16(raw, what) if vtype == _T_STRING else _ansi(raw)
        return _no_nul(text.rstrip("\x00"), what)
    if vtype == _T_BINARY:
        return raw.hex().upper()
    if vtype == _T_SID:
        if _sid_length(raw, 0) != len(raw):
            _fail("a SID is followed by extra bytes")
        return _sid_text(raw)
    if vtype == _T_BOOL:
        return _bool(raw)
    if vtype == _T_SIZE:
        if len(raw) not in (4, 8):
            _fail("a size_t value is neither 4 nor 8 bytes")
        vtype = _T_HEX32 if len(raw) == _WIDTHS[_T_HEX32] else _T_HEX64
    return _fixed(vtype, raw)


def _fixed(vtype: int, raw: bytes) -> str:
    width = _WIDTHS.get(vtype)
    if width is None:
        _fail(f"value type 0x{vtype:02x} is not supported")
    if len(raw) != width:
        _fail(f"a value of type 0x{vtype:02x} has {len(raw)} bytes, not {width}")
    if vtype in _INT_FORMATS:
        return str(struct.unpack(_INT_FORMATS[vtype], raw)[0])
    if vtype in (_T_HEX32, _T_HEX64):
        return f"0x{int.from_bytes(raw, 'little'):x}"
    if vtype in (_T_REAL32, _T_REAL64):
        return _real(raw)
    if vtype == _T_GUID:
        return "{" + str(uuid.UUID(bytes_le=raw)).upper() + "}"
    if vtype == _T_FILETIME:
        return _filetime(raw)
    return _systemtime(raw)


def _array(vtype: int, raw: bytes, hint: int) -> list[str]:
    """Render an array value into its items; ``hint`` is the token's type for size_t."""
    base = vtype & 0x7F
    if base == _T_STRING:
        return [_no_nul(s, "a string") for s in _split_terminated(_utf16(raw, "a string array"))]
    if base == _T_ANSI:
        return [_no_nul(s, "an ANSI string") for s in _split_terminated(_ansi(raw))]
    if base == _T_SID:
        return _sid_array(raw)
    if base == _T_SIZE:
        if hint not in (_T_HEX32 | _T_ARRAY, _T_HEX64 | _T_ARRAY, _T_HEX32, _T_HEX64):
            _fail("a size_t array does not say whether its items have 4 or 8 bytes")
        base = _T_HEX32 if hint & 0x7F == _T_HEX32 else _T_HEX64
    width = _WIDTHS.get(base)
    if width is None:
        _fail(f"arrays of value type 0x{base:02x} are not supported")
    if len(raw) % width:
        _fail(f"an array of type 0x{base:02x} does not hold a whole number of items")
    if len(raw) // width > _MAX_ARRAY_ITEMS:
        _fail("an array has too many items")
    return [_scalar(base, raw[i : i + width]) for i in range(0, len(raw), width)]


def _sid_array(raw: bytes) -> list[str]:
    items: list[str] = []
    pos = 0
    while pos < len(raw):
        length = _sid_length(raw, pos)
        if len(items) >= _MAX_ARRAY_ITEMS:
            _fail("an array has too many items")
        items.append(_sid_text(raw[pos : pos + length]))
        pos += length
    return items


# --- Binary XML ---


class _Chunk:
    """One chunk's bytes plus what Binary XML caches per chunk: names and templates."""

    __slots__ = ("chars", "data", "def_bytes", "defs", "names", "nodes")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.names: dict[int, str] = {}
        # Definition by header offset, or the reason it cannot be read.
        self.defs: dict[int, _Elem | str] = {}
        self.def_bytes = 0
        self.nodes = 0
        self.chars = 0

    # Bounded readers. ``end`` is the end of the region being read, never the chunk's.

    def u8(self, pos: int, end: int) -> int:
        if pos < 0 or pos >= end:
            _fail("data ends inside a token")
        return self.data[pos]

    def u16(self, pos: int, end: int) -> int:
        if pos < 0 or pos + 2 > end:
            _fail("data ends inside a token")
        return int(struct.unpack_from("<H", self.data, pos)[0])

    def u32(self, pos: int, end: int) -> int:
        if pos < 0 or pos + 4 > end:
            _fail("data ends inside a token")
        return int(struct.unpack_from("<I", self.data, pos)[0])

    def spend_nodes(self, count: int = 1) -> None:
        self.nodes += count
        if self.nodes > _MAX_NODES:
            _fail("the event holds too many elements")

    def spend_chars(self, count: int) -> None:
        self.chars += count
        if self.chars > _MAX_TEXT_CHARS:
            _fail("the event holds too much text")

    # Names

    def name_at(self, offset: int, end: int) -> tuple[str, int]:
        """Return the name stored at a chunk offset and the byte size of its record."""
        if offset < _CHUNK_HEADER_SIZE:
            _fail("a name points into the chunk header")
        count = self.u16(offset + 6, end)
        if count == 0 or count > _MAX_NAME_CHARS:
            _fail("a name has an impossible length")
        size = 8 + 2 * count + 2
        if offset + size > end:
            _fail("data ends inside a name")
        name = self.names.get(offset)
        if name is None:
            raw = self.data[offset + 8 : offset + size]
            if raw[-2:] != b"\x00\x00":
                _fail("a name is not terminated")
            name = _no_nul(_utf16(raw[:-2], "a name"), "a name")
            self.names[offset] = name
        return name, size

    def name_ref(self, pos: int, end: int) -> tuple[str, int]:
        """Read a name reference at ``pos``; inline names follow the reference."""
        offset = self.u32(pos, end)
        pos += 4
        if offset == pos:
            name, size = self.name_at(offset, end)
            return name, pos + size
        return self.name_at(offset, _CHUNK_SIZE)[0], pos

    # Text pieces

    def length_prefixed(self, pos: int, end: int, what: str) -> tuple[str, int]:
        count = self.u16(pos, end)
        stop = pos + 2 + 2 * count
        if stop > end:
            _fail(f"data ends inside {what}")
        text = _utf16(self.data[pos + 2 : stop], what)
        return _no_nul(text, what), stop

    def text_piece(self, kind: str, pos: int, end: int) -> tuple[str | _Subst, int]:
        """Read one text-bearing token at ``pos`` (the token byte itself)."""
        token = self.data[pos]
        pos += 1
        if kind == "text":
            if self.u8(pos, end) != _T_STRING:
                _fail("a value token is not a string")
            return self.length_prefixed(pos + 1, end, "text")
        if kind == "cdata":
            return self.length_prefixed(pos, end, "a CDATA section")
        if kind == "charref":
            code = self.u16(pos, end)
            if code == 0 or code in _SURROGATES:
                _fail("a character reference is not a character")
            return chr(code), pos + 2
        if kind == "entity":
            name, pos = self.name_ref(pos, end)
            if name not in _ENTITIES:
                _fail("an entity reference names an unknown entity")
            return _ENTITIES[name], pos
        slot = self.u16(pos, end)
        hint = self.u8(pos + 2, end)
        return _Subst(slot, token == _TOKEN_OPTIONAL_SUBST, hint), pos + _SUBST_TOKEN_SIZE

    def skip_pi(self, pos: int, end: int) -> int:
        """Skip a processing instruction; it carries nothing an event needs."""
        _, pos = self.name_ref(pos + 1, end)
        if self.u8(pos, end) != _TOKEN_PI_DATA:
            _fail("a processing instruction has no data")
        return self.length_prefixed(pos + 1, end, "processing instruction data")[1]

    # Element parsing (template definitions and plain elements)

    def attribute_value(self, pos: int, end: int) -> tuple[list[_AttrPart], int]:
        parts: list[_AttrPart] = []
        while pos < end:
            kind = _TEXT_TOKENS.get(self.data[pos])
            if kind is None:
                break
            if kind not in _ATTRIBUTE_VALUE_KINDS:
                _fail("an attribute holds a CDATA section")
            piece, pos = self.text_piece(kind, pos, end)
            _add_part(parts, piece)
        return parts, pos

    def attributes(self, elem: _Elem, pos: int, end: int) -> int:
        size = self.u32(pos, end)
        pos += 4
        stop = pos + size
        if stop > end:
            _fail("an attribute list extends beyond its element")
        while pos < stop:
            token = self.u8(pos, stop)
            if token not in _TOKEN_ATTRIBUTE:
                _fail("an attribute list holds something that is not an attribute")
            name, pos = self.name_ref(pos + 1, stop)
            parts, pos = self.attribute_value(pos, stop)
            elem.attrs.append((name, parts))
            if (token == _TOKEN_ATTRIBUTE[0]) != (pos == stop):
                _fail("an attribute list ends early or runs on")
        return stop

    def element(self, pos: int, end: int, depth: int, *, in_definition: bool) -> tuple[_Elem, int]:
        """Parse the element whose open token is at ``pos``.

        Only elements in a template definition carry a 2 byte dependency id (unused here);
        elements written directly in a record or an embedded value do not.
        """
        if depth >= _MAX_ELEMENT_DEPTH:
            _fail("elements are nested too deeply")
        token = self.u8(pos, end)
        skip = 2 if in_definition else 0
        size = self.u32(pos + 1 + skip, end)  # of everything after this field
        pos += 5 + skip
        stop = pos + size
        if stop > end:
            _fail("an element extends beyond its parent")
        name, pos = self.name_ref(pos, stop)
        elem = _Elem(name)
        if token == _TOKEN_OPEN_ELEMENT[1]:
            pos = self.attributes(elem, pos, stop)
        closing = self.u8(pos, stop)
        pos += 1
        if closing == _TOKEN_CLOSE_START:
            pos = self.content(elem, pos, stop, depth, in_definition=in_definition)
        elif closing != _TOKEN_CLOSE_EMPTY:
            _fail("an element start is not closed")
        if pos != stop:
            _fail("an element's size does not match its content")
        return elem, pos

    def content(self, elem: _Elem, pos: int, end: int, depth: int, *, in_definition: bool) -> int:
        """Parse element content up to and including the end-element token."""
        while True:
            token = self.u8(pos, end)
            if token == _TOKEN_END_ELEMENT:
                return pos + 1
            kind = _TEXT_TOKENS.get(token)
            if kind is not None:
                piece, pos = self.text_piece(kind, pos, end)
                _add_part(elem.children, piece)
            elif token in _TOKEN_OPEN_ELEMENT:
                child, pos = self.element(pos, end, depth + 1, in_definition=in_definition)
                elem.children.append(child)
            elif token == _TOKEN_PI_TARGET:
                pos = self.skip_pi(pos, end)
            else:
                _fail(f"unexpected token 0x{token:02x} in element content")

    # Templates

    def definition(self, header: int, limit: int) -> _Elem:
        """Return the template definition whose header is at ``header``, parsing it once."""
        cached = self.defs.get(header)
        if cached is None:
            try:
                cached = self.parse_definition(header, limit)
            except _DecodeError as exc:
                cached = str(exc)
            self.defs[header] = cached
        if isinstance(cached, str):
            _fail(cached)
        return cached

    def parse_definition(self, header: int, limit: int) -> _Elem:
        # Header: next definition offset (4), template GUID (16), data size (4).
        size = self.u32(header + 20, limit)
        start = header + 24
        stop = start + size
        if stop > limit:
            _fail("a template definition extends beyond its data")
        self.def_bytes += size
        if self.def_bytes > _MAX_DEFINITION_BYTES:
            _fail("this chunk holds too much template data")
        pos = start
        while self.u8(pos, stop) == _TOKEN_FRAGMENT_HEADER:
            pos = self.fragment_header(pos, stop)
        if self.u8(pos, stop) not in _TOKEN_OPEN_ELEMENT:
            _fail("a template definition does not start with an element")
        elem, pos = self.element(pos, stop, 0, in_definition=True)
        if pos + 1 != stop or self.data[pos] != _TOKEN_EOF:
            _fail("a template definition does not end where its size says")
        return elem

    def fragment_header(self, pos: int, end: int) -> int:
        if pos + 4 > end or self.data[pos + 1 : pos + 3] != b"\x01\x01":
            _fail("a fragment header is not version 1.1")
        return pos + 4

    def instance_values(self, pos: int, end: int) -> tuple[_Instance, int]:
        count = self.u32(pos, end)
        if count > _MAX_SUBSTITUTIONS:
            _fail("a template instance has too many values")
        pos += 4
        data_pos = pos + 4 * count
        if data_pos > end:
            _fail("a template instance's value list is cut short")
        slots: list[tuple[int, int, int]] = []
        for size, vtype in struct.iter_unpack("<HBx", self.data[pos:data_pos]):
            if data_pos + size > end:
                _fail("a template value extends beyond the record")
            slots.append((vtype, data_pos, size))
            data_pos += size
        return _Instance(slots), data_pos

    def template(self, pos: int, end: int, depth: int) -> tuple[list[_Node], int]:
        """Parse a template instance whose token is at ``pos`` and build its element."""
        # Token, 1 unknown byte, 4 byte template id (unused), 4 byte definition offset.
        offset = self.u32(pos + 6, end)
        pos += 10
        if offset == pos:
            limit = pos + 24 + self.u32(pos + 20, end)
            if limit > end:
                _fail("a template definition extends beyond its record")
            elem = self.definition(pos, limit)
            pos = limit
        elif _CHUNK_HEADER_SIZE <= offset <= _CHUNK_SIZE - 24:
            elem = self.definition(offset, _CHUNK_SIZE)
        else:
            _fail("a template points outside the chunk")
        inst, pos = self.instance_values(pos, end)
        return self.build(elem, inst, depth), pos

    # Building the element tree

    def value(self, inst: _Instance, sub: _Subst) -> str | list[str] | _Embedded | None:
        """Return the rendered value a substitution names; ``None`` is a NULL value."""
        if sub.slot >= len(inst.slots):
            _fail("a substitution names a value the template instance does not have")
        vtype, start, size = inst.slots[sub.slot]
        key = (sub.slot, sub.hint)
        if key in inst.cache:
            return inst.cache[key]
        result: str | list[str] | _Embedded | None
        if vtype == _T_NULL:
            result = None
        elif vtype == _T_BINXML:
            result = _Embedded(start, size)
        elif vtype & _T_ARRAY:
            result = _array(vtype, self.data[start : start + size], sub.hint)
        else:
            result = _scalar(vtype, self.data[start : start + size])
        inst.cache[key] = result
        return result

    def attribute_text(self, parts: list[_AttrPart], inst: _Instance) -> str | None:
        """Return an attribute's value, or ``None`` when it must not be written."""
        out: list[str] = []
        for part in parts:
            if isinstance(part, str):
                out.append(part)
                continue
            val = self.value(inst, part)
            if val is None:
                if part.optional:
                    return None
            elif isinstance(val, str):
                self.spend_chars(len(val))
                out.append(val)
            else:
                _fail("an attribute holds an array or Binary XML value")
        return "".join(out) or None

    def build(self, elem: _Elem, inst: _Instance, depth: int) -> list[_Node]:
        """Fill in an element: a list, because an array value repeats its element."""
        self.spend_nodes()
        attrs: dict[str, str] = {}
        for name, parts in elem.attrs:
            self.spend_nodes()
            text = self.attribute_text(parts, inst)
            if text is not None:
                attrs[name] = text
        items = self.child_items(elem, inst, depth)
        if items is None:
            return []
        arrays = [item for item in items if isinstance(item, list)]
        if not arrays:
            return [_Node(elem.name, attrs, _merge(cast("list[_Node | str]", items)))]
        if any(len(a) != len(arrays[0]) for a in arrays):
            _fail("arrays in one element have different lengths")
        copies = max(len(arrays[0]), 1)  # an empty array still makes one empty element
        self.spend_nodes(copies - 1)
        return [
            _Node(elem.name, attrs, _merge([_pick(item, n) for item in items]))
            for n in range(copies)
        ]

    def child_items(
        self, elem: _Elem, inst: _Instance, depth: int
    ) -> list[_Node | str | list[str]] | None:
        """Resolve content; ``None`` means an optional NULL value removes the element."""
        items: list[_Node | str | list[str]] = []
        for child in elem.children:
            if isinstance(child, str):
                items.append(child)
            elif isinstance(child, _Elem):
                items.extend(self.build(child, inst, depth))
            else:
                val = self.value(inst, child)
                if val is None:
                    if child.optional:
                        return None
                elif isinstance(val, _Embedded):
                    self.spend_nodes()
                    items.extend(self.stream(val.start, val.start + val.size, depth + 1))
                else:
                    self.spend_chars(sum(map(len, val)) if isinstance(val, list) else len(val))
                    items.append(val)
        return items

    # Whole streams

    def stream(self, pos: int, end: int, depth: int) -> list[_Node]:
        """Decode a Binary XML stream (a record body or an embedded value) to elements."""
        if depth > _MAX_TEMPLATE_DEPTH:
            _fail("templates are nested too deeply")
        nodes: list[_Node] = []
        while pos < end:
            token = self.data[pos]
            if token == _TOKEN_EOF:
                # Windows pads a record to 8 bytes with whatever was in memory, so a few
                # bytes after the end token are allowed; more are not.
                if end - pos - 1 >= _RECORD_PADDING:
                    _fail("data follows the end of the Binary XML")
                break
            if token == _TOKEN_FRAGMENT_HEADER:
                pos = self.fragment_header(pos, end)
            elif token == _TOKEN_PI_TARGET:
                pos = self.skip_pi(pos, end)
            elif token == _TOKEN_TEMPLATE:
                built, pos = self.template(pos, end, depth)
                nodes.extend(built)
            elif token in _TOKEN_OPEN_ELEMENT:
                elem, pos = self.element(pos, end, 0, in_definition=False)
                nodes.extend(self.build(elem, _NO_VALUES, depth))
            else:
                _fail(f"unexpected token 0x{token:02x} at the start of Binary XML")
        return nodes

    def record(self, start: int, end: int) -> _Node:
        """Decode one record's Binary XML into its single event element."""
        self.nodes = 0
        self.chars = 0
        nodes = self.stream(start, end, 0)
        if len(nodes) != 1:
            _fail("the record does not hold exactly one element")
        return nodes[0]


def _pick(item: _Node | str | list[str], n: int) -> _Node | str:
    """Return item ``n`` of an array value; any other item is the same in every repeat."""
    if isinstance(item, list):
        return item[n] if item else ""
    return item


def _add_part(parts: list[Any], piece: str | _Subst) -> None:
    """Append a piece of text, joining it to a text piece before it."""
    if isinstance(piece, str) and parts and isinstance(parts[-1], str):
        parts[-1] += piece
    else:
        parts.append(piece)


def _merge(items: list[_Node | str]) -> list[_Node | str]:
    """Join neighbouring text pieces."""
    merged: list[_Node | str] = []
    for item in items:
        if isinstance(item, str) and merged and isinstance(merged[-1], str):
            merged[-1] += item
        else:
            merged.append(item)
    return merged


# --- From the element tree to an Event ---


def _system_fields(system: _Node) -> dict[str, str]:
    """Flatten ``<System>`` to ``Element`` and ``Element@Attribute`` keys."""
    fields: dict[str, str] = {}
    for child in system.elements():
        entries = {f"{child.name}@{key}": value for key, value in child.attrs.items()}
        if any(isinstance(c, str) and c for c in child.children) or not entries:
            entries[child.name] = child.text()
        for key, value in entries.items():
            if key in fields:
                _fail(f"<System> holds {key} twice")
            fields[key] = value
    return fields


def _integer(fields: dict[str, str], key: str) -> int:
    """Read an unsigned whole number of at most 64 bits (EventID, Version, record numbers).

    The text is bounded before it is converted: a substituted string of thousands of digits
    must become a damaged record, not Python's integer-conversion limit error.
    """
    text = fields[key]
    if not (text.isascii() and text.isdecimal()):
        _fail(f"{key} is not a whole number")
    if len(text) > _MAX_INTEGER_DIGITS or int(text) > _MAX_INTEGER:
        _fail(f"{key} does not fit in 64 bits")
    return int(text)


def _event_time(text: str) -> datetime:
    match = _SYSTEM_TIME.fullmatch(text)
    if match is None:
        _fail("TimeCreated is not a date and time")
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    fraction = (match.group(7) or "").ljust(9, "0")
    try:
        # A FILETIME counts 100 ns; a datetime keeps 1 µs, so the last digits go.
        return datetime(year, month, day, hour, minute, second, int(fraction[:6]), tzinfo=UTC)
    except ValueError:
        _fail("TimeCreated is not a real date and time")


def _unique(data: dict[str, str], key: str) -> str:
    """Return ``key``, or ``key#2``, ``key#3`` and so on when it is taken."""
    if key not in data:
        return key
    number = 2
    while f"{key}#{number}" in data:
        number += 1
    return f"{key}#{number}"


def _event_data(section: _Node, data: dict[str, str]) -> None:
    position = 0
    for child in section.elements():
        if child.name == "Data":
            position += 1  # counts every Data element, named or not, as the XML reader does
        name = child.attrs.get("Name")
        if not name and child.name == "Data":
            name = f"param{position}"
        data[_unique(data, name or child.name)] = child.text()


def _flatten(node: _Node, prefix: str, data: dict[str, str]) -> None:
    """Add a UserData element's attributes and leaf elements to ``data``."""
    for key, value in node.attrs.items():
        if key != "xmlns" and not key.startswith("xmlns:"):
            data[_unique(data, f"{prefix}{key}")] = value
    for child in node.elements():
        path = f"{prefix}{child.name}"
        if child.elements():
            _flatten(child, f"{path}/", data)
        else:
            _flatten_leaf(child, path, data)


def _flatten_leaf(node: _Node, path: str, data: dict[str, str]) -> None:
    data[_unique(data, path)] = node.text()
    for key, value in node.attrs.items():
        if key != "xmlns" and not key.startswith("xmlns:"):
            data[_unique(data, f"{path}@{key}")] = value


def _user_data(section: _Node, data: dict[str, str]) -> None:
    children = section.elements()
    if len(children) > 1:
        _fail("<UserData> holds more than one element")
    for child in children:
        _flatten(child, "", data)


def _event_from(root: _Node, header_id: int, file_name: str) -> Event:
    """Map a decoded ``<Event>`` element to an :class:`Event`."""
    if root.name != "Event":
        _fail("the record's element is not <Event>")
    sections = root.elements()
    systems = [s for s in sections if s.name == "System"]
    if len(systems) != 1:
        _fail("the event does not hold exactly one <System>")
    fields = _system_fields(systems[0])
    for key in ("EventID", "TimeCreated@SystemTime", "Channel", "Computer"):
        if key not in fields:
            _fail(f"<System> has no {key}")
    # A provider with no registered name (some ETW providers) is known by its GUID, which
    # is what Event Viewer shows as the source then.
    provider = fields.get("Provider@Name") or fields.get("Provider@Guid")
    if provider is None:
        _fail("<System> has no Provider@Name")
    # The event's own number is what Event Viewer shows. It differs from the record header's
    # number in forwarded logs, where the event keeps the number it had on its source machine.
    record_id = _integer(fields, "EventRecordID") if "EventRecordID" in fields else header_id
    data: dict[str, str] = {}
    for section in sections:
        if section.name == "EventData":
            _event_data(section, data)
        elif section.name == "UserData":
            _user_data(section, data)
    return Event(
        event_id=_integer(fields, "EventID"),
        time=_event_time(fields["TimeCreated@SystemTime"]),
        computer=fields["Computer"],
        channel=fields["Channel"],
        provider=provider,
        record_id=record_id,
        data=data,
        source=Source(file_name, f"record {header_id}"),
        version=_integer(fields, "Version") if "Version" in fields else 0,
        system={
            _SYSTEM_RENAMES.get(key, key): value
            for key, value in fields.items()
            if key not in _SYSTEM_CONSUMED and (value or "@" in key)
        },
    )


# --- The container ---


class _FileHeader(NamedTuple):
    chunk_count: int
    flags: int
    crc_ok: bool  # True also when the header says it stores no checksum


def _crc(*parts: bytes) -> int:
    value = 0
    for part in parts:
        value = zlib.crc32(part, value)
    return value


def _read_header(path: Path) -> tuple[_FileHeader, int]:
    """Check the file header and return it with the file's size.

    Raises:
        InputError: The file cannot be read, is not an EVTX file, or has a header that
            no Windows version writes.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(_FILE_HEADER_SIZE)
            size = handle.seek(0, 2)
    except OSError as exc:
        msg = f"cannot read {path.name}: {exc.strerror or exc}"
        raise InputError(msg) from None
    if not raw.startswith(_FILE_MAGIC):
        msg = f"{path.name} is not a Windows event log (.evtx) file: wrong signature"
        raise InputError(msg)
    if len(raw) < _FILE_HEADER_SIZE:
        msg = f"{path.name} is cut off inside its {_FILE_HEADER_SIZE} byte file header"
        raise InputError(msg)
    header_size, minor, major, block_size, chunk_count = struct.unpack_from("<IHHHH", raw, 32)
    flags, stored_crc = struct.unpack_from("<II", raw, 120)
    if header_size != _FILE_HEADER_FIELD or block_size != _FILE_HEADER_SIZE:
        msg = f"{path.name} has a file header that is not the EVTX layout"
        raise InputError(msg)
    if major != _MAJOR_VERSION or minor not in _SUPPORTED_MINOR_VERSIONS:
        msg = f"{path.name} is EVTX format version {major}.{minor}; only 3.0 to 3.2 are read"
        raise InputError(msg)
    crc_ok = bool(flags & _NO_CRC32_FLAG) or _crc(raw[:120]) == stored_crc
    return _FileHeader(chunk_count, flags, crc_ok), size


def read_evtx(path: Path, options: ReadOptions) -> Iterator[Event | Problem]:
    """Read every event record in a Windows ``.evtx`` file.

    The header is checked when this is called, so a file that is not an event log
    fails here, before any item is produced. Records are then decoded lazily, one
    chunk at a time, in file order. Anything that cannot be read becomes a
    :class:`Problem`; see the module documentation for what each case reports.

    Args:
        path: The ``.evtx`` file.
        options: Unused; an ``.evtx`` file records everything needed to read it.

    Returns:
        An iterator of events and problems, in file order.

    Raises:
        InputError: The file cannot be read or is not an EVTX file.
    """
    del options
    header, size = _read_header(path)
    return _read_chunks(path, header, size)


def _file_notes(name: str, header: _FileHeader, size: int) -> Iterator[Problem]:
    """Yield what the file header and the file's size say about how far to trust it."""
    here = Source(name, "file header")
    present, extra = divmod(size - _FILE_HEADER_SIZE, _CHUNK_SIZE)
    if header.flags & _NO_CRC32_FLAG:
        yield Problem(
            here,
            "the file says it stores no checksums, so whether its chunks and records are "
            "intact could not be checked",
        )
    elif not header.crc_ok:
        yield Problem(
            here,
            "the file header checksum does not match, so its chunk count and flags are not "
            "trusted; chunks were found by scanning the file",
        )
    if header.flags & _DIRTY_FLAG:
        yield Problem(
            here,
            "the log was not closed cleanly (it is marked dirty), so the chunk count in "
            f"its header ({header.chunk_count}) may be stale; the {present} chunks present "
            "were read by scanning, and the last records may be incomplete",
        )
    elif header.chunk_count != present:
        yield Problem(
            here,
            f"the header counts {header.chunk_count} chunks but the file holds {present}; "
            "chunks were found by scanning the file",
        )
    if extra:
        yield Problem(
            Source(name, f"end of file, offset {size - extra}"),
            f"the file ends with {extra} bytes that do not make a whole chunk "
            "(it was cut off or was still being written)",
        )


def _read_chunks(path: Path, header: _FileHeader, size: int) -> Iterator[Event | Problem]:
    yield from _file_notes(path.name, header, size)
    empty: list[int] = []
    with path.open("rb") as handle:
        for index in range((size - _FILE_HEADER_SIZE) // _CHUNK_SIZE):
            handle.seek(_FILE_HEADER_SIZE + index * _CHUNK_SIZE)
            data = handle.read(_CHUNK_SIZE)
            if data == _ZERO_CHUNK:
                empty.append(index)
                continue
            if empty:
                yield _empty_chunks_problem(path.name, empty)
                empty = []
            yield from _read_chunk(
                path.name, index, data, no_crc=bool(header.flags & _NO_CRC32_FLAG)
            )


def _empty_chunks_problem(name: str, empty: list[int]) -> Problem:
    which = f"chunk {empty[0]}" if len(empty) == 1 else f"chunks {empty[0]} to {empty[-1]}"
    return Problem(
        Source(name, which),
        f"{which} is all zeros, but later chunks hold records; records may have been lost",
    )


class _ChunkHeader(NamedTuple):
    first_id: int
    last_id: int
    free_offset: int
    records_crc: int
    no_crc: bool  # the chunk says it stores no checksums
    where: str  # how to name the chunk in messages


def _chunk_header(name: str, index: int, data: bytes) -> _ChunkHeader | Problem:
    """Check a chunk's header; return it, or the problem that makes the chunk unusable."""
    if not data.startswith(_CHUNK_MAGIC):
        return Problem(
            Source(name, f"chunk {index}"),
            f"chunk {index} does not start with the chunk signature and is skipped",
        )
    first_id, last_id = struct.unpack_from("<2Q", data, 24)
    where = f"chunk {index}, records {first_id} to {last_id}"
    header_size, _last_offset, free, records_crc = struct.unpack_from("<4I", data, 40)
    flags, header_crc = struct.unpack_from("<2I", data, 120)
    no_crc = bool(flags & _NO_CRC32_FLAG)
    source = Source(name, f"chunk {index}")
    if header_size != _FILE_HEADER_FIELD:
        return Problem(source, f"{where} has an unknown header size and is skipped")
    if not no_crc and _crc(data[:120], data[128:_CHUNK_HEADER_SIZE]) != header_crc:
        return Problem(
            source, f"the header checksum of {where} does not match; the chunk is skipped"
        )
    if not _CHUNK_HEADER_SIZE <= free <= _CHUNK_SIZE:
        return Problem(source, f"{where} has a free-space offset outside the chunk and is skipped")
    return _ChunkHeader(first_id, last_id, free, records_crc, no_crc, where)


def _read_chunk(name: str, index: int, data: bytes, *, no_crc: bool) -> Iterator[Event | Problem]:
    """Yield the events and problems of one chunk."""
    head = _chunk_header(name, index, data)
    if isinstance(head, Problem):
        yield head
        return
    source = Source(name, f"chunk {index}")
    if head.no_crc:
        if not no_crc:
            yield Problem(
                source,
                f"{head.where} says it stores no checksums, so whether it is intact could "
                "not be checked",
            )
    elif _crc(data[_CHUNK_HEADER_SIZE : head.free_offset]) != head.records_crc:
        yield Problem(
            source,
            f"the records checksum of {head.where} does not match; its records were read one "
            "by one and may be incomplete or damaged",
        )
    tally = _Tally()
    yield from _read_records(name, index, data, head.free_offset, tally)
    expected = head.last_id - head.first_id + 1
    claimed = head.last_id >= head.first_id and (head.last_id or tally.records)
    if claimed and tally.records != expected:
        yield Problem(
            source,
            f"{head.where} should hold {expected} records by its header, "
            f"but {tally.records} were found",
        )


class _Tally:
    """Counts the record structures found in a chunk, readable or not."""

    __slots__ = ("records",)

    def __init__(self) -> None:
        self.records = 0


def _read_records(
    name: str, index: int, data: bytes, free: int, tally: _Tally
) -> Iterator[Event | Problem]:
    """Walk the records of a chunk, resynchronizing after anything that is not one."""
    chunk = _Chunk(data)
    pos = _CHUNK_HEADER_SIZE
    while pos < free:
        if data[pos : pos + 4] != _RECORD_MAGIC:
            if not data[pos:free].strip(b"\x00"):
                return  # Zero padding up to the free-space offset is normal.
            yield Problem(
                Source(name, f"chunk {index}, offset {pos}"),
                f"chunk {index} has bytes at offset {pos} where a record should start",
            )
            pos = _next_record(data, pos, free)
            continue
        tally.records += 1
        size, record_id = struct.unpack_from("<IQ", data, pos + 4) if pos + 16 <= free else (0, 0)
        stop = pos + size
        if (
            size < _RECORD_MIN_SIZE
            or stop > free
            or struct.unpack_from("<I", data, stop - 4)[0] != size
        ):
            yield Problem(
                Source(name, f"chunk {index}, offset {pos}"),
                f"the record at offset {pos} of chunk {index} has a size that does not match "
                "its copy at the end of the record, or runs past the chunk's records",
                record_id or None,
            )
            pos = _next_record(data, pos + 3, free)
            continue
        yield _decode_record(chunk, name, index, record_id, (pos, stop))
        pos = stop


def _next_record(data: bytes, pos: int, free: int) -> int:
    """Return where the next record signature after ``pos`` starts, or ``free``."""
    found = data.find(_RECORD_MAGIC, pos + 1, free)
    return free if found < 0 else found


def _decode_record(
    chunk: _Chunk, name: str, index: int, record_id: int, bounds: tuple[int, int]
) -> Event | Problem:
    try:
        root = chunk.record(bounds[0] + _RECORD_HEADER_SIZE, bounds[1] - 4)
        return _event_from(root, record_id, name)
    except _DecodeError as exc:
        return Problem(
            Source(name, f"record {record_id}"),
            f"record {record_id} in chunk {index} cannot be read: {exc}",
            record_id,
        )
