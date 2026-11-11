# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the three text-export readers (XML, JSON, CSV).

The readers parse files that are untrusted data. This module holds what they have in
common: reading a text file in bounded chunks with strict decoding, splitting it into
bounded lines, parsing timestamps without guessing, rendering values the way Windows
event XML would, and naming duplicate fields.

Nothing here knows about one format. Each reader keeps its own rules for what a record
means.
"""

from __future__ import annotations

import codecs
import itertools
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, TypeVar

from faithful_toledot.errors import InputError

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator, Mapping, MutableMapping
    from pathlib import Path

    from faithful_toledot.events import ReadOptions

T = TypeVar("T")

READ_CHUNK = 64 * 1024
"""Bytes read from a file at a time. Memory use does not depend on the file's size."""
MAX_NAME_CHARS = 256
"""Longest field name, attribute value, or label accepted. Real names are under 64."""
MAX_VALUE_CHARS = 1 << 20
"""Longest single field value accepted, in characters. Real values are far shorter."""
MAX_EVENT_CHARS = 8 << 20
"""Most characters one event may hold in all its values together."""
MAX_FIELDS = 1024
"""Most data fields one event may hold. Real events have under 100."""

SYSTEM_ORDER = (
    "Keywords",
    "Level",
    "Task",
    "Opcode",
    "ActivityID",
    "RelatedActivityID",
    "ProcessID",
    "ThreadID",
    "UserID",
)
"""The order ``Event.system`` keys are written in, so every format agrees."""


class TimestampError(ValueError):
    """A timestamp is not valid, or cannot be read without a guess."""


class NaiveTimestampError(TimestampError):
    """A timestamp carries no UTC offset and no offset was supplied."""


class AmbiguousDateError(TimestampError):
    """A numeric date could be day first or month first and no order was supplied."""


# --- reading text -------------------------------------------------------------------


def sniff_encoding(head: bytes, name: str) -> tuple[str, int]:
    """Choose a codec from the first bytes of a file.

    Args:
        head: At least the first four bytes of the file, or all of a shorter file.
        name: The file's name, for messages.

    Returns:
        The codec name and the length of the byte order mark to skip. UTF-8 (with or
        without a mark) and UTF-16 with a mark are accepted. A file with no mark is read
        as UTF-8, and decoding is strict, so anything else fails instead of being altered.

    Raises:
        InputError: The file is UTF-32, or looks like UTF-16 without a byte order mark.
    """
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8", 3
    if head.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        msg = f"{name} is UTF-32 text, which toledot does not read; re-export it as UTF-8 or UTF-16"
        raise InputError(msg)
    if head.startswith(b"\xff\xfe"):
        return "utf-16-le", 2
    if head.startswith(b"\xfe\xff"):
        return "utf-16-be", 2
    if b"\x00" in head[:4]:
        msg = (
            f"{name} contains NUL bytes at its start. It looks like UTF-16 without a byte "
            "order mark; re-export it as UTF-8 or as UTF-16 with a mark"
        )
        raise InputError(msg)
    return "utf-8", 0


def read_chunks(path: Path) -> Generator[str, None, None]:
    """Yield a file's text in chunks, decoded strictly.

    The file is opened when iteration starts and closed when it ends or the generator is
    closed. A NUL character, a byte sequence that is not valid in the file's encoding
    (including a lone UTF-16 surrogate), and a file cut in the middle of a character are
    all errors, never replaced.

    Raises:
        InputError: The file cannot be read, is empty, or fails one of the checks above.
    """
    name = path.name
    try:
        with path.open("rb") as handle:
            head = handle.read(READ_CHUNK)
            if not head:
                msg = f"{name} is empty"
                raise InputError(msg)
            codec, skip = sniff_encoding(head[:4], name)
            label = codec.upper().removesuffix("-LE").removesuffix("-BE")
            decoder = codecs.getincrementaldecoder(codec)("strict")
            data = head[skip:]
            offset = skip
            chars = 0
            while data:
                try:
                    text = decoder.decode(data)
                except UnicodeDecodeError as exc:
                    # Hand on the text before the bad bytes, so records in it are not lost.
                    held = decoder.getstate()[0]
                    good = codecs.getincrementaldecoder(codec)("strict").decode(
                        (held + data)[: exc.start]
                    )
                    if good:
                        yield good
                    where = offset - len(held) + exc.start
                    msg = f"{name} is not valid {label} text (near byte {where})"
                    raise InputError(msg) from None
                nul = text.find("\x00")
                if nul >= 0:
                    if nul:
                        yield text[:nul]
                    msg = f"{name} contains a NUL character (near character {chars + nul})"
                    raise InputError(msg)
                chars += len(text)
                offset += len(data)
                if text:
                    yield text
                data = handle.read(READ_CHUNK)
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                msg = f"{name} ends in the middle of a {label} character; the file is cut short"
                raise InputError(msg) from None
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror or exc}"
        raise InputError(msg) from None


_EOL = re.compile(r"\r\n|\r|\n")


def split_lines(
    chunks: Iterable[str], *, max_chars: int, keepends: bool
) -> Generator[tuple[int, str | None], None, None]:
    r"""Split text chunks into numbered lines, none longer than ``max_chars``.

    A line ends at ``\r\n``, ``\r`` or ``\n``, including when the two characters of a
    ``\r\n`` fall in different chunks, so line numbers are exact. A line longer than
    ``max_chars`` is discarded without being held in memory and reported as ``None``.
    Work is linear in the size of the input.

    Args:
        chunks: Pieces of text, in order.
        max_chars: The longest line to return, not counting its terminator.
        keepends: Whether each line keeps its terminator, as ``csv`` needs.

    Yields:
        The 1-based line number and the line, or ``None`` for a line over the limit.
    """
    parts: list[str] = []
    size = 0
    dropped = False
    number = 0
    carry = ""
    for chunk in itertools.chain(chunks, (None,)):
        if chunk is None:
            text = carry
        else:
            text = carry + chunk
            carry = ""
            if text.endswith("\r"):  # may be the first half of \r\n; wait for the next chunk
                carry = "\r"
                text = text[:-1]
        pos = 0
        for match in _EOL.finditer(text):
            tail = text[pos : match.start()]
            number += 1
            if dropped or size + len(tail) > max_chars:
                yield number, None
            else:
                body = "".join(parts) + tail
                yield number, (body + match.group() if keepends else body)
            parts.clear()
            size = 0
            dropped = False
            pos = match.end()
        rest = text[pos:]
        if rest and not dropped:
            parts.append(rest)
            size += len(rest)
            if size > max_chars:
                dropped = True
                parts.clear()
                size = 0
    if dropped or parts:
        number += 1
        yield number, (None if dropped else "".join(parts))


def eager(items: Generator[T, None, None], *, empty: str) -> Iterator[T]:
    """Run a reader until its first item, so structural errors surface at the call.

    Args:
        items: A reader's generator.
        empty: The :class:`InputError` message if the file holds no records at all.

    Raises:
        InputError: The generator raised one before its first item, or yielded nothing.
    """
    try:
        first = next(items)
    except StopIteration:
        raise InputError(empty) from None
    return _resume(first, items)


def _resume(first: T, items: Generator[T, None, None]) -> Iterator[T]:
    try:
        yield first
        yield from items
    finally:
        items.close()


def check_options(options: ReadOptions) -> None:
    """Refuse a ``local_offset`` that is not a real UTC offset.

    Raises:
        InputError: The offset is 24 hours or more in either direction.
    """
    offset = options.local_offset
    if offset is not None and not timedelta(hours=-24) < offset < timedelta(hours=24):
        msg = "local_offset must be less than 24 hours from UTC"
        raise InputError(msg)


# --- timestamps ---------------------------------------------------------------------

_ISO = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:[.,]([0-9]{1,9}))?"
    r" ?(Z|z|[+-][0-9]{2}(?::?[0-9]{2})?)?",
    re.ASCII,
)
_ISO_START = re.compile(r"[0-9]{4}-", re.ASCII)
_CLOCK = re.compile(
    r"([0-9]{1,2})([/.])([0-9]{1,2})\2([0-9]{4})[ T]+"
    r"([0-9]{1,2}):([0-9]{2})(?::([0-9]{2})(?:[.,]([0-9]{1,9}))?)?"
    r"[\s\u202f\u00a0]*([AaPp][Mm])?",
    re.ASCII,
)


def _offset(text: str) -> timezone:
    if text in {"Z", "z"}:
        return UTC
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    hours = int(digits[:2])
    minutes = int(digits[2:] or "0")
    if hours > 23 or minutes > 59:  # noqa: PLR2004 - fixed limits of the format
        msg = "its UTC offset is not valid"
        raise TimestampError(msg)
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _make(
    clock: tuple[int, int, int, int, int, int],
    fraction: str | None,
    zone: timezone | None,
    local_offset: timedelta | None,
) -> datetime:
    """Build a UTC time from (year, month, day, hour, minute, second) and a zone."""
    if zone is None:
        if local_offset is None:
            msg = "it has no UTC offset"
            raise NaiveTimestampError(msg)
        zone = timezone(local_offset)
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    try:
        return datetime(*clock, micro, tzinfo=zone).astimezone(UTC)
    except (ValueError, OverflowError):
        msg = "it is not a real date and time"
        raise TimestampError(msg) from None


def parse_iso(text: str, *, local_offset: timedelta | None) -> datetime:
    """Parse an ISO 8601 timestamp such as ``2026-11-10T02:15:03.1234567Z`` into UTC.

    The offset may be ``Z``, ``+HH``, ``+HH:MM`` or ``+HHMM``. The ``T`` may be a space.
    Up to nine fractional digits are accepted and cut to microseconds, the most a Python
    ``datetime`` holds, so Windows' 100 nanosecond ticks lose their last digit.

    Args:
        text: The timestamp.
        local_offset: The offset to assume when the text has none, or ``None`` to refuse.

    Raises:
        NaiveTimestampError: The text has no offset and ``local_offset`` is ``None``.
        TimestampError: The text is not a valid timestamp.
    """
    match = _ISO.fullmatch(text)
    if match is None:
        msg = "it is not an ISO 8601 timestamp"
        raise TimestampError(msg)
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    clock = (int(year), int(month), int(day), int(hour), int(minute), int(second))
    return _make(clock, fraction, _offset(zone) if zone else None, local_offset)


def parse_clock(text: str, *, local_offset: timedelta | None, day_first: bool | None) -> datetime:
    """Parse a numeric local date and time such as ``11/10/2026 8:15:03 PM`` into UTC.

    This is the form Event Viewer and ``Export-Csv`` write. It has no offset, so
    ``local_offset`` is required. With ``day_first`` ``None``, a date is accepted only
    if one reading is impossible (``13/10/2026``) or both readings agree (``05/05/2026``).

    Raises:
        NaiveTimestampError: ``local_offset`` is ``None``.
        AmbiguousDateError: Day and month could be either way round and ``day_first`` is
            ``None``.
        TimestampError: The text is not a valid date and time.
    """
    match = _CLOCK.fullmatch(text)
    if match is None:
        msg = "it is not a recognised date and time"
        raise TimestampError(msg)
    first, _sep, second_part, year, hour_text, minute, second, fraction, meridiem = match.groups()
    if local_offset is None:
        msg = "it has no UTC offset"
        raise NaiveTimestampError(msg)
    day, month = _day_and_month(int(first), int(second_part), day_first=day_first)
    hour = int(hour_text)
    if meridiem is not None:
        if not 1 <= hour <= 12:  # noqa: PLR2004 - fixed limits of the format
            msg = "its hour is not valid with AM or PM"
            raise TimestampError(msg)
        hour = hour % 12 + (12 if meridiem.lower() == "pm" else 0)
    clock = (int(year), month, day, hour, int(minute), int(second or "0"))
    return _make(clock, fraction, None, local_offset)


def _day_and_month(a: int, b: int, *, day_first: bool | None) -> tuple[int, int]:
    """Decide which of two numbers is the day, or refuse if that is a guess."""
    if day_first is True:
        return a, b
    if day_first is False:
        return b, a
    if a == b or (a > 12 and b <= 12):  # noqa: PLR2004 - fixed limits of the format
        return a, b
    if b > 12 and a <= 12:  # noqa: PLR2004 - fixed limits of the format
        return b, a
    if a > 12 and b > 12:  # noqa: PLR2004 - fixed limits of the format
        msg = "it is not a real date and time"
        raise TimestampError(msg)
    msg = "its day and month could be either way round"
    raise AmbiguousDateError(msg)


def parse_timestamp(
    text: str,
    *,
    local_offset: timedelta | None,
    day_first: bool | None = None,
    allow_clock: bool = False,
) -> datetime:
    """Parse an ISO 8601 timestamp, or (if ``allow_clock``) a numeric local date and time.

    See :func:`parse_iso` and :func:`parse_clock` for the rules and errors.
    """
    if allow_clock and _ISO_START.match(text) is None:
        return parse_clock(text, local_offset=local_offset, day_first=day_first)
    return parse_iso(text, local_offset=local_offset)


def iso_utc(moment: datetime) -> str:
    """Write a UTC time the way Windows event XML does: ``2026-11-10T02:15:03.1230000Z``."""
    utc = moment.astimezone(UTC)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond:06d}0Z"


# --- rendering values ---------------------------------------------------------------

_DECIMAL = re.compile(r"-?[0-9]{1,20}", re.ASCII)
_UNSIGNED = re.compile(r"[0-9]{1,20}", re.ASCII)
_HEX = re.compile(r"0[xX][0-9a-fA-F]{1,16}", re.ASCII)
_GUID = re.compile(
    r"\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?",
    re.ASCII,
)


def parse_unsigned(text: str, maximum: int) -> int | None:
    """Return the non-negative decimal integer in ``text`` if it is at most ``maximum``."""
    text = text.strip()
    if _UNSIGNED.fullmatch(text) is None:
        return None
    value = int(text)
    return value if value <= maximum else None


def render_keywords(text: str) -> str:
    """Write an event's keyword mask as Windows event XML does, such as ``0x8020000000000000``.

    ``Get-WinEvent`` exports the mask as a signed 64-bit decimal number; XML writes the
    same bits in hexadecimal. A value already in ``0x`` form is returned in lower case.

    Raises:
        ValueError: The text is neither a 64-bit decimal number nor a hexadecimal one.
    """
    if _HEX.fullmatch(text):
        return "0x" + text[2:].lower()
    if _DECIMAL.fullmatch(text):
        number = int(text)
        if -(1 << 63) <= number < (1 << 64):
            return f"0x{number & ((1 << 64) - 1):x}"
    msg = "Keywords is not a 64-bit number"
    raise ValueError(msg)


def render_guid(text: str) -> str:
    """Write a GUID as Windows event XML does: upper case, in braces.

    Raises:
        ValueError: The text is not a GUID.
    """
    match = _GUID.fullmatch(text)
    if match is None:
        msg = "an ID is not a GUID"
        raise ValueError(msg)
    return "{" + match.group(1).upper() + "}"


def system_from_export(raw: Mapping[str, str]) -> dict[str, str]:
    """Build ``Event.system`` from text values read from a JSON or CSV export.

    Args:
        raw: Values by canonical name (``Keywords``, ``Level``, ``Task``, ``Opcode``,
            ``ActivityID``, ``RelatedActivityID``, ``ProcessID``, ``ThreadID``,
            ``UserID``). Empty values are left out.

    Raises:
        ValueError: A value is not what its name requires. The message names the field.
    """
    system: dict[str, str] = {}
    for key in SYSTEM_ORDER:
        text = raw.get(key, "")
        if not text:
            continue
        if key == "Keywords":
            system[key] = render_keywords(text)
        elif key in {"ActivityID", "RelatedActivityID"}:
            try:
                system[key] = render_guid(text)
            except ValueError:
                msg = f"{key} is not a GUID"
                raise ValueError(msg) from None
        elif key == "UserID":
            if len(text) > MAX_NAME_CHARS:
                msg = "UserID is too long"
                raise ValueError(msg)
            system[key] = text
        else:
            if _UNSIGNED.fullmatch(text) is None:
                msg = f"{key} is not a non-negative whole number"
                raise ValueError(msg)
            system[key] = text
    return system


def add_data(data: MutableMapping[str, str], counts: dict[str, int], name: str, value: str) -> None:
    """Add a field, naming a repeat ``name#2``, ``name#3`` and so on.

    The first field of a name keeps the name. A later field of the same name is stored as
    ``name#2``, then ``name#3``; if such a name is itself already taken, the next free
    number is used, so no value is ever overwritten. ``counts`` holds how many times each
    name has been seen and belongs to one event.
    """
    seen = counts.get(name, 0)
    key = name
    if seen or name in data:
        seen = max(seen, 1) + 1
        key = f"{name}#{seen}"
        while key in data:
            seen += 1
            key = f"{name}#{seen}"
    else:
        seen = 1
    counts[name] = seen
    data[key] = value
