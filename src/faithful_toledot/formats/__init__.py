# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Readers for every input format, and the one function that picks between them.

The format is decided from the file's first bytes, never from its name: a file
named ``.csv`` that holds XML is read as XML.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from faithful_toledot.errors import InputError
from faithful_toledot.formats import bundle, csv, evtx, json, xml

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from faithful_toledot.events import Event, LogFacts, Problem, ReadOptions

FORMATS = ("evtx", "collection", "xml", "json", "csv")
_SNIFF = 4096
_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


def detect(path: Path) -> str:
    """Name the format of a file from its first bytes.

    Returns:
        One of :data:`FORMATS`.

    Raises:
        InputError: The file cannot be read, is empty, or is none of the formats.
    """
    try:
        with path.open("rb") as handle:
            start = handle.read(_SNIFF)
    except OSError as exc:
        msg = f"cannot read {path.name}: {exc.strerror or exc}"
        raise InputError(msg) from None
    if not start:
        msg = f"{path.name} is empty"
        raise InputError(msg)
    if start.startswith(b"ElfFile\x00"):
        return "evtx"
    if bundle.is_bundle(start):
        return "collection"
    text = start
    utf16 = start.startswith(_BOMS[1:])
    for bom in _BOMS:
        text = text.removeprefix(bom)
    if utf16 or (len(text) > 1 and 0 in (text[0], text[1])):
        text = text.replace(b"\x00", b"")
    text = text.lstrip(b" \t\r\n")
    if text.startswith(b"<"):
        return "xml"
    if text.startswith((b"{", b"[")):
        return "json"
    if b"," in text or b"\t" in text:
        return "csv"
    msg = (
        f"{path.name} is not an event log toledot can read. It reads .evtx files, XML, "
        "JSON, and CSV exports, and files written by its own collectors"
    )
    raise InputError(msg)


def read(
    path: Path, options: ReadOptions, kind: str | None = None
) -> Iterator[Event | Problem | LogFacts]:
    """Read one input file in whatever format it is.

    Args:
        path: The file.
        options: What the file itself may not say; see :class:`ReadOptions`.
        kind: The format, when the caller already detected it.

    Raises:
        InputError: The file is unreadable as a whole.
    """
    readers = {
        "evtx": evtx.read_evtx,
        "collection": bundle.read_bundle,
        "xml": xml.read_xml,
        "json": json.read_json,
        "csv": csv.read_csv,
    }
    return readers[kind or detect(path)](path, options)
