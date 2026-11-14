# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read input files and build the account: the one path from files to findings."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from faithful_toledot import catalog as catalog_module
from faithful_toledot import correlate, formats
from faithful_toledot.errors import InputError
from faithful_toledot.outputs.safety import visible

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from faithful_toledot.changes import Account
    from faithful_toledot.events import ReadOptions

_BLOCK = 1024 * 1024


@dataclass(frozen=True)
class InputFile:
    """One input file as it was when toledot read it.

    Attributes:
        name: The file's name as given.
        format: The detected format, one of :data:`faithful_toledot.formats.FORMATS`.
        scope: ``unfiltered`` when the user stated the file is a whole log, else
            ``unknown``; a collection file states its own scope.
        size: Its size in bytes.
        sha256: The SHA-256 of its bytes.
    """

    name: str
    format: str
    scope: str
    size: int
    sha256: str


def display_name(path: Path) -> str:
    r"""Return a file's name as valid text, showing bytes that are not UTF-8 as ``\xff``."""
    return os.fsencode(path.name).decode("utf-8", "backslashreplace")


def display_path(path: Path) -> str:
    r"""Return a path as the user gave it, as valid text (bytes that are not UTF-8 as ``\xff``)."""
    return os.fsencode(str(path)).decode("utf-8", "backslashreplace")


class _TextNamed:
    """A path whose ``name`` is always valid text; everything else is the real path's.

    The readers take a path and make their own source names from ``path.name``. On
    Linux a name can hold bytes that are not UTF-8, and the report could not be
    written with them. Readers see this wrapper, so every name they make is text.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self.name = display_name(path)

    def __str__(self) -> str:
        return str(self._path)

    def __getattr__(self, attribute: str) -> Any:
        return getattr(self._path, attribute)


def fingerprint(path: Path) -> tuple[int, str]:
    """Return a file's size and SHA-256, reading it in blocks.

    Raises:
        InputError: The file cannot be read.
    """
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while block := handle.read(_BLOCK):
                digest.update(block)
                size += len(block)
    except OSError as exc:
        msg = f"cannot read {display_path(path)}: {exc.strerror or exc}"
        raise InputError(msg) from None
    return size, digest.hexdigest()


def run(
    paths: list[Path],
    options: ReadOptions,
    *,
    whole_logs: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
) -> tuple[Account, list[InputFile]]:
    """Read every file and return the account with a record of each input.

    Every file is hashed and its format detected before any is parsed, so a file
    that cannot be used stops the run before work is spent on the others.

    Args:
        paths: The input files, in the order given.
        options: What the files may not say about themselves.
        whole_logs: The user states every file is a whole log, not a filtered export.
        since: Leave out changes before this time.
        until: Leave out changes at or after this time.

    Raises:
        InputError: A file is given twice, two files show the same name, a file cannot be
            read, or a file is in no known format.
    """
    seen: dict[str, str] = {}
    names: set[str] = set()
    files: list[InputFile] = []
    readable = [cast("Path", _TextNamed(path)) for path in paths]
    for path in readable:
        size, digest = fingerprint(path)
        if digest in seen:
            msg = f"{path.name} has the same contents as {seen[digest]}; give each file once"
            raise InputError(msg)
        # Compare names as reports show them: a zero-width space and the text
        # "\u200b" are different names that print the same.
        shown = visible(path.name)
        if shown in names:
            msg = f"two input files are named {shown}; rename one so every citation names one file"
            raise InputError(msg)
        seen[digest] = path.name
        names.add(shown)
        scope = "unfiltered" if whole_logs else "unknown"
        files.append(InputFile(path.name, formats.detect(path), scope, size, digest))
    inputs = [
        correlate.Input(file.name, formats.read(path, options, file.format), file.scope)
        for path, file in zip(readable, files, strict=True)
    ]
    account = correlate.build(inputs, catalog_module.load(), since=since, until=until)
    return account, files
