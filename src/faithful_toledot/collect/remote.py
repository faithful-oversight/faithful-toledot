# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the collector on a domain controller over PowerShell remoting.

The packaged script is sent to the controller and run there with ``-ToPipeline``.
Its lines stream back and are written to a file next to the destination, and the
file is published only after its end line checks out: the event count and the
SHA-256 the script computed over what it sent must match what arrived. A partial
file is never left behind.

faithful-core runs the connection, the transport rules, the secret handling, and the
rule that every failure discards the private file; see ``faithful_core.collect.winrm``.
This module holds what is toledot's own: the checks on each line, the end line, the
script's parameters, and the result.

Rights: the account must be allowed to open a PowerShell remoting session on the
controller (by default, members of Administrators or Remote Management Users) and
to read the logs (Event Log Readers, or an administrator). Microsoft documents both
groups; whether a just-enough-administration endpoint can be narrowed further for
this script has not been tested.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import os
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from faithful_core.collect import names, winrm

from faithful_toledot.errors import CollectionError
from faithful_toledot.formats import bundle

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from pathlib import Path

install_hint = functools.partial(names.install_hint, "faithful-toledot")
"""Say how to install toledot with extras, for the messages faithful-core writes."""
_END = b'{"end":'
_END_KEY = b'"end"'


@dataclass(frozen=True)
class Result:
    """What a collection wrote.

    Attributes:
        path: The published file.
        events: How many events it holds.
        gaps: What the collector could not read, as ``area: reason`` sentences.
    """

    path: Path
    events: int
    gaps: tuple[str, ...]


def parameters(
    since: datetime | None,
    until: datetime | None,
    days: int,
    channels: list[str],
    *,
    every_event: bool,
) -> dict[str, Any]:
    """Return the script's parameters for a remote run."""
    values: dict[str, Any] = {"ToPipeline": True, "Method": "psrp", "Channel": channels}
    if since is not None:
        values["Since"] = bundle.format_time(since)
    else:
        values["Days"] = days
    if until is not None:
        values["Until"] = bundle.format_time(until)
    if every_event:
        values["All"] = True
    return values


class _Sink:
    """Write streamed lines to a private file and check them as they come."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination
        self.temp = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.part"
        descriptor = os.open(self.temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.handle = os.fdopen(descriptor, "wb")
        self.digest = hashlib.sha256()
        self.events = 0
        self.trailer: bundle.Trailer | None = None
        self.lines = 0

    @property
    def ended(self) -> bool:
        return self.trailer is not None

    def take(self, item: object) -> None:
        if self.trailer is not None:
            msg = "the collector sent output after its end line"
            raise CollectionError(msg)
        if not isinstance(item, str) or not item.isascii() or "\n" in item or "\r" in item:
            msg = (
                f"the collector sent something that is not one line of text (line {self.lines + 1})"
            )
            raise CollectionError(msg)
        raw = item.encode("ascii") + b"\n"
        if len(raw) > bundle.MAX_LINE:
            msg = f"line {self.lines + 1} from the collector is too long"
            raise CollectionError(msg)
        if self.lines == 0 and not raw.startswith(bundle.MARKER):
            msg = "the collector's first line is not a toledot header"
            raise CollectionError(msg)
        # The header and end line must pass the rules read_bundle applies, or the file
        # would be published and then refused by the reader.
        if self.lines == 0:
            try:
                bundle.check_header(raw, self.destination.name)
            except bundle.BadLineError as exc:
                msg = f"the collector's header is not valid: {exc}"
                raise CollectionError(msg) from None
        elif _END_KEY in raw:
            self.trailer = self._end_line(raw)
        self.lines += 1
        self.handle.write(raw)
        if self.trailer is not None:
            return
        self.digest.update(raw)
        if self.lines > 1:
            self.events += 1

    @staticmethod
    def _end_line(raw: bytes) -> bundle.Trailer | None:
        """Return the checked end line, or ``None`` when ``raw`` is an event line."""
        try:
            value = bundle.decode_line(raw)
        except bundle.BadLineError as exc:
            if raw.startswith(_END):
                msg = f"the collector's end line is not valid: {exc}"
                raise CollectionError(msg) from None
            return None  # an event that merely mentions "end" in its text
        if "end" not in value:
            return None
        try:
            return bundle.check_end(value)
        except bundle.BadLineError as exc:
            msg = f"the collector's end line is not valid: {exc}"
            raise CollectionError(msg) from None

    def finish(self) -> Result:
        """Check the end line against what arrived."""
        self.handle.close()
        trailer = self.trailer
        if trailer is None:
            msg = "the collection ended without its end line, so it did not finish"
            raise CollectionError(msg)
        if trailer.events != self.events or trailer.sha256 != self.digest.hexdigest():
            msg = (
                f"the collection's end line does not match what arrived ({self.events} events "
                "received); the transfer was damaged"
            )
            raise CollectionError(msg)
        gaps = tuple(f"{area}: {reason}" for area, reason in trailer.gaps)
        if trailer.unlisted_gaps:
            gaps += (f"{trailer.unlisted_gaps} further gaps are not listed",)
        return Result(self.destination, self.events, gaps)

    def publish(self, *, force: bool) -> None:
        """Put the checked file in place without following a link or clobbering."""
        winrm.publish_file(self.temp, self.destination, force=force)

    def discard(self) -> None:
        with contextlib.suppress(OSError):
            self.handle.close()
        with contextlib.suppress(OSError):
            self.temp.unlink()


def collect(  # noqa: PLR0913 - one argument per collection choice
    target: winrm.Target,
    script: str,
    script_parameters: dict[str, Any],
    destination: Path,
    *,
    force: bool,
    clock: Callable[[], float] = time.monotonic,
) -> Result:
    """Run the collector on the target and write its file to ``destination``.

    Raises:
        CollectionError: The connection, authentication, or collection failed, or
            what arrived does not match the collector's end line. Every message has
            the secret removed, and no partial file is left.
    """
    try:
        sink = _Sink(destination)
    except OSError as exc:
        msg = f"cannot write to {destination.parent}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    return winrm.collect(
        target,
        script,
        script_parameters,
        destination,
        sink=sink,
        noun="collector",
        hint=install_hint("live"),
        force=force,
        clock=clock,
    )
