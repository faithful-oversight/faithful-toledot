# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the collector on a domain controller over PowerShell remoting.

The packaged script is sent to the controller and run there with ``-ToPipeline``.
Its lines stream back and are written to a file next to the destination, and the
file is published only after its end line checks out: the event count and the
SHA-256 the script computed over what it sent must match what arrived. A partial
file is never left behind.

Transport security is not optional. HTTPS (port 5986) always verifies the server's
certificate against the system's roots or ``--ca-file``. Plain HTTP (port 5985) is
accepted only with Kerberos, Negotiate, or NTLM message encryption required, which
pypsrp then enforces. Basic and CredSSP authentication are not offered.

Rights: the account must be allowed to open a PowerShell remoting session on the
controller (by default, members of Administrators or Remote Management Users) and
to read the logs (Event Log Readers, or an administrator). Microsoft documents both
groups; whether a just-enough-administration endpoint can be narrowed further for
this script has not been tested.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from faithful_toledot.collect.secrets import redact, remember
from faithful_toledot.errors import CollectionError
from faithful_toledot.formats import bundle

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from pathlib import Path

AUTHS = ("kerberos", "negotiate", "ntlm")
TRANSPORTS = ("https", "http")
POLL_SECONDS = 5
"""How long one wait for output lasts before toledot checks the idle timeout."""
_END = b'{"end":'
_INSTALL = 'remote collection needs pypsrp; install it with: pip install "faithful-toledot[live]"'


@dataclass(frozen=True)
class Target:
    r"""Where and how to connect.

    Attributes:
        server: The controller's fully qualified DNS name.
        auth: One of :data:`AUTHS`.
        username: ``DOMAIN\\user``, or ``None`` to use the current Kerberos ticket.
        secret: The password, already resolved, or ``None``.
        transport: ``https`` or ``http`` (with message encryption).
        port: The port, or ``None`` for 5986 or 5985.
        ca_file: A PEM file of certificate authorities to trust for HTTPS.
        connect_timeout: Seconds to wait for the connection.
        idle_timeout: Seconds without output after which collection stops.
    """

    server: str
    auth: str
    username: str | None = None
    secret: str | None = field(default=None, repr=False)
    transport: str = "https"
    port: int | None = None
    ca_file: Path | None = None
    connect_timeout: int = 30
    idle_timeout: int = 600


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


def settings(target: Target) -> dict[str, Any]:
    """Return the WSMan settings for a target, refusing any insecure combination.

    Raises:
        CollectionError: The authentication or transport is not one toledot offers.
    """
    if target.auth not in AUTHS or target.transport not in TRANSPORTS:
        msg = f"--auth must be one of {', '.join(AUTHS)} over https or encrypted http"
        raise CollectionError(msg)
    https = target.transport == "https"
    if target.ca_file is not None and not https:
        msg = "--ca-file applies to https only"
        raise CollectionError(msg)
    return {
        "server": target.server,
        "port": target.port or (5986 if https else 5985),
        "ssl": https,
        "auth": target.auth,
        "username": target.username,
        "password": target.secret,
        # A path is a CA bundle to verify against; True uses the system's roots.
        # There is no setting that turns verification off.
        "cert_validation": str(target.ca_file) if target.ca_file else True,
        "encryption": "auto" if https else "always",
        "connection_timeout": target.connect_timeout,
        "operation_timeout": POLL_SECONDS,
        "read_timeout": POLL_SECONDS + 30,
    }


def _client() -> tuple[Any, Any, Any, int]:
    """Import pypsrp's WSMan, RunspacePool, and PowerShell, and its running state."""
    try:
        wsman = importlib.import_module("pypsrp.wsman")
        powershell = importlib.import_module("pypsrp.powershell")
        objects = importlib.import_module("pypsrp.complex_objects")
    except ImportError:
        raise CollectionError(_INSTALL) from None
    running: int = objects.PSInvocationState.RUNNING
    return wsman.WSMan, powershell.RunspacePool, powershell.PowerShell, running


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
        self.trailer: dict[str, Any] | None = None
        self.lines = 0

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
        self.lines += 1
        self.handle.write(raw)
        if raw.startswith(_END):
            self.trailer = json.loads(raw)
            return
        self.digest.update(raw)
        if self.lines > 1:
            self.events += 1

    def finish(self) -> tuple[int, tuple[str, ...]]:
        """Check the end line against what arrived."""
        self.handle.close()
        trailer = self.trailer
        if trailer is None:
            msg = "the collection ended without its end line, so it did not finish"
            raise CollectionError(msg)
        if trailer.get("events") != self.events or trailer.get("sha256") != self.digest.hexdigest():
            msg = (
                f"the collection's end line does not match what arrived ({self.events} events "
                "received); the transfer was damaged"
            )
            raise CollectionError(msg)
        gaps = tuple(
            f"{gap.get('area')}: {gap.get('reason')}"
            for gap in trailer.get("gaps", [])
            if isinstance(gap, dict)
        )
        return self.events, gaps

    def publish(self, *, force: bool) -> None:
        """Put the checked file in place without following a link or clobbering."""
        if force:
            self.temp.replace(self.destination)
            return
        try:
            os.link(self.temp, self.destination)
        except FileExistsError:
            msg = f"{self.destination} already exists; pass --force to replace it"
            raise CollectionError(msg) from None
        self.temp.unlink()

    def discard(self) -> None:
        with contextlib.suppress(OSError):
            self.handle.close()
        with contextlib.suppress(OSError):
            self.temp.unlink()


def collect(  # noqa: PLR0913 - one argument per collection choice
    target: Target,
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
    if target.secret:
        remember(target.secret)
    if destination.exists() and not force:
        msg = f"{destination} already exists; pass --force to replace it"
        raise CollectionError(msg)
    wsman_class, pool_class, powershell_class, running = _client()
    try:
        sink = _Sink(destination)
    except OSError as exc:
        msg = f"cannot write to {destination.parent}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    try:
        with wsman_class(**settings(target)) as wsman, pool_class(wsman) as pool:
            shell = powershell_class(pool)
            shell.add_script(script)
            shell.add_parameters(script_parameters)
            shell.begin_invoke()
            _drain(shell, sink, running, target.idle_timeout, clock)
            _check_failed(shell, sink, target.server)
        events, gaps = sink.finish()
        sink.publish(force=force)
    except CollectionError as exc:
        sink.discard()
        raise CollectionError(redact(str(exc))) from None
    except Exception as exc:  # noqa: BLE001 - any library error, made safe to show
        sink.discard()
        text = redact(str(exc)) or type(exc).__name__
        msg = f"remote collection from {target.server} failed: {text}"
        raise CollectionError(msg) from None
    return Result(destination, events, gaps)


def _check_failed(shell: Any, sink: _Sink, server: str) -> None:
    """Report the script's own error when it stopped before its end line."""
    if sink.trailer is None and shell.had_errors:
        errors = [str(error) for error in getattr(shell.streams, "error", [])]
        reason = errors[0] if errors else "the script stopped with an error"
        msg = f"the collector failed on {server}: {reason}"
        raise CollectionError(msg)


def _drain(
    shell: Any, sink: _Sink, running_state: int, idle_timeout: int, clock: Callable[[], float]
) -> None:
    """Take output as it arrives until the script ends, or stop it when it stalls."""
    last = clock()
    while True:
        running = shell.state == running_state
        if running:
            shell.poll_invoke(timeout=POLL_SECONDS)
        output = shell.output
        if output:
            for item in output:
                sink.take(item)
            output.clear()
            last = clock()
        if not running:
            return
        if clock() - last > idle_timeout:
            with contextlib.suppress(Exception):
                shell.stop()
            msg = f"the collector sent nothing for {idle_timeout} seconds and was stopped"
            raise CollectionError(msg)
