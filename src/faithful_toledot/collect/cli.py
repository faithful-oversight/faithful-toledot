# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The ``collect`` and ``collector`` commands."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from faithful_toledot.arguments import bounded, moment
from faithful_toledot.collect import names, remote, script, secrets
from faithful_toledot.console import say
from faithful_toledot.errors import UsageError
from faithful_toledot.outputs.files import refuse_aliases, write_files
from faithful_toledot.outputs.safety import command_line, terminal

if TYPE_CHECKING:
    import argparse
    from typing import Any

MAX_DAYS = 3650
_days = bounded(1, MAX_DAYS, "a whole number of days")
_seconds = bounded(1, 86400, "a whole number of seconds")
_port = bounded(1, 65535, "a port")


def add_arguments(commands: Any) -> None:
    """Register ``collect`` and ``collector`` on the main parser's subcommands."""
    collect = commands.add_parser(
        "collect",
        help="collect change events from a domain controller over PowerShell remoting",
        description=(
            "Run toledot's read-only collector on a domain controller over PowerShell "
            "remoting and write its events to a file for 'toledot report'. HTTPS always "
            "verifies the certificate; HTTP is used only with message encryption."
        ),
    )
    collect.add_argument("--server", required=True, help="the controller's DNS name")
    collect.add_argument("--auth", choices=remote.AUTHS, default="kerberos")
    collect.add_argument("--username", help="DOMAIN\\user or user@domain.example")
    collect.add_argument(
        "--secret", metavar="REF",
        help="where the password is: env:NAME, file:PATH, keyring:SERVICE/USER, "
        "vault:MOUNT/PATH#FIELD, aws:SECRET_ID[#FIELD], or azure:VAULT/NAME",
    )  # fmt: skip
    collect.add_argument("--transport", choices=remote.TRANSPORTS, default="https")
    collect.add_argument("--port", type=_port, help="default: 5986 for https, 5985 for http")
    collect.add_argument("--ca-file", type=Path, help="PEM certificate authorities for https")
    collect.add_argument("--since", type=moment, metavar="TIME", help="collect from this time")
    collect.add_argument("--until", type=moment, metavar="TIME", help="collect before this time")
    collect.add_argument("--days", type=_days, default=7, help="the last N days (default: 7)")
    collect.add_argument(
        "--channel",
        action="append",
        metavar="LOG",
        help="a log to read (default: Security, System)",
    )
    collect.add_argument(
        "--all", action="store_true", help="collect every event, not only the ones toledot reads"
    )
    collect.add_argument(
        "--timeout", type=_seconds, default=600,
        help="stop when the collector sends nothing for this many seconds (default: 600)",
    )  # fmt: skip
    collect.add_argument("-o", "--output", required=True, type=Path, metavar="FILE")
    collect.add_argument("--force", action="store_true", help="replace an existing file")
    collect.set_defaults(run=run_collect)

    collector = commands.add_parser(
        "collector",
        help="write the PowerShell collector to run on a domain controller yourself",
        description=f"Write {script.NAME}, the read-only collector, to a file.",
    )
    collector.add_argument("-o", "--output", type=Path, default=Path(script.NAME), metavar="FILE")
    collector.add_argument("--force", action="store_true", help="replace an existing file")
    collector.set_defaults(run=run_collector)


def run_collect(args: argparse.Namespace) -> int:
    """Collect over PowerShell remoting. Names are checked before any secret is read."""
    server = names.server_name(args.server)
    username = names.account_name(args.username)
    if args.since and args.until and args.since >= args.until:
        msg = "--since must be earlier than --until"
        raise UsageError(msg)
    if args.secret and not username:
        msg = "--secret needs --username"
        raise UsageError(msg)
    if args.auth == "ntlm" and not username:
        msg = "--auth ntlm needs --username and --secret; only Kerberos can use the current logon"
        raise UsageError(msg)
    if username and not args.secret:
        msg = "--username needs --secret; leave both out to use the current Kerberos ticket"
        raise UsageError(msg)
    target = remote.Target(
        server=server,
        auth=args.auth,
        username=username,
        secret=None,
        transport=args.transport,
        port=args.port,
        ca_file=args.ca_file,
        idle_timeout=args.timeout,
    )
    remote.settings(target)  # refuse a bad combination before the secret is read
    # The files this command reads are never the file it writes, even with --force.
    refuse_aliases([args.output], _read_files(args))
    if args.secret:
        target = remote.Target(**{**vars(target), "secret": secrets.resolve(args.secret)})
    channels = args.channel or ["Security", "System"]
    values = remote.parameters(args.since, args.until, args.days, channels, every_event=args.all)
    result = remote.collect(target, script.text(), values, args.output, force=args.force)
    say(terminal(f"Collected {result.events} events from {server} into {result.path}."))
    for gap in result.gaps:
        say(terminal(f"  not read: {gap}"))
    command = command_line("toledot", "report", str(result.path), "-o", "report")
    say(terminal(f"Write the account with: {command}"))
    return 0


def _read_files(args: argparse.Namespace) -> list[tuple[str, Path]]:
    """The files ``collect`` reads, by role: the CA file and a ``file:`` secret."""
    found: list[tuple[str, Path]] = []
    if args.ca_file:
        found.append(("CA file", args.ca_file))
    provider, _, location = (args.secret or "").partition(":")
    if provider == "file" and location:
        found.append(("secret file", Path(location)))
    return found


def run_collector(args: argparse.Namespace) -> int:
    """Write the packaged collector script."""
    path: Path = args.output
    written = write_files(path.parent, {path.name: script.text()}, force=args.force)
    command = f".\\{script.NAME} -OutFile dc01-events.jsonl -Days 30"
    say(terminal(f"Wrote {written[0]}. On the domain controller, in an elevated PowerShell:"))
    say(terminal(f"  {command}"))
    return 0
