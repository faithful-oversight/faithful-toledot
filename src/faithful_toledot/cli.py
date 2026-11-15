# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_toledot import __version__, catalog, example, outputs, pipeline
from faithful_toledot.arguments import moment
from faithful_toledot.collect import cli as collect_cli
from faithful_toledot.collect.secrets import redact
from faithful_toledot.console import harden_streams, say, stop_stdout
from faithful_toledot.errors import ToledotError, UsageError
from faithful_toledot.events import ReadOptions
from faithful_toledot.outputs import render
from faithful_toledot.outputs.files import write_files
from faithful_toledot.outputs.safety import command_line, terminal

if TYPE_CHECKING:
    from collections.abc import Sequence

FORMATS = ("json", "md", "html", "csv")
SCHEMAS = {"report": "report-v1", "events": "events-v1", "manifest": "manifest-v1"}
_OFFSET = re.compile(r"([+-])([0-9]{2}):([0-9]{2})")
_MAX_OFFSET_HOURS = 14


class ExitCode(IntEnum):
    """Process exit codes. These values are part of the public interface."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    INPUT_ERROR = 3
    INTERNAL_ERROR = 4


def _offset(text: str) -> timedelta:
    """Parse ``--local-offset``, such as ``-06:00``."""
    match = _OFFSET.fullmatch(text)
    hours, minutes = (int(match.group(2)), int(match.group(3))) if match else (99, 0)
    if hours > _MAX_OFFSET_HOURS or minutes > 59 or (hours == _MAX_OFFSET_HOURS and minutes):  # noqa: PLR2004
        msg = f"{text!r} is not a UTC offset; write it like -06:00 or +05:30"
        raise argparse.ArgumentTypeError(msg)
    sign = -1 if match and match.group(1) == "-" else 1
    return sign * timedelta(hours=hours, minutes=minutes)


def _formats(text: str) -> list[str]:
    chosen = [part.strip() for part in text.split(",") if part.strip()]
    unknown = [part for part in chosen if part not in FORMATS]
    if unknown or not chosen:
        msg = f"choose formats from {', '.join(FORMATS)}, separated by commas"
        raise argparse.ArgumentTypeError(msg)
    return list(dict.fromkeys(chosen))


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="toledot",
        description=(
            "AD Change Narrative: turn exported Active Directory change events into a "
            "plain account of who changed what, when, and from where."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    report = commands.add_parser(
        "report",
        help="read event files and write the account of changes",
        description=(
            "Read event log files and write the account of changes. Reads .evtx files, "
            "XML, JSON, and CSV exports, and files written by toledot's collectors. "
            "The format is detected from each file's contents."
        ),
    )
    report.add_argument("inputs", nargs="+", type=Path, metavar="FILE", help="an event file")
    report.add_argument(
        "-o", "--output", required=True, type=Path, metavar="DIR", help="folder for the reports"
    )
    report.add_argument(
        "-f", "--format", type=_formats, default=list(FORMATS), metavar="LIST",
        help="report formats, separated by commas: json, md, html, csv (default: all)",
    )  # fmt: skip
    report.add_argument("--since", type=moment, metavar="TIME", help="leave out earlier changes")
    report.add_argument(
        "--until", type=moment, metavar="TIME", help="leave out changes at or after this time"
    )
    report.add_argument(
        "--whole-logs", action="store_true",
        help="state that every file is a whole log, not a filtered export; absent record "
        "numbers then count as missing events",
    )  # fmt: skip
    report.add_argument(
        "--local-offset", type=_offset, metavar="+HH:MM",
        help="the UTC offset of times in exports that carry none, such as CSV",
    )  # fmt: skip
    report.add_argument(
        "--date-order", choices=("day-first", "month-first"),
        help="how to read a date such as 03/04/2026 in exports that leave it open",
    )  # fmt: skip
    report.add_argument(
        "--fail-on", choices=("unconfirmed", "incomplete", "never"), default="unconfirmed",
        help=(
            "exit 1 unless the input shows the account is whole (unconfirmed, the "
            "default), only when events are known or likely to be missing "
            "(incomplete), or never"
        ),
    )  # fmt: skip
    report.add_argument("--force", action="store_true", help="replace existing report files")
    report.set_defaults(run=_report)

    listing = commands.add_parser(
        "events",
        help="list the events toledot understands",
        description=(
            "List the Windows events toledot understands, its catalog, one per line, with "
            "the log, the event ID, the kind of change, and a title. Events marked "
            "'partly inferred' have details Microsoft's documentation does not confirm."
        ),
    )
    listing.set_defaults(run=_events)

    schema = commands.add_parser(
        "schema", help="print a JSON schema", description="Print a JSON schema, offline."
    )
    schema.add_argument("name", choices=sorted(SCHEMAS))
    schema.set_defaults(run=_schema)

    sample = commands.add_parser(
        "example",
        help="write synthetic event files to try toledot with",
        description="Write synthetic event files. Every name and address in them is made up.",
    )
    sample.add_argument("directory", type=Path, metavar="DIR")
    sample.add_argument("--force", action="store_true", help="replace existing files")
    sample.set_defaults(run=_example)

    collect_cli.add_arguments(commands)
    return parser


def _now() -> datetime:
    """The report time: the clock, or ``SOURCE_DATE_EPOCH`` for a repeatable report."""
    fixed = os.environ.get("SOURCE_DATE_EPOCH", "")
    if fixed.isascii() and fixed.isdigit():
        try:
            return datetime.fromtimestamp(int(fixed), UTC)
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(UTC).replace(microsecond=0)


def _report(args: argparse.Namespace) -> int:
    if args.since and args.until and args.since >= args.until:
        msg = "--since must be earlier than --until"
        raise UsageError(msg)
    options = ReadOptions(
        local_offset=args.local_offset,
        day_first=None if args.date_order is None else args.date_order == "day-first",
        names_for=catalog.names_for,
        labels_for=catalog.labels_for,
    )
    account, inputs = pipeline.run(
        args.inputs, options, whole_logs=args.whole_logs, since=args.since, until=args.until
    )
    document = outputs.build_report(
        account,
        inputs=[vars(item) for item in inputs],
        window=(args.since, args.until),
        generated_at=_now(),
        version=__version__,
    )
    written = outputs.write_reports(args.output, document, args.format, force=args.force)
    # Decide the exit code first: nothing printed after this can change it.
    failing = {"unconfirmed": {"unconfirmed", "incomplete"}, "incomplete": {"incomplete"}}
    code = (
        ExitCode.FINDINGS
        if account.completeness in failing.get(args.fail_on, set())
        else ExitCode.OK
    )
    say(render.terminal_summary(document))
    say(terminal(f"Reports written to {args.output}: {', '.join(p.name for p in written)}"))
    return int(code)


def _events(_: argparse.Namespace) -> int:
    lines = []
    for info in sorted(catalog.load().events, key=lambda e: (e.channel, e.id)):
        mark = "" if info.confirmed else "  [partly inferred; see the catalog notes]"
        lines.append(f"{info.channel:<9}{info.id:<6}{info.category:<10}{info.title}{mark}")
    say("\n".join(lines))
    return int(ExitCode.OK)


def _schema(args: argparse.Namespace) -> int:
    name = f"schema/{SCHEMAS[args.name]}.schema.json"
    say(files("faithful_toledot").joinpath(name).read_text(encoding="utf-8"), end="")
    return int(ExitCode.OK)


def _example(args: argparse.Namespace) -> int:
    data = {name: content.decode("utf-8") for name, content in example.build().items()}
    written = write_files(args.directory, data, force=args.force)
    command = command_line(
        "toledot", "report", *map(str, written), "-o", str(args.directory / "report")
    )
    say(terminal(f"Wrote synthetic events to {args.directory}. Try:\n  {command}"))
    return int(ExitCode.OK)


def _join_offsets(argv: Sequence[str]) -> list[str]:
    """Let ``--local-offset -06:00`` work: argparse would read ``-06:00`` as an option."""
    joined: list[str] = []
    waiting = False
    for item in argv:
        if waiting and item.startswith("-") and item[1:2].isdigit():
            joined[-1] = f"--local-offset={item}"
        else:
            joined.append(item)
        waiting = item == "--local-offset"
    return joined


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return an exit code.

    Printing never changes the exit code: the streams cannot fail on an unencodable
    character, and a closed pipe stops the output and keeps the code already decided.
    """
    harden_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(_join_offsets(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else int(ExitCode.USAGE)
    except OSError:
        stop_stdout()  # --help or --version printed into a closed pipe (EINVAL on Windows)
        return int(ExitCode.OK)
    if not getattr(args, "run", None):
        parser.print_help(sys.stderr)
        return int(ExitCode.USAGE)
    try:
        return int(args.run(args))
    except ToledotError as exc:
        say(f"toledot: error: {terminal(redact(str(exc)))}", error=True)
        return int(ExitCode.USAGE if isinstance(exc, UsageError) else ExitCode.INPUT_ERROR)
    except Exception as exc:  # noqa: BLE001 - last-resort handler keeps crashes distinct
        say(
            f"toledot: internal error: {type(exc).__name__}: {terminal(redact(str(exc)))}\n"
            "This is a bug in toledot. Please report it.",
            error=True,
        )
        return int(ExitCode.INTERNAL_ERROR)
