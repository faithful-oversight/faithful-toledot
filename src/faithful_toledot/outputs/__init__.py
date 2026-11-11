# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Build the versioned report document and write it, in every format, with a manifest.

Every renderer reads only the report dictionary built here, so all formats agree.
The dictionary is plain JSON: the same account and arguments always give the same
dictionary, and nothing in it depends on the clock or the environment.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from faithful_toledot import narrative
from faithful_toledot.errors import ToledotError
from faithful_toledot.outputs.files import write_files
from faithful_toledot.outputs.render import (
    render_csv,
    render_html,
    render_markdown,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from faithful_toledot.changes import Account, EventRef, Party

SCHEMA_VERSION = "1.0"
SCHEMA_ID = "https://faithful-oversight.github.io/faithful-toledot/schema/report-v1.schema.json"
MANIFEST_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_ID = (
    "https://faithful-oversight.github.io/faithful-toledot/schema/manifest-v1.schema.json"
)
MAX_ACTORS = 50
"""How many actors the summary lists, most active first."""
FILE_NAMES = {
    "json": "toledot-report.json",
    "md": "toledot-report.md",
    "html": "toledot-report.html",
    "csv": "toledot-changes.csv",
}
"""Output formats in the order they are written, with their file names."""
MANIFEST_NAME = "toledot-manifest.json"
INPUT_KEYS = ("name", "format", "scope", "size", "sha256")

LIMITATIONS = (
    (
        "toledot reports what the events record. It cannot show a change that Windows did not "
        "audit, and it does not judge whether a change was authorized."
    ),
    (
        '"From where" is the source the logon session recorded. A proxy, a jump host, or '
        "network address translation can hide the real origin."
    ),
    (
        "Times are UTC, as recorded by each computer's own clock. Clocks that disagree are not "
        "corrected."
    ),
    "Names that come from other events are shown apart from the names a change event recorded.",
    (
        "Old values exist only where Windows recorded them: directory service change events "
        "(event 5136 and its relatives) record the value that changed, and most other events "
        "do not."
    ),
    (
        "A clean record-number check does not prove that nothing was removed. Someone able to "
        "rewrite the log can renumber it, and an export that was filtered cannot be checked "
        "at all."
    ),
)

Report = dict[str, Any]


def format_time(value: datetime) -> str:
    """Write a time as RFC 3339 in UTC with a trailing ``Z``.

    Fractional seconds appear only when they are not zero. A time without a zone is
    taken to be UTC, since every time toledot reads is.
    """
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        text += f".{value.microsecond:06d}".rstrip("0")
    return text + "Z"


def _time(value: datetime | None) -> str | None:
    return None if value is None else format_time(value)


def _party(who: Party) -> dict[str, Any]:
    return {
        "sid": who.sid,
        "name": who.name,
        "domain": who.domain,
        "dn": who.dn,
        "object_class": who.object_class,
        "guid": who.guid,
        "well_known": who.well_known,
        "known_as": who.known_as,
        "display": narrative.party(who),
    }


def _event_ref(ref: EventRef) -> dict[str, Any]:
    return {
        "event_id": ref.event_id,
        "record_id": ref.record_id,
        "time": format_time(ref.time),
        "file": ref.source.file,
        "position": ref.source.position,
    }


def _ranked(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _actors(account: Account) -> list[dict[str, Any]]:
    tally: Counter[tuple[str, str | None]] = Counter()
    for change in account.changes:
        tally[(narrative.party(change.actor), change.actor.sid)] += 1
    ranked = sorted(tally.items(), key=lambda item: (-item[1], item[0][0], item[0][1] or ""))
    return [{"name": name, "sid": sid, "changes": n} for (name, sid), n in ranked[:MAX_ACTORS]]


def _change(change: Any) -> dict[str, Any]:
    origin = change.origin
    return {
        "id": change.id,
        "time": format_time(change.time),
        "computer": change.computer,
        "category": change.category,
        "action": change.action,
        "title": change.title,
        "sentence": change.sentence,
        "actor": _party(change.actor),
        "target": _party(change.target),
        "member": None if change.member is None else _party(change.member),
        "details": [
            {
                "label": d.label,
                "kind": d.kind,
                "old": d.old,
                "new": d.new,
                "meaning": d.meaning,
                "attribute": d.attribute,
            }
            for d in change.details
        ],
        "origin": {
            "status": origin.status,
            "logon_id": origin.logon_id,
            "address": origin.address,
            "port": origin.port,
            "workstation": origin.workstation,
            "logon_type": origin.logon_type,
            "logon_type_name": origin.logon_type_name,
            "logon_time": _time(origin.logon_time),
            "source": (
                None
                if origin.source is None
                else {"file": origin.source.file, "position": origin.source.position}
            ),
            "statement": narrative.origin(origin),
        },
        "events": [
            {
                "event_id": e.event_id,
                "record_id": e.record_id,
                "time": format_time(e.time),
                "file": e.source.file,
                "position": e.source.position,
            }
            for e in change.events
        ],
        "related": list(change.related),
        "notes": list(change.notes),
    }


def build_report(
    account: Account,
    *,
    inputs: Sequence[Mapping[str, Any]],
    window: tuple[datetime | None, datetime | None],
    generated_at: datetime,
    version: str,
) -> Report:
    """Assemble the report document that follows the published schema.

    Args:
        account: What toledot found.
        inputs: One mapping per input file with ``name``, ``format``, ``scope``,
            ``size`` and ``sha256``. Other keys are not copied.
        window: The ``since`` and ``until`` the user asked for, each or both ``None``.
        generated_at: When the report is made. Passed in so the report is repeatable.
        version: toledot's version.
    """
    changes = account.changes
    return {
        "$schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "toledot", "version": version},
        "generated_at": format_time(generated_at),
        "inputs": [{key: item[key] for key in INPUT_KEYS} for item in inputs],
        "window": {"since": _time(window[0]), "until": _time(window[1])},
        "summary": {
            "complete": account.complete,
            "completeness": account.completeness,
            "changes": len(changes),
            "notices": {
                "warning": sum(n.severity == "warning" for n in account.notices),
                "info": sum(n.severity != "warning" for n in account.notices),
            },
            "problems": len(account.problems),
            "events": {
                name: account.counts.get(name, 0)
                for name in ("changes", "context", "notices", "other", "duplicates")
            },
            "by_category": _ranked(Counter(c.category for c in changes)),
            "by_action": _ranked(Counter(c.action for c in changes)),
            "actors": _actors(account),
            "first_change": _time(changes[0].time) if changes else None,
            "last_change": _time(changes[-1].time) if changes else None,
        },
        "notices": [
            {
                "time": format_time(n.time),
                "computer": n.computer,
                "kind": n.kind,
                "severity": n.severity,
                "text": n.text,
                "actor": _party(n.actor),
                "event": _event_ref(n.event),
            }
            for n in account.notices
        ],
        "coverage": [
            {
                "computer": c.computer,
                "channel": c.channel,
                "events": c.events,
                "first": _time(c.first),
                "last": _time(c.last),
                "first_record": c.first_record,
                "last_record": c.last_record,
                "continuity": c.continuity,
                "missing": [[a, b] for a, b in c.missing],
                "missing_count": c.missing_count,
                "scope": c.scope,
                "overwritten_before": _time(c.overwritten_before),
                "checked": c.checked,
                "statement": c.statement,
            }
            for c in account.coverage
        ],
        "problems": [
            {
                "file": p.source.file,
                "position": p.source.position,
                "record_id": p.record_id,
                "reason": p.reason,
            }
            for p in account.problems
        ],
        "changes": [_change(c) for c in changes],
        "other_events": [
            {"channel": channel, "event_id": event_id, "count": n}
            for (channel, event_id), n in sorted(account.other_ids.items())
        ],
        "limitations": list(LIMITATIONS),
    }


def render_json(report: Report) -> str:
    """Render the report as indented JSON in its documented key order."""
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate cannot be written as UTF-8; JSON escapes keep it exactly.
        text = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    return text


def _manifest(report: Report, outputs: Mapping[str, str]) -> str:
    files = []
    for name, text in outputs.items():
        data = text.encode("utf-8")
        files.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {
        "$schema": MANIFEST_SCHEMA_ID,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": report["tool"],
        "generated_at": report["generated_at"],
        "files": files,
        "inputs": [
            {"name": i["name"], "size": i["size"], "sha256": i["sha256"]} for i in report["inputs"]
        ],
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def write_reports(
    directory: Path, report: Report, formats: Sequence[str], *, force: bool
) -> list[Path]:
    """Write the chosen formats and a manifest, all together or not at all.

    The files are ``toledot-report.json``, ``toledot-report.md``,
    ``toledot-report.html`` and ``toledot-changes.csv``, always in that order
    whatever order ``formats`` gives. The manifest ``toledot-manifest.json`` goes
    last and lists the size and SHA-256 of each file and of each input.

    Raises:
        ToledotError: No format was chosen, a format is unknown, a file exists and
            ``force`` is false, or writing failed. Nothing is left half written.
    """
    unknown = sorted(set(formats) - FILE_NAMES.keys())
    if unknown:
        msg = f"unknown report format {unknown[0]!r}; choose from {', '.join(FILE_NAMES)}"
        raise ToledotError(msg)
    if not formats:
        msg = "no report format chosen"
        raise ToledotError(msg)
    renderers = {
        "json": render_json,
        "md": render_markdown,
        "html": render_html,
        "csv": render_csv,
    }
    outputs = {FILE_NAMES[f]: renderers[f](report) for f in FILE_NAMES if f in formats}
    outputs[MANIFEST_NAME] = _manifest(report, outputs)
    return write_files(directory, outputs, force=force)
