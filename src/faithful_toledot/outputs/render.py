# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""Render the report dictionary as Markdown, HTML, and CSV, and as a terminal summary.

Every renderer reads only the report dictionary, so all formats agree. Values
from event data are untrusted: Markdown is escaped so a value cannot forge a
heading, link, table, or HTML tag; the HTML page escapes everything, forbids
scripts and network access, and never puts a value in a URL; CSV cells are
protected against formula injection. Long values are shortened in Markdown and
HTML with a visible marker when the JSON report is written beside them, and kept
whole otherwise. CSV and JSON always keep full values.

The CSV is UTF-8 without a byte order mark and uses ``\r\n`` line ends. A
spreadsheet that guesses the encoding wrongly can be told it
is UTF-8 when importing.
"""

from __future__ import annotations

import csv
import html
import io
import re
from typing import TYPE_CHECKING, Any

from faithful_toledot.outputs.safety import csv_cell, escape_markdown, terminal, visible

if TYPE_CHECKING:
    from collections.abc import Iterable

    from faithful_toledot.outputs import Report

TITLE = "Account of changes"
MAX_VALUE = 300
"""Longest value shown in full in Markdown and HTML, in characters."""
MAX_LISTED = 25
"""How many notices or problems Markdown and HTML list before pointing to the JSON report."""
MAX_INFO = 20
"""How many routine log events Markdown and HTML list."""
MAX_ROWS = 100
"""How many coverage or other-event rows Markdown and HTML show."""
MAX_RANGES = 10
"""How many absent record-number ranges are written out for one log."""
MAX_ACTORS_SHOWN = 20
"""How many actors the Markdown and HTML summaries show."""
CSV_COLUMNS = (
    "change_id", "time_utc", "computer", "category", "action", "actor", "actor_sid",
    "target", "target_sid", "target_dn", "member", "member_sid", "detail_label",
    "detail_kind", "old_value", "new_value", "meaning", "origin_status", "origin_address",
    "origin_workstation", "logon_type", "logon_id", "event_ids", "record_ids", "files",
    "account_completeness",
)  # fmt: skip
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"
"""Content security policy: no scripts, no network access, no form submission."""

_STATE_WORDS = {"complete": "Complete", "unconfirmed": "Not confirmed", "incomplete": "Incomplete"}
_ID = re.compile(r"[A-Za-z0-9]{1,20}")


# Words ------------------------------------------------------------------------------


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def _logs_missing(report: Report) -> int:
    return sum(
        1
        for c in report["coverage"]
        if (c["continuity"] == "gaps" and c["scope"] == "unfiltered") or c["overwritten_before"]
    )


def headline(report: Report) -> tuple[str, str]:
    """Say whether the account is complete, and what it holds, in plain words.

    The state is the account's completeness: ``complete`` only when the input gives
    evidence that nothing is missing, ``unconfirmed`` when nothing shows events missing
    but the input cannot show that none are, and ``incomplete`` otherwise. The text is
    a sentence or two with its full stops.
    """
    summary = report["summary"]
    n = summary["changes"]
    state = summary["completeness"]
    lead = _plural(n, "change") + " described" if n else "No changes found in the input"
    if state == "complete":
        if not n:
            return state, "No changes found in the input."
        return state, f"{lead}. Nothing in the input suggests events are missing."
    if state == "unconfirmed":
        unchecked = sum(1 for c in report["coverage"] if not c["checked"])
        reason = (
            f"{_plural(unchecked, 'log')} cannot show whether events are missing"
            if unchecked
            else "no events were read"
        )
        return state, (
            f"{lead}. Nothing in the input shows events missing, but {reason}, so the "
            "account may not be whole."
        )
    parts = []
    if summary["notices"]["warning"]:
        parts.append(_plural(summary["notices"]["warning"], "notice"))
    if summary["problems"]:
        parts.append(_plural(summary["problems"], "problem") + " with the input")
    if missing := _logs_missing(report):
        parts.append(_plural(missing, "log") + " with missing events")
    why = ": " + ", ".join(parts) if parts else ""
    return "incomplete", f"{lead}, but the account is incomplete{why}."


def _day(time: str) -> str:
    return time[:10]


def _clock(time: str) -> str:
    return time[11:19] + " UTC"


def _shorten(value: str, *, shorten: bool = True) -> str:
    """Cut a long value, saying how long it is. The JSON report keeps it whole.

    With ``shorten`` false the value is returned whole: the report format that is being
    written is then the only place the value is, so it must not point elsewhere.
    """
    if not shorten or len(value) <= MAX_VALUE:
        return value
    return f"{value[:MAX_VALUE]}… ({len(value)} characters; full value in the JSON report)"


def _shown(value: str | None, *, shorten: bool = True) -> str:
    if value is None:
        return ""
    return _shorten(value, shorten=shorten) if value else "(empty)"


def _span(report: Report) -> str:
    window = report["window"]
    if window["since"] and window["until"]:
        return f"Period: from {window['since']} until {window['until']}."
    if window["since"]:
        return f"Period: from {window['since']} onward."
    if window["until"]:
        return f"Period: before {window['until']}."
    return "Period: everything in the input."


def _ranges(missing: list[list[int]]) -> str:
    text = ", ".join(f"{a}" if a == b else f"{a}\u2013{b}" for a, b in missing[:MAX_RANGES])
    extra = len(missing) - MAX_RANGES
    return text + (f", and {extra} more ranges" if extra > 0 else "") if text else "none"


def _records(c: dict[str, Any]) -> str:
    if c["first_record"] is None:
        return "none numbered"
    return f"{c['first_record']}\u2013{c['last_record']}"


def _detail_words(d: dict[str, Any], *, shorten: bool = True) -> str:
    """One detail as plain words: what changed, from what, to what."""
    old, new = _shown(d["old"], shorten=shorten), _shown(d["new"], shorten=shorten)
    kind = d["kind"]
    if kind == "initial":
        text = f"created as {new}"
    elif kind == "set":
        text = f"set to {new} (earlier value not recorded)"
    elif kind == "changed":
        text = f"{old} → {new}"
    elif kind == "added":
        text = f"added {new}"
    elif kind == "removed":
        text = f"removed {old or new}"
    else:
        text = new or old
    if d["meaning"]:
        text += f" (meaning: {d['meaning']})"
    return text


def _evidence(e: dict[str, Any]) -> str:
    record = f"record {e['record_id']}" if e["record_id"] is not None else "no record number"
    return f"event {e['event_id']}, {record} ({e['file']}, {e['position']})"


def _by_day(report: Report) -> list[tuple[str, list[dict[str, Any]]]]:
    days: dict[str, list[dict[str, Any]]] = {}
    for change in report["changes"]:
        days.setdefault(_day(change["time"]), []).append(change)
    return list(days.items())


def _more(total: int, shown: int) -> str:
    return f"{total - shown} more in the JSON report."


# Markdown ---------------------------------------------------------------------------


def _md(value: object) -> str:
    return escape_markdown(str(value))


def _md_table(head: tuple[str, ...], rows: Iterable[Iterable[object]]) -> list[str]:
    lines = ["| " + " | ".join(head) + " |", "|" + " --- |" * len(head)]
    lines += ["| " + " | ".join(_md(cell) for cell in row) + " |" for row in rows]
    return lines


def _split_notices(report: Report) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    notices = report["notices"]
    return (
        [n for n in notices if n["severity"] == "warning"],
        [n for n in notices if n["severity"] != "warning"],
    )


def _md_notice(n: dict[str, Any], *, shorten: bool) -> str:
    return (
        f"- {_md(n['time'])} on {_md(n['computer'])}: {_md(n['kind'])}: "
        f"{_md(_shorten(n['text'], shorten=shorten))} By {_md(n['actor']['display'])}. "
        f"Evidence: {_md(_evidence(n['event']))}."
    )


def _md_completeness(report: Report, *, shorten: bool) -> list[str]:
    state, text = headline(report)
    lines = ["## Completeness", "", f"**{_STATE_WORDS[state]}.** {_md(text)}", ""]
    warnings, infos = _split_notices(report)
    if warnings:
        lines += [
            (
                "These events bear on whether the log can be trusted to be whole (a cleared "
                "log, dropped events, a changed audit policy or a clock changed by a person):"
            ),
            "",
        ]
        lines += [_md_notice(n, shorten=shorten) for n in warnings[:MAX_LISTED]]
        if len(warnings) > MAX_LISTED:
            lines.append(f"- {_md(_more(len(warnings), MAX_LISTED))}")
        lines.append("")
    coverage = report["coverage"]
    lines += ["### What each log holds", ""]
    if coverage:
        rows = [
            (
                c["computer"], c["channel"], c["events"], c["first"] or "", c["last"] or "",
                _records(c), c["continuity"], c["scope"], _ranges(c["missing"]),
                _shorten(c["statement"], shorten=shorten),
            )
            for c in coverage[:MAX_ROWS]
        ]  # fmt: skip
        lines += _md_table(COVERAGE_HEAD, rows)
        if len(coverage) > MAX_ROWS:
            lines += ["", _md(_more(len(coverage), MAX_ROWS))]
    else:
        lines.append("No events were read.")
    lines.append("")
    problems = report["problems"]
    if problems:
        lines += [
            "### Problems with the input",
            "",
            (
                "These records or files could not be read, or conflicted, so any change they "
                "hold is not in this account:"
            ),
            "",
        ]
        for p in problems[:MAX_LISTED]:
            record = f", record {p['record_id']}" if p["record_id"] is not None else ""
            lines.append(
                f"- {_md(p['file'])}, {_md(p['position'])}{_md(record)}: "
                f"{_md(_shorten(p['reason'], shorten=shorten))}"
            )
        if len(problems) > MAX_LISTED:
            lines.append(f"- {_md(_more(len(problems), MAX_LISTED))}")
        lines.append("")
    if infos:
        lines += [
            "### Routine log events",
            "",
            "These do not suggest missing events.",
            "",
        ]
        lines += [_md_notice(n, shorten=shorten) for n in infos[:MAX_INFO]]
        if len(infos) > MAX_INFO:
            lines.append(f"- {_md(_more(len(infos), MAX_INFO))}")
        lines.append("")
    return lines


COVERAGE_HEAD = (
    "Computer", "Log", "Events", "First", "Last", "Records", "Continuity", "Scope",
    "Absent records", "What it means",
)  # fmt: skip


def _md_summary(report: Report) -> list[str]:
    s = report["summary"]
    ev = s["events"]
    lines = [
        "## Summary",
        "",
        (
            f"{_plural(s['changes'], 'change')}, "
            f"{_plural(s['notices']['warning'], 'warning notice')}, "
            f"{s['notices']['info']} routine log events, {_plural(s['problems'], 'problem')}. "
            f"Events read: {ev['changes']} in changes, {ev['context']} as context, "
            f"{ev['notices']} as notices, {ev['other']} not described, "
            f"{ev['duplicates']} duplicates, {ev['outside_window']} outside the period."
        ),
        "",
    ]
    if s["changes"]:
        lines += [f"First change {_md(s['first_change'])}, last {_md(s['last_change'])}.", ""]
        lines += [*_md_table(("Category", "Changes"), s["by_category"].items()), ""]
        lines += [*_md_table(("Action", "Changes"), s["by_action"].items()), ""]
        actors = s["actors"][:MAX_ACTORS_SHOWN]
        lines += _md_table(
            ("Actor", "SID", "Changes"), [(a["name"], a["sid"] or "", a["changes"]) for a in actors]
        )
        if len(s["actors"]) > len(actors):
            lines += ["", _md(_more(len(s["actors"]), len(actors)))]
        lines.append("")
    return lines


def _unlisted_related(c: dict[str, Any]) -> str:
    """Words for related changes that are counted but not listed."""
    unlisted = c["related_total"] - len(c["related"])
    return f", and {unlisted} more within the same moments" if unlisted > 0 else ""


def _md_change(c: dict[str, Any], *, shorten: bool) -> list[str]:
    lines = [
        f"### {_md(c['id'])} · {_md(_clock(c['time']))} · {_md(c['sentence'])}",
        "",
        f"- Computer: {_md(c['computer'])}. Kind: {_md(c['category'])}, {_md(c['action'])}.",
    ]
    for d in c["details"]:
        attribute = f" [attribute: {d['attribute']}]" if d["attribute"] else ""
        lines.append(f"- {_md(d['label'])}: {_md(_detail_words(d, shorten=shorten) + attribute)}")
    lines.append(f"- From where: {_md(c['origin']['statement'])}")
    if c["related"]:
        lines.append(f"- Related changes: {_md(', '.join(c['related']) + _unlisted_related(c))}")
    lines += [f"- Note: {_md(n)}" for n in c["notes"]]
    evidence = "; ".join(_evidence(e) for e in c["events"])
    lines.append(f"- Evidence: {_md(evidence) if evidence else 'none'}")
    return [*lines, ""]


def render_markdown(report: Report, *, shorten: bool = True) -> str:
    """Render a Markdown digest to read top to bottom or paste into a ticket.

    Args:
        report: The report dictionary.
        shorten: Cut values over :data:`MAX_VALUE` characters and point to the JSON
            report. Pass false when the JSON report is not written, so nothing is cut.
    """
    _, text = headline(report)
    lines = [
        f"# {TITLE}",
        "",
        f"**{_md(text)}**",
        "",
        (
            f"Generated {_md(report['generated_at'])} by toledot "
            f"{_md(report['tool']['version'])}. {_md(_span(report))} All times are UTC."
        ),
        "",
    ]
    lines += _md_completeness(report, shorten=shorten)
    lines += _md_summary(report)
    days = _by_day(report)
    if not days:
        lines += ["## Changes", "", "No changes were found in the input.", ""]
    for day, changes in days:
        lines += [f"## Changes on {_md(day)} (UTC): {len(changes)}", ""]
        for change in changes:
            lines += _md_change(change, shorten=shorten)
    others = report["other_events"]
    if others:
        lines += [
            "## Other events read",
            "",
            "These events were read but are not changes toledot describes.",
            "",
        ]
        lines += _md_table(
            ("Log", "Event ID", "Count"), [tuple(o.values()) for o in others[:MAX_ROWS]]
        )
        if len(others) > MAX_ROWS:
            lines += ["", _md(_more(len(others), MAX_ROWS))]
        lines.append("")
    lines += ["## Inputs", ""]
    lines += _md_table(
        ("File", "Format", "Scope", "Bytes", "SHA-256"),
        [(i["name"], i["format"], i["scope"], i["size"], i["sha256"]) for i in report["inputs"]],
    )
    lines += ["", "## Limitations", ""]
    lines += [f"- {_md(item)}" for item in report["limitations"]]
    return "\n".join(lines) + "\n"


# CSV --------------------------------------------------------------------------------


def render_csv(report: Report) -> str:
    """Render one row per detail; a change without details gets one row.

    Values are complete, never shortened. Every cell is protected against formula
    injection. The last column, ``account_completeness``, holds the account's
    completeness (``complete``, ``unconfirmed`` or ``incomplete``) on every row, so the
    caveat travels with the change list when it is the only file kept.
    """
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    completeness = report["summary"]["completeness"]
    for c in report["changes"]:
        member = c["member"] or {}
        files = list(dict.fromkeys(e["file"] for e in c["events"]))
        common = (
            c["id"], c["time"], c["computer"], c["category"], c["action"],
            c["actor"]["display"], c["actor"]["sid"], c["target"]["display"],
            c["target"]["sid"], c["target"]["dn"], member.get("display"), member.get("sid"),
        )  # fmt: skip
        origin = c["origin"]
        tail = (
            origin["status"], origin["address"], origin["workstation"], origin["logon_type"],
            origin["logon_id"], "; ".join(str(e["event_id"]) for e in c["events"]),
            "; ".join("" if e["record_id"] is None else str(e["record_id"]) for e in c["events"]),
            "; ".join(files),
        )  # fmt: skip
        for d in c["details"] or [None]:
            mid = (
                (None,) * 5
                if d is None
                else (d["label"], d["kind"], d["old"], d["new"], d["meaning"])
            )
            row = (*common, *mid, *tail, completeness)
            writer.writerow([csv_cell("" if v is None else str(v)) for v in row])
    return buffer.getvalue()


# Terminal ---------------------------------------------------------------------------


def terminal_summary(report: Report) -> str:
    """A few plain lines for the terminal: the state, the counts, and the period."""
    state, text = headline(report)
    s = report["summary"]
    lines = [f"toledot {report['tool']['version']}", text]
    lines += [f"  {category}: {n}" for category, n in s["by_category"].items()]
    if s["first_change"]:
        lines.append(f"  first change {s['first_change']}, last {s['last_change']}")
    if state != "complete":
        lines.append("  See the Completeness section of the report before relying on this account.")
    return "\n".join(terminal(line) for line in lines)


# HTML -------------------------------------------------------------------------------

_CSS = """
:root{--fg:#1f2328;--muted:#4d5661;--bg:#fff;--panel:#f6f8fa;--line:#d1d9e0;
--ok:#116329;--warn:#7d4e00;--accent:#0550ae;--mark:#fff8c5;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#9da7b3;--bg:#0d1117;
--panel:#151b23;--line:#3d444d;--ok:#56d364;--warn:#e3b341;--accent:#79c0ff;--mark:#3b2e00}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:78rem;margin:0 auto;padding:1rem 1.25rem 4rem}
h1{font-size:1.6rem;margin:1.25rem 0 .25rem}
h2{font-size:1.25rem;margin:2.25rem 0 .6rem;padding-bottom:.25rem;
border-bottom:1px solid var(--line)}
h3{font-size:1.05rem;margin:1.5rem 0 .5rem}
h4{font-size:1rem;margin:0;font-weight:600}
a{color:var(--accent)}
.skip{position:absolute;left:-999px;top:0;background:var(--bg);padding:.5rem 1rem;z-index:10}
.skip:focus{left:.5rem;top:.5rem}
nav.top{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);
padding:.5rem 1.25rem;display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;font-size:.9rem}
.muted{color:var(--muted)}
.small{font-size:.85rem}
.state{border:2px solid currentColor;border-radius:8px;padding:.75rem 1rem;margin:1rem 0;
background:var(--panel);font-weight:600}
.state.complete{color:var(--ok)}.state.incomplete,.state.unconfirmed{color:var(--warn)}
.state .word{text-transform:uppercase;letter-spacing:.04em;margin-right:.5rem}
.state span.t{color:var(--fg)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(8rem,1fr));gap:.6rem;margin:1rem 0}
.cardn{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.5rem .8rem}
.cardn b{display:block;font-size:1.5rem;line-height:1.2}
.cardn span{color:var(--muted);font-size:.85rem}
.tablewrap{overflow-x:auto;margin:.5rem 0 1rem}
table{border-collapse:collapse;width:100%;font-size:.88rem}
caption{position:absolute;left:-999px}
th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top;
overflow-wrap:anywhere}
thead th{background:var(--panel)}
tbody th{font-weight:600;background:var(--bg)}
.list{padding-left:1.2rem}
.list li{margin:.35rem 0}
.val{white-space:pre-wrap;overflow-wrap:anywhere}
code,.mono{font:.88em ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
overflow-wrap:anywhere}
.days{display:flex;flex-wrap:wrap;gap:.25rem 1rem;font-size:.9rem;margin:.5rem 0}
article.change{border:1px solid var(--line);border-radius:8px;margin:.6rem 0;
background:var(--bg);break-inside:avoid-page}
article.change>header{background:var(--panel);border-radius:8px 8px 0 0;padding:.5rem .8rem;
border-bottom:1px solid var(--line)}
article.change .meta{color:var(--muted);font-size:.82rem;margin-top:.15rem}
article.change .body{padding:.4rem .8rem .6rem}
.id{font-weight:700;margin-right:.4rem}
.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 .5rem;
font-size:.78rem;margin-right:.3rem;background:var(--bg)}
dl.d{margin:.3rem 0;display:grid;grid-template-columns:minmax(8rem,14rem) 1fr;gap:.2rem .8rem}
dl.d dt{font-weight:600}dl.d dd{margin:0}
.chg{background:var(--mark);padding:0 .2rem;border-radius:3px}
.note{border-left:4px solid var(--warn);padding:.15rem .7rem;margin:.4rem 0}
details{margin:.4rem 0}
summary{cursor:pointer;font-size:.88rem;color:var(--accent)}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
footer{margin-top:3rem}
@media (max-width:40rem){dl.d{grid-template-columns:1fr}}
@media print{nav.top,.skip{display:none}main{max-width:none;padding:0}
details::details-content{content-visibility:visible;display:block;block-size:auto}
details:not([open])>*:not(summary){display:block}
summary{color:inherit}a{color:inherit;text-decoration:none}
article.change>header{background:none}}
"""


def _h(value: object) -> str:
    return html.escape(visible(str(value)), quote=True)


def _hv(value: str | None, *, shorten: bool) -> str:
    return f'<span class="val">{_h(_shown(value, shorten=shorten))}</span>'


def _table(caption: str, head: tuple[str, ...], rows: Iterable[Iterable[str]]) -> str:
    """A table whose cells are already escaped HTML; the first cell of a row is its header."""
    heads = "".join(f'<th scope="col">{h}</th>' for h in head)
    body = []
    for row in rows:
        first, *rest = list(row)
        cells = "".join(f"<td>{cell}</td>" for cell in rest)
        body.append(f'<tr><th scope="row">{first}</th>{cells}</tr>')
    return (
        f'<div class="tablewrap"><table><caption>{_h(caption)}</caption>'
        f"<thead><tr>{heads}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _h_detail(d: dict[str, Any], *, shorten: bool) -> str:
    kind = d["kind"]
    old, new = _hv(d["old"], shorten=shorten), _hv(d["new"], shorten=shorten)
    if kind == "initial":
        value = f'created as <span class="chg">{new}</span>'
    elif kind == "set":
        value = (
            f'set to <span class="chg">{new}</span> '
            '<span class="muted">(earlier value not recorded)</span>'
        )
    elif kind == "changed":
        value = f'{old} <span aria-label="changed to">→</span> <span class="chg">{new}</span>'
    elif kind == "added":
        value = f'added <span class="chg">{new}</span>'
    elif kind == "removed":
        value = f'removed <span class="chg">{_hv(d["old"] or d["new"], shorten=shorten)}</span>'
    else:
        value = _hv(d["new"] or d["old"], shorten=shorten)
    if d["meaning"]:
        value += f' <span class="muted">(meaning: {_h(d["meaning"])})</span>'
    if d["attribute"]:
        value += (
            f'<br><span class="muted small">attribute: <code>{_h(d["attribute"])}</code></span>'
        )
    return f"<dt>{_h(d['label'])}</dt><dd>{value}</dd>"


def _h_change(c: dict[str, Any], index: int, anchors: dict[str, str], *, shorten: bool) -> str:
    details = "".join(_h_detail(d, shorten=shorten) for d in c["details"])
    related = ", ".join(
        f'<a href="#{anchors[r]}">{_h(r)}</a>' if r in anchors else _h(r) for r in c["related"]
    ) + _h(_unlisted_related(c))
    notes = "".join(f'<p class="note">{_h(n)}</p>' for n in c["notes"])
    evidence = "".join(f"<li>{_h(_evidence(e))}</li>" for e in c["events"])
    return (
        f'<article class="change" id="c{index}" aria-labelledby="h{index}"><header>'
        f'<h4 id="h{index}"><span class="id">{_h(c["id"])}</span>{_h(c["sentence"])}</h4>'
        f'<div class="meta">{_h(_clock(c["time"]))} · {_h(c["computer"])} · '
        f'<span class="tag">{_h(c["category"])}</span><span class="tag">{_h(c["action"])}</span>'
        f'</div></header><div class="body">'
        + (f'<dl class="d">{details}</dl>' if details else "")
        + f"<p>{_h(c['origin']['statement'])}</p>"
        + (f'<p class="small"><b>Related changes:</b> {related}</p>' if related else "")
        + notes
        + f"<details><summary>Evidence ({len(c['events'])} events)</summary>"
        f'<ul class="list small">{evidence}</ul></details>'
        "</div></article>"
    )


def _h_notice(n: dict[str, Any], *, shorten: bool) -> str:
    return (
        f"<li><b>{_h(n['kind'])}</b> at {_h(n['time'])} on {_h(n['computer'])}: "
        f"{_h(_shorten(n['text'], shorten=shorten))} By {_h(n['actor']['display'])}. "
        f'<span class="muted small">{_h(_evidence(n["event"]))}</span></li>'
    )


def _h_completeness(report: Report, *, shorten: bool) -> str:
    state, text = headline(report)
    icon = "✔" if state == "complete" else "⚠"
    parts = [
        '<h2 id="completeness">Completeness</h2>',
        (
            f'<p class="state {state}" role="status"><span class="word">{icon} '
            f'{_STATE_WORDS[state]}</span><span class="t">{_h(text)}</span></p>'
        ),
    ]
    warnings, infos = _split_notices(report)
    if warnings:
        extra = (
            f"<li>{_h(_more(len(warnings), MAX_LISTED))}</li>" if len(warnings) > MAX_LISTED else ""
        )
        items = "".join(_h_notice(n, shorten=shorten) for n in warnings[:MAX_LISTED])
        parts.append(
            "<h3>Notices that bear on completeness</h3><p>These events bear on whether the log "
            "can be trusted to be whole.</p>"
            f'<ul class="list">{items}{extra}</ul>'
        )
    if infos:
        extra = f"<li>{_h(_more(len(infos), MAX_INFO))}</li>" if len(infos) > MAX_INFO else ""
        items = "".join(_h_notice(n, shorten=shorten) for n in infos[:MAX_INFO])
        parts.append(
            f"<details><summary>Routine log events ({len(infos)})</summary>"
            "<p>These do not suggest missing events.</p>"
            f'<ul class="list">{items}{extra}</ul>'
            "</details>"
        )
    parts.append("<h3>What each log holds</h3>")
    coverage = report["coverage"]
    if coverage:
        rows = [
            (
                _h(c["computer"]),
                _h(c["channel"]),
                _h(c["events"]),
                _h(f"{c['first'] or ''} to {c['last'] or ''}" if c["first"] else "none"),
                _h(_records(c)),
                _h(c["continuity"]),
                _h(c["scope"]),
                _h(_ranges(c["missing"])),
                _h(_shorten(c["statement"], shorten=shorten)),
            )
            for c in coverage[:MAX_ROWS]
        ]
        parts.append(_table("What each log holds", COVERAGE_HEAD_HTML, rows))
        if len(coverage) > MAX_ROWS:
            parts.append(f"<p>{_h(_more(len(coverage), MAX_ROWS))}</p>")
    else:
        parts.append("<p>No events were read.</p>")
    problems = report["problems"]
    if problems:
        items = "".join(
            f"<li><code>{_h(p['file'])}</code>, {_h(p['position'])}"
            + (f", record {_h(p['record_id'])}" if p["record_id"] is not None else "")
            + f": {_h(_shorten(p['reason'], shorten=shorten))}</li>"
            for p in problems[:MAX_LISTED]
        )
        extra = (
            f"<li>{_h(_more(len(problems), MAX_LISTED))}</li>" if len(problems) > MAX_LISTED else ""
        )
        parts.append(
            "<h3>Problems with the input</h3><p>These records or files could not be read, or "
            "conflicted, so any change they hold is not in this account.</p>"
            f'<ul class="list">{items}{extra}</ul>'
        )
    return "".join(parts)


COVERAGE_HEAD_HTML = (
    "Computer", "Log", "Events", "Time span", "Records", "Continuity", "Scope",
    "Absent records", "What it means",
)  # fmt: skip


def _h_summary(report: Report) -> str:
    s = report["summary"]
    ev = s["events"]
    cards = "".join(
        f'<div class="cardn"><b>{_h(n)}</b><span>{_h(label)}</span></div>'
        for n, label in (
            (s["changes"], "changes"),
            (s["notices"]["warning"], "warning notices"),
            (s["notices"]["info"], "routine log events"),
            (s["problems"], "problems"),
            (ev["context"], "context events"),
            (ev["other"], "events not described"),
            (ev["duplicates"], "duplicates"),
        )
    )
    parts = ['<h2 id="summary">Summary</h2>', f'<div class="cards">{cards}</div>']
    if s["changes"]:
        parts.append(
            f"<p>First change {_h(s['first_change'])}, last {_h(s['last_change'])}. "
            f"{_h(_span(report))}</p>"
        )
        parts.append(
            _table(
                "Changes by category",
                ("Category", "Changes"),
                [(_h(k), _h(v)) for k, v in s["by_category"].items()],
            )
        )
        parts.append(
            _table(
                "Changes by action",
                ("Action", "Changes"),
                [(_h(k), _h(v)) for k, v in s["by_action"].items()],
            )
        )
        actors = s["actors"][:MAX_ACTORS_SHOWN]
        parts.append(
            _table(
                "Most active actors",
                ("Actor", "SID", "Changes"),
                [(_h(a["name"]), _h(a["sid"] or ""), _h(a["changes"])) for a in actors],
            )
        )
        if len(s["actors"]) > len(actors):
            parts.append(f"<p>{_h(_more(len(s['actors']), len(actors)))}</p>")
    else:
        parts.append(f"<p>{_h(_span(report))}</p>")
    return "".join(parts)


def render_html(report: Report, *, shorten: bool = True) -> str:
    """Render one self-contained page: no scripts, no external requests, no URLs from data.

    Args:
        report: The report dictionary.
        shorten: Cut values over :data:`MAX_VALUE` characters and point to the JSON
            report. Pass false when the JSON report is not written, so nothing is cut.
    """
    anchors = {c["id"]: f"c{i}" for i, c in enumerate(report["changes"], start=1)}
    days = _by_day(report)
    if days:
        jump = " ".join(
            f'<a href="#day{i}">{_h(day)} ({len(items)})</a>'
            for i, (day, items) in enumerate(days, start=1)
        )
        sections = []
        counter = 0
        for i, (day, items) in enumerate(days, start=1):
            cards = []
            for c in items:
                counter += 1
                cards.append(_h_change(c, counter, anchors, shorten=shorten))
            sections.append(
                f'<section aria-labelledby="dayh{i}"><h3 id="day{i}"><span id="dayh{i}">'
                f"{_h(day)} (UTC)</span> "
                f'<span class="muted small">{_plural(len(items), "change")}</span></h3>'
                + "".join(cards)
                + "</section>"
            )
        changes = f'<p class="days"><b>Jump to day:</b> {jump}</p>' + "".join(sections)
    else:
        changes = "<p>No changes were found in the input.</p>"
    others = report["other_events"]
    other = ""
    if others:
        rows = [(_h(o["channel"]), _h(o["event_id"]), _h(o["count"])) for o in others[:MAX_ROWS]]
        other = (
            '<h2 id="other">Other events read</h2><p>These events were read but are not '
            "changes toledot describes.</p>"
            + _table("Other events read", ("Log", "Event ID", "Count"), rows)
            + (f"<p>{_h(_more(len(others), MAX_ROWS))}</p>" if len(others) > MAX_ROWS else "")
        )
    inputs = _table(
        "Inputs",
        ("File", "Format", "Scope", "Bytes", "SHA-256"),
        [
            (
                _h(i["name"]),
                _h(i["format"]),
                _h(i["scope"]),
                _h(i["size"]),
                f"<code>{_h(i['sha256'])}</code>",
            )
            for i in report["inputs"]
        ],
    )
    limits = "".join(f"<li>{_h(item)}</li>" for item in report["limitations"])
    _, text = headline(report)
    version = _h(report["tool"]["version"])
    nav = (
        '<a href="#completeness">Completeness</a><a href="#summary">Summary</a>'
        '<a href="#changes">Changes by day</a>'
        + ('<a href="#other">Other events</a>' if other else "")
        + '<a href="#inputs">Inputs</a><a href="#limitations">Limitations</a>'
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TITLE}</title>
<style>{_CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to the report</a>
<nav class="top" aria-label="Sections">{nav}</nav>
<main id="main">
<header>
<h1>{TITLE}</h1>
<p class="muted">Generated {_h(report["generated_at"])} by toledot {version}. \
{_h(_span(report))} All times are UTC.</p>
</header>
{_h_completeness(report, shorten=shorten)}
{_h_summary(report)}
<h2 id="changes">Changes by day</h2>
{changes}
{other}
<h2 id="inputs">Inputs</h2>
{inputs}
<h2 id="limitations">Limitations</h2>
<ul class="list">{limits}</ul>
<footer class="muted small">{_h(text)}</footer>
</main>
</body>
</html>
"""
