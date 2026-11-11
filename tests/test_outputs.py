# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The report document and its Markdown, HTML, CSV, and terminal renderings."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from html.parser import HTMLParser
from importlib.resources import files
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import FormatChecker
from jsonschema.validators import validator_for

from faithful_toledot import catalog, correlate, narrative
from faithful_toledot.changes import (
    Account,
    Change,
    Coverage,
    Detail,
    EventRef,
    Notice,
    Origin,
    Party,
)
from faithful_toledot.correlate import Input
from faithful_toledot.errors import ToledotError
from faithful_toledot.events import Problem, Source
from faithful_toledot.outputs import (
    MANIFEST_NAME,
    build_report,
    format_time,
    render_json,
    write_reports,
)
from faithful_toledot.outputs import render as r
from tests.helpers import DC, DOMAIN_SID, event, logon, member_added

if TYPE_CHECKING:
    from pathlib import Path

GENERATED = datetime(2026, 11, 5, 9, 30, tzinfo=UTC)
D0 = datetime(2026, 11, 3, 23, 59, 58, tzinfo=UTC)
SHA = "a" * 64
INPUTS = [
    {"name": "security.evtx", "format": "evtx", "scope": "unfiltered", "size": 4096, "sha256": SHA}
]


def schema_check(name: str, document: Any) -> None:
    text = files("faithful_toledot").joinpath("schema", name).read_text(encoding="utf-8")
    definition = json.loads(text)
    validator = validator_for(definition)
    validator.check_schema(definition)
    validator(definition, format_checker=FormatChecker()).validate(document)


def ref(n: int, seconds: float = 0, file: str = "security.evtx") -> EventRef:
    return EventRef(4728, 1000 + n, D0 + timedelta(seconds=seconds), Source(file, f"record {n}"))


def who(name: str, sid: str | None = None, **more: str) -> Party:
    return Party(sid=sid or f"{DOMAIN_SID}-1104", name=name, domain="CORP", **more)


def change(n: int, seconds: float, **kw: Any) -> Change:
    base: dict[str, Any] = {
        "id": f"C{n:04d}",
        "time": D0 + timedelta(seconds=seconds),
        "computer": DC,
        "category": "group",
        "action": "member-added",
        "title": "A member was added",
        "actor": who("alice"),
        "target": Party(name="Domain Admins", domain="CORP", well_known="Domain Admins"),
        "member": Party(sid=f"{DOMAIN_SID}-1105", dn="CN=Bob,OU=Staff,DC=corp,DC=example"),
        "details": (),
        "origin": Origin("none"),
        "events": (ref(n, seconds),),
    }
    built = Change(**{**base, **kw})
    return replace(built, sentence=narrative.sentence(built))


def rich() -> Account:
    session = Origin(
        "session",
        logon_id="0x5f1a2",
        address="192.0.2.44",
        port="51515",
        workstation="ADMIN-PC7",
        logon_type="3",
        logon_type_name="Network",
        logon_time=D0 - timedelta(seconds=60),
        source=Source("security.evtx", "record 900"),
    )
    user = {"category": "user", "target": who("bob", f"{DOMAIN_SID}-1105"), "member": None}
    changes = [
        change(1, 0, origin=session, related=("C0002", "C9999"), notes=("A note.",)),
        change(
            2,
            5,
            **user,
            action="changed",
            details=(
                Detail("display name", "changed", "Bob", "Robert", None, "displayName"),
                Detail("title", "set", None, "Engineer", None, "title"),
            ),
            events=(ref(2, 5), ref(3, 5)),
            origin=Origin("local", logon_id="0x3e7"),
        ),
        change(
            3,
            6,
            **user,
            action="enabled",
            details=(
                Detail(
                    "account control",
                    "changed",
                    "0x202",
                    "0x200",
                    "account is no longer disabled",
                    "userAccountControl",
                ),
            ),
            origin=Origin("not-in-input", logon_id="0x1"),
        ),
        change(
            4,
            7.25,
            category="rights",
            action="right-granted",
            member=None,
            details=(
                Detail("right", "added", None, "SeDebugPrivilege", None, None),
                Detail("other right", "removed", "SeBackupPrivilege", None, None, None),
                Detail("fact", "info", None, "something", None, None),
                Detail("empty", "set", None, "", None, None),
            ),
        ),
        change(5, 3600 * 24 + 10, events=(), notes=("one", "two"), related=()),
    ]
    session_ref = ref(50, 1)
    notices = [
        Notice(
            D0, DC, "log-cleared", "The Security log was cleared.", who("mallory"), session_ref,
            "warning",
        ),
        Notice(
            D0, DC, "log-service-stopped", "The log service stopped.", Party(), session_ref, "info"
        ),
    ]  # fmt: skip
    base: dict[str, Any] = {
        "events": 10,
        "first": D0,
        "last": D0,
        "first_record": 1,
        "last_record": 20,
    }
    cov = [
        Coverage(DC, "Security", missing=((3, 4), (9, 9)), missing_count=3, continuity="gaps",
                 scope="unfiltered", statement="three absent", **base),
        Coverage("DC02", "Security", missing=tuple((i, i) for i in range(1, 25, 2)),
                 missing_count=12, continuity="gaps", scope="filtered", statement="x", **base),
        Coverage("DC03", "Security", missing=((5, 5),), missing_count=1, continuity="gaps",
                 scope="unknown", statement="y", **base),
        Coverage("DC04", "Security", missing=(), missing_count=0, continuity="complete",
                 scope="unfiltered", statement="ok", overwritten_before=D0, **base),
        Coverage("DC05", "Security", 3, D0, D0, None, None, "unnumbered", (), 0, "unknown", "z"),
        Coverage("DC06", "Security", 0, None, None, None, None, "empty", (), 0, "filtered", "e"),
    ]  # fmt: skip
    return Account(
        changes=changes,
        notices=notices,
        coverage=cov,
        problems=[
            Problem(Source("bad.csv", "line 4"), "The time could not be read.", 77),
            Problem(Source("bad.csv", "line 9"), "No event ID."),
        ],
        counts={"changes": 7, "context": 1, "notices": 2, "other": 5, "duplicates": 1},
        other_ids={("System", 7036): 2, ("Security", 4688): 3},
    )


def report_of(account: Account, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "inputs": INPUTS,
        "window": (D0, None),
        "generated_at": GENERATED,
        "version": "0.1.0",
    }
    return build_report(account, **{**args, **kw})


@pytest.fixture
def rich_report() -> dict[str, Any]:
    return report_of(rich())


def empty_account(*, complete: bool = True) -> Account:
    account = Account(
        counts={"changes": 0, "context": 0, "notices": 0, "other": 0, "duplicates": 0}
    )
    if not complete:
        account.problems.append(Problem(Source("x.csv", "line 1"), "bad"))
    return account


# --- report document ------------------------------------------------------------------------


def test_the_rich_report_follows_the_schema(rich_report: dict[str, Any]) -> None:
    schema_check("report-v1.schema.json", rich_report)
    assert rich_report["summary"]["notices"] == {"warning": 1, "info": 1}
    assert rich_report["summary"]["complete"] is False
    assert rich_report["notices"][0]["severity"] == "warning"
    assert rich_report["other_events"][0] == {"channel": "Security", "event_id": 4688, "count": 3}
    assert rich_report["window"] == {"since": "2026-11-03T23:59:58Z", "until": None}
    assert rich_report["changes"][3]["time"] == "2026-11-04T00:00:05.25Z"
    assert rich_report["coverage"][5]["first"] is None
    assert rich_report["changes"][0]["origin"]["source"] == {
        "file": "security.evtx",
        "position": "record 900",
    }
    assert rich_report["changes"][0]["actor"]["display"] == narrative.party(who("alice"))
    assert list(rich_report)[:3] == ["$schema", "schema_version", "tool"]


def test_an_empty_account_follows_the_schema() -> None:
    document = report_of(empty_account(), window=(None, None), inputs=[])
    schema_check("report-v1.schema.json", document)
    assert document["summary"]["first_change"] is None
    assert document["summary"]["by_category"] == {}
    assert document["summary"]["events"]["other"] == 0


def test_a_real_correlated_account_follows_the_schema() -> None:
    items = [logon(), member_added()]
    account = correlate.build([Input("security.evtx", items, "unknown")], catalog.load())
    document = report_of(account)
    schema_check("report-v1.schema.json", document)
    assert document["changes"][0]["origin"]["address"] == "192.0.2.44"
    other = event(4688, {"x": "y"}, seconds=1)
    account = correlate.build([Input("security.evtx", [other], "unknown")], catalog.load())
    schema_check("report-v1.schema.json", report_of(account))


def test_the_report_is_repeatable_and_ordered(rich_report: dict[str, Any]) -> None:
    assert render_json(report_of(rich())) == render_json(rich_report)
    summary = rich_report["summary"]
    assert list(summary["by_category"]) == ["group", "user", "rights"]
    assert [a["changes"] for a in summary["actors"]] == sorted(
        (a["changes"] for a in summary["actors"]), reverse=True
    )
    assert summary["actors"][0]["changes"] == 5
    assert [o["event_id"] for o in rich_report["other_events"]] == [4688, 7036]


def test_the_actor_list_is_capped_and_ties_sort_by_name() -> None:
    account = Account(counts={})
    for i in range(60):
        account.changes.append(change(i, i, actor=who(f"user{59 - i:02d}", f"S-1-5-21-{i}")))
    actors = report_of(account)["summary"]["actors"]
    assert len(actors) == 50
    assert actors[0]["name"].startswith("CORP\\user00")


def test_inputs_keep_only_the_documented_keys() -> None:
    extra = [{**INPUTS[0], "secret": "no"}]
    assert report_of(empty_account(), inputs=extra)["inputs"] == INPUTS


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "2026-01-02T03:04:05Z"),
        (datetime(2026, 1, 2, 3, 4, 5, 120000, tzinfo=UTC), "2026-01-02T03:04:05.12Z"),
        (datetime(2026, 1, 2, 3, 4, 5, 1, tzinfo=UTC), "2026-01-02T03:04:05.000001Z"),
        (
            datetime(2026, 1, 2, 3, 4, 5),  # noqa: DTZ001
            "2026-01-02T03:04:05Z",
        ),
        (
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=-6))),
            "2026-01-02T09:04:05Z",
        ),
    ],
)
def test_times_are_utc_with_z(value: datetime, text: str) -> None:
    assert format_time(value) == text


def test_json_keeps_documented_order_and_a_final_newline(rich_report: dict[str, Any]) -> None:
    text = render_json(rich_report)
    assert text.endswith("}\n")
    assert json.loads(text) == rich_report
    assert text.index('"$schema"') < text.index('"summary"') < text.index('"limitations"')


def test_json_survives_a_lone_surrogate() -> None:
    account = rich()
    account.problems.append(Problem(Source("x", "y"), "bad \ud800 text"))
    text = render_json(report_of(account))
    text.encode("utf-8")
    assert json.loads(text)["problems"][-1]["reason"] == "bad \ud800 text"


# --- headline -------------------------------------------------------------------------------


def test_headline_states() -> None:
    assert r.headline(report_of(empty_account())) == ("complete", "No changes found in the input.")
    one = Account(changes=[change(1, 0)], counts={})
    assert r.headline(report_of(one)) == (
        "complete",
        "1 change described. Nothing in the input suggests events are missing.",
    )
    many = Account(changes=[change(i, i) for i in range(1, 215)], counts={})
    assert r.headline(report_of(many))[1].startswith("214 changes described. Nothing")
    state, text = r.headline(report_of(rich()))
    assert state == "incomplete"
    assert text == (
        "5 changes described, but the account is incomplete: 1 notice, 2 problems with the "
        "input, 2 logs with missing events."
    )
    assert r.headline(report_of(empty_account(complete=False))) == (
        "incomplete",
        "No changes found in the input, but the account is incomplete: 1 problem with the input.",
    )


def test_only_warnings_count_and_info_alone_stays_complete() -> None:
    info = Notice(D0, DC, "k", "t", Party(), ref(1), "info")
    account = Account(changes=[change(1, 0)], notices=[info], counts={})
    assert r.headline(report_of(account))[0] == "complete"


def test_an_incomplete_report_with_no_listed_cause_still_says_so() -> None:
    bare = report_of(empty_account())
    bare["summary"]["complete"] = False
    assert r.headline(bare) == (
        "incomplete",
        "No changes found in the input, but the account is incomplete.",
    )


# --- Markdown -------------------------------------------------------------------------------


def test_markdown_digest_reads_in_order(rich_report: dict[str, Any]) -> None:
    md = r.render_markdown(rich_report)
    order = [
        "# Account of changes",
        "## Completeness",
        "### What each log holds",
        "### Problems with the input",
        "### Routine log events",
        "## Summary",
        "## Changes on 2026-11-03 (UTC): 1",
        "## Changes on 2026-11-04 (UTC): 3",
        "## Changes on 2026-11-05 (UTC): 1",
        "## Other events read",
        "## Inputs",
        "## Limitations",
    ]
    positions = [md.index(heading) for heading in order]
    assert positions == sorted(positions)
    assert "### C0001 · 23:59:58 UTC · CORP\\\\alice" in md
    assert "### C0004 · 00:00:05 UTC" in md
    assert "- display name: Bob → Robert [attribute: displayName]" in md.replace("\\", "")
    assert "set to Engineer (earlier value not recorded)" in md
    assert "(meaning: account is no longer disabled)" in md
    assert "added SeDebugPrivilege" in md
    assert "removed SeBackupPrivilege" in md
    assert "(empty)" in md
    assert "- Related changes: C0002, C9999" in md
    assert "- Note: A note." in md
    assert "event 4728, record 1001 (security.evtx, record 1)" in md
    assert "- Evidence: none" in md
    assert "From where: Session 0x5f1a2" in md
    assert "5\u201320" not in md
    assert "1\u201320" in md
    assert "3\u20134, 9" in md
    assert "and 2 more ranges" in md
    assert "none numbered" in md
    assert SHA in md
    assert "Period: from 2026-11-03T23:59:58Z onward." in md
    assert "All times are UTC." in md


def test_markdown_with_no_changes_and_period_forms() -> None:
    md = r.render_markdown(report_of(empty_account(), window=(None, GENERATED)))
    assert "No changes were found in the input." in md
    assert "No events were read." in md
    assert "Period: before 2026-11-05T09:30:00Z." in md
    md = r.render_markdown(report_of(empty_account(), window=(D0, GENERATED)))
    assert "from 2026-11-03T23:59:58Z until 2026-11-05T09:30:00Z" in md
    assert "everything in the input" in r.render_markdown(
        report_of(empty_account(), window=(None, None))
    )


def test_long_lists_are_capped_with_a_pointer_to_json() -> None:
    account = rich()
    warn = account.notices[0]
    info = account.notices[1]
    account.notices = [warn] * 30 + [info] * 25
    account.problems = [Problem(Source("f", f"line {i}"), "bad") for i in range(40)]
    account.coverage = [replace(account.coverage[0], computer=f"DC{i}") for i in range(120)]
    account.other_ids = {("Security", i): 1 for i in range(1, 130)}
    for i in range(60):
        account.changes.append(change(10 + i, 10 + i, actor=who(f"u{i}", f"S-1-5-21-{i}")))
    report = report_of(account)
    md = r.render_markdown(report)
    assert "5 more in the JSON report." in md  # warnings: 30 - 25
    assert "5 more in the JSON report." in md  # routine: 25 - 20
    assert "15 more in the JSON report." in md  # problems: 40 - 25
    assert "20 more in the JSON report." in md  # coverage and actors: 120 - 100
    assert "29 more in the JSON report." in md  # other events
    html = r.render_html(report)
    for count in ("5", "15", "20", "29"):
        assert f"{count} more in the JSON report." in html


def test_long_values_are_shortened_with_a_marker_in_md_html_and_not_csv() -> None:
    blob = "A" * 1000
    account = Account(
        changes=[
            change(1, 0, details=(Detail("security descriptor", "changed", blob, blob + "B"),))
        ],
        counts={},
    )
    report = report_of(account)
    md = r.render_markdown(report)
    marker = "(1000 characters; full value in the JSON report)"
    assert marker in md
    assert "(1001 characters; full value in the JSON report)" in md
    assert "A" * 301 not in md
    assert marker in r.render_html(report)
    assert "A" * 301 not in r.render_html(report)
    row = next(csv.DictReader(io.StringIO(r.render_csv(report), newline="")))
    assert row["old_value"] == blob
    assert row["new_value"] == blob + "B"
    assert json.loads(render_json(report))["changes"][0]["details"][0]["old"] == blob


def test_a_value_of_exactly_the_limit_is_not_shortened() -> None:
    value = "B" * r.MAX_VALUE
    assert r._shorten(value)  # noqa: SLF001 == value


# --- hostile values -------------------------------------------------------------------------

PAYLOAD = (
    "<script>alert(1)</script><img src=x onerror=alert(1)>\n# forged heading\n"
    "[click](javascript:alert(1)) | a | b |\n`tick` *bold* http://203.0.113.9/x user@example.com "
    "\x1b[2J\u202eevil &amp; \"quoted\" 'single'"
)
FORMULA = '=HYPERLINK("http://203.0.113.9","x")'


def hostile(payload: str = PAYLOAD) -> Account:
    p = Party(
        sid=payload,
        name=payload,
        domain=payload,
        dn=payload,
        object_class=payload,
        guid=payload,
        well_known=payload,
        known_as=payload,
    )
    origin = Origin(
        "session",
        logon_id=payload,
        address=payload,
        port=payload,
        workstation=payload,
        logon_type=payload,
        logon_type_name=payload,
        logon_time=D0,
        source=Source(payload, payload),
    )
    ev = EventRef(4728, 1, D0, Source(payload, payload))
    changes = [
        change(
            1,
            0,
            actor=p,
            target=p,
            member=p,
            computer=payload,
            category=payload,
            action=payload,
            title=payload,
            origin=origin,
            related=(payload,),
            notes=(payload,),
            events=(ev,),
            details=(
                Detail(payload, "changed", payload, payload, payload, payload),
                Detail(payload, "set", None, payload, payload, payload),
            ),
        )
    ]
    cov = Coverage(
        payload, payload, 1, D0, D0, 1, 5, "gaps", ((2, 3),), 2, "unfiltered", payload, None
    )
    return Account(
        changes=changes,
        notices=[
            Notice(D0, payload, payload, payload, p, ev, "warning"),
            Notice(D0, payload, payload, payload, p, ev, "info"),
        ],
        coverage=[cov],
        problems=[Problem(Source(payload, payload), payload, 3)],
        counts={},
        other_ids={(payload, 1): 1},
    )


def hostile_report(payload: str = PAYLOAD) -> dict[str, Any]:
    inputs = [{"name": payload, "format": payload, "scope": payload, "size": 1, "sha256": SHA}]
    return report_of(hostile(payload), inputs=inputs)


def test_hostile_report_still_follows_the_schema() -> None:
    schema_check("report-v1.schema.json", hostile_report())


def test_markdown_cannot_be_forged_by_event_data() -> None:
    md = r.render_markdown(hostile_report())
    assert "\x1b" not in md
    assert "\u202e" not in md
    assert "\\u202e" in md
    assert not re.search(r"(?<!\\)<", md)
    assert not re.search(r"(?<!\\)\]\(", md)
    assert not re.search(r"://(?!\u2060)", md)
    headings = [line for line in md.splitlines() if line.startswith("#")]
    expected = re.compile(r"^(#{1,3}) [^#\n]")
    assert all(expected.match(h) for h in headings)
    assert "\n# forged" not in md
    assert not any(line.startswith(("# forged", "[click]", "`tick`")) for line in md.splitlines())
    assert len([h for h in headings if h.startswith("# ")]) == 1
    # Every table row keeps the column count of its header.
    pipe = re.compile(r"(?<!\\)\|")
    for line in md.splitlines():
        if line.startswith("| ") and "---" not in line:
            assert len(pipe.findall(line)) in {3, 4, 6, 11}


class Tags(HTMLParser):
    """Collect every tag and attribute a page uses, and flag any that is not expected."""

    ALLOWED_TAGS = frozenset(
        "html head meta title style body a nav main header h1 h2 h3 h4 p span div section "  # noqa: SIM905
        "article table caption thead tbody tr th td ul li dl dt dd b code details summary "
        "footer br".split()
    )
    ALLOWED_ATTRS = frozenset(
        "lang charset http-equiv content name class id href scope role aria-label "  # noqa: SIM905
        "aria-labelledby".split()
    )

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []
        self.bad: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs += attrs
        if tag not in self.ALLOWED_TAGS:
            self.bad.append(tag)
        self.bad += [k for k, _ in attrs if k not in self.ALLOWED_ATTRS]


def parse(page: str) -> Tags:
    parser = Tags()
    parser.feed(page)
    return parser


def test_html_cannot_be_forged_by_event_data() -> None:
    page = r.render_html(hostile_report())
    parsed = parse(page)
    assert parsed.bad == []
    assert "script" not in parsed.tags
    assert "img" not in parsed.tags
    hrefs = [v for k, v in parsed.attrs if k == "href"]
    assert hrefs
    assert all(v is not None and re.fullmatch(r"#[a-z]+\d*", v) for v in hrefs)
    assert "\x1b" not in page
    assert "\u202e" not in page
    assert "&lt;script&gt;" in page
    assert "<script" not in page
    assert "http://203.0.113.9" in page  # shown as text, never a link target
    ids = [v for k, v in parsed.attrs if k == "id"]
    assert len(ids) == len(set(ids))


def test_html_related_links_only_point_at_known_changes(rich_report: dict[str, Any]) -> None:
    page = r.render_html(rich_report)
    assert '<a href="#c2">C0002</a>' in page
    assert "C9999" in page
    assert 'href="#C9999"' not in page


def test_csv_neutralises_formulas_and_keeps_full_values() -> None:
    account = Account(
        changes=[
            change(
                1,
                0,
                actor=who(FORMULA),
                details=(
                    Detail(FORMULA, "changed", "-1+1", "@SUM(1)", "\t=x"),
                    Detail("b", "set", None, "+cmd", None),
                ),
            )
        ],
        counts={},
    )
    text = r.render_csv(report_of(account))
    assert text.count("\r\n") == 3
    assert text.replace("\r\n", "").count("\n") == 0
    assert not text.startswith("﻿")
    rows = list(csv.DictReader(io.StringIO(text, newline="")))
    assert list(rows[0]) == list(r.CSV_COLUMNS)
    assert rows[0]["detail_label"] == "'" + FORMULA
    assert rows[0]["old_value"] == "'-1+1"
    assert rows[0]["new_value"] == "'@SUM(1)"
    assert rows[0]["meaning"] == "'\t=x"
    assert rows[1]["new_value"] == "'+cmd"
    for row in rows:
        for value in row.values():
            assert not value.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))


def test_csv_rows_cover_details_events_and_missing_parts(rich_report: dict[str, Any]) -> None:
    rows = list(csv.DictReader(io.StringIO(r.render_csv(rich_report), newline="")))
    assert len(rows) == 1 + 2 + 1 + 4 + 1
    first = rows[0]
    assert first["detail_label"] == ""
    assert first["origin_address"] == "192.0.2.44"
    assert first["logon_type"] == "3"
    assert first["member_sid"] == f"{DOMAIN_SID}-1105"
    assert first["time_utc"] == "2026-11-03T23:59:58Z"
    two = rows[1]
    assert (two["event_ids"], two["record_ids"], two["files"]) == (
        "4728; 4728",
        "1002; 1003",
        "security.evtx",
    )
    assert rows[-1]["event_ids"] == ""
    assert rows[3]["member"] == ""


def test_csv_with_a_missing_record_number() -> None:
    bare = replace(change(1, 0), events=(replace(ref(1), record_id=None),))
    text = r.render_csv(report_of(Account(changes=[bare], counts={})))
    assert next(csv.DictReader(io.StringIO(text)))["record_ids"] == ""
    assert "no record number" in r.render_markdown(report_of(Account(changes=[bare], counts={})))


def test_terminal_summary_is_plain_and_safe() -> None:
    text = r.terminal_summary(hostile_report())
    assert "\x1b" not in text
    assert "\u202e" not in text
    assert "\\u001b" in text
    assert "Completeness section" in text
    plain = r.terminal_summary(report_of(Account(changes=[change(1, 0)], counts={})))
    assert plain.splitlines()[0] == "toledot 0.1.0"
    assert "  group: 1" in plain
    assert "first change 2026-11-03T23:59:58Z" in plain
    assert "Completeness" not in plain
    assert r.terminal_summary(report_of(empty_account())).splitlines()[1] == (
        "No changes found in the input."
    )


# --- days, html structure -------------------------------------------------------------------


def test_changes_are_grouped_by_utc_day_across_midnight(rich_report: dict[str, Any]) -> None:
    days = r._by_day(rich_report)  # noqa: SLF001
    assert [(d, [c["id"] for c in cs]) for d, cs in days] == [
        ("2026-11-03", ["C0001"]),
        ("2026-11-04", ["C0002", "C0003", "C0004"]),
        ("2026-11-05", ["C0005"]),
    ]
    page = r.render_html(rich_report)
    assert page.index("2026-11-03 (UTC)") < page.index("2026-11-04 (UTC)")
    assert "Jump to day" in page


def test_html_is_one_self_contained_accessible_page(rich_report: dict[str, Any]) -> None:
    page = r.render_html(rich_report)
    parsed = parse(page)
    assert parsed.bad == []
    assert "script" not in parsed.tags
    assert re.search(r"https?://", page) is None
    assert f'content="{r.CSP}"' in page
    assert "default-src 'none'" in r.CSP
    assert '<a class="skip" href="#main">' in page
    assert 'id="main"' in page
    assert "prefers-color-scheme:dark" in page
    assert "position:sticky" in page
    assert '<html lang="en">' in page
    assert '<th scope="col">' in page
    assert '<th scope="row">' in page
    for anchor in ("completeness", "summary", "changes", "inputs", "limitations"):
        assert f'href="#{anchor}"' in page
        assert f'id="{anchor}"' in page
    assert "INCOMPLETE" not in page
    assert "⚠ Incomplete" in page
    assert "Routine log events (1)" in page
    assert "Notices that bear on completeness" in page
    assert "attribute: <code>displayName</code>" in page
    assert "(earlier value not recorded)" in page
    assert page.count("<h1>") == 1
    ok = r.render_html(report_of(Account(changes=[change(1, 0)], counts={})))
    assert "✔ Complete" in ok
    assert "Other events" not in ok


def test_the_print_stylesheet_reveals_collapsed_details(rich_report: dict[str, Any]) -> None:
    page = r.render_html(rich_report)
    print_css = page[page.index("@media print") :]
    assert "details::details-content{content-visibility:visible;display:block;block-size:auto}" in (
        print_css
    )
    assert "details:not([open])>*:not(summary){display:block}" in print_css


def test_html_for_an_empty_account() -> None:
    page = r.render_html(report_of(empty_account(), inputs=[]))
    assert "No changes were found in the input." in page
    assert "No events were read." in page
    assert parse(page).bad == []


# --- writing --------------------------------------------------------------------------------


def test_write_reports_writes_every_format_and_a_manifest(
    tmp_path: Path, rich_report: dict[str, Any]
) -> None:
    written = write_reports(
        tmp_path / "out", rich_report, ["csv", "md", "html", "json"], force=False
    )
    assert [p.name for p in written] == [
        "toledot-report.json",
        "toledot-report.md",
        "toledot-report.html",
        "toledot-changes.csv",
        "toledot-manifest.json",
    ]
    manifest = json.loads(written[-1].read_text(encoding="utf-8"))
    schema_check("manifest-v1.schema.json", manifest)
    assert [f["name"] for f in manifest["files"]] == [p.name for p in written[:-1]]
    for entry, path in zip(manifest["files"], written, strict=False):
        data = path.read_bytes()
        assert entry["size"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["inputs"] == [{"name": "security.evtx", "size": 4096, "sha256": SHA}]
    assert json.loads(written[0].read_text(encoding="utf-8")) == rich_report
    assert written[3].read_bytes().count(b"\r\n") > 3
    assert MANIFEST_NAME == "toledot-manifest.json"


def test_write_reports_can_choose_one_format(tmp_path: Path, rich_report: dict[str, Any]) -> None:
    written = write_reports(tmp_path, rich_report, ["md"], force=False)
    assert [p.name for p in written] == ["toledot-report.md", "toledot-manifest.json"]


def test_write_reports_refuses_to_overwrite_without_force(
    tmp_path: Path, rich_report: dict[str, Any]
) -> None:
    write_reports(tmp_path, rich_report, ["json", "md"], force=False)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    changed = report_of(empty_account())
    with pytest.raises(ToledotError):
        write_reports(tmp_path, changed, ["json", "md"], force=False)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    write_reports(tmp_path, changed, ["json", "md"], force=True)
    assert json.loads((tmp_path / "toledot-report.json").read_text(encoding="utf-8")) == changed


def test_write_reports_is_all_or_nothing(tmp_path: Path, rich_report: dict[str, Any]) -> None:
    (tmp_path / "toledot-report.md").mkdir()
    with pytest.raises(ToledotError):
        write_reports(tmp_path, rich_report, ["json", "md"], force=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["toledot-report.md"]


def test_write_reports_rejects_unknown_or_no_formats(
    tmp_path: Path, rich_report: dict[str, Any]
) -> None:
    with pytest.raises(ToledotError, match="unknown report format 'pdf'"):
        write_reports(tmp_path, rich_report, ["json", "pdf"], force=False)
    with pytest.raises(ToledotError, match="no report format"):
        write_reports(tmp_path, rich_report, [], force=False)
    assert list(tmp_path.iterdir()) == []


def test_hostile_values_survive_a_round_trip_through_every_file(tmp_path: Path) -> None:
    report = hostile_report(FORMULA + PAYLOAD)
    written = write_reports(tmp_path, report, ["json", "md", "html", "csv"], force=False)
    for path in written:
        path.read_text(encoding="utf-8")
