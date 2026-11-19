# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Events logged for success and failure are worded by the outcome the event itself records."""

from __future__ import annotations

import dataclasses
import json
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from faithful_toledot import catalog, correlate, pipeline
from faithful_toledot.events import ReadOptions
from faithful_toledot.formats.bundle import encode
from tests import evtx_builder as b
from tests.helpers import BOB, SESSION, event
from tests.test_formats_bundle import header
from tests.test_formats_csv import ps_csv, ps_row, viewer_csv, viewer_row
from tests.test_formats_xml import event as xml_event

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_toledot.changes import Account
    from faithful_toledot.events import Event

SUCCESS, FAILURE = 0x8020000000000000, 0x8010000000000000
FIELDS = {
    "TargetUserName": "bob",
    "TargetDomainName": "CORP",
    "TargetSid": BOB,
    "SubjectUserSid": "S-1-5-21-1-2-3-1104",
    "SubjectUserName": "alice",
    "SubjectDomainName": "CORP",
    "SubjectLogonId": SESSION,
}
OPTIONS = ReadOptions(
    local_offset=timedelta(0),
    day_first=False,
    names_for=catalog.names_for,
    labels_for=catalog.labels_for,
)
WORDS = {
    "success": ("password-reset", " reset the password of"),
    "failure": ("password-reset-failed", "attempted, unsuccessfully, to reset the password of"),
    "unknown": ("password-reset-attempted", "attempted to reset the password of"),
}


def check(path: Path, outcome: str) -> None:
    account, _ = pipeline.run([path], OPTIONS)
    assert not account.problems, account.problems
    (change,) = account.changes
    action, words = WORDS[outcome]
    assert change.action == action
    assert words in change.sentence
    assert account.counts["changes"] == 1


def message_4724() -> str:
    def section(name: str, rows: list[tuple[str, str]]) -> str:
        return f"{name}:\r\n" + "".join(f"\t{k}:\t\t{v}\r\n" for k, v in rows) + "\r\n"

    return "An attempt was made to reset an account's password.\r\n\r\n" + section(
        "Subject",
        [("Security ID", FIELDS["SubjectUserSid"]), ("Account Name", "alice"),
         ("Account Domain", "CORP"), ("Logon ID", SESSION)],
    ) + section(
        "Target Account",
        [("Security ID", BOB), ("Account Name", "bob"), ("Account Domain", "CORP")],
    )  # fmt: skip


def with_system(keywords: str | None, **extra: str) -> dict[str, str]:
    return {**({"Keywords": keywords} if keywords else {}), **extra}


@pytest.mark.parametrize(
    ("keywords", "outcome"),
    [
        ("0x8020000000000000", "success"),
        ("0x8010000000000000", "failure"),
        ("0x8030000000000000", "unknown"),  # both bits: contradictory
        ("0x8000000000000000", "unknown"),  # neither bit
        ("not a number", "unknown"),
        (None, "unknown"),
    ],
)
def test_the_keywords_mask_decides_and_anything_else_is_an_attempt(
    keywords: str | None, outcome: str
) -> None:
    item = dataclasses.replace(event(4724, FIELDS), system=with_system(keywords))
    account = correlate.build([correlate.Input("security.evtx", [item], "unknown")], catalog.load())
    assert account.changes[0].action == WORDS[outcome][0]


def test_the_password_change_event_works_the_same_way() -> None:
    item = dataclasses.replace(event(4723, FIELDS), system={"Keywords": "0x8010000000000000"})
    account = correlate.build([correlate.Input("security.evtx", [item], "unknown")], catalog.load())
    assert account.changes[0].action == "password-change-failed"
    assert "attempted, unsuccessfully, to change the password of" in account.changes[0].sentence


@pytest.mark.parametrize(("mask", "outcome"), [(SUCCESS, "success"), (FAILURE, "failure")])
def test_evtx(tmp_path: Path, mask: int, outcome: str) -> None:
    data = list(FIELDS.items())
    content = b.security_event(1, 4724, data=data, keywords=mask)
    path = tmp_path / "log.evtx"
    path.write_bytes(b.build_evtx([b.make_chunk([content], first_id=1)]))
    check(path, outcome)


@pytest.mark.parametrize(("keywords", "outcome"), [("0x8020000000000000", "success"),
                                                    ("0x8010000000000000", "failure")])  # fmt: skip
def test_xml(tmp_path: Path, keywords: str, outcome: str) -> None:
    body = "<EventData>" + "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in FIELDS.items())
    text = xml_event(4724, body=body + "</EventData>").replace("0x8020000000000000", keywords)
    path = tmp_path / "e.xml"
    path.write_text(text, encoding="utf-8")
    check(path, outcome)


@pytest.mark.parametrize(
    ("keywords", "outcome"),
    [(-9214364837600034816, "success"), (-9218868437227405312, "failure")],
)
def test_get_winevent_json(tmp_path: Path, keywords: int, outcome: str) -> None:
    record = {
        "Id": 4724, "Version": 0, "Keywords": keywords, "RecordId": 4120,
        "ProviderName": "Microsoft-Windows-Security-Auditing", "LogName": "Security",
        "MachineName": "dc01.corp.example", "TimeCreated": "2026-11-10T02:15:03.123Z",
        "Properties": [{"Value": value} for value in FIELDS.values()],
    }  # fmt: skip
    path = tmp_path / "e.json"
    path.write_text(json.dumps([record]), encoding="utf-8")
    check(path, outcome)


@pytest.mark.parametrize(
    ("keywords", "outcome"),
    [("-9214364837600034816", "success"), ("-9218868437227405312", "failure"), ("", "unknown")],
)
def test_get_winevent_csv(tmp_path: Path, keywords: str, outcome: str) -> None:
    row = ps_row(Message=message_4724(), Id="4724", Keywords=keywords, RecordId="4120")
    path = tmp_path / "e.csv"
    path.write_text(ps_csv(row), encoding="utf-8")
    check(path, outcome)


@pytest.mark.parametrize(
    ("level", "outcome"),
    [("Audit Success", "success"), ("Audit Failure", "failure"), ("Information", "unknown")],
)
def test_event_viewer_csv_uses_its_level_text(tmp_path: Path, level: str, outcome: str) -> None:
    row = viewer_row(Message=message_4724(), Level=level, **{"Event ID": "4724"})
    path = tmp_path / "v.csv"
    path.write_text(viewer_csv(row), encoding="utf-8")
    check(path, outcome)


@pytest.mark.parametrize(("keywords", "outcome"), [("0x8020000000000000", "success"),
                                                    ("0x8010000000000000", "failure")])  # fmt: skip
def test_collection_file(tmp_path: Path, keywords: str, outcome: str) -> None:
    item = dataclasses.replace(event(4724, FIELDS), system={"Keywords": keywords})
    path = tmp_path / "c.jsonl"
    path.write_bytes(encode(header(), [item]))
    check(path, outcome)


# --- review finding TOL-4: copies of one event that disagree about the outcome ---------------

OK_SYSTEM = {"Keywords": "0x8020000000000000"}
BAD_SYSTEM = {"Keywords": "0x8010000000000000"}
OK_LEVEL = {"LevelDisplayName": "Audit Success"}
BAD_LEVEL = {"LevelDisplayName": "Audit Failure"}
NO_SYSTEM: dict[str, str] = {}
BOTH_BITS = {"Keywords": "0x8030000000000000"}  # contradictory, so no evidence
ATTEMPT = "password-reset-attempted"
SUCCEEDED = "password-reset"
FAILED = "password-reset-failed"


def copies(*systems: dict[str, str], numbered: bool = True) -> list[Event]:
    first = dataclasses.replace(event(4724, FIELDS), record_id=7 if numbered else None)
    return [dataclasses.replace(first, system=system) for system in systems]


def build_inputs(items: list[Event], *, split: bool) -> Account:
    """Read the copies as one input, or each as its own input, as overlapping exports are."""
    inputs = (
        [correlate.Input(f"export{n}.evtx", [item], "unknown") for n, item in enumerate(items)]
        if split
        else [correlate.Input("security.evtx", items, "unknown")]
    )
    return correlate.build(inputs, catalog.load())


@pytest.mark.parametrize(
    ("one", "other"),
    [
        (OK_SYSTEM, BAD_SYSTEM),  # the reviewer's reproduction
        (OK_LEVEL, BAD_LEVEL),  # the Event Viewer CSV representation
        (OK_SYSTEM, BAD_LEVEL),  # one export of each kind
        (BAD_SYSTEM, OK_LEVEL),
    ],
)
@pytest.mark.parametrize("split", [False, True])
def test_conflicting_known_outcomes_for_one_record_are_a_problem_in_either_order(
    one: dict[str, str], other: dict[str, str], *, split: bool
) -> None:
    results = [build_inputs(copies(*pair), split=split) for pair in ((one, other), (other, one))]
    for account in results:
        (change,) = account.changes
        assert change.action == ATTEMPT  # neither success nor failure is claimed
        assert "attempted to reset the password of" in change.sentence
        assert any("disagree about whether" in note for note in change.notes)
        (problem,) = account.problems
        assert "Record 7" in problem.reason
        assert "disagree about whether the attempt succeeded" in problem.reason
        assert account.counts["duplicates"] == 1
        assert account.counts["changes"] == 1
        assert not account.complete
    assert [r.changes[0].action for r in results] == [ATTEMPT, ATTEMPT]


@pytest.mark.parametrize("known", [OK_SYSTEM, BAD_SYSTEM, OK_LEVEL, BAD_LEVEL])
@pytest.mark.parametrize("unknown", [NO_SYSTEM, BOTH_BITS, {"Keywords": "garbage"}])
@pytest.mark.parametrize("split", [False, True])
def test_a_copy_without_outcome_evidence_never_overrides_one_with_it(
    known: dict[str, str], unknown: dict[str, str], *, split: bool
) -> None:
    expected = SUCCEEDED if known in (OK_SYSTEM, OK_LEVEL) else FAILED
    for pair in ((known, unknown), (unknown, known)):
        account = build_inputs(copies(*pair), split=split)
        assert [c.action for c in account.changes] == [expected]
        assert not account.problems
        assert account.counts["duplicates"] == 1


@pytest.mark.parametrize("pair", [(OK_SYSTEM, OK_SYSTEM), (OK_SYSTEM, OK_LEVEL), (NO_SYSTEM,) * 2])
def test_agreeing_copies_are_plain_duplicates(pair: tuple[dict[str, str], ...]) -> None:
    account = build_inputs(copies(*pair), split=True)
    assert len(account.changes) == 1
    assert not account.problems
    assert account.counts["duplicates"] == 1


@pytest.mark.parametrize("order", [(OK_SYSTEM, BAD_SYSTEM, OK_SYSTEM), (BAD_SYSTEM, OK_SYSTEM) * 2])
def test_a_third_copy_does_not_repeat_the_problem_or_pick_a_side(
    order: tuple[dict[str, str], ...],
) -> None:
    account = build_inputs(copies(*order), split=True)
    assert [c.action for c in account.changes] == [ATTEMPT]
    assert len(account.problems) == 1


@pytest.mark.parametrize("first", [NO_SYSTEM, OK_SYSTEM, BAD_SYSTEM])
def test_evidence_from_two_later_copies_that_conflict_is_a_problem_too(
    first: dict[str, str],
) -> None:
    if first == NO_SYSTEM:
        orders = [(NO_SYSTEM, OK_SYSTEM, BAD_SYSTEM), (BAD_SYSTEM, NO_SYSTEM, OK_SYSTEM)]
    else:
        orders = [(first, OK_SYSTEM, BAD_SYSTEM)]
    for order in orders:
        account = build_inputs(copies(*order), split=True)
        assert [c.action for c in account.changes] == [ATTEMPT]
        assert len(account.problems) == 1


def test_unnumbered_copies_in_two_inputs_that_conflict_are_a_problem_in_either_order() -> None:
    for pair in ((OK_SYSTEM, BAD_SYSTEM), (BAD_SYSTEM, OK_SYSTEM), (OK_LEVEL, BAD_SYSTEM)):
        account = build_inputs(copies(*pair, numbered=False), split=True)
        assert [c.action for c in account.changes] == [ATTEMPT]
        assert len(account.problems) == 1
        assert account.counts["duplicates"] == 1
        assert not account.complete


@pytest.mark.parametrize("pair", [(NO_SYSTEM, OK_SYSTEM), (OK_SYSTEM, NO_SYSTEM)])
def test_an_unnumbered_copy_with_evidence_wins_over_one_without(
    pair: tuple[dict[str, str], ...],
) -> None:
    account = build_inputs(copies(*pair, numbered=False), split=True)
    assert [c.action for c in account.changes] == [SUCCEEDED]
    assert not account.problems


def test_identical_unnumbered_rows_in_one_input_stay_separate_events_with_their_own_outcome() -> (
    None
):
    # Event Viewer CSV times have whole seconds: a failed and then a successful attempt
    # can look alike. Within one export they are two events, each worded by its own row.
    account = build_inputs(copies(OK_LEVEL, BAD_LEVEL, numbered=False), split=False)
    assert sorted(c.action for c in account.changes) == sorted([FAILED, SUCCEEDED])
    assert not account.problems


def test_a_copy_that_matches_one_of_two_alike_rows_does_not_disturb_the_other() -> None:
    first = copies(OK_LEVEL, BAD_LEVEL, numbered=False)
    again = copies(BAD_LEVEL, numbered=False)[0]
    account = correlate.build(
        [
            correlate.Input("a.csv", first, "unknown"),
            correlate.Input("b.csv", [again], "unknown"),
        ],
        catalog.load(),
    )
    assert sorted(c.action for c in account.changes) == sorted([FAILED, SUCCEEDED])
    assert not account.problems
    assert account.counts["duplicates"] == 1


def test_other_events_are_unaffected_by_their_system_fields() -> None:
    first = dataclasses.replace(event(4728, FIELDS), record_id=9, system=OK_SYSTEM)
    second = dataclasses.replace(first, system=BAD_SYSTEM)
    account = build_inputs([first, second], split=True)
    assert len(account.changes) == 1
    assert not account.problems
