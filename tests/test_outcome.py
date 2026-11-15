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
