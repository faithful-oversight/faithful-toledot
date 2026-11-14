# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""How events become changes, origins, notices, and coverage."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from faithful_toledot import catalog, correlate, narrative
from faithful_toledot.correlate import Input, build
from faithful_toledot.events import Event, LogFacts, Problem, Source
from tests.helpers import (
    ALICE,
    BOB,
    DC,
    SESSION,
    SUBJECT,
    at,
    ds_change,
    event,
    logon,
    member_added,
)

if TYPE_CHECKING:
    from faithful_toledot.changes import Account

ADDED, DELETED = "%%14674", "%%14675"


SVCHOST = "C:\\Windows\\System32\\svchost.exe"


def account(
    *items: Event | Problem | LogFacts, scope: str = "unknown", **options: object
) -> Account:
    return build([Input("security.evtx", list(items), scope)], catalog.load(), **options)  # type: ignore[arg-type]


def logoff(session: str = SESSION, *, seconds: float = 0) -> Event:
    data = {
        "TargetUserSid": ALICE,
        "TargetUserName": "alice",
        "TargetDomainName": "CORP",
        "TargetLogonId": session,
        "LogonType": "3",
    }
    return event(4634, data, seconds=seconds)


# --- one event, one change ------------------------------------------------------------------


def test_a_membership_change_names_actor_member_group_and_origin() -> None:
    result = account(logon(), member_added())
    (change,) = result.changes
    assert (change.id, change.category, change.action) == ("C0001", "group", "member-added")
    assert change.actor.sid == ALICE
    assert change.actor.name == "alice"
    assert change.target.well_known == "Domain Admins, if this is a domain SID"
    assert change.member is not None
    assert change.member.sid == BOB
    assert change.member.dn == "CN=Bob Example,OU=Staff,DC=corp,DC=example"
    assert change.origin.status == "session"
    assert (change.origin.address, change.origin.logon_type_name) == ("192.0.2.44", "Network")
    assert change.sentence.startswith("CORP\\alice (")
    assert "to the group CORP\\Domain Admins" in change.sentence
    assert result.counts == {
        "changes": 1, "context": 1, "notices": 0, "other": 0, "duplicates": 0, "outside_window": 0,
    }  # fmt: skip
    assert result.complete


def test_a_failed_sid_history_attempt_is_never_narrated_or_counted_as_an_add() -> None:
    data = {
        "SourceUserName": "-",
        "TargetUserName": "victim",
        "TargetDomainName": "CORP",
        "TargetSid": BOB,
        "SubjectUserName": "alice",
        "SubjectDomainName": "CORP",
        "SubjectLogonId": SESSION,
        "PrivilegeList": "-",
    }
    result = account(event(4766, data), event(4765, {**data, "SidList": "-"}, seconds=5))
    failed, added = result.changes
    assert failed.action == "sid-history-failed"
    assert "attempted, unsuccessfully, to add SID history" in failed.sentence
    assert "added SID history" not in failed.sentence
    assert added.action == "sid-history-added"
    assert "attempted" not in added.sentence
    assert added.sentence.count("added SID history") == 1


def test_placeholders_are_absent_not_names() -> None:
    result = account(member_added(MemberName="-", SubjectUserName="-", SubjectDomainName="-"))
    (change,) = result.changes
    assert change.actor.name is None
    assert change.member is not None
    assert change.member.dn is None
    assert change.sentence.startswith(f"{ALICE} added {BOB} to")


def test_a_sid_is_named_from_other_events_only_when_they_agree() -> None:
    renamed = {**SUBJECT, "TargetSid": BOB, "TargetUserName": "bob", "TargetDomainName": "CORP"}
    one = account(member_added(MemberName="-"), event(4725, renamed, seconds=5))
    assert one.changes[0].member is not None
    assert one.changes[0].member.known_as == "CORP\\bob"
    assert "named CORP\\bob in other events" in one.changes[0].sentence
    other = {**renamed, "TargetUserName": "robert"}
    two = account(
        member_added(MemberName="-"), event(4725, renamed, seconds=5), event(4722, other, seconds=9)
    )
    assert two.changes[0].member is not None
    assert two.changes[0].member.known_as is None
    # The name an event itself records is never repeated as a name from elsewhere.
    assert one.changes[1].target.known_as is None


# --- origin ---------------------------------------------------------------------------------


def test_origin_is_not_guessed_when_the_logon_is_not_in_the_input() -> None:
    (change,) = account(member_added()).changes
    assert change.origin.status == "not-in-input"
    assert change.origin.address is None
    assert "is not in the input" in narrative.origin(change.origin)


def test_origin_uses_the_latest_logon_before_the_change_on_the_same_computer() -> None:
    result = account(
        logon(address="198.51.100.9", seconds=-500),
        logon(address="192.0.2.44", seconds=-60),
        logon(address="203.0.113.5", seconds=30),  # the ID reused later
        replace(logon(address="203.0.113.77", seconds=-10), computer="DC02.corp.example"),
        member_added(),
    )
    assert result.changes[0].origin.address == "192.0.2.44"


def test_a_session_that_logged_off_before_the_change_is_not_its_origin() -> None:
    result = account(logon(seconds=-60), logoff(seconds=-30), member_added())
    origin = result.changes[0].origin
    assert origin.status == "ended"
    assert "had ended with a logoff before this change" in narrative.origin(origin)


@pytest.mark.parametrize("order", [1, -1])
def test_two_different_logons_for_one_session_give_no_origin(order: int) -> None:
    first = logon(address="192.0.2.44")
    second = replace(logon(address="203.0.113.99"), record_id=first.record_id)
    result = build(
        [Input("a", [first, second][::order]), Input("b", [member_added()])], catalog.load()
    )
    (change,) = result.changes
    assert change.origin.status == "conflicting"
    assert "two different logons" in narrative.origin(change.origin)
    (problem,) = result.problems  # the same record number with different content
    assert "more than once with different content" in problem.reason


def test_copies_of_one_logon_record_with_different_times_give_no_origin() -> None:
    first = logon(seconds=-60, address="192.0.2.44")
    later = replace(logon(seconds=-30, address="203.0.113.99"), record_id=first.record_id)
    for order in ([first, later], [later, first]):
        result = build(
            [Input("a", order[:1]), Input("b", [*order[1:], member_added()])], catalog.load()
        )
        assert result.changes[0].origin.status == "conflicting"
        assert not result.complete


def test_two_unnumbered_logons_that_disagree_also_give_no_origin() -> None:
    one = replace(logon(address="192.0.2.44"), record_id=None)
    two = replace(logon(address="203.0.113.99"), record_id=None)
    assert account(one, two, member_added()).changes[0].origin.status == "conflicting"


def test_logon_events_that_name_no_session_are_context_only() -> None:
    explicit = event(4648, {**SUBJECT, "TargetUserName": "bob"}, seconds=-50)
    nameless = event(4634, {"TargetUserSid": ALICE}, seconds=-40)
    result = account(logon(), explicit, nameless, member_added())
    assert result.changes[0].origin.status == "session"
    assert result.counts["context"] == 3


def test_identical_copies_of_a_logon_count_once_and_keep_the_origin() -> None:
    copy = logon()
    result = build([Input("a", [copy]), Input("b", [copy, member_added()])], catalog.load())
    assert result.changes[0].origin.status == "session"
    assert (result.counts["context"], result.counts["duplicates"]) == (1, 1)


@pytest.mark.parametrize("boundary", [1100, 4608])
def test_a_logon_before_a_restart_is_not_the_origin_of_a_later_change(boundary: int) -> None:
    stop = event(boundary, {}, seconds=-30)
    result = account(logon(seconds=-60), stop, member_added())
    origin = result.changes[0].origin
    assert origin.status == "restarted"
    assert "only unique between restarts" in narrative.origin(origin)
    assert result.notices[0].severity == "info"  # restarts are routine on their own


def numbered_at(item: Event, record: int, seconds: float) -> Event:
    return replace(item, record_id=record, time=at(seconds))


@pytest.mark.parametrize(
    ("boundary_record", "status"),
    [
        (101, "restarted"),  # the same second, but after the logon in the log
        (99, "session"),  # the same second, and before the logon: the logon is fresh
    ],
)
def test_record_numbers_order_a_restart_that_shares_the_logon_time(
    boundary_record: int, status: str
) -> None:
    signed_in = numbered_at(logon(), 100, -60)
    stopped = numbered_at(event(1100, {}), boundary_record, -60)
    change = numbered_at(member_added(), 102, 0)
    assert account(signed_in, stopped, change).changes[0].origin.status == status


def test_a_restart_at_the_logon_time_with_no_order_is_not_trusted() -> None:
    signed_in = replace(logon(seconds=-60), record_id=None)
    stopped = replace(event(4608, {}, seconds=-60), record_id=None)
    assert account(signed_in, stopped, member_added()).changes[0].origin.status == "restarted"


@pytest.mark.parametrize(("boundary_record", "status"), [(101, "session"), (99, "restarted")])
def test_record_numbers_order_a_restart_that_shares_the_change_time(
    boundary_record: int, status: str
) -> None:
    signed_in = numbered_at(logon(), 50, -60)
    stopped = numbered_at(event(1100, {}), boundary_record, 0)
    change = numbered_at(member_added(), 100, 0)
    assert account(signed_in, stopped, change).changes[0].origin.status == status


@pytest.mark.parametrize(
    "when",
    [datetime(1, 1, 1, tzinfo=UTC), datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)],
)
def test_changes_at_the_ends_of_time_are_described(when: datetime) -> None:
    first = replace(member_added(), time=when)
    second = replace(member_added(1), time=when)
    result = account(replace(logon(), time=when), first, second)
    assert [c.related_total for c in result.changes] == [1, 1]


def test_a_logon_after_the_restart_is_used() -> None:
    result = account(logon(seconds=-90), event(4608, {}, seconds=-60), logon(seconds=-30),
                     member_added())  # fmt: skip
    assert result.changes[0].origin.status == "session"


def test_a_restart_on_another_computer_does_not_matter() -> None:
    elsewhere = replace(event(4608, {}, seconds=-30), computer="DC02.corp.example")
    assert account(logon(), elsewhere, member_added()).changes[0].origin.status == "session"


def test_a_logon_for_another_account_is_not_the_origin() -> None:
    bobs = logon()
    bobs = replace(bobs, data={**bobs.data, "TargetUserSid": BOB, "TargetUserName": "bob"})
    origin = account(bobs, member_added()).changes[0].origin
    assert origin.status == "other-account"
    assert "different account" in narrative.origin(origin)


def test_the_same_fields_in_another_order_are_the_same_event() -> None:
    added = member_added()
    reordered = replace(added, data=dict(reversed(list(added.data.items()))))
    result = build([Input("a", [added]), Input("b", [reordered])], catalog.load())
    assert len(result.changes) == 1
    assert (result.counts["duplicates"], result.problems) == (1, [])
    unnumbered = [replace(e, record_id=None) for e in (added, reordered)]
    result = build([Input("a", unnumbered[:1]), Input("b", unnumbered[1:])], catalog.load())
    assert len(result.changes) == 1


def test_a_burst_of_changes_lists_a_bounded_number_of_related_ones() -> None:
    burst = [member_added(i / 1000) for i in range(300)]
    result = account(logon(), *burst)
    assert len(result.changes) == 300
    assert max(len(c.related) for c in result.changes) == correlate.MAX_RELATED
    assert {c.related_total for c in result.changes} == {299}
    middle = result.changes[150]
    assert middle.id not in middle.related
    assert sum(len(c.related) for c in result.changes) <= 300 * correlate.MAX_RELATED


def test_a_logoff_at_the_same_moment_as_the_change_may_have_come_after_it() -> None:
    # Event Viewer CSV times have whole seconds, so equal times do not show the order.
    result = account(logon(seconds=-60), logoff(seconds=0), member_added())
    assert result.changes[0].origin.status == "session"


def test_system_sessions_and_events_without_a_session() -> None:
    system = account(member_added(SubjectLogonId="0x3e7"))
    assert system.changes[0].origin.status == "local"
    nameless = account(member_added(SubjectLogonId="-"))
    assert nameless.changes[0].origin.status == "none"
    odd = account(member_added(SubjectLogonId="not a number"))
    assert odd.changes[0].origin.status == "none"


def test_a_decimal_logon_id_matches_a_hexadecimal_one() -> None:
    """Exports that lose the hexadecimal form still link to the logon."""
    result = account(logon(), member_added(SubjectLogonId=str(int(SESSION, 16))))
    assert result.changes[0].origin.status == "session"


@pytest.mark.parametrize(
    ("address", "expected"),
    [("::1", "the computer itself"), ("-", "an address the logon did not record")],
)
def test_origin_wording(address: str, expected: str) -> None:
    result = account(logon(address=address), member_added())
    assert expected in narrative.origin(result.changes[0].origin)


# --- directory service changes --------------------------------------------------------------


def test_a_deleted_and_an_added_value_of_one_attribute_are_one_modification() -> None:
    result = account(
        ds_change("title", "Clerk", DELETED), ds_change("title", "Manager", ADDED, seconds=0.001)
    )
    (change,) = result.changes
    (detail,) = change.details
    assert (detail.kind, detail.old, detail.new) == ("changed", "Clerk", "Manager")
    assert len(change.events) == 2
    assert change.target.object_class == "user"
    assert "changed the user object CN=Bob Example" in change.sentence


def test_many_values_of_one_attribute_are_listed_not_paired() -> None:
    result = account(
        ds_change("member", "CN=A", DELETED),
        ds_change("member", "CN=B", ADDED),
        ds_change("member", "CN=C", ADDED),
    )
    kinds = [(d.kind, d.old, d.new) for d in result.changes[0].details]
    assert kinds == [("removed", "CN=A", None), ("added", None, "CN=B"), ("added", None, "CN=C")]


def test_directory_events_merge_only_within_one_correlation_object_and_computer() -> None:
    other_object = ds_change("title", "X", ADDED)
    other_object = replace(other_object, data={**other_object.data, "ObjectDN": "CN=Other"})
    result = account(
        ds_change("title", "Clerk", DELETED),
        ds_change("title", "Manager", ADDED, correlation="{99999999-0000-0000-0000-000000000000}"),
        other_object,
        replace(ds_change("title", "Y", ADDED), computer="DC02.corp.example"),
        ds_change("title", "Z", ADDED, correlation="{00000000-0000-0000-0000-000000000000}"),
        ds_change("title", "Z2", ADDED, correlation="{00000000-0000-0000-0000-000000000000}"),
    )
    assert len(result.changes) == 6


def test_ldap_account_control_changes_are_decoded() -> None:
    result = account(
        ds_change("userAccountControl", "512", DELETED),
        ds_change("userAccountControl", "66048", ADDED),
    )
    (detail,) = result.changes[0].details
    assert detail.meaning == "turned on: DONT_EXPIRE_PASSWORD"
    unknown = account(
        ds_change("userAccountControl", "512", DELETED),
        ds_change("userAccountControl", "not a number", ADDED),
    )
    assert unknown.changes[0].details[0].meaning is None


def test_an_unknown_directory_operation_is_kept_as_recorded() -> None:
    (change,) = account(ds_change("title", "X", "%%99999")).changes
    (detail,) = change.details
    assert (detail.kind, detail.meaning) == ("info", "operation %%99999")


# --- account attributes ---------------------------------------------------------------------


def user_changed(**fields: str) -> Event:
    info = catalog.load().event(4738)
    assert info is not None
    data = dict.fromkeys(info.versions[-1].fields, "-")
    data.update(SUBJECT)
    data.update(TargetUserName="bob", TargetDomainName="CORP", TargetSid=BOB)
    data.update(OldUacValue="0x10", NewUacValue="0x10")
    data.update(fields)
    return event(4738, data)


def test_only_changed_attributes_are_reported() -> None:
    (change,) = account(user_changed(DisplayName="Bob E. Example")).changes
    assert [(d.label, d.kind, d.new) for d in change.details] == [
        ("display name", "set", "Bob E. Example")
    ]


def test_sam_account_control_values_are_compared_and_decoded() -> None:
    (change,) = account(
        user_changed(OldUacValue="0x10", NewUacValue="0x11", UserAccountControl="%%2080")
    ).changes
    (detail,) = change.details
    assert (detail.label, detail.old, detail.new) == ("account control flags", "0x10", "0x11")
    assert detail.meaning is not None
    assert detail.meaning.startswith("turned on: ")
    undecodable = account(user_changed(OldUacValue="0x10", NewUacValue="junk")).changes[0]
    assert undecodable.details[0].meaning is None


def test_a_code_without_a_documented_meaning_says_so() -> None:
    (change,) = account(user_changed(AccountExpires="%%1794")).changes
    (detail,) = change.details
    assert detail.new == "%%1794"
    assert detail.meaning is not None
    entry = catalog.load().messages["%%1794"]
    assert ("not documented by Microsoft" in detail.meaning) is (not entry.confirmed)


def test_old_and_new_field_pairs_become_changes_and_other_fields_are_kept() -> None:
    data = {
        **SUBJECT,
        "ObjectServer": "Security",
        "OldSd": "D:(A;;GA;;;BA)",
        "NewSd": "D:(A;;GA;;;SY)",
    }
    unknown_pair = account(event(4670, {**data, "Extra": "kept", "NewOnly": "also kept"}))
    details = {d.label: d for d in unknown_pair.changes[0].details}
    sd = details["security descriptor"]
    assert (sd.kind, sd.old, sd.new) == (
        "changed", "D:(A;;GA;;;BA)", "D:(A;;GA;;;SY)",
    )  # fmt: skip
    assert details["Extra"].kind == "info"
    assert details["NewOnly"].new == "also kept"
    same = account(event(4670, {**SUBJECT, "OldSd": "x", "NewSd": "x"}))
    assert not [d for d in same.changes[0].details if d.label == "security descriptor"]


def test_user_rights_are_listed_one_by_one() -> None:
    data = {
        **SUBJECT,
        "TargetSid": BOB,
        "PrivilegeList": "SeBackupPrivilege\n\t\t\tSeDebugPrivilege",
    }
    granted = account(event(4704, data)).changes[0]
    assert [(d.kind, d.new) for d in granted.details] == [
        ("added", "SeBackupPrivilege"), ("added", "SeDebugPrivilege"),
    ]  # fmt: skip
    removed = account(event(4705, data)).changes[0]
    assert {d.kind for d in removed.details} == {"removed"}


def test_an_event_without_a_field_it_normally_has_carries_a_note() -> None:
    data = dict(member_added().data)
    del data["MemberSid"], data["SubjectUserName"]
    (change,) = account(event(4728, data)).changes
    (note,) = change.notes
    assert "lacks MemberSid, SubjectUserName" in note
    assert account(member_added()).changes[0].notes == ()


# --- related changes, order, window ---------------------------------------------------------


def test_changes_by_one_session_within_moments_are_related() -> None:
    result = account(
        member_added(0),
        member_added(1.5),
        member_added(3.4),
        member_added(30),
        member_added(30.5, SubjectLogonId="0x999"),
        replace(member_added(30.2), computer="DC02.corp.example"),
    )
    by_id = {c.id: c.related for c in result.changes}
    assert by_id["C0001"] == ("C0002",)
    assert by_id["C0002"] == ("C0001", "C0003")
    assert by_id["C0003"] == ("C0002",)
    assert [by_id[i] for i in ("C0004", "C0005", "C0006")] == [(), (), ()]


def test_changes_are_in_time_order_whatever_the_input_order() -> None:
    late, early = member_added(50), member_added(-50)
    result = build([Input("b.evtx", [late]), Input("a.evtx", [early])], catalog.load())
    assert [c.time for c in result.changes] == [at(-50), at(50)]
    assert [c.id for c in result.changes] == ["C0001", "C0002"]


def test_the_window_limits_changes_but_not_the_logons_behind_them() -> None:
    result = account(
        logon(seconds=-600), member_added(-300), member_added(0), member_added(300),
        since=at(-10), until=at(300),
    )  # fmt: skip
    (change,) = result.changes
    assert change.time == at(0)
    assert change.origin.status == "session"


# --- duplicates and conflicts ---------------------------------------------------------------


def test_the_same_record_from_two_inputs_is_one_change() -> None:
    original = member_added()
    copy = replace(original, source=Source("copy.xml", "event 1"))
    result = build([Input("a", [original]), Input("b", [copy])], catalog.load())
    assert len(result.changes) == 1
    assert result.counts["duplicates"] == 1
    assert result.complete


def test_two_inputs_that_disagree_about_a_record_are_a_problem() -> None:
    original = member_added()
    forged = replace(original, data={**original.data, "MemberSid": ALICE})
    result = build([Input("a", [original]), Input("b", [forged])], catalog.load())
    # Both are kept, such as an archived log and the current one reusing a number.
    assert [c.member.sid for c in result.changes if c.member] == [BOB, ALICE]
    (problem,) = result.problems
    assert "more than once with different content. Both are kept" in problem.reason
    assert not result.complete


def test_events_without_record_numbers_cannot_be_deduplicated() -> None:
    one = replace(member_added(), record_id=None)
    result = account(one, one)
    assert len(result.changes) == 2
    assert result.coverage[0].continuity == "unnumbered"


def test_the_same_unnumbered_event_in_two_overlapping_exports_counts_once() -> None:
    one = replace(member_added(), record_id=None)
    other = replace(member_added(5), record_id=None)
    result = build([Input("monday.csv", [one]), Input("week.csv", [one, other])], catalog.load())
    assert len(result.changes) == 2
    assert result.counts["duplicates"] == 1


def test_a_rename_means_an_account_has_no_single_name() -> None:
    carol = f"{BOB}9"
    created = event(
        4720,
        {**SUBJECT, "TargetUserName": "carol1", "TargetDomainName": "CORP", "TargetSid": carol},
    )
    renamed = event(4781, {**SUBJECT, "OldTargetUserName": "carol1", "NewTargetUserName": "carol2",
                           "TargetDomainName": "CORP", "TargetSid": carol}, seconds=10)  # fmt: skip
    added = member_added(20, MemberSid=carol, MemberName="CN=carol2,OU=Staff,DC=corp,DC=example")
    change = account(created, renamed, added).changes[-1]
    assert change.member is not None
    assert change.member.known_as is None
    assert "carol1" not in change.sentence


def test_event_viewer_words_for_directory_operations_pair_like_the_codes() -> None:
    (change,) = account(
        ds_change("description", "old", "Value Deleted"),
        ds_change("description", "new", "Value Added"),
    ).changes
    assert [(d.kind, d.old, d.new) for d in change.details] == [("changed", "old", "new")]


def test_system_sessions_do_not_relate_changes() -> None:
    result = account(*(member_added(i, SubjectLogonId="0x3e7") for i in range(3)))
    assert [c.related for c in result.changes] == [(), (), ()]


def test_a_log_that_still_holds_record_one_has_lost_nothing() -> None:
    result = account(facts(oldest_record=1), member_added())
    assert result.coverage[0].overwritten_before is None


def test_log_facts_follow_the_name_the_events_use() -> None:
    short = facts(computer="DC01", asked_since=None)
    result = account(short, member_added())
    assert [c.computer for c in result.coverage] == [DC]
    two = [member_added(), replace(member_added(1), computer="DC01.other.example")]
    unclear = account(short, *two)
    assert sorted(c.computer for c in unclear.coverage) == sorted(
        ["DC01", DC, "DC01.other.example"]
    )


# --- notices --------------------------------------------------------------------------------


def test_a_cleared_log_is_a_notice_and_makes_the_account_incomplete() -> None:
    result = account(event(1102, {**SUBJECT}, seconds=5), member_added())
    (notice,) = result.notices
    assert notice.kind == "log-cleared"
    assert "The log was cleared." in notice.text
    assert notice.actor.name == "alice"
    assert len(result.changes) == 1
    assert not result.complete


def test_an_audit_policy_change_is_both_a_change_and_a_notice() -> None:
    result = account(
        event(4719, {**SUBJECT, "SubcategoryGuid": "{0cce9235-69ae-11d9-bed3-505054503030}"})
    )
    assert [c.action for c in result.changes] == ["policy-changed"]
    assert [n.kind for n in result.notices] == ["audit-policy-changed"]
    assert (result.counts["changes"], result.counts["notices"]) == (1, 0)  # its event, once


@pytest.mark.parametrize("window", [{}, {"since": at(5)}, {"until": at(5)}])
def test_every_event_read_is_counted_once(window: dict[str, Any]) -> None:
    items = [
        logon(), member_added(), member_added(1), member_added(10), member_added(10),
        ds_change("description", "a", "%%14675", seconds=2),
        ds_change("description", "b", "%%14674", seconds=2),
        event(1102, {**SUBJECT}, seconds=3), event(4719, {**SUBJECT}, seconds=4),
        event(9999, {}), event(4616, {**SUBJECT}, seconds=12),
    ]  # fmt: skip
    items[4] = replace(items[3])  # the same record twice
    result = account(*items, **window)
    assert sum(result.counts.values()) == len(items)


def test_notices_outside_the_window_are_left_out() -> None:
    result = account(
        event(1102, {**SUBJECT}, seconds=-100), event(4719, {**SUBJECT}, seconds=-90), since=at(0)
    )
    assert result.notices == []
    assert result.changes == []


# --- coverage and problems ------------------------------------------------------------------


def numbered(*records: int | None, event_id: int = 4728) -> list[Event]:
    return [
        replace(member_added(index), record_id=record, event_id=event_id)
        for index, record in enumerate(records)
    ]


def test_coverage_reports_absent_record_numbers() -> None:
    result = account(*numbered(10, 11, 15, 16, 20))
    (log,) = result.coverage
    assert (log.computer, log.channel, log.events) == (DC, "Security", 5)
    assert (log.first_record, log.last_record) == (10, 20)
    assert log.continuity == "gaps"
    assert log.missing == ((12, 14), (17, 19))
    assert log.missing_count == 6
    assert "toledot cannot tell which" in log.statement
    # Of unknown scope, a gap is neither proof of missing events nor of none missing.
    assert (log.checked, result.completeness) == (False, "unconfirmed")


@pytest.mark.parametrize(
    ("scope", "completeness", "words"),
    [
        ("unfiltered", "incomplete", "events are missing"),
        ("filtered", "complete", "this is expected"),
        ("nonsense", "unconfirmed", "toledot cannot tell which"),
    ],
)
def test_what_a_gap_means_depends_on_the_stated_scope(
    scope: str, completeness: str, words: str
) -> None:
    result = account(*numbered(1, 3), scope=scope)
    assert words in result.coverage[0].statement
    assert result.completeness == completeness
    assert result.complete is (completeness == "complete")


@pytest.mark.parametrize(
    ("records", "scope", "completeness"),
    [
        ((1, 2, 3), "unknown", "complete"),  # continuous numbers are evidence
        ((None, None), "unknown", "unconfirmed"),  # an export with no record numbers
        ((), "unknown", "unconfirmed"),  # nothing read at all
    ],
)
def test_complete_needs_evidence(
    records: tuple[int | None, ...], scope: str, completeness: str
) -> None:
    assert account(*numbered(*records), scope=scope).completeness == completeness


def test_coverage_handles_any_order_overlaps_and_unnumbered_events() -> None:
    result = account(*numbered(5, 3, 4, 4, None, 9, 1, event_id=4688))
    (log,) = result.coverage
    assert log.missing == ((2, 2), (6, 8))
    assert "1 events carry no record number" in log.statement
    assert result.counts["other"] == 7
    assert result.other_ids == {("Security", 4688): 7}
    whole = account(*numbered(1, 2, 3))
    assert whole.coverage[0].continuity == "complete"
    assert whole.coverage[0].missing_count == 0
    single = account(*numbered(1, 3)).coverage[0]
    assert "1 record number between the first and the last is absent" in single.statement


def test_logs_are_tracked_per_computer_and_channel() -> None:
    result = account(
        member_added(),
        replace(member_added(), computer="dc02.corp.example"),
        event(104, {"Channel": "Security"}, channel="System"),
    )
    assert [(c.computer, c.channel) for c in result.coverage] == [
        ("DC01.corp.example", "Security"),
        ("DC01.corp.example", "System"),
        ("dc02.corp.example", "Security"),
    ]


def test_reader_problems_are_kept_and_make_the_account_incomplete() -> None:
    problem = Problem(Source("security.evtx", "record 7"), "The record is truncated.", 7)
    result = account(problem, member_added())
    assert result.problems == [problem]
    assert not result.complete


def test_problems_beyond_the_limit_are_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(correlate, "MAX_PROBLEMS", 2)
    problems = [Problem(Source("f", f"record {i}"), "bad") for i in range(5)]
    result = account(*problems)
    assert len(result.problems) == 3
    assert "3 further problems are not listed" in result.problems[-1].reason


def test_missing_ranges_listed_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(correlate, "MAX_MISSING_RANGES", 2)
    log = account(*numbered(1, 3, 5, 7, 9)).coverage[0]
    assert len(log.missing) == 2
    assert log.missing_count == 4


# --- what a collector recorded about the log -------------------------------------------------


def facts(**overrides: object) -> LogFacts:
    values: dict[str, object] = {
        "computer": DC,
        "channel": "Security",
        "source": Source("events.jsonl", "line 1"),
        "oldest_time": at(-100),
        "asked_since": at(-1000),
        "filtered": True,
    }
    values.update(overrides)
    return LogFacts(**values)  # type: ignore[arg-type]


def test_a_log_that_no_longer_reached_back_far_enough_is_incomplete() -> None:
    result = account(
        facts(), facts(oldest_time=at(-50)), facts(oldest_time=at(-70)), member_added()
    )
    (log,) = result.coverage
    assert log.overwritten_before == at(-50)
    assert "earlier events had been overwritten and are missing" in log.statement
    assert log.scope == "filtered"
    assert not result.complete


@pytest.mark.parametrize(
    "overrides",
    [{"oldest_time": at(-2000)}, {"asked_since": None}, {"oldest_time": None}],
)
def test_a_log_that_reached_back_far_enough_is_not_flagged(overrides: dict[str, object]) -> None:
    result = account(facts(**overrides), member_added())
    assert result.coverage[0].overwritten_before is None
    assert result.complete


def test_a_collected_log_with_no_events_is_still_reported() -> None:
    result = account(facts(filtered=False, asked_since=None))
    (log,) = result.coverage
    assert (log.events, log.first, log.continuity, log.scope) == (0, None, "empty", "unfiltered")
    assert "found none of the events" in log.statement


def test_a_collection_says_its_own_scope_even_with_whole_logs() -> None:
    result = account(facts(asked_since=None), *numbered(1, 3), scope="unfiltered")
    assert result.coverage[0].scope == "filtered"  # the gap is expected, not missing events
    assert result.complete
    declared = account(facts(filtered=False, asked_since=None), *numbered(1, 3))
    assert declared.coverage[0].scope == "unfiltered"
    assert not declared.complete


def test_an_export_without_a_channel_still_finds_its_events() -> None:
    """Event Viewer CSV keeps neither the log name nor the computer."""
    bare = replace(member_added(), channel="", computer="")
    (change,) = account(bare).changes
    assert change.action == "member-added"


def test_narrative_falls_back_when_an_event_records_little() -> None:
    nameless = account(event(4720, {"SubjectLogonId": "-"})).changes[0]
    assert nameless.sentence == (
        "an account the event does not name created the user account a user account the "
        "event does not name."
    )
    typed = account(logon(kind="77"), member_added()).changes[0]
    assert "as logon type 77 from" in narrative.origin(typed.origin)
    untyped = account(logon(kind="-"), member_added()).changes[0]
    assert "a logon of unrecorded type" in narrative.origin(untyped.origin)
    guid_only = account(replace(ds_change("title", "x", ADDED), event_id=5141)).changes[0]
    assert "deleted the user object" in guid_only.sentence
    assert narrative.sentence(replace(nameless, action="mystery", title="Odd thing")).endswith(
        "made a change (odd thing) to a user account the event does not name."
    )


# --- what real logs taught ------------------------------------------------------------------


def test_file_and_registry_object_events_are_not_directory_changes() -> None:
    data = {
        **SUBJECT,
        "ObjectType": "File",
        "ObjectName": "C:\\Windows\\x.dll",
        "OldSd": "a",
        "NewSd": "b",
    }
    result = account(event(4907, data), event(4670, {**data, "ObjectType": "Key"}))
    assert result.changes == []
    assert result.counts["other"] == 2


def test_a_rename_is_one_change_from_the_old_name_to_the_new() -> None:
    data = {
        "OldTargetUserName": "bob", "NewTargetUserName": "robert", "TargetDomainName": "CORP",
        "TargetSid": BOB, **SUBJECT, "PrivilegeList": "-",
    }  # fmt: skip
    (change,) = account(event(4781, data)).changes
    assert [(d.label, d.kind, d.old, d.new) for d in change.details] == [
        ("account name", "changed", "bob", "robert")
    ]
    assert "renamed the account CORP\\bob" in change.sentence
    unchanged = account(event(4781, {**data, "NewTargetUserName": "bob"})).changes[0]
    assert unchanged.details == ()


def test_a_new_accounts_unset_attributes_are_not_listed() -> None:
    info = catalog.load().event(4720)
    assert info is not None
    data = dict.fromkeys(info.versions[-1].fields, "%%1793")
    data.update(SUBJECT)
    data.update(TargetUserName="carol", TargetDomainName="CORP", TargetSid=f"{BOB}9")
    data.update(SamAccountName="carol", OldUacValue="0x0", NewUacValue="0x15")
    (change,) = account(event(4720, data)).changes
    labels = [d.label for d in change.details]
    assert "SAM account name" in labels
    assert "display name" not in labels
    assert {d.kind for d in change.details if d.label == "SAM account name"} == {"initial"}
    cleared = account(user_changed(DisplayName="%%1793")).changes[0]
    assert [d.new for d in cleared.details] == ["%%1793"]  # on a change, it was cleared


def test_a_well_known_rid_is_not_taken_as_proof_of_a_domain() -> None:
    fixed = account(member_added(TargetSid="S-1-5-32-544")).changes[0]
    assert fixed.target.well_known == "Administrators"


@pytest.mark.parametrize(
    ("event_id", "actor_sid", "severity", "complete"),
    [
        (4616, "S-1-5-19", "info", True),  # with svchost.exe, below
        (4616, ALICE, "warning", False),
        (1100, ALICE, "info", True),
        (1102, "S-1-5-18", "warning", False),
    ],
)
def test_routine_log_events_are_information_not_warnings(
    event_id: int, actor_sid: str, severity: str, *, complete: bool
) -> None:
    data = {**SUBJECT, "SubjectUserSid": actor_sid, "ProcessName": SVCHOST}
    result = account(event(event_id, data))
    (notice,) = result.notices
    assert notice.severity == severity
    assert ("Events may be missing" in notice.text) is (severity == "warning")
    assert result.complete is complete


@pytest.mark.parametrize(
    ("data", "text"),
    [
        (
            {"PreviousTime": "2026-11-03T14:00:00Z", "NewTime": "2026-11-03T14:00:03Z"},
            "The system time was changed from 2026-11-03T14:00:00Z to 2026-11-03T14:00:03Z.",
        ),
        (
            {"PreviousDate": "\u200e11/\u200e3/2026", "PreviousTime": "2:00:00 PM",
             "NewDate": "11/3/2026", "NewTime": "6:00:00 PM"},
            "The system time was changed from 11/3/2026 2:00:00 PM to 11/3/2026 6:00:00 PM.",
        ),
        ({"NewTime": "2026-11-03T18:00:00Z"}, "The system time was changed."),
    ],
)  # fmt: skip
def test_a_time_change_says_from_and_to(data: dict[str, str], text: str) -> None:
    (notice,) = account(event(4616, {**SUBJECT, **data})).notices
    assert notice.text.startswith(text)
    synced = {**SUBJECT, **data, "SubjectUserSid": "S-1-5-19", "ProcessName": SVCHOST}
    (service,) = account(event(4616, synced)).notices
    assert service.text == text.replace(
        "The system time was changed", "The Windows Time service adjusted the system time"
    )


@pytest.mark.parametrize(
    ("sid", "process", "new_time", "severity"),
    [
        ("S-1-5-19", SVCHOST, "2026-11-03T14:04:59Z", "info"),
        ("S-1-5-20", SVCHOST, "2026-11-03T13:55:01Z", "info"),
        ("S-1-5-19", SVCHOST, "2026-11-03T14:05:01Z", "warning"),  # too far for a correction
        ("S-1-5-18", "C:\\Windows\\System32\\cmd.exe", "2026-11-03T14:00:01Z", "warning"),
        ("S-1-5-18", "C:\\Tools\\vmtoolsd.exe", "2026-11-03T18:00:00Z", "warning"),
        ("S-1-5-18", "", "2026-11-03T14:00:01Z", "warning"),
        ("S-1-5-19", SVCHOST, "not a time", "info"),  # version 0 style: the process decides
    ],
)  # fmt: skip
def test_only_small_corrections_by_the_time_service_are_routine(
    sid: str, process: str, new_time: str, severity: str
) -> None:
    data = {**SUBJECT, "SubjectUserSid": sid, "ProcessName": process,
            "PreviousTime": "2026-11-03T14:00:00Z", "NewTime": new_time}  # fmt: skip
    (notice,) = account(event(4616, data)).notices
    assert notice.severity == severity


def test_dropped_events_carry_their_undocumented_reason() -> None:
    (notice,) = account(event(1101, {"Reason": "0"})).notices
    assert notice.text.startswith(
        "Windows dropped audit events before they were written (reason code 0, not documented"
    )
    (bare,) = account(event(1101, {})).notices
    assert bare.text.startswith("Windows dropped audit events before they were written. ")


@pytest.mark.parametrize(
    ("provider", "channel", "kept"),
    [
        ("Microsoft-Windows-Eventlog", "Security", True),
        ("Eventlog", "", True),
        ("", "", True),
        (".NET Runtime Optimization Service", "", False),
        (".NET Runtime Optimization Service", "Security", False),
    ],
)
def test_an_event_id_counts_only_from_its_own_provider(
    provider: str, channel: str, *, kept: bool
) -> None:
    other = replace(
        event(1101, {"param1": "failed to compile"}), provider=provider, channel=channel
    )
    assert bool(account(other).notices) is kept


def test_event_viewer_display_names_match_their_providers() -> None:
    shown = replace(member_added(), provider="Microsoft Windows security auditing.", channel="")
    assert len(account(shown).changes) == 1


def test_code_lists_in_other_fields_are_put_in_words_only_when_all_are_known() -> None:
    known = sorted(catalog.load().messages)[:2]
    data = {**SUBJECT, "AuditPolicyChanges": ", ".join(known), "Mixed": f"{known[0]}, %%99999"}
    (change,) = account(event(4719, {**data, "Plain": "text"})).changes
    by_label = {d.label: d for d in change.details}
    assert by_label["AuditPolicyChanges"].meaning is not None
    assert by_label["Mixed"].meaning is None
    assert by_label["Plain"].meaning is None
    assert f"changed policy on {DC} (" in change.sentence
