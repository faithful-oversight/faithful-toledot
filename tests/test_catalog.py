# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the event catalog and its strict loader."""

from __future__ import annotations

import copy
import dataclasses
import tomllib
from importlib import resources
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from faithful_toledot import catalog
from faithful_toledot.catalog import Catalog, CatalogError
from faithful_toledot.events import ReadOptions

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_TEXT = resources.files("faithful_toledot.data").joinpath("events.toml").read_text(encoding="utf-8")
_RAW: dict[str, Any] = tomllib.loads(_TEXT)

USER = [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781, 4765, 4766, 4794, 4780]
COMPUTER = [4741, 4742, 4743]
GROUP = [
    *range(4727, 4731),
    4737,
    *range(4731, 4736),
    *range(4754, 4759),
    *range(4744, 4749),
    *range(4749, 4754),
    *range(4759, 4765),
]
DIRECTORY = [5136, 5137, 5138, 5139, 5141]
POLICY = [4739, 4713, 4719, 4706, 4707, 4716, 4865, 4866, 4867, 4670, 4704, 4705, 4717, 4718, 4907]
CONTEXT = [4624, 4634, 4647, 4648, 4672, 4768, 4769, 4776, 1102, 1100, 1101, 1104, 1105, 4616]
REQUIRED = [("Security", n) for n in USER + COMPUTER + GROUP + DIRECTORY + POLICY + CONTEXT]
REQUIRED.append(("System", 104))


def fresh() -> dict[str, Any]:
    return copy.deepcopy(_RAW)


def event_of(raw: dict[str, Any], channel: str, event_id: int) -> dict[str, Any]:
    for item in raw["event"]:
        if item["channel"] == channel and item["id"] == event_id:
            found: dict[str, Any] = item
            return found
    raise AssertionError((channel, event_id))


@pytest.fixture(scope="module")
def cat() -> Catalog:
    return catalog.load()


# --- the shipped data ---------------------------------------------------------------------


def test_packaged_catalog_loads_and_is_cached(cat: Catalog) -> None:
    assert catalog.load() is cat
    assert len(cat.events) == len(_RAW["event"])


@pytest.mark.parametrize(("channel", "event_id"), REQUIRED)
def test_every_scope_event_is_present(cat: Catalog, channel: str, event_id: int) -> None:
    info = cat.event(event_id, channel)
    assert info is not None
    assert info.id == event_id
    assert (channel, event_id) in cat.wanted_ids


def test_wanted_ids_is_exactly_the_catalog(cat: Catalog) -> None:
    assert cat.wanted_ids == {(e.channel, e.id) for e in cat.events}
    assert len(cat.wanted_ids) == len(cat.events)


def test_structural_invariants_hold_for_every_event(cat: Catalog) -> None:
    for info in cat.events:
        known = info.all_fields
        for version in info.versions:
            assert len(set(version.fields)) == len(version.fields), info.id
        assert set(info.roles) <= catalog.ROLE_NAMES
        assert set(info.roles.values()) <= known
        assert {a.field for a in info.attributes} <= known
        assert set(info.labels.values()) <= known
        assert info.category in catalog.CATEGORIES
        assert info.action in catalog.ACTIONS
        if not info.confirmed:
            assert info.notes


def test_every_source_url_is_https_on_an_allowed_host(cat: Catalog) -> None:
    urls = [e.source for e in cat.events]
    urls += [m.source for m in cat.messages.values()]
    urls += [f.source for f in cat.sam_flags.values()] + [f.source for f in cat.ldap_flags.values()]
    urls += [s.source for s in cat.sids.values()] + [r.source for r in cat.rids.values()]
    urls += [item["source"] for item in _RAW["logon_type"]]
    assert urls
    for url in urls:
        parts = urlsplit(url)
        assert parts.scheme == "https", url
        assert parts.hostname in catalog.ALLOWED_SOURCE_HOSTS, url


def test_ids_are_unique_per_channel_in_the_raw_file() -> None:
    pairs = [(e["channel"], e["id"]) for e in _RAW["event"]]
    assert len(pairs) == len(set(pairs))


def test_4624_versions_append_fields(cat: Catalog) -> None:
    info = cat.event(4624, "Security")
    assert info is not None
    by_version = {v.version: v for v in info.versions}
    assert len(by_version[0].fields) == 20
    assert len(by_version[1].fields) == 21
    assert len(by_version[2].fields) == 27
    assert by_version[1].fields[:20] == by_version[0].fields
    assert by_version[2].fields[:21] == by_version[1].fields
    assert by_version[0].derived
    assert not by_version[2].derived
    assert info.roles["logon_id"] == "TargetLogonId"
    assert info.roles["actor_logon_id"] == "SubjectLogonId"


def test_account_change_events_carry_attribute_lists(cat: Catalog) -> None:
    for event_id in (4720, 4738, 4741, 4742):
        info = cat.event(event_id)
        assert info is not None
        kinds = {a.kind for a in info.attributes}
        assert {"uac-old", "uac-new", "uac-control", "logon-hours", "sid-history"} <= kinds
    changed = cat.event(4738)
    assert changed is not None
    assert changed.fields(0, 27) is not None
    assert changed.fields(0, 27)[0] == "Dummy"  # type: ignore[index]


def test_directory_events_expose_object_roles(cat: Catalog) -> None:
    for event_id in (5136, 5137, 5138, 5139, 5141):
        info = cat.event(event_id)
        assert info is not None
        assert {"object_dn", "object_guid", "object_class"} <= set(info.roles)
    moved = cat.event(5139)
    assert moved is not None
    assert moved.roles["object_dn"] == "NewObjectDN"
    assert {"OldObjectDN", "NewObjectDN"} <= moved.all_fields


def test_unconfirmed_entries_are_reported_honestly(cat: Catalog) -> None:
    for event_id in (4727, 4744, 4759, 4765, 4766, 4780, 1101):
        info = cat.event(event_id, "Security")
        assert info is not None
        assert not info.confirmed
    system = cat.event(104, "System")
    assert system is not None
    assert not system.confirmed
    assert cat.event(4720) is not None
    assert cat.event(4720).confirmed  # type: ignore[union-attr]


def test_models_are_frozen(cat: Catalog) -> None:
    info = cat.event(4720)
    assert info is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.id = 1  # type: ignore[misc]
    with pytest.raises(TypeError):
        info.roles["actor_sid"] = "x"  # type: ignore[index]
    with pytest.raises(TypeError):
        cat.messages["%%1"] = None  # type: ignore[index]


# --- lookups -------------------------------------------------------------------------------


def test_event_lookup_by_channel_and_ambiguity() -> None:
    raw = fresh()
    clone = copy.deepcopy(event_of(raw, "Security", 1102))
    clone["channel"] = "Other"
    raw["event"].append(clone)
    both = catalog.from_mapping(raw)
    assert both.event(1102, "Security") is not None
    assert both.event(1102, "Other") is not None
    assert both.event(1102) is None
    assert both.names_for(1102, 0, 4) is None
    assert both.event(4720) is not None
    assert both.event(99999) is None
    assert both.event(1102, "Nope") is None


def test_fields_selection_logic(cat: Catalog) -> None:
    info = cat.event(4624)
    assert info is not None
    v2 = info.fields(2, 27)
    assert v2 is not None
    assert v2[-1] == "ElevatedToken"
    v1 = info.fields(1, 21)
    assert v1 is not None
    assert v1[-1] == "ImpersonationLevel"
    assert info.fields(2, 20) is None  # version known, count disagrees: refuse
    assert info.fields(7, 20) == info.fields(0, 20)  # unknown version, unique count
    assert info.fields(7, 99) is None  # unknown version, unknown count
    assert info.fields(0, -1) is None
    single = cat.event(4720)
    assert single is not None
    assert single.fields(0, 26) is not None
    assert single.fields(3, 26) == single.fields(0, 26)  # unknown version, one candidate
    assert single.fields(3, 25) is None


def test_fields_with_two_versions_of_equal_size_is_ambiguous() -> None:
    raw = fresh()
    event = event_of(raw, "Security", 4647)
    event["version"].append({"version": 5, "fields": list(reversed(event["version"][0]["fields"]))})
    info = catalog.from_mapping(raw).event(4647)
    assert info is not None
    assert info.fields(5, 4) == tuple(reversed(info.fields(0, 4) or ()))
    assert info.fields(9, 4) is None


def test_names_and_labels_match_the_read_options_shape(cat: Catalog) -> None:
    options = ReadOptions(names_for=catalog.names_for, labels_for=catalog.labels_for)
    names = options.names_for(4728, 0, 10)
    assert names is not None
    assert names[0] == "MemberName"
    assert options.names_for(4728, 0, 9) is None
    assert options.names_for(1, 0, 3) is None
    labels = options.labels_for(4728)
    assert labels is not None
    assert labels["Member/Account Name"] == "MemberName"
    assert labels["Subject/Security ID"] == "SubjectUserSid"
    assert options.labels_for(1100) is None
    assert options.labels_for(1) is None
    assert cat.labels_for(4728) == labels
    assert cat.names_for(4728, 0, 10) == names


def test_userdata_events(cat: Catalog) -> None:
    for event_id in (1100, 1101, 1102, 1104, 1105):
        info = cat.event(event_id)
        assert info is not None
        assert info.userdata
    assert cat.names_for(1100, 0, 0) == ()
    assert cat.names_for(1105, 0, 2) == ("Channel", "BackupPath")


# --- reference tables and decoders ----------------------------------------------------------


def test_messages(cat: Catalog) -> None:
    assert cat.message("%%14674") == "value added"
    assert cat.message("%%14675") == "value deleted"
    assert cat.messages["%%14674"].confirmed
    assert not cat.messages["%%1794"].confirmed
    assert cat.message("%%1794") == "<never>"
    assert cat.message("%%1793") == "<value not set>"
    assert cat.message("%%99999") is None
    assert cat.message("") is None
    assert cat.message("%%2089") == "flag set: password never expires"


def test_logon_types(cat: Catalog) -> None:
    expected = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
    }
    expected |= {9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive"}
    expected |= {12: "CachedRemoteInteractive", 13: "CachedUnlock"}
    for number, name in expected.items():
        assert cat.logon_type(number) == name
        assert cat.logon_type(str(number)) == name
        assert catalog.logon_type_name(number) == name
    assert cat.logon_type(1) is None
    assert cat.logon_type("6") is None
    assert cat.logon_type("0x3") is None
    assert cat.logon_type("-") is None
    assert cat.logon_type("") is None
    assert cat.logon_type("3 ") is None


def test_sam_and_ldap_layouts_differ(cat: Catalog) -> None:
    assert cat.sam_flags[0x1].name == "USER_ACCOUNT_DISABLED"
    assert cat.ldap_flags[0x2].name == "ACCOUNTDISABLE"
    assert 0x1 not in cat.ldap_flags or cat.ldap_flags[0x1].name == "SCRIPT"
    assert cat.decode_sam_uac("0x1") == ("USER_ACCOUNT_DISABLED",)
    assert cat.decode_sam_uac("0x2") == ("USER_HOME_DIRECTORY_REQUIRED",)
    assert cat.decode_ldap_uac("2") == ("ACCOUNTDISABLE",)
    assert cat.decode_ldap_uac("0x2") == ("ACCOUNTDISABLE",)
    assert cat.decode_ldap_uac("0x8") == ("HOMEDIR_REQUIRED",)


def test_decode_sam_uac_examples(cat: Catalog) -> None:
    assert cat.decode_sam_uac("0x15") == (
        "USER_ACCOUNT_DISABLED",
        "USER_PASSWORD_NOT_REQUIRED",
        "USER_NORMAL_ACCOUNT",
    )
    assert cat.decode_sam_uac("0x211") == (
        "USER_ACCOUNT_DISABLED",
        "USER_NORMAL_ACCOUNT",
        "USER_DONT_EXPIRE_PASSWORD",
    )
    assert cat.decode_sam_uac("0x0") == ()
    assert cat.decode_sam_uac("0X10") == ("USER_NORMAL_ACCOUNT",)
    assert catalog.decode_sam_uac("0x80") == ("USER_WORKSTATION_TRUST_ACCOUNT",)
    assert catalog.decode_ldap_uac("514") == ("ACCOUNTDISABLE", "NORMAL_ACCOUNT")
    assert catalog.decode_ldap_uac("66050") == (
        "ACCOUNTDISABLE",
        "NORMAL_ACCOUNT",
        "DONT_EXPIRE_PASSWORD",
    )


@pytest.mark.parametrize(
    "text",
    [
        "",
        "-",
        "15",
        "0x",
        "0xZZ",
        "0x1_0",
        " 0x15",
        "0x15 ",
        "0x1ffffffff",
        "-0x1",
        "0x80000000",
        "0x" + "0" * 20,
        "\x00",
    ],
)
def test_decode_sam_uac_refuses_what_it_cannot_read(cat: Catalog, text: str) -> None:
    assert cat.decode_sam_uac(text) is None


@pytest.mark.parametrize(
    "text",
    ["", "-", "abc", "4294967296", "99999999999", "1.5", "0x", "-2", " 2", "2 ", "4294967295"],
)
def test_decode_ldap_uac_refuses_what_it_cannot_read(cat: Catalog, text: str) -> None:
    assert cat.decode_ldap_uac(text) is None


@given(st.sets(st.sampled_from(sorted(catalog.load().sam_flags))))
def test_sam_decode_matches_the_bit_table(bits: set[int]) -> None:
    flags = catalog.load().sam_flags
    value = sum(bits)
    names = catalog.decode_sam_uac(hex(value))
    assert names == tuple(flags[bit].name for bit in sorted(bits))


@given(st.sets(st.sampled_from(sorted(catalog.load().ldap_flags))))
def test_ldap_decode_matches_the_bit_table(bits: set[int]) -> None:
    flags = catalog.load().ldap_flags
    value = sum(bits)
    assert catalog.decode_ldap_uac(str(value)) == tuple(flags[bit].name for bit in sorted(bits))
    assert catalog.decode_ldap_uac(hex(value)) == tuple(flags[bit].name for bit in sorted(bits))


@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_an_unknown_bit_always_refuses_the_decode(value: int) -> None:
    known = sum(catalog.load().sam_flags)
    result = catalog.decode_sam_uac(hex(value))
    assert (result is None) == bool(value & ~known)


@given(st.text(max_size=30))
def test_decoders_never_raise_on_arbitrary_text(text: str) -> None:
    for decoded in (catalog.decode_sam_uac(text), catalog.decode_ldap_uac(text)):
        assert decoded is None or isinstance(decoded, tuple)
    named = catalog.name_sid(text)
    assert named is None or isinstance(named, catalog.SidName)


def test_well_known_sids(cat: Catalog) -> None:
    system = cat.name_sid("S-1-5-18")
    assert system is not None
    assert (system.name, system.kind, system.scope, system.domain_sid) == (
        "SYSTEM",
        "well-known",
        "any",
        None,
    )
    assert system.confirmed
    admins = catalog.name_sid("S-1-5-32-544")
    assert admins is not None
    assert admins.name == "Administrators"
    local_service = cat.name_sid("S-1-5-19")
    assert local_service is not None
    assert not local_service.confirmed
    assert cat.name_sid("S-1-5-9999") is None


def test_domain_relative_rids(cat: Catalog) -> None:
    domain = "S-1-5-21-1111111111-2222222222-3333333333"
    expected = {
        500: "Administrator",
        502: "krbtgt",
        512: "Domain Admins",
        516: "Domain Controllers",
        518: "Schema Admins",
        519: "Enterprise Admins",
        525: "Protected Users",
        553: "RAS and IAS Servers",
    }
    for rid, name in expected.items():
        found = cat.name_sid(f"{domain}-{rid}")
        assert found is not None
        assert found.name == name
        assert found.kind == "well-known-rid"
        assert found.domain_sid == domain
        assert found.confirmed
    assert cat.name_sid(f"{domain}-518").scope == "root-domain"  # type: ignore[union-attr]
    assert cat.name_sid(f"{domain}-512").scope == "domain"  # type: ignore[union-attr]
    assert cat.name_sid(f"{domain}-1104") is None
    assert cat.name_sid(f"{domain}-") is None
    assert cat.name_sid("S-1-5-21-1-2-3") is None
    assert cat.name_sid("S-1-5-21-1-2-3-4-512") is None
    assert cat.name_sid("S-1-5-21-4294967296-2-3-512") is None
    assert cat.name_sid("S-1-5-21-1-2-3-4294967296") is None
    assert cat.name_sid("s-1-5-18") is None
    assert cat.name_sid("") is None
    assert cat.name_sid("S-1-5-21-" + "9" * 300) is None


# --- strict loading -------------------------------------------------------------------------


def _drop_meta(raw: dict[str, Any]) -> None:
    del raw["meta"]


def _unknown_top(raw: dict[str, Any]) -> None:
    raw["surprise"] = []


def _bad_schema(raw: dict[str, Any]) -> None:
    raw["meta"]["schema"] = 2


def _meta_key(raw: dict[str, Any]) -> None:
    raw["meta"]["extra"] = "x"


def _meta_not_table(raw: dict[str, Any]) -> None:
    raw["meta"] = 5


def _events_not_list(raw: dict[str, Any]) -> None:
    raw["event"] = 5


def _event_not_table(raw: dict[str, Any]) -> None:
    raw["event"] = [5]


def _on(event_id: int, edit: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    def run(raw: dict[str, Any]) -> None:
        edit(event_of(raw, "Security", event_id))

    return run


def _set(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    def run(event: dict[str, Any]) -> None:
        event[key] = value

    return run


def _del(key: str) -> Callable[[dict[str, Any]], None]:
    def run(event: dict[str, Any]) -> None:
        del event[key]

    return run


def _version_edit(edit: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    def run(event: dict[str, Any]) -> None:
        edit(event["version"][0])

    return run


def _unconfirm(table: dict[str, Any]) -> None:
    table["confirmed"] = False
    table.pop("notes", None)


def _no_versions(event: dict[str, Any]) -> None:
    event["version"] = []


def _dup_version(event: dict[str, Any]) -> None:
    event["version"].append(copy.deepcopy(event["version"][0]))


def _dup_field(event: dict[str, Any]) -> None:
    event["version"][0]["fields"].append(event["version"][0]["fields"][0])


def _role(role: str, value: object) -> Callable[[dict[str, Any]], None]:
    def run(event: dict[str, Any]) -> None:
        event["roles"][role] = value

    return run


def _attribute(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    def run(event: dict[str, Any]) -> None:
        event["attribute"][0][key] = value

    return run


def _dup_attribute(event: dict[str, Any]) -> None:
    event["attribute"].append(copy.deepcopy(event["attribute"][0]))


def _label(label: str, value: object) -> Callable[[dict[str, Any]], None]:
    def run(event: dict[str, Any]) -> None:
        event["labels"][label] = value

    return run


def _duplicate_event(raw: dict[str, Any]) -> None:
    raw["event"].append(copy.deepcopy(raw["event"][0]))


def _message(edit: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    def run(raw: dict[str, Any]) -> None:
        edit(raw["message"][0])

    return run


def _table(name: str, edit: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    def run(raw: dict[str, Any]) -> None:
        edit(raw[name][0])

    return run


def _dup_entry(name: str) -> Callable[[dict[str, Any]], None]:
    def run(raw: dict[str, Any]) -> None:
        raw[name].append(copy.deepcopy(raw[name][0]))

    return run


def _assign(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    def run(table: dict[str, Any]) -> None:
        table[key] = value

    return run


def _same_name_new_bit(name: str) -> Callable[[dict[str, Any]], None]:
    def run(raw: dict[str, Any]) -> None:
        clone = copy.deepcopy(raw[name][0])
        clone["bit"] = 0x40000000
        raw[name].append(clone)

    return run


def _long(n: int) -> str:
    return "x" * n


BAD_CATALOGS: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
    ("unknown top-level key", _unknown_top, "unknown top-level key"),
    ("missing meta", _drop_meta, "missing [meta]"),
    ("wrong schema", _bad_schema, "schema must be"),
    ("unknown meta key", _meta_key, "unknown key 'extra'"),
    ("meta not a table", _meta_not_table, "meta: must be a table"),
    ("events not an array", _events_not_list, "must be an array of tables"),
    ("event not a table", _event_not_table, "must be a table"),
    ("duplicate event", _duplicate_event, "listed twice"),
    ("unknown event key", _on(4720, _set("colour", "red")), "unknown key 'colour'"),
    ("missing event key", _on(4720, _del("title")), "missing key 'title'"),
    ("id zero", _on(4720, _set("id", 0)), "between 1 and 65535"),
    ("id too big", _on(4720, _set("id", 70000)), "between 1 and 65535"),
    ("id boolean", _on(4720, _set("id", value=True)), "must be an integer"),
    ("id text", _on(4720, _set("id", "4720")), "must be an integer"),
    ("empty channel", _on(4720, _set("channel", "")), "non-empty string"),
    ("long title", _on(4720, _set("title", _long(201))), "longer than 200"),
    ("bad category", _on(4720, _set("category", "weather")), "unknown value 'weather'"),
    ("bad action", _on(4720, _set("action", "exploded")), "unknown value 'exploded'"),
    ("http source", _on(4720, _set("source", "http://learn.microsoft.com/x")), "https link"),
    ("foreign source", _on(4720, _set("source", "https://example.com/x")), "https link"),
    (
        "credential in source",
        _on(4720, _set("source", "https://a@learn.microsoft.com/x")),
        "https link",
    ),
    ("source not text", _on(4720, _set("source", 5)), "non-empty string"),
    ("confirmed not bool", _on(4720, _set("confirmed", "yes")), "true or false"),
    (
        "unconfirmed without notes",
        _on(4720, _unconfirm),
        "must say why",
    ),
    ("long notes", _on(4720, _set("notes", _long(2001))), "longer than 2000"),
    ("labels_complete without labels", _on(1100, _set("labels_complete", value=True)), "no labels"),
    ("userdata not bool", _on(4720, _set("userdata", 1)), "true or false"),
    ("no versions", _on(4720, _no_versions), "at least one version"),
    ("versions not array", _on(4720, _set("version", 3)), "array of tables"),
    ("duplicate version", _on(4720, _dup_version), "listed twice"),
    ("version key unknown", _on(4720, _version_edit(_assign("extra", 1))), "unknown key 'extra'"),
    (
        "version out of range",
        _on(4720, _version_edit(_assign("version", 256))),
        "between 0 and 255",
    ),
    ("fields not list", _on(4720, _version_edit(_assign("fields", "a"))), "must be a list"),
    (
        "bad field name",
        _on(4720, _version_edit(_assign("fields", ["ok", "bad name"]))),
        "bad field name",
    ),
    ("field not text", _on(4720, _version_edit(_assign("fields", [5]))), "bad field name"),
    ("duplicate field", _on(4720, _dup_field), "appears twice"),
    ("derived not bool", _on(4624, _version_edit(_assign("derived", "yes"))), "true or false"),
    ("roles not table", _on(4720, _set("roles", [1])), "must be a table"),
    ("unknown role", _on(4720, _role("boss", "SubjectUserSid")), "unknown role 'boss'"),
    ("role field unknown", _on(4720, _role("actor_sid", "Nonexistent")), "no version has"),
    ("role value not text", _on(4720, _role("actor_sid", 7)), "bad field name"),
    ("attribute unknown kind", _on(4720, _attribute("kind", "magic")), "unknown value 'magic'"),
    ("attribute unknown field", _on(4720, _attribute("field", "Nonexistent")), "no version has"),
    ("attribute unknown key", _on(4720, _attribute("extra", 1)), "unknown key 'extra'"),
    ("attribute duplicate", _on(4720, _dup_attribute), "listed twice"),
    ("attributes not array", _on(4720, _set("attribute", 1)), "array of tables"),
    ("labels not table", _on(4720, _set("labels", [1])), "must be a table"),
    ("empty label", _on(4720, _label("", "SubjectUserSid")), "bad label"),
    ("long label", _on(4720, _label(_long(201), "SubjectUserSid")), "bad label"),
    ("label field unknown", _on(4720, _label("X/Y", "Nonexistent")), "no version has"),
    ("message bad code", _message(_assign("code", "1794")), "must look like"),
    ("message duplicate", _dup_entry("message"), "listed twice"),
    (
        "message unconfirmed without notes",
        _message(_unconfirm),
        "must say why",
    ),
    ("message unknown key", _message(_assign("extra", 1)), "unknown key 'extra'"),
    ("logon type duplicate", _dup_entry("logon_type"), "listed twice"),
    ("logon type range", _table("logon_type", _assign("value", 256)), "between 0 and 255"),
    (
        "logon type foreign source",
        _table("logon_type", _assign("source", "https://example.org/")),
        "https link",
    ),
    ("sam bit not single", _table("sam_uac_flag", _assign("bit", 3)), "not a single bit"),
    ("sam bit duplicate", _dup_entry("sam_uac_flag"), "listed twice"),
    (
        "sam name duplicate",
        _same_name_new_bit("sam_uac_flag"),
        "name 'USER_ACCOUNT_DISABLED' listed twice",
    ),
    ("ldap bit zero", _table("ldap_uac_flag", _assign("bit", 0)), "between 1 and"),
    ("sid malformed", _table("well_known_sid", _assign("sid", "S-2-5")), "not a SID"),
    ("sid duplicate", _dup_entry("well_known_sid"), "listed twice"),
    ("rid duplicate", _dup_entry("well_known_rid"), "listed twice"),
    (
        "rid bad scope",
        _table("well_known_rid", _assign("scope", "galaxy")),
        "unknown value 'galaxy'",
    ),
    ("sid list not array", lambda raw: raw.__setitem__("well_known_sid", {}), "array of tables"),
]


@pytest.mark.parametrize(
    ("case", "mutate", "expected"), BAD_CATALOGS, ids=[c[0] for c in BAD_CATALOGS]
)
def test_malformed_catalogs_are_rejected_with_a_clear_message(
    case: str, mutate: Callable[[dict[str, Any]], None], expected: str
) -> None:
    raw = fresh()
    mutate(raw)
    with pytest.raises(CatalogError) as caught:
        catalog.from_mapping(raw)
    assert expected in str(caught.value), case
    assert str(caught.value).startswith("event catalog: ")
    assert isinstance(caught.value, ValueError)


def test_unmodified_mapping_validates() -> None:
    assert len(catalog.from_mapping(fresh()).events) == len(_RAW["event"])


def test_parse_accepts_text_and_rejects_bad_toml() -> None:
    assert len(catalog.parse(_TEXT).events) == len(_RAW["event"])
    with pytest.raises(CatalogError, match="not valid TOML"):
        catalog.parse("[[event]\nid = ")


def test_parse_bytes_checks_size_and_encoding() -> None:
    assert len(catalog.parse_bytes(_TEXT.encode()).events) == len(_RAW["event"])
    with pytest.raises(CatalogError, match="larger than"):
        catalog.parse_bytes(b"#" * (catalog.MAX_CATALOG_BYTES + 1))
    with pytest.raises(CatalogError, match="not valid UTF-8"):
        catalog.parse_bytes(b"\xff\xfe[meta]\n")


def test_minimal_catalog_is_valid_and_empty_tables_are_allowed() -> None:
    small = catalog.parse("[meta]\nschema = 1\n")
    assert small.events == ()
    assert small.wanted_ids == frozenset()
    assert small.message("%%1") is None
    assert small.name_sid("S-1-5-18") is None
    assert small.decode_sam_uac("0x0") == ()
    assert small.decode_sam_uac("0x1") is None


def test_load_reports_an_unreadable_packaged_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Missing:
        def joinpath(self, _name: str) -> Missing:
            return self

        def open(self, _mode: str) -> object:
            return (tmp_path / "absent.toml").open("rb")

    monkeypatch.setattr(resources, "files", lambda _package: Missing())
    catalog.load.cache_clear()
    try:
        with pytest.raises(CatalogError, match=r"cannot read packaged events\.toml"):
            catalog.load()
    finally:
        monkeypatch.undo()
        catalog.load.cache_clear()
    assert catalog.load().events


def test_shipped_file_roundtrips_through_a_temp_copy(tmp_path: Path) -> None:
    copy_path = tmp_path / "events.toml"
    copy_path.write_text(_TEXT, encoding="utf-8")
    assert len(catalog.parse_bytes(copy_path.read_bytes()).events) == len(_RAW["event"])
