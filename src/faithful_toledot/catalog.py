# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The event catalog: the one place that knows what each Windows event means.

The data lives in ``data/events.toml``. This module loads it, checks every key,
and hands out frozen, typed answers. A catalog that is malformed in any way is
refused with a :class:`CatalogError`, never partly used: a wrong field name in an
audit tool is worse than a missing one.

What the catalog knows:

* For each event (by channel and id): the ordered field names of each schema
  version, which fields play which role (who did it, to what, from where), the
  per-attribute "new value" fields, and the labels used in the English message
  text.
* The ``%%NNNN`` insertion strings that Windows writes into event data, the logon
  types, both user-account-control bit layouts, and well-known SIDs and RIDs.

Every entry carries a ``source`` (a Microsoft or standards page) and a
``confirmed`` flag. ``confirmed = false`` means a detail could not be confirmed
from a primary source; the entry's note says which.

Two bit layouts, easy to confuse:
    ``OldUacValue`` and ``NewUacValue`` in events 4720, 4738, 4741 and 4742 use
    the SAM account-control layout (``USER_ACCOUNT_DISABLED`` is ``0x1``). The
    ``userAccountControl`` attribute in LDAP, which appears as the
    ``AttributeValue`` of a 5136 event, uses a different layout
    (``ACCOUNTDISABLE`` is ``0x2``). Decode each with its own function.
"""

from __future__ import annotations

import functools
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from types import MappingProxyType
from typing import TYPE_CHECKING, NoReturn
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping

CATALOG_RESOURCE = "events.toml"
SCHEMA_VERSION = 1
MAX_CATALOG_BYTES = 4 * 1024 * 1024
"""A catalog file larger than this is refused. The shipped file is well under 1 MiB."""
MAX_TEXT = 2000
"""Longest free-text value (a note) accepted for any entry."""
MAX_SHORT = 200
"""Longest title, label, name or URL accepted for any entry."""
MAX_SID_TEXT = 200
"""Longest SID text :meth:`Catalog.name_sid` will look at (a real SID is under 190)."""
MAX_UAC_TEXT = 16
"""Longest account-control text the decoders will look at."""
MASK32 = 0xFFFF_FFFF

ALLOWED_SOURCE_HOSTS = frozenset(
    {
        "learn.microsoft.com",
        "docs.microsoft.com",
        "technet.microsoft.com",
        "msdn.microsoft.com",
        "www.rfc-editor.org",
        "datatracker.ietf.org",
    }
)
"""Hosts a ``source`` URL may point at: Microsoft documentation and IETF standards."""

CATEGORIES = frozenset(
    {"user", "computer", "group", "directory", "policy", "trust", "rights", "logon", "integrity"}
)
ACTIONS = frozenset(
    {
        "created",
        "deleted",
        "enabled",
        "disabled",
        "changed",
        "renamed",
        "moved",
        "restored",
        "member-added",
        "member-removed",
        "password-change-attempted",
        "password-reset-attempted",
        "locked",
        "unlocked",
        "sid-history-added",
        "sid-history-failed",
        "permissions-changed",
        "audit-settings-changed",
        "policy-changed",
        "trust-created",
        "trust-removed",
        "trust-changed",
        "right-granted",
        "right-removed",
        "logon",
        "logon-explicit",
        "logoff",
        "authentication",
        "special-privileges",
        "log-cleared",
        "log-service-stopped",
        "system-started",
        "log-full",
        "log-backed-up",
        "events-dropped",
        "time-changed",
    }
)
ROLE_NAMES = frozenset(
    {
        "actor_sid",
        "actor_name",
        "actor_domain",
        "actor_logon_id",
        "target_sid",
        "target_name",
        "target_domain",
        "target_dn",
        "member_sid",
        "member_dn",
        "object_dn",
        "object_guid",
        "object_class",
        "source_address",
        "source_port",
        "workstation",
        "logon_type",
        "logon_id",
        "privileges",
    }
)
ATTRIBUTE_KINDS = frozenset(
    {
        "text",
        "sid",
        "uac-old",
        "uac-new",
        "uac-control",
        "filetime-text",
        "spn-list",
        "sid-history",
        "logon-hours",
        "delegation-list",
        "counter",
        "duration",
        "flag",
    }
)
SID_SCOPES = frozenset({"domain", "root-domain"})

_FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_MESSAGE_CODE = re.compile(r"%%[0-9]{1,6}")
_SID_TEXT = re.compile(r"S-1-[0-9]{1,10}(?:-[0-9]{1,10}){0,14}")
_DOMAIN_SID = re.compile(r"S-1-5-21-([0-9]{1,10})-([0-9]{1,10})-([0-9]{1,10})-([0-9]{1,10})")
_HEX_TEXT = re.compile(r"0[xX][0-9A-Fa-f]{1,8}")
_DEC_TEXT = re.compile(r"[0-9]{1,10}")

_TOP_LEVEL = frozenset(
    {
        "meta",
        "event",
        "message",
        "logon_type",
        "sam_uac_flag",
        "ldap_uac_flag",
        "well_known_sid",
        "well_known_rid",
    }
)
_EVENT_REQUIRED = frozenset(
    {"id", "channel", "provider", "title", "category", "action", "source", "confirmed", "version"}
)
_EVENT_OPTIONAL = frozenset(
    {"notes", "userdata", "labels_complete", "roles", "attribute", "labels"}
)


class CatalogError(ValueError):
    """The event catalog is malformed or could not be read."""


def _fail(where: str, problem: str) -> NoReturn:
    msg = f"event catalog: {where}: {problem}"
    raise CatalogError(msg)


@dataclass(frozen=True)
class VersionInfo:
    """The fields of one schema version of an event.

    Attributes:
        version: The ``Version`` value in the event's ``System`` section.
        fields: Element names in the order Windows writes them.
        derived: True when the list was derived from Microsoft's version
            history rather than read from a sample XML.
    """

    version: int
    fields: tuple[str, ...]
    derived: bool = False


@dataclass(frozen=True)
class Attribute:
    """One per-attribute field of an event, such as ``DisplayName`` in 4738.

    Attributes:
        field: The field name.
        label: A short plain-words label for the narrative.
        kind: One of :data:`ATTRIBUTE_KINDS`.
        unchanged: The text meaning "this attribute was not changed".
    """

    field: str
    label: str
    kind: str
    unchanged: str = "-"


@dataclass(frozen=True)
class EventInfo:
    """What the catalog knows about one event.

    Attributes:
        id: The event id.
        channel: The log, such as ``Security``.
        provider: The provider name.
        title: A short title in our own words.
        category: One of :data:`CATEGORIES`.
        action: One of :data:`ACTIONS`.
        source: The documentation page the entry rests on.
        confirmed: False when some detail could not be confirmed; see ``notes``.
        notes: What is uncertain, or other facts a reader needs.
        userdata: True when the values are ``UserData`` children, not ``Data``.
        versions: Field lists per schema version, ascending by version.
        roles: Role name to field name (see :data:`ROLE_NAMES`).
        attributes: Per-attribute fields in order.
        labels: Message label (``Section/Label``) to field name.
        labels_complete: True when every field of the newest version has a label.
    """

    id: int
    channel: str
    provider: str
    title: str
    category: str
    action: str
    source: str
    confirmed: bool
    notes: str | None
    userdata: bool
    versions: tuple[VersionInfo, ...]
    roles: Mapping[str, str]
    attributes: tuple[Attribute, ...]
    labels: Mapping[str, str]
    labels_complete: bool

    def fields(self, version: int, count: int) -> tuple[str, ...] | None:
        """Return the field names for a record, or ``None`` when not safely known.

        If the catalog has the record's version, its list is returned only when
        it has exactly ``count`` entries; a mismatch means the export is not what
        the catalog describes, and guessing would mislabel values. If the version
        is not in the catalog, the list is returned only when exactly one known
        version has ``count`` fields.

        Args:
            version: The record's schema version.
            count: How many unnamed values the record has.

        Returns:
            The names in order, or ``None``.
        """
        for known in self.versions:
            if known.version == version:
                return known.fields if len(known.fields) == count else None
        same = [known for known in self.versions if len(known.fields) == count]
        return same[0].fields if len(same) == 1 else None

    @property
    def all_fields(self) -> frozenset[str]:
        """Every field name that appears in any version."""
        return frozenset(name for known in self.versions for name in known.fields)


@dataclass(frozen=True)
class Message:
    """What one ``%%NNNN`` insertion string means.

    Attributes:
        code: The code as written, such as ``%%1794``.
        text: A short English meaning in our own words.
        source: The page the code was seen on.
        confirmed: False when Microsoft's page does not state the meaning.
        notes: Why the entry is or is not confirmed.
    """

    code: str
    text: str
    source: str
    confirmed: bool
    notes: str | None


@dataclass(frozen=True)
class Flag:
    """One bit of an account-control value.

    Attributes:
        bit: The bit's value.
        name: Microsoft's symbolic name.
        label: A short plain-words label.
        source: The page the bit comes from.
    """

    bit: int
    name: str
    label: str
    source: str


@dataclass(frozen=True)
class SidName:
    """The name of a well-known SID or well-known domain-relative RID.

    Attributes:
        name: The principal's name, such as ``Domain Admins``.
        kind: ``well-known`` for a fixed SID, ``well-known-rid`` for a domain
            SID whose last part is a well-known RID.
        source: The documentation page.
        confirmed: False when the cited page does not list this SID.
        scope: For ``well-known-rid``, ``domain`` or ``root-domain`` (the group
            exists only in the forest root domain); ``any`` for a fixed SID.
        domain_sid: For ``well-known-rid``, the SID of the domain or machine.
            A SID alone cannot tell a domain from a machine.
    """

    name: str
    kind: str
    source: str
    confirmed: bool
    scope: str = "any"
    domain_sid: str | None = None


@dataclass(frozen=True)
class _Rid:
    rid: int
    name: str
    scope: str
    source: str
    confirmed: bool


@dataclass(frozen=True)
class Catalog:
    """The validated catalog. Build it with :func:`load` or :func:`parse`.

    Attributes:
        events: Every event, in file order.
        messages: ``%%NNNN`` code to its :class:`Message`.
        logon_types: Logon type number to its name.
        sam_flags: SAM-layout account-control bits.
        ldap_flags: LDAP-layout ``userAccountControl`` bits.
    """

    events: tuple[EventInfo, ...]
    messages: Mapping[str, Message]
    logon_types: Mapping[int, str]
    sam_flags: Mapping[int, Flag]
    ldap_flags: Mapping[int, Flag]
    sids: Mapping[str, SidName]
    rids: Mapping[int, _Rid]
    by_key: Mapping[tuple[str, int], EventInfo]
    by_id: Mapping[int, tuple[EventInfo, ...]]

    @property
    def wanted_ids(self) -> frozenset[tuple[str, int]]:
        """The ``(channel, event id)`` pairs a reader should keep."""
        return frozenset(self.by_key)

    def event(self, event_id: int, channel: str | None = None) -> EventInfo | None:
        """Look up an event.

        Args:
            event_id: The event id.
            channel: The log. If ``None``, the event is returned only when
                exactly one channel defines it.

        Returns:
            The entry, or ``None`` when unknown or ambiguous.
        """
        if channel is not None:
            return self.by_key.get((channel, event_id))
        found = self.by_id.get(event_id, ())
        return found[0] if len(found) == 1 else None

    def names_for(self, event_id: int, version: int, count: int) -> tuple[str, ...] | None:
        """Return field names for a nameless record; see ``ReadOptions.names_for``."""
        info = self.event(event_id)
        return None if info is None else info.fields(version, count)

    def labels_for(self, event_id: int) -> Mapping[str, str] | None:
        """Return the message-label map for an event; see ``ReadOptions.labels_for``."""
        info = self.event(event_id)
        if info is None or not info.labels:
            return None
        return info.labels

    def message(self, code: str) -> str | None:
        """Return the short meaning of a ``%%NNNN`` code, or ``None`` if unknown.

        The meaning may come from an unconfirmed entry; use :attr:`messages` to
        see the ``confirmed`` flag.
        """
        entry = self.messages.get(code)
        return None if entry is None else entry.text

    def logon_type(self, value: str | int) -> str | None:
        """Return the name of a logon type, or ``None`` if unknown or malformed.

        Args:
            value: The number as an int, or as decimal text as Windows writes it.
        """
        if isinstance(value, str):
            if not _DEC_TEXT.fullmatch(value):
                return None
            value = int(value)
        return self.logon_types.get(value)

    def decode_sam_uac(self, text: str) -> tuple[str, ...] | None:
        """Decode an ``OldUacValue`` or ``NewUacValue`` (SAM layout).

        Args:
            text: Hexadecimal text such as ``0x15``.

        Returns:
            Symbolic names of the set bits, lowest bit first. ``None`` when the
            text is not a 32-bit hex number, or when any set bit is not known:
            a partial decode would silently drop a flag.
        """
        value = _parse_flags(text, allow_decimal=False)
        return None if value is None else _decode_bits(value, self.sam_flags)

    def decode_ldap_uac(self, text: str) -> tuple[str, ...] | None:
        """Decode an LDAP ``userAccountControl`` value.

        Args:
            text: Decimal text, as LDAP writes it, or ``0x`` hexadecimal.

        Returns:
            Symbolic names of the set bits, lowest bit first, or ``None`` as for
            :meth:`decode_sam_uac`.
        """
        value = _parse_flags(text, allow_decimal=True)
        return None if value is None else _decode_bits(value, self.ldap_flags)

    def name_sid(self, sid: str) -> SidName | None:
        """Name a well-known SID, or a domain SID with a well-known RID.

        Args:
            sid: SID text such as ``S-1-5-18`` or ``S-1-5-21-a-b-c-512``.

        Returns:
            The name, or ``None`` when the SID is not one the catalog knows or is
            malformed. A name for a ``-500`` style SID says the RID is
            well-known; it does not prove the SID belongs to a domain rather
            than a machine.
        """
        if len(sid) > MAX_SID_TEXT:
            return None
        fixed = self.sids.get(sid)
        if fixed is not None:
            return fixed
        match = _DOMAIN_SID.fullmatch(sid)
        if match is None:
            return None
        parts = [int(part) for part in match.groups()]
        if any(part > MASK32 for part in parts):
            return None
        entry = self.rids.get(parts[3])
        if entry is None:
            return None
        return SidName(
            name=entry.name,
            kind="well-known-rid",
            source=entry.source,
            confirmed=entry.confirmed,
            scope=entry.scope,
            domain_sid="S-1-5-21-" + "-".join(str(part) for part in parts[:3]),
        )


def _parse_flags(text: str, *, allow_decimal: bool) -> int | None:
    if len(text) > MAX_UAC_TEXT:
        return None
    if _HEX_TEXT.fullmatch(text):
        return int(text, 16)
    if allow_decimal and _DEC_TEXT.fullmatch(text):
        value = int(text)
        return value if value <= MASK32 else None
    return None


def _decode_bits(value: int, flags: Mapping[int, Flag]) -> tuple[str, ...] | None:
    names: list[str] = []
    remaining = value
    for bit in sorted(flags):
        if value & bit:
            names.append(flags[bit].name)
            remaining &= ~bit
    return None if remaining else tuple(names)


# --- validation helpers -----------------------------------------------------------------


def _table(raw: object, where: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        _fail(where, "must be a table")
    return raw


def _tables(raw: object, where: str) -> list[dict[str, object]]:
    if not isinstance(raw, list):
        _fail(where, "must be an array of tables")
    return [_table(item, f"{where} #{index + 1}") for index, item in enumerate(raw)]


def _keys(
    table: dict[str, object], where: str, required: frozenset[str], optional: frozenset[str]
) -> None:
    for key in table:
        if key not in required and key not in optional:
            _fail(where, f"unknown key {key!r}")
    for key in sorted(required):
        if key not in table:
            _fail(where, f"missing key {key!r}")


def _str(table: dict[str, object], key: str, where: str, *, limit: int = MAX_SHORT) -> str:
    value = table[key]
    if not isinstance(value, str) or not value:
        _fail(where, f"{key!r} must be a non-empty string")
    if len(value) > limit:
        _fail(where, f"{key!r} is longer than {limit} characters")
    return value


def _opt_str(
    table: dict[str, object], key: str, where: str, *, limit: int = MAX_TEXT
) -> str | None:
    return _str(table, key, where, limit=limit) if key in table else None


def _bool(table: dict[str, object], key: str, where: str, *, default: bool | None = None) -> bool:
    if key not in table and default is not None:
        return default
    value = table[key]
    if not isinstance(value, bool):
        _fail(where, f"{key!r} must be true or false")
    return value


def _int(table: dict[str, object], key: str, where: str, *, low: int, high: int) -> int:
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(where, f"{key!r} must be an integer")
    if not low <= value <= high:
        _fail(where, f"{key!r} must be between {low} and {high}")
    return value


def _choice(table: dict[str, object], key: str, where: str, allowed: frozenset[str]) -> str:
    value = _str(table, key, where)
    if value not in allowed:
        _fail(where, f"{key!r} has unknown value {value!r}")
    return value


def _source(table: dict[str, object], where: str) -> str:
    value = _str(table, "source", where)
    parts = urlsplit(value)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_SOURCE_HOSTS or parts.username:
        _fail(
            where, f"'source' must be an https link to a Microsoft or standards site, got {value!r}"
        )
    return value


def _field_name(value: object, where: str) -> str:
    if not isinstance(value, str) or not _FIELD_NAME.fullmatch(value):
        _fail(where, f"bad field name {value!r}")
    return value


def _confirmation(table: dict[str, object], where: str) -> tuple[bool, str | None]:
    confirmed = _bool(table, "confirmed", where)
    notes = _opt_str(table, "notes", where)
    if not confirmed and notes is None:
        _fail(where, "an unconfirmed entry must say why in 'notes'")
    return confirmed, notes


# --- events -------------------------------------------------------------------------------


def _parse_versions(raw: object, where: str) -> tuple[VersionInfo, ...]:
    found: dict[int, VersionInfo] = {}
    for table in _tables(raw, f"{where} versions"):
        label = f"{where} version"
        _keys(table, label, frozenset({"version", "fields"}), frozenset({"derived"}))
        number = _int(table, "version", label, low=0, high=255)
        label = f"{where} version {number}"
        if number in found:
            _fail(label, "listed twice")
        raw_fields = table["fields"]
        if not isinstance(raw_fields, list):
            _fail(label, "'fields' must be a list")
        names = tuple(_field_name(item, label) for item in raw_fields)
        if len(set(names)) != len(names):
            _fail(label, "a field name appears twice")
        derived = _bool(table, "derived", label, default=False)
        found[number] = VersionInfo(number, names, derived)
    if not found:
        _fail(where, "needs at least one version")
    return tuple(found[number] for number in sorted(found))


def _parse_roles(raw: object, where: str, known: frozenset[str]) -> dict[str, str]:
    roles: dict[str, str] = {}
    for role, value in _table(raw, f"{where} roles").items():
        if role not in ROLE_NAMES:
            _fail(where, f"unknown role {role!r}")
        name = _field_name(value, where)
        if name not in known:
            _fail(where, f"role {role!r} names field {name!r}, which no version has")
        roles[role] = name
    return roles


def _parse_attributes(raw: object, where: str, known: frozenset[str]) -> tuple[Attribute, ...]:
    attributes: list[Attribute] = []
    for table in _tables(raw, f"{where} attribute"):
        label = f"{where} attribute"
        _keys(table, label, frozenset({"field", "label", "kind"}), frozenset({"unchanged"}))
        name = _field_name(table["field"], label)
        if name not in known:
            _fail(label, f"names field {name!r}, which no version has")
        if any(item.field == name for item in attributes):
            _fail(label, f"field {name!r} is listed twice")
        unchanged = _opt_str(table, "unchanged", label, limit=MAX_SHORT) or "-"
        attributes.append(
            Attribute(
                name,
                _str(table, "label", label),
                _choice(table, "kind", label, ATTRIBUTE_KINDS),
                unchanged,
            )
        )
    return tuple(attributes)


def _parse_labels(raw: object, where: str, known: frozenset[str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for label, value in _table(raw, f"{where} labels").items():
        if not label or len(label) > MAX_SHORT:
            _fail(where, f"bad label {label!r}")
        name = _field_name(value, where)
        if name not in known:
            _fail(where, f"label {label!r} names field {name!r}, which no version has")
        labels[label] = name
    return labels


def _parse_event(raw: object, index: int) -> EventInfo:
    where = f"event #{index}"
    table = _table(raw, where)
    _keys(table, where, _EVENT_REQUIRED, _EVENT_OPTIONAL)
    event_id = _int(table, "id", where, low=1, high=0xFFFF)
    channel = _str(table, "channel", where)
    where = f"event {channel}/{event_id}"
    versions = _parse_versions(table["version"], where)
    known = frozenset(name for version in versions for name in version.fields)
    confirmed, notes = _confirmation(table, where)
    labels = _parse_labels(table.get("labels", {}), where, known)
    complete = _bool(table, "labels_complete", where, default=False)
    if complete and not labels:
        _fail(where, "'labels_complete' is true but there are no labels")
    return EventInfo(
        id=event_id,
        channel=channel,
        provider=_str(table, "provider", where),
        title=_str(table, "title", where),
        category=_choice(table, "category", where, CATEGORIES),
        action=_choice(table, "action", where, ACTIONS),
        source=_source(table, where),
        confirmed=confirmed,
        notes=notes,
        userdata=_bool(table, "userdata", where, default=False),
        versions=versions,
        roles=MappingProxyType(_parse_roles(table.get("roles", {}), where, known)),
        attributes=_parse_attributes(table.get("attribute", []), where, known),
        labels=MappingProxyType(labels),
        labels_complete=complete,
    )


# --- reference tables ----------------------------------------------------------------------


def _parse_messages(raw: object) -> dict[str, Message]:
    messages: dict[str, Message] = {}
    for table in _tables(raw, "message"):
        where = "message"
        _keys(
            table, where, frozenset({"code", "text", "source", "confirmed"}), frozenset({"notes"})
        )
        code = _str(table, "code", where)
        where = f"message {code}"
        if not _MESSAGE_CODE.fullmatch(code):
            _fail(where, "code must look like %%1234")
        if code in messages:
            _fail(where, "listed twice")
        confirmed, notes = _confirmation(table, where)
        messages[code] = Message(
            code, _str(table, "text", where), _source(table, where), confirmed, notes
        )
    return messages


def _parse_logon_types(raw: object) -> dict[int, str]:
    found: dict[int, str] = {}
    for table in _tables(raw, "logon_type"):
        where = "logon_type"
        _keys(table, where, frozenset({"value", "name", "source"}), frozenset())
        value = _int(table, "value", where, low=0, high=255)
        if value in found:
            _fail(f"logon_type {value}", "listed twice")
        _source(table, f"logon_type {value}")
        found[value] = _str(table, "name", f"logon_type {value}")
    return found


def _parse_flags_table(raw: object, name: str) -> dict[int, Flag]:
    found: dict[int, Flag] = {}
    for table in _tables(raw, name):
        _keys(table, name, frozenset({"bit", "name", "label", "source"}), frozenset())
        bit = _int(table, "bit", name, low=1, high=MASK32)
        if bit & (bit - 1):
            _fail(name, f"bit {bit:#x} is not a single bit")
        if bit in found:
            _fail(name, f"bit {bit:#x} listed twice")
        flag = Flag(
            bit, _str(table, "name", name), _str(table, "label", name), _source(table, name)
        )
        if any(other.name == flag.name for other in found.values()):
            _fail(name, f"name {flag.name!r} listed twice")
        found[bit] = flag
    return found


def _parse_sids(raw: object) -> dict[str, SidName]:
    found: dict[str, SidName] = {}
    for table in _tables(raw, "well_known_sid"):
        where = "well_known_sid"
        _keys(table, where, frozenset({"sid", "name", "source", "confirmed"}), frozenset({"notes"}))
        sid = _str(table, "sid", where)
        where = f"well_known_sid {sid}"
        if not _SID_TEXT.fullmatch(sid):
            _fail(where, "not a SID")
        if sid in found:
            _fail(where, "listed twice")
        confirmed, _notes = _confirmation(table, where)
        found[sid] = SidName(
            _str(table, "name", where), "well-known", _source(table, where), confirmed
        )
    return found


def _parse_rids(raw: object) -> dict[int, _Rid]:
    found: dict[int, _Rid] = {}
    for table in _tables(raw, "well_known_rid"):
        where = "well_known_rid"
        _keys(
            table,
            where,
            frozenset({"rid", "name", "scope", "source", "confirmed"}),
            frozenset({"notes"}),
        )
        rid = _int(table, "rid", where, low=0, high=MASK32)
        where = f"well_known_rid {rid}"
        if rid in found:
            _fail(where, "listed twice")
        confirmed, _notes = _confirmation(table, where)
        found[rid] = _Rid(
            rid,
            _str(table, "name", where),
            _choice(table, "scope", where, SID_SCOPES),
            _source(table, where),
            confirmed,
        )
    return found


def _check_meta(raw: object) -> None:
    table = _table(raw, "meta")
    _keys(table, "meta", frozenset({"schema"}), frozenset({"note"}))
    if table["schema"] != SCHEMA_VERSION:
        _fail("meta", f"schema must be {SCHEMA_VERSION}, got {table['schema']!r}")


def from_mapping(raw: Mapping[str, object]) -> Catalog:
    """Validate a parsed catalog and build a :class:`Catalog`.

    Args:
        raw: The decoded TOML document.

    Returns:
        The catalog.

    Raises:
        CatalogError: If anything is unknown, missing, duplicated, or out of range.
    """
    table = _table(dict(raw), "catalog")
    for key in table:
        if key not in _TOP_LEVEL:
            _fail("catalog", f"unknown top-level key {key!r}")
    if "meta" not in table:
        _fail("catalog", "missing [meta]")
    _check_meta(table["meta"])
    events = tuple(
        _parse_event(item, index + 1)
        for index, item in enumerate(_tables(table.get("event", []), "event"))
    )
    by_key: dict[tuple[str, int], EventInfo] = {}
    by_id: dict[int, list[EventInfo]] = {}
    for info in events:
        pair = (info.channel, info.id)
        if pair in by_key:
            _fail(f"event {info.channel}/{info.id}", "listed twice")
        by_key[pair] = info
        by_id.setdefault(info.id, []).append(info)
    return Catalog(
        events=events,
        messages=MappingProxyType(_parse_messages(table.get("message", []))),
        logon_types=MappingProxyType(_parse_logon_types(table.get("logon_type", []))),
        sam_flags=MappingProxyType(
            _parse_flags_table(table.get("sam_uac_flag", []), "sam_uac_flag")
        ),
        ldap_flags=MappingProxyType(
            _parse_flags_table(table.get("ldap_uac_flag", []), "ldap_uac_flag")
        ),
        sids=MappingProxyType(_parse_sids(table.get("well_known_sid", []))),
        rids=MappingProxyType(_parse_rids(table.get("well_known_rid", []))),
        by_key=MappingProxyType(by_key),
        by_id=MappingProxyType({key: tuple(value) for key, value in by_id.items()}),
    )


def parse_bytes(data: bytes) -> Catalog:
    """Decode, parse and validate catalog bytes.

    Args:
        data: The catalog file's bytes, UTF-8 TOML.

    Returns:
        The catalog.

    Raises:
        CatalogError: If the data is too large, not UTF-8, not TOML, or invalid.
    """
    if len(data) > MAX_CATALOG_BYTES:
        _fail("file", f"larger than {MAX_CATALOG_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        msg = f"event catalog: file: not valid UTF-8 ({error.reason})"
        raise CatalogError(msg) from error
    return parse(text)


def parse(text: str) -> Catalog:
    """Parse and validate catalog text.

    Args:
        text: TOML text.

    Returns:
        The catalog.

    Raises:
        CatalogError: If the text is not TOML or the catalog is invalid.
    """
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        msg = f"event catalog: file: not valid TOML ({error})"
        raise CatalogError(msg) from error
    return from_mapping(raw)


@functools.cache
def load() -> Catalog:
    """Load and validate the packaged catalog once.

    Returns:
        The shared catalog.

    Raises:
        CatalogError: If the packaged file is missing or invalid.
    """
    resource = resources.files("faithful_toledot.data").joinpath(CATALOG_RESOURCE)
    try:
        with resource.open("rb") as stream:
            data = stream.read(MAX_CATALOG_BYTES + 1)
    except OSError as error:
        msg = f"event catalog: cannot read packaged {CATALOG_RESOURCE}: {error.strerror or error}"
        raise CatalogError(msg) from error
    return parse_bytes(data)


def names_for(event_id: int, version: int, count: int) -> tuple[str, ...] | None:
    """Field names for a nameless record, from the packaged catalog.

    Matches ``ReadOptions.names_for``.
    """
    return load().names_for(event_id, version, count)


def labels_for(event_id: int) -> Mapping[str, str] | None:
    """Message labels for an event, from the packaged catalog.

    Matches ``ReadOptions.labels_for``.
    """
    return load().labels_for(event_id)


def decode_sam_uac(text: str) -> tuple[str, ...] | None:
    """Decode a SAM-layout ``OldUacValue``/``NewUacValue`` with the packaged catalog."""
    return load().decode_sam_uac(text)


def decode_ldap_uac(text: str) -> tuple[str, ...] | None:
    """Decode an LDAP ``userAccountControl`` value with the packaged catalog."""
    return load().decode_ldap_uac(text)


def logon_type_name(value: str | int) -> str | None:
    """Name a logon type with the packaged catalog."""
    return load().logon_type(value)


def name_sid(sid: str) -> SidName | None:
    """Name a well-known SID with the packaged catalog."""
    return load().name_sid(sid)
