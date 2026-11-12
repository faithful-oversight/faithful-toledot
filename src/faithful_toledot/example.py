# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""A synthetic set of events for trying toledot without a domain.

Everything here is invented: the domain ``corp.example``, its accounts and SIDs, and
the addresses, which come from the ranges reserved for documentation. The story is
a week on two domain controllers: routine account work, a privileged group change
made from a workstation, and a cleared log.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from faithful_toledot import catalog
from faithful_toledot.events import Event, Source
from faithful_toledot.formats import bundle

DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
START = datetime(2026, 11, 2, 8, 0, 0, tzinfo=UTC)
FILES = ("dc01-events.jsonl", "dc02-events.jsonl")
_PROVIDER = "Microsoft-Windows-Security-Auditing"
_LOG_PROVIDER = "Microsoft-Windows-Eventlog"  # writes 1100-1108 into the Security log
_LOG_SERVICE_IDS = range(1100, 1109)
_PEOPLE = {
    "alice.admin": ("1104", "192.0.2.44", "ADMIN-PC7"),
    "helpdesk.sam": ("1131", "192.0.2.61", "HELPDESK-03"),
    "svc_provision": ("1150", "198.51.100.20", "IDM01"),
}


def _sid(rid: str) -> str:
    return f"{DOMAIN_SID}-{rid}"


def _subject(name: str, session: str) -> dict[str, str]:
    return {
        "SubjectUserSid": _sid(_PEOPLE[name][0]),
        "SubjectUserName": name,
        "SubjectDomainName": "CORP",
        "SubjectLogonId": session,
    }


def _fields(event_id: int, values: dict[str, str], fill: str = "-") -> dict[str, str]:
    """Lay values out in the event's own field order, filling the rest."""
    info = catalog.load().event(event_id, "Security")
    if info is None:  # pragma: no cover - the example uses catalogued events only
        raise LookupError(event_id)
    data = dict.fromkeys(info.versions[-1].fields, fill)
    data.update(values)
    return data


class _Log:
    """Builds one computer's events with rising record numbers."""

    def __init__(self, computer: str, first_record: int) -> None:
        self.computer = computer
        self.record = first_record
        self.events: list[Event] = []

    def add(self, minutes: float, event_id: int, data: dict[str, str], *, skip: int = 0) -> None:
        self.record += 1 + skip
        self.events.append(
            Event(
                event_id=event_id,
                time=START + timedelta(minutes=minutes),
                computer=self.computer,
                channel="Security",
                provider=_LOG_PROVIDER if event_id in _LOG_SERVICE_IDS else _PROVIDER,
                record_id=self.record,
                data=data,
                source=Source("example", f"record {self.record}"),
            )
        )

    def logon(self, minutes: float, name: str, session: str, *, kind: str = "3") -> None:
        rid, address, workstation = _PEOPLE[name]
        values = {
            "SubjectUserSid": "S-1-0-0",
            "SubjectLogonId": "0x0",
            "TargetUserSid": _sid(rid),
            "TargetUserName": name,
            "TargetDomainName": "CORP",
            "TargetLogonId": session,
            "LogonType": kind,
            "LogonProcessName": "Kerberos",
            "AuthenticationPackageName": "Kerberos",
            "WorkstationName": workstation if kind != "3" else "-",
            "IpAddress": address,
            "IpPort": "49731",
        }
        self.add(minutes, 4624, _fields(4624, values))

    def directory(  # noqa: PLR0913, PLR0917 - one argument per field of the event
        self, minutes: float, who: tuple[str, str], dn: str, attribute: str, value: str, op: str,
        correlation: str, object_class: str = "user",
    ) -> None:  # fmt: skip
        values = {
            "OpCorrelationID": correlation,
            **_subject(*who),
            "DSName": "corp.example",
            "DSType": "%%14676",
            "ObjectDN": dn,
            "ObjectGUID": "{6f1c2a9e-5b7d-4c3a-9e1f-0a2b3c4d5e6f}",
            "ObjectClass": object_class,
            "AttributeLDAPDisplayName": attribute,
            "AttributeSyntaxOID": "2.5.5.12",
            "AttributeValue": value,
            "OperationType": op,
        }
        self.add(minutes, 5136, _fields(5136, values))


def _dc01() -> _Log:
    log = _Log("DC01.corp.example", 48210)
    idm, desk, admin = (
        ("svc_provision", "0x2a51c"),
        ("helpdesk.sam", "0x3b7f02"),
        ("alice.admin", "0x5f1a2"),
    )
    new_sid, new_dn = _sid("1207"), "CN=Dana Whitfield,OU=Staff,DC=corp,DC=example"
    target = {"TargetUserName": "dana.whitfield", "TargetDomainName": "CORP", "TargetSid": new_sid}
    log.logon(5, *idm)
    created = {
        **target, **_subject(*idm), "SamAccountName": "dana.whitfield",
        "DisplayName": "Dana Whitfield", "UserPrincipalName": "dana.whitfield@corp.example",
        "PasswordLastSet": "%%1794", "AccountExpires": "%%1794", "PrimaryGroupId": "513",
        "OldUacValue": "0x0", "NewUacValue": "0x15", "UserAccountControl": "%%2080 %%2082 %%2084",
    }  # fmt: skip
    log.add(6, 4720, _fields(4720, created, "%%1793"))
    log.add(6.01, 4724, _fields(4724, {**target, **_subject(*idm)}))
    changed = {**target, **_subject(*idm), "OldUacValue": "0x15", "NewUacValue": "0x10"}
    log.add(6.02, 4738, _fields(4738, changed))
    log.add(6.03, 4722, _fields(4722, {**target, **_subject(*idm)}))
    staff = {
        "MemberName": new_dn, "MemberSid": new_sid, "TargetUserName": "Staff-All",
        "TargetDomainName": "CORP", "TargetSid": _sid("2101"), **_subject(*idm),
    }  # fmt: skip
    log.add(6.5, 4728, _fields(4728, staff))
    log.logon(190, *desk)
    reset = {"TargetUserName": "omar.reyes", "TargetDomainName": "CORP", "TargetSid": _sid("1188")}
    log.add(192, 4724, _fields(4724, {**reset, **_subject(*desk)}))
    log.add(192.2, 4767, _fields(4767, {**reset, **_subject(*desk)}))
    log.logon(1505, *admin)
    correlation = "{3d0f7c11-8a52-4e6b-b1c9-7e2a4f5d6c80}"
    log.directory(1507, admin, new_dn, "title", "Analyst", "%%14675", correlation)
    log.directory(1507, admin, new_dn, "title", "Finance Systems Lead", "%%14674", correlation)
    admins = {
        "MemberName": new_dn, "MemberSid": new_sid, "TargetUserName": "Domain Admins",
        "TargetDomainName": "CORP", "TargetSid": _sid("512"), **_subject(*admin),
    }  # fmt: skip
    log.add(1509, 4728, _fields(4728, admins))
    control = "{9b2e6d40-1f3c-4a7e-8d55-0c1b2a3f4e5d}"
    log.directory(1509.4, admin, new_dn, "userAccountControl", "512", "%%14675", control)
    log.directory(1509.4, admin, new_dn, "userAccountControl", "66048", "%%14674", control)
    policy = {
        "DomainPolicyChanged": "Password Policy", "DomainName": "CORP", "DomainSid": DOMAIN_SID,
        **_subject(*admin), "MinPasswordLength": "8", "PasswordHistoryLength": "5",
    }  # fmt: skip
    log.add(2890, 4739, _fields(4739, policy))
    # Record numbers jump here: the events between were not in the export.
    log.add(4300, 4729, _fields(4729, admins), skip=412)
    return log


def _dc02() -> _Log:
    log = _Log("DC02.corp.example", 9100)
    admin = ("alice.admin", "0x77e310")
    log.logon(5750, *admin, kind="10")
    log.add(5752, 1102, _subject(*admin))
    group = {
        "TargetUserName": "Temp-Vendors", "TargetDomainName": "CORP", "TargetSid": _sid("2240"),
        **_subject(*admin), "SamAccountName": "Temp-Vendors",
    }  # fmt: skip
    log.add(5760, 4727, _fields(4727, group))
    member = {
        "MemberName": "-", "MemberSid": _sid("1188"), "TargetUserName": "Temp-Vendors",
        "TargetDomainName": "CORP", "TargetSid": _sid("2240"), **_subject(*admin),
    }  # fmt: skip
    log.add(5761, 4728, _fields(4728, member))
    orphan = {
        "TargetUserName": "old.contractor", "TargetDomainName": "CORP", "TargetSid": _sid("1099"),
        **_subject("helpdesk.sam", "0x91c4d7"),
    }  # fmt: skip
    log.add(6100, 4726, _fields(4726, orphan))
    return log


def _header(log: _Log, oldest: datetime) -> dict[str, Any]:
    ids = sorted(number for channel, number in catalog.load().wanted_ids if channel == "Security")
    return {
        "toledot_events": 1,
        "collector": {"name": "toledot example", "version": "1", "method": "powershell"},
        "collected_at": bundle.format_time(START + timedelta(days=7)),
        "computer": log.computer,
        "operator": "CORP\\auditor",
        "query": {
            "channels": ["Security"],
            "event_ids": ids,
            "since": bundle.format_time(START - timedelta(hours=8)),
            "until": None,
        },
        "logs": [
            {
                "channel": "Security",
                "oldest_record_id": log.events[0].record_id,
                "oldest_time": bundle.format_time(oldest),
                "newest_record_id": log.record + 40,
                "record_count": 20000,
                "max_size_bytes": 134217728,
                "mode": "circular",
            }
        ],
    }


def build() -> dict[str, bytes]:
    """Return the example files by name.

    The second file's log had already been overwritten up to a point after the
    start of the period asked for, so toledot reports it as incomplete.
    """
    first, second = _dc01(), _dc02()
    return {
        FILES[0]: bundle.encode(_header(first, START - timedelta(days=30)), first.events),
        FILES[1]: bundle.encode(_header(second, START + timedelta(days=3)), second.events),
    }
