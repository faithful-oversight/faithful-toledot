# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic events for tests. Every name, SID, and address here is made up."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import count

from faithful_toledot.events import Event, Source

DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
ALICE = f"{DOMAIN_SID}-1104"
BOB = f"{DOMAIN_SID}-1105"
DC = "DC01.corp.example"
T0 = datetime(2026, 11, 3, 14, 0, 0, tzinfo=UTC)
SESSION = "0x5f1a2"
_records = count(1000)

SUBJECT = {
    "SubjectUserSid": ALICE,
    "SubjectUserName": "alice",
    "SubjectDomainName": "CORP",
    "SubjectLogonId": SESSION,
}


def at(seconds: float) -> datetime:
    """A time ``seconds`` after the start of the synthetic scenario."""
    return T0 + timedelta(seconds=seconds)


def event(  # noqa: PLR0913 - one argument per event field a test may set
    event_id: int,
    data: dict[str, str],
    *,
    seconds: float = 0,
    record: int | None = -1,
    computer: str = DC,
    channel: str = "Security",
    file: str = "security.evtx",
) -> Event:
    """Build one synthetic event; ``record=-1`` takes the next record number."""
    number = next(_records) if record == -1 else record
    return Event(
        event_id=event_id,
        time=at(seconds),
        computer=computer,
        channel=channel,
        provider=(
            "Microsoft-Windows-Eventlog"
            if 1100 <= event_id <= 1108 or event_id == 104
            else "Microsoft-Windows-Security-Auditing"
        ),
        record_id=number,
        data=data,
        source=Source(file, f"record {number}"),
    )


def logon(
    session: str = SESSION, *, address: str = "192.0.2.44", seconds: float = -60, kind: str = "3"
) -> Event:
    """A network logon for alice that starts ``session``."""
    return event(
        4624,
        {
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserSid": ALICE,
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "TargetLogonId": session,
            "LogonType": kind,
            "WorkstationName": "ADMIN-PC7",
            "IpAddress": address,
            "IpPort": "51515",
        },
        seconds=seconds,
    )


def member_added(seconds: float = 0, **extra: str) -> Event:
    """Alice adds bob to Domain Admins."""
    data = {
        "MemberName": "CN=Bob Example,OU=Staff,DC=corp,DC=example",
        "MemberSid": BOB,
        "TargetUserName": "Domain Admins",
        "TargetDomainName": "CORP",
        "TargetSid": f"{DOMAIN_SID}-512",
        **SUBJECT,
        "PrivilegeList": "-",
    }
    return event(4728, {**data, **extra}, seconds=seconds)


def ds_change(
    attribute: str,
    value: str,
    operation: str,
    *,
    seconds: float = 0,
    correlation: str = "{11111111-2222-3333-4444-555555555555}",
) -> Event:
    """One directory service value event (5136) on bob's user object."""
    return event(
        5136,
        {
            "OpCorrelationID": correlation,
            "AppCorrelationID": "-",
            **SUBJECT,
            "DSName": "corp.example",
            "DSType": "%%14676",
            "ObjectDN": "CN=Bob Example,OU=Staff,DC=corp,DC=example",
            "ObjectGUID": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "ObjectClass": "user",
            "AttributeLDAPDisplayName": attribute,
            "AttributeSyntaxOID": "2.5.5.12",
            "AttributeValue": value,
            "OperationType": operation,
        },
        seconds=seconds,
    )
