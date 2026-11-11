# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Plain sentences for changes, origins, and coverage.

Every sentence says only what the events recorded. Where an event recorded
nothing, the sentence says so instead of leaving a blank.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from faithful_toledot.changes import Change, Origin, Party

_NOUNS = {
    "user": "user account",
    "computer": "computer account",
    "group": "group",
    "directory": "directory object",
    "policy": "policy",
    "trust": "trust",
    "rights": "account",
}
_VERBS = {
    "created": "created the {noun} {target}",
    "deleted": "deleted the {noun} {target}",
    "enabled": "enabled the {noun} {target}",
    "disabled": "disabled the {noun} {target}",
    "changed": "changed the {noun} {target}",
    "renamed": "renamed the account {target}",
    "moved": "moved the {noun} {target}",
    "restored": "restored the deleted {noun} {target}",
    "member-added": "added {member} to the group {target}",
    "member-removed": "removed {member} from the group {target}",
    "password-changed": "attempted to change the password of {target}",
    "password-reset": "attempted to reset the password of {target}",
    "locked": "locked out the {noun} {target}",
    "unlocked": "unlocked the {noun} {target}",
    "sid-history-added": "added SID history to the {noun} {target}",
    "permissions-changed": "changed permissions on {target}",
    "audit-settings-changed": "changed the auditing settings on {target}",
    "policy-changed": "changed policy on {computer} ({title})",
    "trust-created": "created a trust with {target}",
    "trust-removed": "removed the trust with {target}",
    "trust-changed": "changed the trust with {target}",
    "right-granted": "granted a user right to {target}",
    "right-removed": "removed a user right from {target}",
}
_LOOPBACK = frozenset({"::1", "127.0.0.1", "localhost"})


def party(who: Party | None, *, nothing: str = "an account the event does not name") -> str:
    """Name an account or object the way the event recorded it.

    The recorded name comes first. A name from other events, or a well-known name,
    follows in parentheses with the SID, so a reader can tell what was recorded.
    """
    if who is None or who.empty:
        return nothing
    if who.name:
        base = f"{who.domain}\\{who.name}" if who.domain else who.name
    else:
        base = who.dn or who.sid or who.guid or nothing
    extras = []
    if who.well_known and who.well_known != who.name:
        extras.append(f"well-known: {who.well_known}")
    if who.known_as:
        extras.append(f"named {who.known_as} in other events")
    if who.sid and who.sid != base:
        extras.append(who.sid)
    if who.dn and who.dn != base:
        extras.append(who.dn)
    return f"{base} ({'; '.join(extras)})" if extras else base


def origin(where: Origin) -> str:
    """Say where the actor's session came from, or exactly why that is not known."""
    if where.status == "none":
        return "The event names no logon session, so where it came from is not recorded."
    if where.status == "local":
        return f"Made by the computer's own system session ({where.logon_id})."
    if where.status == "not-in-input":
        return (
            f"The logon event for session {where.logon_id} is not in the input, so where "
            "it came from is not known."
        )
    kind = where.logon_type_name or (
        f"logon type {where.logon_type}" if where.logon_type else "a logon of unrecorded type"
    )
    if where.address in _LOOPBACK:
        place = "the computer itself (loopback address)"
    elif where.address:
        place = where.address + (f" port {where.port}" if where.port and where.port != "0" else "")
    else:
        place = "an address the logon did not record"
    station = f", workstation name {where.workstation}" if where.workstation else ""
    started = f"{where.logon_time:%Y-%m-%d %H:%M:%S} UTC" if where.logon_time else "an unknown time"
    return f"Session {where.logon_id} began at {started} as {kind} from {place}{station}."


def sentence(change: Change) -> str:
    """Describe one change in a sentence: who did what to what."""
    template = _VERBS.get(change.action, "made a change ({title}) to {target}")
    noun = _NOUNS.get(change.category, "object")
    if change.category == "directory" and change.target.object_class:
        noun = f"{change.target.object_class} object"
    text = template.format(
        noun=noun,
        target=party(change.target, nothing=f"a {noun} the event does not name"),
        member=party(change.member),
        title=change.title[:1].lower() + change.title[1:],
        computer=change.computer,
    )
    return f"{party(change.actor)} {text}."


def overwritten_statement(before: datetime | None) -> str:
    """Say that a log no longer reached back as far as the collection asked."""
    if before is None:
        return ""
    return (
        f" The collection asked for earlier events, but the log's oldest record is from "
        f"{before:%Y-%m-%d %H:%M:%S} UTC: earlier events had been overwritten and are missing."
    )


def coverage_statement(continuity: str, scope: str, missing: int, unnumbered: int) -> str:
    """Say what the record numbers do and do not show about completeness."""
    extra = (
        f" {unnumbered} events carry no record number and are not part of this check."
        if unnumbered and continuity != "unnumbered"
        else ""
    )
    if continuity == "empty":
        return "The collector read this log and found none of the events it asked for."
    if continuity == "unnumbered":
        return (
            "The export kept no record numbers, so toledot cannot tell whether events are missing."
        )
    if continuity == "complete":
        return (
            "Every record number between the first and the last is present. Events before "
            "the first or after the last are outside this input." + extra
        )
    numbers = f"{missing} record number{'' if missing == 1 else 's'}"
    verb = "is" if missing == 1 else "are"
    if scope == "unfiltered":
        return (
            f"{numbers} between the first and the last {verb} absent from a log given as "
            "complete: events are missing." + extra
        )
    if scope == "filtered":
        return (
            f"{numbers} between the first and the last {verb} absent. The input says it "
            "holds chosen events only, so this is expected and does not show whether any "
            "chosen event is missing." + extra
        )
    return (
        f"{numbers} between the first and the last {verb} absent. Either the export was "
        "filtered or events are missing; toledot cannot tell which." + extra
    )
