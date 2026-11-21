# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Turn a stream of events into an account of changes.

The rules, each chosen so that toledot never says more than the events do:

* One catalogued change event is one change. The only events merged are directory
  service changes (5136) that share a correlation ID and an object on one computer:
  Windows writes one event per value, and a "value deleted" with a "value added"
  for one attribute is one modification.
* "From where" follows the logon ID. A change names its actor's session; the latest
  logon event with that ID on the same computer, not followed by a logoff before
  the change, says where the session came from. Without that event the origin is
  "not in the input", never a guess.
* A SID is named from other events only when every event that names it agrees.
* The same record read from two inputs is counted once. Two inputs that disagree
  about one record are a problem, and the first is kept. Copies that disagree only
  about success or failure are one event with a problem and no stated outcome.
* Record numbers that are absent are reported. They mean missing events only when
  the input is the whole log, which toledot cannot tell by itself.
"""

from __future__ import annotations

import bisect
import hashlib
import itertools
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from faithful_toledot import narrative
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
from faithful_toledot.events import Event, LogFacts, Problem, Source

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from faithful_toledot.catalog import Attribute, Catalog, EventInfo

SCOPES = ("unfiltered", "filtered", "unknown")
RELATED_WINDOW = timedelta(seconds=2)
CLOCK_SYNC_LIMIT = timedelta(minutes=5)
"""The largest clock correction treated as routine; Kerberos tolerates 5 minutes of skew."""
"""Changes by one session this close together are marked as related."""
MAX_MISSING_RANGES = 1000
"""Absent record ranges listed per log; beyond this only the count is kept."""
MAX_TIED = 64
"""Most entries of one session examined at a change's own moment; beyond it, the answer is
that the order is unknown."""
MAX_PROBLEMS = 10_000
"""Problems kept in full. Further ones are counted, and one problem says so."""

_NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
_EMPTY = frozenset({"", "-"})
_SYSTEM_SESSIONS = frozenset({0x3E7, 0x3E4, 0x3E5})
"""Logon IDs of the computer's own sessions: SYSTEM, NETWORK SERVICE, LOCAL SERVICE."""
_HEX = re.compile(r"0[xX][0-9A-Fa-f]{1,16}")
_DEC = re.compile(r"[0-9]{1,20}")
_DS_ADDED, _DS_DELETED = "%%14674", "%%14675"
_NOTICE_KINDS = {
    "log-cleared": "The log was cleared.",
    "log-service-stopped": "The event logging service stopped, as it does at shutdown.",
    "events-dropped": "Windows dropped audit events before they were written.",
    "log-full": "The log was full.",
    "log-backed-up": "The log was archived and a new one started.",
    "time-changed": "The system time was changed.",
    "system-started": "Windows started.",
}
_ROUTINE_NOTICES = frozenset({"log-service-stopped", "log-backed-up", "system-started"})
_BOUNDARIES = frozenset({"log-service-stopped", "system-started"})
"""Actions after which a logon ID may name a different session: Microsoft documents logon
IDs as unique only between reboots, and a stopped log service may mean a restart."""
MAX_RELATED = 20
"""The most related changes listed for one change; the rest are counted."""
_SERVICE_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})
"""SYSTEM, LOCAL SERVICE, and NETWORK SERVICE: the accounts Windows itself runs as."""
_MISSING = " Events may be missing from this account around this time."
_LABELS = {"TargetUserName": "account name", "Sd": "security descriptor"}
_NOT_SET = "%%1793"
_UNDOCUMENTED = " [code meaning not documented by Microsoft]"
_AUDIT_POLICY_EVENT = 4719
_LOCAL_OBJECT_TYPES = frozenset({"File", "Key"})


@dataclass(frozen=True)
class Input:
    """One input file's records, and what is known about its scope.

    Attributes:
        name: The file's name, for messages.
        items: Its events and problems, in file order.
        scope: ``unfiltered`` when the user states it is a whole log, ``filtered``
            when the file says it holds chosen events only, else ``unknown``.
    """

    name: str
    items: Iterable[Event | Problem | LogFacts]
    scope: str = "unknown"


@dataclass
class _Log:
    """Running facts about one log on one computer."""

    computer: str
    channel: str
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    unnumbered: int = 0
    ranges: list[list[int]] = field(default_factory=list)
    scopes: set[str] = field(default_factory=set)
    overwritten_before: datetime | None = None

    def add(self, event: Event, scope: str) -> None:
        self.count += 1
        self.scopes.add(scope)
        if self.first is None or event.time < self.first:
            self.first = event.time
        if self.last is None or event.time > self.last:
            self.last = event.time
        number = event.record_id
        if number is None:
            self.unnumbered += 1
        elif self.ranges and self.ranges[-1][1] + 1 == number:
            self.ranges[-1][1] = number
        else:
            self.ranges.append([number, number])


@dataclass(frozen=True, slots=True)
class _Logon:
    """What a logon event says about a session, kept small: logs hold millions."""

    record_id: int | None
    time: datetime
    address: str | None
    port: str | None
    workstation: str | None
    logon_type: str | None
    source: Source
    account: str | None = None
    place: tuple[str, int | None] = ("", None)
    """The log and record number, to order events that share a timestamp."""


@dataclass(frozen=True, slots=True)
class _Entry:
    """A logon or a logoff of one session: its time, its place in its log, and the logon."""

    time: datetime
    place: tuple[str, int | None]
    """The log and record number, to order events that share a timestamp."""
    source: Source
    logon: _Logon | None
    """The logon, or ``None`` for a logoff."""


@dataclass
class _Slot:
    """What the copies of one event logged on success and failure say about its outcome."""

    own: str
    """What the first copy that made this slot said: ``unknown``, ``success`` or ``failure``."""
    input_number: int
    effective: str
    """What every copy says together: ``conflict`` when two known outcomes disagree."""


@dataclass
class _State:
    catalog: Catalog
    account: Account = field(default_factory=Account)
    logs: dict[tuple[str, str], _Log] = field(default_factory=dict)
    kept: dict[tuple[str, str, int], bytes] = field(default_factory=dict)
    events: list[tuple[Event, EventInfo]] = field(default_factory=list)
    sessions: dict[tuple[str, int], list[_Entry]] = field(default_factory=dict)
    names: dict[str, set[str]] = field(default_factory=dict)
    dropped_problems: int = 0
    unnumbered: dict[tuple[str, str, bytes], int] = field(default_factory=dict)
    boundaries: dict[str, list[_Moment]] = field(default_factory=dict)
    disputed: set[tuple[str, str, int]] = field(default_factory=set)
    """Records read more than once with different content (computer, log, number)."""
    disputed_sessions: set[tuple[str, int]] = field(default_factory=set)
    slots: dict[tuple[object, ...], list[_Slot]] = field(default_factory=dict)
    """Per event (record, or content when unnumbered): what its copies say about its outcome."""
    input_number: int = 0
    latest: dict[tuple[tuple[str, int], int], _Verdict] = field(default_factory=dict)
    """Per session and moment: what the session's latest entry at that moment says."""

    def problem(self, problem: Problem) -> None:
        if len(self.account.problems) < MAX_PROBLEMS:
            self.account.problems.append(problem)
        else:
            self.dropped_problems += 1

    def count(self, what: str) -> None:
        self.account.counts[what] = self.account.counts.get(what, 0) + 1


def build(
    inputs: Iterable[Input],
    catalog: Catalog,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Account:
    """Read every input and return the account of what changed.

    Args:
        inputs: The inputs to read. Each is consumed once, in order.
        catalog: The event catalog.
        since: Leave out changes and notices before this time. Earlier logon events
            are still used to say where a session came from.
        until: Leave out changes and notices at or after this time.

    Returns:
        The changes in time order, with notices, coverage, and problems.
    """
    state = _State(catalog)
    for name in ("changes", "context", "notices", "other", "duplicates", "outside_window"):
        state.account.counts[name] = 0
    for number, source in enumerate(inputs):
        state.input_number = number
        scope = source.scope if source.scope in SCOPES else "unknown"
        facts: list[LogFacts] = []
        computers: set[str] = set()
        for item in source.items:
            if isinstance(item, Problem):
                state.problem(item)
            elif isinstance(item, LogFacts):
                facts.append(item)
                # A collection states what it asked the log for, and that statement
                # is better evidence than a blanket --whole-logs.
                scope = "filtered" if item.filtered else "unfiltered"
            else:
                computers.add(item.computer)
                _take(state, item, scope)
        for item in facts:
            _take_facts(state, _same_computer(item, computers))
    _finish_sessions(state)
    window = (since, until)
    state.events.sort(key=_order)
    changes = list(_changes(state, window))
    state.account.changes = _relate(changes)
    state.account.notices.sort(key=lambda n: (n.time, n.computer))
    state.account.coverage = [_coverage(log) for _, log in sorted(state.logs.items())]
    if state.dropped_problems:
        text = (
            f"{state.dropped_problems} further problems are not listed; "
            f"only the first {MAX_PROBLEMS} are kept."
        )
        state.account.problems.append(Problem(Source("all inputs", "end"), text))
    return state.account


def _order(pair: tuple[Event, EventInfo]) -> tuple[datetime, str, int]:
    event = pair[0]
    return (event.time, event.computer.casefold(), event.record_id or 0)


def _same_computer(facts: LogFacts, computers: set[str]) -> LogFacts:
    """Name a collector's log facts after the computer its events name.

    The collector names the computer from DNS and each event names it from the event
    log, so ``DC01`` and ``DC01.corp.example`` can both mean one controller. Facts are
    renamed only when exactly one event computer has the same first label.
    """
    wanted = facts.computer.casefold()
    if any(name.casefold() == wanted for name in computers):
        return facts
    label = wanted.split(".", 1)[0]
    matches = {name for name in computers if name.casefold().split(".", 1)[0] == label}
    if len(matches) != 1:
        return facts
    return replace(facts, computer=matches.pop())


def _take_facts(state: _State, facts: LogFacts) -> None:
    """Note what a collector recorded about a log when it read it."""
    key = (facts.computer.casefold(), facts.channel.casefold())
    log = state.logs.setdefault(key, _Log(facts.computer, facts.channel))
    log.scopes.add("filtered" if facts.filtered else "unfiltered")
    if (
        facts.asked_since is not None
        and facts.oldest_time is not None
        and facts.oldest_record != 1  # a log that still holds record 1 has lost nothing
        and facts.oldest_time > facts.asked_since
        and (log.overwritten_before is None or facts.oldest_time > log.overwritten_before)
    ):
        log.overwritten_before = facts.oldest_time


def _provider_key(name: str) -> str:
    """Reduce a provider's name or Event Viewer display text to comparable letters.

    ``Microsoft-Windows-Security-Auditing`` and Event Viewer's ``Microsoft Windows
    security auditing.`` both become ``securityauditing``.
    """
    text = name.casefold().rstrip(".")
    for prefix in ("microsoft-windows-", "microsoft windows "):
        text = text.removeprefix(prefix)
    return "".join(character for character in text if character.isalnum())


def _lookup(state: _State, event: Event) -> EventInfo | None:
    """The catalog entry for an event, or ``None`` when another provider reuses the id.

    Event ids are only unique within a provider: ``.NET Runtime Optimization Service``
    also writes event 1101, and an Event Viewer CSV export has no channel to tell them apart.
    """
    info = state.catalog.event(event.event_id, event.channel or None)
    if info is None or not event.provider:
        return info
    return info if _provider_key(event.provider) == _provider_key(info.provider) else None


def _take(state: _State, event: Event, scope: str) -> None:
    """File one event: count it, check for a duplicate, and keep it if it matters."""
    computer = event.computer.casefold()
    info = _lookup(state, event)
    if info is not None and event.record_id is not None:
        key = (computer, event.channel.casefold(), event.record_id)
        digest = _fingerprint(event)
        seen = state.kept.get(key)
        if seen is not None:
            if seen == digest:
                _merge_outcome(state, event, info, (*key, digest))
                state.count("duplicates")
                return
            text = (
                f"Record {event.record_id} of the {event.channel} log on {event.computer} "
                "is in the input more than once with different content. Both are kept: "
                "they may be two events that reuse the number, such as one from an "
                "archived log, or one event read from a damaged copy."
            )
            state.problem(Problem(event.source, text, event.record_id))
            state.disputed.add(key)
        else:
            state.kept[key] = digest
        _register_outcome(state, event, info, (*key, digest))
    elif info is not None:
        # With no record number, the same event from two overlapping exports can only
        # be recognised by its content. Within one export, identical rows are kept.
        key_unnumbered = (computer, event.channel.casefold(), _fingerprint(event))
        first = state.unnumbered.setdefault(key_unnumbered, state.input_number)
        if first != state.input_number:
            _merge_outcome(state, event, info, key_unnumbered)
            state.count("duplicates")
            return
        _register_outcome(state, event, info, key_unnumbered)
    log = state.logs.setdefault(
        (computer, event.channel.casefold()), _Log(event.computer, event.channel)
    )
    log.add(event, scope)
    if info is not None and event.data.get("ObjectType") in _LOCAL_OBJECT_TYPES:
        # Permission and auditing events for files and registry keys are not directory
        # changes; Windows servicing writes thousands of them.
        info = None
    if info is None:
        state.count("other")
        key_other = (event.channel, event.event_id)
        state.account.other_ids[key_other] = state.account.other_ids.get(key_other, 0) + 1
        return
    _learn_names(state, event, info)
    if info.action in _BOUNDARIES:
        state.boundaries.setdefault(computer, []).append(_moment(event))
    if info.category == "logon":
        state.count("context")
        _note_session(state, event, info)
        return
    state.events.append((event, info))


def _fingerprint(event: Event) -> bytes:
    """Hash what makes an event itself, so two copies can be compared cheaply."""
    digest = hashlib.sha256()
    parts = [str(event.event_id), event.time.isoformat(), event.provider]
    # Exports list fields in different orders; the same fields are the same event.
    for name, value in sorted(event.data.items()):
        parts += [name, value]
    for part in parts:
        raw = part.encode("utf-8", "surrogatepass")
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.digest()


_UNKNOWN, _SUCCESS, _FAILURE, _CONFLICT = "unknown", "success", "failure", "conflict"


def _outcome_tag(event: Event, info: EventInfo) -> str | None:
    """What one copy says about success: ``unknown``, ``success`` or ``failure``.

    ``None`` for an event that is not logged on both success and failure, which has
    nothing to disagree about. The fingerprint leaves this out on purpose, so that copies
    from exports that carry less outcome metadata are still recognised as copies.
    """
    if info.action not in _OUTCOMES or info.channel != "Security":
        return None
    said = _audit_outcome(event)
    return _UNKNOWN if said is None else _SUCCESS if said else _FAILURE


def _register_outcome(
    state: _State, event: Event, info: EventInfo, base: tuple[object, ...]
) -> None:
    """Note what a kept event says about its outcome, as the first of its copies."""
    tag = _outcome_tag(event, info)
    if tag is None:
        return
    slots = state.slots.setdefault(base, [])
    if all(slot.own != tag for slot in slots):
        slots.append(_Slot(tag, state.input_number, tag))


def _merge_outcome(state: _State, event: Event, info: EventInfo, base: tuple[object, ...]) -> None:
    """Fold a later copy's outcome into the event it copies, whatever order they arrive in.

    A copy that says nothing changes nothing, and one that says more fills in what an
    earlier copy left out. Two known outcomes that differ leave the event's outcome
    unstated and are a problem: neither export is trusted over the other.
    """
    said = _outcome_tag(event, info)
    candidates = state.slots.get(base, [])
    if said in {None, _UNKNOWN} or not candidates:
        return
    slot = next(
        (
            candidate
            for wanted in (said, _UNKNOWN, _CONFLICT)
            for candidate in candidates
            if candidate.effective == wanted
        ),
        candidates[0],
    )
    if slot.effective in {said, _CONFLICT}:
        return
    if slot.effective == _UNKNOWN:
        slot.effective = said or _UNKNOWN
        return
    slot.effective = _CONFLICT
    which = (
        f"Record {event.record_id} of the {event.channel} log on {event.computer}"
        if event.record_id is not None
        else f"An unnumbered event {event.event_id} on {event.computer} at {event.time.isoformat()}"
    )
    text = (
        f"{which} is in the input more than once, and the copies disagree about whether the "
        "attempt succeeded or failed. One event is kept and its outcome is not stated."
    )
    state.problem(Problem(event.source, text, event.record_id))


def _outcome_of(state: _State, event: Event, info: EventInfo) -> str | None:
    """What every copy of an event says about its outcome, or ``None`` if it has no outcome."""
    own = _outcome_tag(event, info)
    if own is None:
        return None
    computer, channel = event.computer.casefold(), event.channel.casefold()
    base = (
        (computer, channel, event.record_id, _fingerprint(event))
        if event.record_id is not None
        else (computer, channel, _fingerprint(event))
    )
    return next((slot.effective for slot in state.slots.get(base, []) if slot.own == own), own)


def _text(event: Event, info: EventInfo, role: str) -> str | None:
    """A role's recorded value, or ``None`` when absent or a placeholder."""
    name = info.roles.get(role)
    if name is None:
        return None
    value = event.data.get(name)
    return None if value is None or value in _EMPTY else value


def _number_of(text: str | None) -> int | None:
    """Read a logon ID written as ``0x3e7`` or, by exports that lose the form, ``999``."""
    if text is None:
        return None
    if _HEX.fullmatch(text):
        return int(text, 16)
    if _DEC.fullmatch(text):
        return int(text)
    return None


def _learn_names(state: _State, event: Event, info: EventInfo) -> None:
    for prefix in ("actor", "target"):
        sid = _text(event, info, f"{prefix}_sid")
        name = _text(event, info, f"{prefix}_name")
        if sid is None or name is None or not sid.startswith("S-1-"):
            continue
        if f"{prefix}_domain" not in info.roles:
            # No domain is recorded (event 4740 holds a computer name where the domain
            # would be), so a bare name could disagree with the real one for the same SID.
            continue
        domain = _text(event, info, f"{prefix}_domain")
        names = state.names.setdefault(sid, set())
        names.add(f"{domain}\\{name}" if domain else name)
        renamed = event.data.get("NewTargetUserName") if prefix == "target" else None
        if renamed and renamed not in _EMPTY:
            # After a rename the account has had two names, so neither is "the" name.
            names.add(f"{domain}\\{renamed}" if domain else renamed)


def _note_session(state: _State, event: Event, info: EventInfo) -> None:
    """Index a logon or logoff by computer and logon ID."""
    computer = event.computer.casefold()
    if info.action == "logon":
        number = _number_of(_text(event, info, "logon_id"))
        is_logon = True
    elif info.action == "logoff":
        # Logoff events name the ended session in their target fields.
        number = _number_of(_text(event, info, "logon_id") or _text(event, info, "actor_logon_id"))
        if number is None:
            number = _number_of(event.data.get("TargetLogonId"))
        is_logon = False
    else:
        return
    if number is None:
        return
    if (computer, event.channel.casefold(), event.record_id) in state.disputed:
        # Copies of one logon record disagree, perhaps only on the time: no copy of that
        # session can be trusted to say where it came from.
        state.disputed_sessions.add((computer, number))
    place = (event.channel.casefold(), event.record_id)
    held = None
    if is_logon:
        held = _Logon(
            event.record_id,
            event.time,
            _text(event, info, "source_address"),
            _text(event, info, "source_port"),
            _text(event, info, "workstation"),
            _text(event, info, "logon_type"),
            event.source,
            _text(event, info, "target_sid"),
            place,
        )
    state.sessions.setdefault((computer, number), []).append(
        _Entry(event.time, place, event.source, held)
    )


def _entry_order(entry: _Entry) -> tuple[datetime, str, bool, int, str, str]:
    """Sort by time, then by log and record number, so the order never depends on the input."""
    channel, number = entry.place
    return (
        entry.time,
        channel,
        number is None,
        number or 0,
        entry.source.file,
        entry.source.position,
    )


def _finish_sessions(state: _State) -> None:
    """Put each session's logons and logoffs in time order."""
    for entries in state.sessions.values():
        entries.sort(key=_entry_order)
    for moments in state.boundaries.values():
        moments.sort(key=lambda moment: moment[0])


_Verdict = tuple[str, "_Logon | None"]
"""What a session's entries say: ``("none", None)`` when there are none, ``("ended", None)``
after a logoff, ``("session", logon)`` after a logon, or ``("conflicting" | "unordered",
None)`` when the entries cannot be reduced to one of those."""


def _effect(entry: _Entry) -> tuple[str, tuple[str | None, ...]]:
    """What one entry does to a session, comparable between entries."""
    if entry.logon is None:
        return ("ended", ())
    return ("session", _session_facts(entry.logon))


def _verdict_effect(verdict: _Verdict) -> tuple[str, tuple[str | None, ...]]:
    logon = verdict[1]
    return (verdict[0], _session_facts(logon) if logon is not None else ())


def _order_against(entry: _Entry, place: tuple[str, int | None]) -> int | None:
    """Whether an entry of the change's own moment came before (-1) or after (1) the change.

    Record numbers order two events only within one log. ``None`` means the input cannot say.
    """
    channel, number = entry.place
    if channel != place[0] or number is None or place[1] is None or number == place[1]:
        return None
    return -1 if number < place[1] else 1


def _latest_of(entries: list[_Entry]) -> _Verdict:
    """What the latest of entries that share one time says.

    Record numbers order entries of one log. Entries that cannot be ordered, because
    they are in different logs or lack a record number, are each possibly the latest;
    they give an answer only when they agree. Two different logons are ``conflicting``;
    any other disagreement is ``unordered``.
    """
    by_log: dict[str, list[_Entry]] = {}
    for entry in entries:
        by_log.setdefault(entry.place[0], []).append(entry)
    last: list[_Entry] = []
    for group in by_log.values():
        if any(entry.place[1] is None for entry in group):
            last += group
        else:
            top = max(entry.place[1] or 0 for entry in group)
            last += [entry for entry in group if entry.place[1] == top]
    effects = {_effect(entry) for entry in last}
    if len(effects) > 1:
        both_logons = all(entry.logon is not None for entry in last)
        return ("conflicting" if both_logons else "unordered", None)
    first = min(last, key=_entry_order)
    if first.logon is None:
        return ("ended", None)
    return ("session", first.logon)


def _before_moment(
    state: _State, key: tuple[str, int], entries: list[_Entry], index: int
) -> _Verdict:
    """What the session says after every entry up to index, which ends a moment."""
    if index < 0:
        return ("none", None)
    moment = entries[index].time
    start = bisect.bisect_left(entries, moment, key=lambda entry: entry.time)
    place = (key, start)
    found = state.latest.get(place)
    if found is None:
        found = state.latest[place] = _latest_of(entries[start : index + 1])
    return found


def _session_at(
    state: _State, key: tuple[str, int], when: datetime, place: tuple[str, int | None]
) -> _Verdict:
    """What a session says at a change, using record numbers to order entries that tie.

    Entries earlier than the change count. An entry stamped with the change's own time
    counts only when it is in the change's log and has a lower record number; one that
    cannot be ordered against the change might be before or after it. If any of those
    would say something other than what the ordered entries say, the answer is
    ``unordered``: toledot does not choose.
    """
    entries = state.sessions.get(key, [])
    first = bisect.bisect_left(entries, when, key=lambda entry: entry.time)
    last = bisect.bisect_right(entries, when, key=lambda entry: entry.time)
    earlier = _before_moment(state, key, entries, first - 1)
    tied = entries[first:last]
    if not tied:
        return earlier
    if len(tied) > MAX_TIED:
        # A session with this many entries in one moment is not a real one; each change
        # would otherwise cost the whole block. The block is not ordered.
        ordered, unknown = [], tied
    else:
        orders = [(entry, _order_against(entry, place)) for entry in tied]
        ordered = [entry for entry, order in orders if order == -1]
        unknown = [entry for entry, order in orders if order is None]
    base = _latest_of(ordered) if ordered else earlier
    if base[0] in {"conflicting", "unordered"}:
        return base
    if all(_effect(entry) == _verdict_effect(base) for entry in unknown):
        return base
    return ("unordered", None)


def _origin(state: _State, event: Event, info: EventInfo) -> Origin:
    recorded = _text(event, info, "actor_logon_id")
    number = _number_of(recorded)
    if number is None:
        return Origin("none")
    if number in _SYSTEM_SESSIONS:
        return Origin("local", logon_id=recorded)
    key = (event.computer.casefold(), number)
    status, logon = _session_at(state, key, event.time, (event.channel.casefold(), event.record_id))
    if logon is None:  # no entry, a logoff, or entries that cannot be reduced to one logon
        return Origin("not-in-input" if status == "none" else status, logon_id=recorded)
    doubt = _doubt(state, event, info, logon)
    if doubt is not None:
        return Origin(doubt, logon_id=recorded, logon_time=logon.time)
    return Origin(
        "session",
        logon_id=recorded,
        address=logon.address,
        port=logon.port,
        workstation=logon.workstation,
        logon_type=logon.logon_type,
        logon_type_name=state.catalog.logon_type(logon.logon_type) if logon.logon_type else None,
        logon_time=logon.time,
        source=logon.source,
    )


def _doubt(state: _State, event: Event, info: EventInfo, logon: _Logon) -> str | None:
    """Why the latest logon for a change's session cannot be taken as its origin, if it can't."""
    number = _number_of(_text(event, info, "actor_logon_id"))
    if (event.computer.casefold(), number) in state.disputed_sessions:
        return "conflicting"
    if _restarted_between(state, event, logon):
        return "restarted"
    actor = _text(event, info, "actor_sid")
    if logon.account and actor and logon.account.casefold() != actor.casefold():
        return "other-account"
    return None


def _shifted(when: datetime, by: timedelta) -> datetime:
    """Move a time, stopping at the first or last representable moment."""
    try:
        return when + by
    except OverflowError:
        edge = datetime.min if by < timedelta(0) else datetime.max  # noqa: DTZ901 - zone set next
        return edge.replace(tzinfo=when.tzinfo)


_Moment = tuple[datetime, str, int | None]
"""When an event happened, with its log and record number for ordering ties."""


def _moment(event: Event) -> _Moment:
    return (event.time, event.channel.casefold(), event.record_id)


def _later(one: _Moment, other: _Moment) -> bool | None:
    """Whether one event came after another, or None when the input cannot say.

    Exports often round times to the second, so events can share a timestamp. Record
    numbers order them only within one log.
    """
    if one[0] != other[0]:
        return one[0] > other[0]
    if one[1] == other[1] and one[2] is not None and other[2] is not None:
        return one[2] > other[2]
    return None


def _restarted_between(state: _State, event: Event, logon: _Logon) -> bool:
    """Whether a restart or a stopped log service may have come between logon and change.

    A boundary whose order against either event cannot be established counts: taking
    an address from a logon that may come from before a restart would be a guess.
    """
    moments = state.boundaries.get(event.computer.casefold(), [])
    start = bisect.bisect_left(moments, logon.time, key=lambda moment: moment[0])
    end = bisect.bisect_right(moments, event.time, key=lambda moment: moment[0])
    logged_on = (logon.time, *logon.place)
    changed = _moment(event)
    return any(
        _later(moment, logged_on) is not False and _later(changed, moment) is not False
        for moment in moments[start:end]
    )


def _session_facts(logon: _Logon) -> tuple[str | None, ...]:
    """What a logon says about where a session came from, for comparing two copies."""
    return (logon.address, logon.port, logon.workstation, logon.logon_type, logon.account)


def _known_as(state: _State, sid: str | None, recorded: str | None) -> str | None:
    """A name for a SID from other events, only when they all agree."""
    names = state.names.get(sid or "", set())
    if len(names) != 1:
        return None
    (name,) = names
    return None if recorded is not None and name.casefold() == recorded.casefold() else name


def _well_known(state: _State, sid: str | None) -> str | None:
    """The well-known name of a SID, worded so a RID is not mistaken for proof.

    A relative identifier such as 512 means Domain Admins only in a domain; the same
    number under a computer's own SID is another account.
    """
    named = state.catalog.name_sid(sid) if sid else None
    if named is None:
        return None
    if named.kind == "well-known-rid":
        return f"{named.name}, if this is a domain SID"
    return named.name


def _party(state: _State, event: Event, info: EventInfo, prefix: str) -> Party:
    sid = _text(event, info, f"{prefix}_sid")
    name = _text(event, info, f"{prefix}_name")
    domain = _text(event, info, f"{prefix}_domain")
    recorded = (f"{domain}\\{name}" if domain else name) if name else None
    return Party(
        sid=sid,
        name=name,
        domain=domain,
        dn=_text(event, info, f"{prefix}_dn"),
        well_known=_well_known(state, sid),
        known_as=_known_as(state, sid, recorded),
    )


def _target(state: _State, event: Event, info: EventInfo) -> Party:
    party = _party(state, event, info, "target")
    dn = _text(event, info, "object_dn")
    if dn is None and party.dn is None:
        return party
    return Party(
        sid=party.sid,
        name=party.name,
        domain=party.domain,
        dn=dn or party.dn,
        object_class=_text(event, info, "object_class"),
        guid=_text(event, info, "object_guid"),
        well_known=party.well_known,
        known_as=party.known_as,
    )


def _member(state: _State, event: Event, info: EventInfo) -> Party | None:
    if "member_sid" not in info.roles and "member_dn" not in info.roles:
        return None
    sid = _text(event, info, "member_sid")
    return Party(
        sid=sid,
        dn=_text(event, info, "member_dn"),
        well_known=_well_known(state, sid),
        known_as=_known_as(state, sid, None),
    )


def _ref(event: Event) -> EventRef:
    return EventRef(event.event_id, event.record_id, event.time, event.source)


def _in_window(time: datetime, window: tuple[datetime | None, datetime | None]) -> bool:
    since, until = window
    return (since is None or time >= since) and (until is None or time < until)


def _changes(state: _State, window: tuple[datetime | None, datetime | None]) -> Iterator[Change]:
    """Build a change for each event, merging directory value events that belong together."""
    groups: dict[tuple[str, str, str], list[Event]] = {}
    order: list[tuple[Event, EventInfo, tuple[str, str, str] | None]] = []
    for event, info in state.events:
        if info.category == "integrity":
            if _in_window(event.time, window):
                state.account.notices.append(_notice(state, event, info))
                state.count("notices")
            else:
                state.count("outside_window")
            continue
        key = _group_key(event, info)
        if key is not None and key in groups:
            groups[key].append(event)
            continue
        if key is not None:
            groups[key] = [event]
        order.append((event, info, key))
    for event, info, key in order:
        members = groups[key] if key is not None else [event]
        if not _in_window(event.time, window):
            state.account.counts["outside_window"] += len(members)
            continue
        if event.event_id == _AUDIT_POLICY_EVENT:
            # Both a change and a notice; its event is counted once, with the changes.
            state.account.notices.append(_notice(state, event, info))
        state.account.counts["changes"] += len(members)
        yield _change(state, info, members)


def _group_key(event: Event, info: EventInfo) -> tuple[str, str, str] | None:
    """The key that joins directory value events of one modification, if any."""
    if info.category != "directory" or info.action != "changed":
        return None
    correlation = event.data.get("OpCorrelationID", "")
    dn = _text(event, info, "object_dn")
    if dn is None or correlation in _EMPTY or correlation.casefold() == _NULL_GUID:
        return None
    return (event.computer.casefold(), correlation.casefold(), dn.casefold())


def _change(state: _State, info: EventInfo, events: list[Event]) -> Change:
    first = events[0]
    if info.category == "directory" and info.action == "changed":
        details = _directory_details(state, events)
    else:
        details = _details(state, first, info)
    # Field names come from the record itself. A record without a field this event
    # normally has was written by another Windows version or was altered; either way
    # the reading below may be missing something, and the reader is told.
    absent = sorted({name for name in info.roles.values() if name not in first.data})
    notes = []
    if absent:
        notes.append(
            f"The event lacks {', '.join(absent)}, which this event normally records; "
            "the description may be incomplete."
        )
    if _outcome_of(state, first, info) == _CONFLICT:
        notes.append(
            "Copies of this event disagree about whether it succeeded or failed, so the "
            "outcome is not stated."
        )
    change = Change(
        id="",
        time=first.time,
        computer=first.computer,
        category=info.category,
        action=_action_for(state, info, first),
        title=info.title,
        actor=_party(state, first, info, "actor"),
        target=_target(state, first, info),
        member=_member(state, first, info),
        details=tuple(details),
        origin=_origin(state, first, info),
        events=tuple(_ref(event) for event in events),
        notes=tuple(notes),
    )
    return _with(change, sentence=narrative.sentence(change))


_AUDIT_FAILURE = 1 << 52
"""Keywords bit for Audit Failure (0x0010000000000000, Microsoft's StandardEventKeywords)."""
_AUDIT_SUCCESS = 1 << 53
"""Keywords bit for Audit Success (0x0020000000000000)."""
_OUTCOMES = {
    "password-change-attempted": ("password-changed", "password-change-failed"),
    "password-reset-attempted": ("password-reset", "password-reset-failed"),
}
"""Events Windows logs on success and on failure: action when unknown, then success, failure."""


def _audit_outcome(event: Event) -> bool | None:
    """Whether the event says it succeeded (True) or failed (False); ``None`` if it does not.

    The answer comes only from the event's own Keywords mask (exactly one of the two audit
    bits), or, for Event Viewer CSV, which has no mask, its Level text. Anything absent,
    unreadable, or contradictory is ``None``: toledot never guesses.
    """
    text = event.system.get("Keywords")
    if text is not None:
        try:
            mask = int(text, 16)
        except ValueError:
            return None
        ok, bad = bool(mask & _AUDIT_SUCCESS), bool(mask & _AUDIT_FAILURE)
        return ok if ok != bad else None
    level = event.system.get("LevelDisplayName", "").strip().casefold()
    return {"audit success": True, "audit failure": False}.get(level)


def _action_for(state: _State, info: EventInfo, event: Event) -> str:
    """The action, using the audit outcome for events logged on success and failure.

    The outcome is what every copy of the event says. Copies that contradict each
    other leave it unstated.
    """
    pair = _OUTCOMES.get(info.action)
    outcome = _outcome_of(state, event, info)
    if pair is None or outcome in {None, _UNKNOWN, _CONFLICT}:
        return info.action
    return pair[0] if outcome == _SUCCESS else pair[1]


def _with(change: Change, **updates: object) -> Change:
    values = {name: getattr(change, name) for name in change.__dataclass_fields__}
    values.update(updates)
    return Change(**values)


def _notice(state: _State, event: Event, info: EventInfo) -> Notice:
    actor = _party(state, event, info, "actor")
    if event.event_id == _AUDIT_POLICY_EVENT:
        kind, text = "audit-policy-changed", "The audit policy was changed."
    else:
        kind, text = info.action, _NOTICE_KINDS.get(info.action, info.title)
    routine = kind in _ROUTINE_NOTICES
    if kind == "time-changed":
        text = _clock_text(event)
        if _clock_sync(event, actor):
            routine = True
            text = text.replace(
                "The system time was changed", "The Windows Time service adjusted the system time"
            )
    elif kind == "events-dropped" and event.data.get("Reason"):
        text = f"{text[:-1]} (reason code {event.data['Reason']}, not documented by Microsoft)."
    if not routine:
        text += _MISSING
    severity = "info" if routine else "warning"
    return Notice(event.time, event.computer, kind, text, actor, _ref(event), severity)


def _clock_sync(event: Event, actor: Party) -> bool:
    """Whether a time change looks like Windows time synchronisation.

    The Windows Time service runs in ``svchost.exe`` under a service account and makes
    small corrections. A change by any other process, or one that moves the clock
    further than ``CLOCK_SYNC_LIMIT``, is reported as a warning even under a service
    account: SYSTEM can be any program.
    """
    process = event.data.get("ProcessName", "").replace("/", "\\").rsplit("\\", 1)[-1]
    if actor.sid not in _SERVICE_SIDS or process.casefold() != "svchost.exe":
        return False
    try:
        before = datetime.fromisoformat(event.data.get("PreviousTime", ""))
        after = datetime.fromisoformat(event.data.get("NewTime", ""))
        moved = abs(after - before)
    except (ValueError, TypeError):
        return True  # version 0 records local text times; the process is the evidence
    return moved <= CLOCK_SYNC_LIMIT


def _clock_text(event: Event) -> str:
    """Words for a time change, with the old and new times when the event records them.

    Version 1 records ISO 8601 UTC times; version 0 records a local date and a local
    time as separate text, which is quoted as written.
    """
    data = event.data

    def when(prefix: str) -> str:
        parts = (data.get(f"{prefix}Date", ""), data.get(f"{prefix}Time", ""))
        return " ".join(part.replace("\u200e", "").strip() for part in parts if part).strip()

    before, after = when("Previous"), when("New")
    if before and after:
        return f"The system time was changed from {before} to {after}."
    return "The system time was changed."


# --- details ---------------------------------------------------------------------------


def _meaning(state: _State, value: str) -> tuple[str | None, bool]:
    """Words for a ``%%NNNN`` value, and whether Microsoft's documentation confirms them."""
    if not value.startswith("%%"):
        return None, True
    entry = state.catalog.messages.get(value)
    return (None, True) if entry is None else (entry.text, entry.confirmed)


def _details(state: _State, event: Event, info: EventInfo) -> list[Detail]:
    """Details of an event that carries its values in its own fields."""
    used = set(info.roles.values())
    consumed: set[str] = set()
    out: list[Detail] = []
    uac: dict[str, str] = {}
    for attribute in info.attributes:
        paired = attribute.kind not in {"uac-old", "uac-new"}
        if paired and _pair_of(attribute.field) in event.data:
            continue  # an old and a new value: reported once, as a change, below
        consumed.add(attribute.field)
        value = event.data.get(attribute.field)
        if value is None:
            continue
        if attribute.kind in {"uac-old", "uac-new"}:
            uac[attribute.kind] = value
            continue
        if value in (attribute.unchanged, "") or (value == _NOT_SET and info.action == "created"):
            continue  # nothing changed, or a new object's attribute that has no value
        if attribute.kind == "uac-control" and {"uac-old", "uac-new"} <= uac.keys():
            continue  # the old and new values say the same, without a code table
        out.append(_attribute_detail(state, attribute, value, created=info.action == "created"))
    if {"uac-old", "uac-new"} <= uac.keys() and uac["uac-old"] != uac["uac-new"]:
        out.append(_flags_detail(state, uac["uac-old"], uac["uac-new"], sam=True))
    privileges = info.roles.get("privileges")
    if privileges and info.category == "rights":
        kind = "added" if info.action == "right-granted" else "removed"
        out += [
            Detail("user right", kind, new=right, attribute=privileges)
            for right in event.data.get(privileges, "").split()
            if right not in _EMPTY
        ]
    caller = info.roles.get("workstation")
    value = event.data.get(caller) if caller and info.category != "logon" else None
    if value is not None and value not in _EMPTY:
        label = "caller computer" if info.action == "locked" else "workstation"
        out.append(Detail(label, "info", new=value, attribute=caller))
    out += _paired_and_other(state, event, used, consumed)
    return out


def _attribute_detail(state: _State, attribute: Attribute, value: str, *, created: bool) -> Detail:
    meaning, confirmed = _meaning(state, value)
    if meaning is not None and not confirmed:
        meaning += _UNDOCUMENTED
    kind = "initial" if created else "set"
    return Detail(attribute.label, kind, new=value, meaning=meaning, attribute=attribute.field)


def _flags_detail(state: _State, old: str, new: str, *, sam: bool) -> Detail:
    decode = state.catalog.decode_sam_uac if sam else state.catalog.decode_ldap_uac
    before, after = decode(old), decode(new)
    meaning = None
    if before is not None and after is not None:
        turned_on = [flag for flag in after if flag not in before]
        turned_off = [flag for flag in before if flag not in after]
        parts = [f"turned on: {', '.join(turned_on)}"] if turned_on else []
        parts += [f"turned off: {', '.join(turned_off)}"] if turned_off else []
        meaning = "; ".join(parts) or None
    field_name = "OldUacValue/NewUacValue" if sam else "userAccountControl"
    return Detail("account control flags", "changed", old, new, meaning, field_name)


def _pair_of(name: str) -> str | None:
    """The field that pairs with an ``Old...`` or ``New...`` field."""
    if name.startswith("Old"):
        return "New" + name[3:]
    return "Old" + name[3:] if name.startswith("New") else None


def _coded(state: _State, value: str) -> str | None:
    """Words for a value made only of ``%%NNNN`` codes, when every code is known."""
    codes = value.replace(",", " ").split()
    if not codes or not all(code.startswith("%%") for code in codes):
        return None
    found = [_meaning(state, code) for code in codes]
    if any(text is None for text, _ in found):
        return None
    text = ", ".join(str(text) for text, _ in found)
    return text if all(confirmed for _, confirmed in found) else text + _UNDOCUMENTED


def _paired_and_other(
    state: _State, event: Event, used: set[str], consumed: set[str]
) -> list[Detail]:
    """Old/New field pairs become changes; other recorded fields are kept as facts."""
    out: list[Detail] = []
    for name, value in event.data.items():
        pair = _pair_of(name)
        if name in consumed or (name in used and (pair is None or pair not in event.data)):
            continue
        if name.startswith("Old") and pair is not None and pair in event.data:
            new = event.data[pair]
            if value != new:
                label = _LABELS.get(name[3:], name[3:])
                out.append(Detail(label, "changed", value, new, attribute=name[3:]))
        elif value not in _EMPTY and (pair is None or pair not in event.data):
            meaning = _coded(state, value)
            out.append(Detail(name, "info", new=value, meaning=meaning, attribute=name))
    return out


def _directory_details(state: _State, events: list[Event]) -> list[Detail]:
    """Pair the deleted and added values of each attribute in one modification."""
    removed: dict[str, list[str]] = {}
    added: dict[str, list[str]] = {}
    other: list[Detail] = []
    for event in events:
        attribute = event.data.get("AttributeLDAPDisplayName", "") or "(attribute not recorded)"
        value = event.data.get("AttributeValue", "")
        operation = event.data.get("OperationType", "")
        # Event Viewer's text exports carry the words instead of the code.
        if operation in {_DS_ADDED, "Value Added"}:
            added.setdefault(attribute, []).append(value)
        elif operation in {_DS_DELETED, "Value Deleted"}:
            removed.setdefault(attribute, []).append(value)
        else:
            text = f"operation {operation or '(not recorded)'}"
            other.append(Detail(attribute, "info", new=value, meaning=text, attribute=attribute))
    out: list[Detail] = []
    for attribute in dict.fromkeys([*removed, *added]):
        gone, came = removed.get(attribute, []), added.get(attribute, [])
        if len(gone) == 1 and len(came) == 1:
            if attribute.casefold() == "useraccountcontrol":
                detail = _flags_detail(state, gone[0], came[0], sam=False)
                out.append(
                    Detail(attribute, "changed", gone[0], came[0], detail.meaning, attribute)
                )
            else:
                out.append(Detail(attribute, "changed", gone[0], came[0], attribute=attribute))
            continue
        out += [Detail(attribute, "removed", old=value, attribute=attribute) for value in gone]
        out += [Detail(attribute, "added", new=value, attribute=attribute) for value in came]
    return out + other


# --- relating and numbering --------------------------------------------------------------


def _relate(changes: list[Change]) -> list[Change]:
    """Mark changes made by one session on one computer within moments of each other."""
    changes.sort(key=lambda c: (c.time, c.computer.casefold(), c.events[0].record_id or 0))
    by_session: dict[tuple[str, int], list[int]] = {}
    for index, change in enumerate(changes):
        number = _number_of(change.origin.logon_id)
        # Every service on a computer shares its system sessions, so they link nothing.
        if number is not None and number not in _SYSTEM_SESSIONS:
            by_session.setdefault((change.computer.casefold(), number), []).append(index)
    ids = [f"C{index + 1:04d}" for index in range(len(changes))]
    related: dict[int, tuple[tuple[str, ...], int]] = {}
    for indexes in by_session.values():
        times = [changes[index].time for index in indexes]
        for position, index in enumerate(indexes):
            when = times[position]
            first = bisect.bisect_left(times, _shifted(when, -RELATED_WINDOW))
            last = bisect.bisect_right(times, _shifted(when, RELATED_WINDOW))
            total = last - first - 1
            if total <= 0:
                continue
            # The nearest in time are listed and the rest only counted, so a burst of
            # automated changes cannot multiply the report by its own size.
            low, high = max(first, position - MAX_RELATED), min(last, position + MAX_RELATED + 1)
            nearby = sorted(
                (p for p in range(low, high) if p != position),
                key=lambda p: (abs(times[p] - when), p),
            )[:MAX_RELATED]
            related[index] = (tuple(ids[indexes[p]] for p in sorted(nearby)), total)
    return [
        _with(
            change,
            id=ids[index],
            related=related.get(index, ((), 0))[0],
            related_total=related.get(index, ((), 0))[1],
        )
        for index, change in enumerate(changes)
    ]


# --- coverage ----------------------------------------------------------------------------


def _coverage(log: _Log) -> Coverage:
    merged: list[list[int]] = []
    for start, end in sorted(log.ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    gaps = [(a[1] + 1, b[0] - 1) for a, b in itertools.pairwise(merged)]
    missing = sum(end - start + 1 for start, end in gaps)
    if "unfiltered" in log.scopes:
        scope = "unfiltered"
    elif log.scopes == {"filtered"}:
        scope = "filtered"
    else:
        scope = "unknown"
    if not log.count:
        continuity = "empty"
    elif not merged:
        continuity = "unnumbered"
    elif gaps:
        continuity = "gaps"
    elif log.unnumbered:
        continuity = "partly-numbered"
    else:
        continuity = "complete"
    return Coverage(
        computer=log.computer,
        channel=log.channel,
        events=log.count,
        first=log.first,
        last=log.last,
        first_record=merged[0][0] if merged else None,
        last_record=merged[-1][1] if merged else None,
        continuity=continuity,
        missing=tuple(gaps[:MAX_MISSING_RANGES]),
        missing_count=missing,
        scope=scope,
        statement=narrative.coverage_statement(continuity, scope, missing, log.unnumbered)
        + narrative.overwritten_statement(log.overwritten_before),
        overwritten_before=log.overwritten_before,
        unnumbered=log.unnumbered,
    )
