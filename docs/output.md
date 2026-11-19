# Reports and output

Every run builds one report document, and every output format renders from it, so the formats always agree. Examples on this page come from the synthetic example, `toledot example`.

## Output files

| File | For |
| --- | --- |
| `toledot-report.html` | People. One self-contained page. |
| `toledot-report.md` | Pull requests, tickets, and change records. |
| `toledot-report.json` | Automation. Follows a published, versioned JSON Schema. |
| `toledot-changes.csv` | Spreadsheets. One row per detail of each change. |
| `toledot-manifest.json` | Evidence handling. The size and SHA-256 of every other file and every input, written last. |

`--format` chooses which of the first four to write. The manifest is always written.

## Report sections

The Markdown and HTML reports have the same sections, in this order:

| Section | What it holds |
| --- | --- |
| Completeness | Whether the account is complete, with the reason. Then the notices that bear on completeness, a table of what each log holds, any problems with the input, and routine log events. Read this section first. |
| Summary | Counts of changes, notices, and problems, and how the events read were used. Counts of changes by category and by action, and the actors with the most changes. |
| Changes | Each change, grouped by day, in time order. |
| Other events read | Events that were read but are not changes toledot describes. Only when there are any. |
| Inputs | Each input file with its format, scope, size, and SHA-256. |
| Limitations | What toledot does not do. Every report states this. |

The headline at the top says one of three things, matching the account's completeness:

- **Complete.** It says how many changes were described and that nothing in the input suggests events are missing.
- **Not confirmed.** Nothing in the input shows events missing, but some log cannot show whether events are missing. The headline says how many logs, or that no events were read, and that the account may not be whole.
- **Incomplete.** It says why: how many notices, problems, and logs with missing events.

The report also records when it was generated, the toledot version, and the period (`--since` and `--until`). All times are UTC.

The Markdown and HTML reports shorten any value longer than 300 characters and say how long it was, but only when the JSON report is written too (it is by default). With `--format` leaving `json` out, they keep every value whole, because nothing else would hold it. When the JSON report is written, they also list at most 25 notices, 25 problems, 20 routine log events, 20 actors, and 100 rows of the coverage table and of the other-events table, then say how many more the JSON report holds. Without the JSON report they list every row. The JSON report and the CSV file always hold full values.

## What complete means

The summary holds a `completeness` of `complete`, `unconfirmed`, or `incomplete`, and a `complete` flag that is true only for `complete`.

The account is **incomplete** when any of these is true:

- A notice has the severity `warning`.
- The input has problems.
- A log with the scope `unfiltered` has absent record numbers.
- A collector found that a log no longer reaches back as far as it asked. A log whose oldest record is number 1 is never reported this way, because it has lost nothing.

Otherwise the account is **unconfirmed** when no log was read, or when any log is not `checked`. A log is `checked` when the input gives positive evidence about it:

- Every record number between its first and its last is present, and every event has a record number. Continuous record numbers show that nothing between the first and the last is absent, even when the scope is `unknown`.
- Or its scope is `filtered` or `unfiltered`, so toledot knows what the input should hold. A collection that asked only for chosen events accounts for its own gaps.

Absent record numbers in a log of `unknown` scope, and an export with no record numbers, leave toledot unable to tell. Such a log is not `checked`. Neither is a log in which any event has no record number, whatever its scope.

Otherwise the account is **complete**.

Complete is a statement about what toledot could check. It is not proof that no event is missing. A complete result does not cover:

- Events before the first or after the last event of a log.
- Events missing from a `filtered` log that the filter would have kept. Record numbers cannot show those.
- Anyone who can rewrite the log. They can renumber it.
- Events Windows never audited. See [Limitations](limitations.md#what-must-be-audited).

Pass `--whole-logs` when an input is a whole log, so that absent record numbers count as missing events. The exit code of `toledot report` follows these levels. See [Command reference](usage.md#exit-code-of-report).

## A change

Each change is one sentence, followed by its details. This change comes from the example:

```json
{
  "id": "C0001",
  "time": "2026-11-02T08:06:00Z",
  "computer": "DC01.corp.example",
  "category": "user",
  "action": "created",
  "title": "User account created",
  "sentence": "CORP\\svc_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) created the user account CORP\\avery.example (S-1-5-21-1111111111-2222222222-3333333333-1207).",
  "actor": {
    "sid": "S-1-5-21-1111111111-2222222222-3333333333-1150",
    "name": "svc_provision",
    "domain": "CORP",
    "dn": null,
    "object_class": null,
    "guid": null,
    "well_known": null,
    "known_as": null,
    "display": "CORP\\svc_provision (S-1-5-21-1111111111-2222222222-3333333333-1150)"
  },
  "target": {"sid": "S-1-5-21-1111111111-2222222222-3333333333-1207", "name": "avery.example", "...": "..."},
  "member": null,
  "details": [
    {"label": "SAM account name", "kind": "initial", "old": null, "new": "avery.example",
     "meaning": null, "attribute": "SamAccountName"}
  ],
  "origin": {
    "status": "session",
    "logon_id": "0x2a51c",
    "address": "198.51.100.20",
    "port": "49731",
    "workstation": null,
    "logon_type": "3",
    "logon_type_name": "Network",
    "logon_time": "2026-11-02T08:05:00Z",
    "source": {"file": "dc01-events.jsonl", "position": "line 2"},
    "statement": "Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731."
  },
  "events": [
    {"event_id": 4720, "record_id": 48212, "time": "2026-11-02T08:06:00Z",
     "file": "dc01-events.jsonl", "position": "line 3"}
  ],
  "related": ["C0002", "C0003", "C0004"],
  "notes": []
}
```

The example is shortened: `target` and `details` hold more properties in the real report.

| Property | Meaning |
| --- | --- |
| `id` | A name for the change within this report, numbered in time order. It is not stable between reports. |
| `time`, `computer` | When the first of its events was recorded, and the computer that recorded it. |
| `category`, `action` | What kind of target, and what happened. Categories: `user`, `computer`, `group`, `directory`, `policy`, `trust`, `rights`. |
| `title` | The event's short title. |
| `sentence` | The change as one plain sentence: who did what to what. |
| `actor` | Who did it. |
| `target` | What it was done to. |
| `member` | The account added to or removed from a group, for membership changes. Otherwise `null`. |
| `details` | What changed, value by value. |
| `origin` | Where the actor's session came from. |
| `events` | The events the change is built from: event ID, record number, time, and the file and position. |
| `related` | Other changes by the same session, on the same computer, within two seconds. They are probably parts of one administrative action. |
| `notes` | Anything a reader needs in order not to over-read the change. For example, that the event lacks a field it normally records. |

### Actor, target, and member

An actor, target, or member holds what the event recorded: `sid`, `name`, `domain`, `dn` (distinguished name), `object_class`, and `guid`. A value the event did not record is `null`. `display` is the text toledot writes in the sentence.

Two properties add information from outside the event. toledot shows each apart from the recorded name, so you can tell them apart:

- `known_as` is a name that other events in the input give for the same SID. toledot sets it only when every event that names the SID agrees on one name, and only when that name differs from the recorded one. After an account rename (4781) the account has had two names, so toledot shows no `known_as` for it. The sentence reads "named CORP\\blake.sample in other events".
- `well_known` is the name of a well-known SID, such as `S-1-5-18`, or of a well-known relative identifier (RID) under a domain SID, such as 512 for Domain Admins. A RID means that group only in a domain, so toledot words it `Domain Admins, if this is a domain SID`.

### Details

Each detail has a `label`, a `kind`, an `old` and a `new` value, an optional `meaning`, and the `attribute` or event field it comes from. The kind says how much the event recorded:

| Kind | Meaning |
| --- | --- |
| `initial` | A value given to a newly created object. |
| `set` | A new value. The old value was not recorded. |
| `changed` | The old and the new value were both recorded. |
| `added` | One value added to a list attribute. |
| `removed` | One value removed from a list attribute. |
| `info` | A recorded fact that is not a value change. |

Values stay exactly as the event recorded them. `meaning` adds words when toledot can decode the value: the names of account control flags that were turned on or off, or the text of a `%%1794`-style code. A meaning that Microsoft's documentation does not confirm ends with `[code meaning not documented by Microsoft]`.

`related` lists up to 20 other changes by the same session on the same computer within two seconds, nearest in time first; `related_total` counts all of them. A burst of automated changes is therefore described with a bounded list.

Directory service change events (5136) record one event for each value. toledot joins the events of one modification, those that share a correlation ID and an object on one computer, into one change. A value that was deleted and one that was added for one attribute become one `changed` detail. When the events do not pair, the values are listed as `removed` and `added`.

### Origin

`origin.status` says how far the link from the change to a logon holds:

| Status | Meaning |
| --- | --- |
| `session` | toledot found the logon event for the actor's session on the same computer. The address, port, workstation name, logon type, and logon time come from it. |
| `local` | The change was made by one of the computer's own system sessions, which have no logon event. |
| `ended` | The input holds only a logoff of that session before the change, and no logon. Where the session came from is not known. A logoff with the same timestamp as the change counts as possibly after it, so it does not set this status. |
| `not-in-input` | The change names a session, but the input holds no logon or logoff event for it before the change. Where it came from is not known. |
| `restarted` | The latest logon for the session is not clearly after Windows started (4608) or the log service stopped (1100) on that computer. Events with the same timestamp are ordered by record number when they are in the same log; when they cannot be ordered, the logon is not trusted. Logon IDs are only unique between restarts, so that logon is not used. |
| `conflicting` | The input holds two different logons for the session at the same moment, or two copies of one logon record that disagree in any way, including their time. toledot does not choose one. |
| `unordered` | A logon or logoff of the session has the same timestamp as the change, and the input cannot show which came first: record numbers order events only within one log, and an export may have none. The two orders would give different answers (a session that started, replaced, or ended at that moment), so toledot does not choose. The same is reported when more than 64 entries of one session share the change's timestamp. |
| `other-account` | The logon was for a different account from the one that made the change, so it is not used. |
| `none` | The change event names no session. |

See [Limitations](limitations.md#how-toledot-links-events) for the rules and their limits.

## Notices

A notice is an event that bears on whether the log can be trusted to be whole. Each has a time, a computer, a `kind`, a `text`, an `actor` as far as the event records one, and the event.

| Severity | Kinds | Effect |
| --- | --- | --- |
| `warning` | `log-cleared`, `events-dropped`, `log-full`, `audit-policy-changed`, and any `time-changed` that is not routine | The account is incomplete. The text adds that events may be missing around that time. |
| `info` | `log-service-stopped`, `log-backed-up`, and a routine `time-changed` by the Windows Time service | Routine. Listed under "Routine log events." The account is not incomplete. |

The events behind them: 1102 and System 104 (log cleared), 1101 (events dropped), 1104 (log full), 1100 (the logging service stopped, as it does at shutdown), 1105 (log archived), 4616 (system time changed), and 4719 (audit policy changed). A time change counts as routine only when a service account (SYSTEM, LOCAL SERVICE, or NETWORK SERVICE) made it through `svchost.exe` and it moved the clock by at most 5 minutes. When the event does not record the times in a form toledot can read, the process alone decides. The text then reads `The Windows Time service adjusted the system time`. Any other time change is a warning. An audit policy change is also a change, so it appears in both lists. `--since` and `--until` apply to notices.

## Coverage

Coverage has one entry for each computer and log in the input. It says what the input holds and what the record numbers show.

| Property | Meaning |
| --- | --- |
| `computer`, `channel` | The computer and the log. |
| `events` | How many events were read from it. |
| `first`, `last` | The earliest and latest event time. |
| `first_record`, `last_record` | The lowest and highest record number. |
| `continuity` | `complete`: every record number between the first and the last is present, and every event has one. `gaps`: some are absent. `partly-numbered`: the numbered events have no gaps, but some events carry no record number. `unnumbered`: the export kept no record numbers. `empty`: the collector read the log and found none of the events it asked for. |
| `unnumbered` | How many events carry no record number. Any such event makes the log not `checked`, whatever the scope: toledot cannot tell whether events are missing around it, so the account is not confirmed and `--fail-on unconfirmed` exits 1. |
| `missing`, `missing_count` | The absent record-number ranges and how many numbers they hold. The JSON report lists at most 1,000 ranges. The Markdown and HTML reports write out 10. |
| `scope` | `unfiltered`: you stated with `--whole-logs` that the input is a whole log, or a collection file says it holds whole logs. `filtered`: a collection file says it holds chosen events only. `unknown`: toledot cannot tell. |
| `overwritten_before` | Set when a collector asked for events from an earlier time than the log's oldest record. Events before this time were already gone when the log was read. Otherwise `null`. |
| `checked` | Whether the input gives evidence about this log's completeness. See [What complete means](#what-complete-means). |
| `statement` | What this means, in a sentence. |

Absent record numbers mean missing events only in an `unfiltered` log. In a `filtered` log they are expected, and the statement says so. In an `unknown` log, the statement says either the export was filtered or events are missing, and that toledot cannot tell which. That log is not `checked`, so the account is not confirmed.

Here are the two rows from the example:

| Computer | Log | Continuity | Scope | Absent records | What it means |
| --- | --- | --- | --- | --- | --- |
| DC01.corp.example | Security | gaps | filtered | 48227–48638 | 412 record numbers between the first and the last are absent. The input says it holds chosen events only, so this is expected and does not show whether any chosen event is missing. |
| DC02.corp.example | Security | complete | filtered | none | Every record number between the first and the last is present. Events before the first or after the last are outside this input. The collection asked for earlier events, but the log's oldest record dates 2026-11-05 08:00:00 UTC. Earlier events had been overwritten and are missing. |

An event that two inputs both hold is counted once. If the two copies of one record disagree, toledot keeps both copies and reports a problem. If the copies are the same event but one says it succeeded and another says it failed (password events 4723, 4724, and 4794), toledot keeps one event, words it as an attempt, adds a note to it, and reports a problem.

## Problems

A problem is a record or file part that toledot could not read, or a conflict. A problem never stops the rest of a file from being read, but the account is incomplete, because any change that record held is not in it. A problem has the `file`, the `position`, the `record_id` when known, and a `reason`. The reason does not repeat the record's content.

These produce problems: an event that fails its format's rules, a damaged or cut-short file, a collection file whose end line is missing or does not match, every gap a collector recorded, two copies of a record number with different content (toledot keeps both copies), and copies of one password event that state different outcomes (toledot keeps one event and does not state the outcome). toledot keeps the first 10,000 problems and adds one problem that says how many more it dropped.

## Other events read

`other_events` counts the events that were read but are not changes toledot describes, by log, and event ID. These are events outside the catalog, events from another provider that reuses an event ID, and permission or auditing events, such as 4670 and 4907, on objects of type `File` or `Key`. Those are not directory changes, and Windows servicing writes thousands of them.

## Summary counts

`summary.events` counts every event read exactly once, by what became of it: `changes`, `context`, `notices`, `other`, `duplicates`, and `outside_window`. `changes` counts the events that make up the changes; one change can join several events, so `summary.changes` is the number of changes. `context` counts the logon and logoff events used to say where sessions came from. An audit policy change is both a change and a notice, and its event is counted once, with the changes. `duplicates` counts events that were read more than once and counted once: the same record number and content twice, or the same unnumbered event in two different inputs, as from overlapping exports. Identical rows within one input are kept. `outside_window` counts change and notice events before `--since` or from `--until` on.

## JSON schemas

`toledot schema` prints a schema for the installed version, with no network access:

```shell
toledot schema report
toledot schema events
toledot schema manifest
```

| Schema | Describes |
| --- | --- |
| `report` | `toledot-report.json`. |
| `events` | One line of a [collection file](formats.md#the-toledot-collection-file). |
| `manifest` | `toledot-manifest.json`. |

The identifier of each schema, such as `https://faithful-oversight.github.io/faithful-toledot/schema/report-v1.schema.json`, is also where the documentation site serves it once the project is public.

The top-level properties of the report are `$schema`, `schema_version`, `tool`, `generated_at`, `inputs`, `window`, `summary`, `notices`, `coverage`, `problems`, `changes`, `other_events`, and `limitations`.

Compatibility promise:

- Within major version 1, a release may add optional properties. Each such change raises the minor `schema_version`, for example from `1.0` to `1.1`, and ships the matching schema.
- A removed or changed property needs a new major schema version.
- Validate each report with the schema for its `schema_version`, which `toledot schema` from the same toledot version prints. A consumer that does not validate should ignore properties it does not know.

## Manifest

Every run writes `toledot-manifest.json`, after every other file. It lists each report file from the run with its size in bytes and SHA-256, and each input file the same way:

```json
{
  "$schema": "https://faithful-oversight.github.io/faithful-toledot/schema/manifest-v1.schema.json",
  "schema_version": "1.0",
  "tool": {"name": "toledot", "version": "0.1.1"},
  "generated_at": "2026-11-11T13:23:06Z",
  "files": [
    {"name": "toledot-report.json", "size": 40607, "sha256": "5128031a..."}
  ],
  "inputs": [
    {"name": "dc01-events.jsonl", "size": 13161, "sha256": "508be81c..."}
  ]
}
```

The preceding hashes are shortened. The manifest makes the set checkable as a whole:

- If the manifest is missing, the run did not finish writing.
- If a file's size or SHA-256 differs from the manifest, the file is partial, edited, or from another run.
- If a file the manifest lists is missing, the set is incomplete.
- If an input file's SHA-256 differs from the manifest, it is not the file the report was made from.

The manifest does not list itself. It covers only the files of its own run. A report file it does not list, for example one left from an earlier run with other `--format` choices, belongs to another run. The hash of an input identifies the file. It does not contain it.

The hashes show that the files are consistent. They do not show who made them: anyone who edits the files can recompute the manifest.

## CSV

`toledot-changes.csv` has one row for each detail of each change, and one row for a change with no details. The columns are:

`change_id`, `time_utc`, `computer`, `category`, `action`, `actor`, `actor_sid`, `target`, `target_sid`, `target_dn`, `member`, `member_sid`, `detail_label`, `detail_kind`, `old_value`, `new_value`, `meaning`, `origin_status`, `origin_address`, `origin_workstation`, `logon_type`, `logon_id`, `event_ids`, `record_ids`, `files`, `account_completeness`.

The last column, `account_completeness`, is the account's completeness: `complete`, `unconfirmed`, or `incomplete`, as in the summary of the JSON report. It is the same on every row. It lets the caveat travel with the change list when the CSV is the only file kept. The CSV holds no notices or problems, so read the other reports for the reasons. A run that finds no changes writes the header row alone.

The columns `event_ids`, `record_ids`, and `files` join several values with a semicolon and a space. The file is UTF-8 with no byte order mark, and its rows end with CRLF. A spreadsheet that guesses the encoding wrongly can be told it is UTF-8 when you import. Values are never shortened.

### Formula neutralization

A spreadsheet can run a cell that starts with `=`, `+`, `-`, or `@`, or with a tab, a carriage return, or a line feed, as a formula. Some programs also accept the full-width forms of those four characters. toledot gives every such cell a leading apostrophe, which spreadsheets show as plain text. Opening the file cannot run anything.

## HTML report

`toledot-report.html` is a single file. It works offline, follows the system's light or dark setting, and prints cleanly. Its content security policy blocks scripts, network requests, and form submission, and every value from the input is escaped. The page has no script and loads nothing. It contains no links made from data.

## Markdown report

`toledot-report.md` holds the same content in Markdown, ready to paste into a pull request, ticket, or change record. Values are escaped so they cannot break a table or inject HTML. Web addresses and email addresses from the input do not turn into links.

## Invisible characters

Event data can hold characters that change how text looks rather than what it says: terminal escape sequences, right-to-left override marks, zero-width characters, soft hyphens, tag characters, and variation selectors. The HTML, Markdown, and CSV reports and the terminal show these as visible escapes. On the terminal, tabs and carriage returns are escaped too, so a value cannot move the cursor back over a line. A character in the Basic Multilingual Plane appears as `\u202e`, and any other character appears with eight digits, as `\U000e0041`. Tab and line breaks are kept. The JSON report keeps the exact values.

## Repeatable output

The same inputs and options give the same files, except for the generation time. Set `SOURCE_DATE_EPOCH` to make that repeatable too. See [Command reference](usage.md#repeatable-reports).
