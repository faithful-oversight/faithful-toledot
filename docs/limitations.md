# Limitations

toledot is narrow on purpose. This page lists what it cannot do, so nobody relies on it for more than it provides.

## Out of scope

The tool will not:

- Monitor or alert in real time. It reads files after the fact.
- Judge whether a change was authorized. It reports what happened. Whether it should have happened is for you to decide.
- Show a change that Windows did not record. See [What must be audited](#what-must-be-audited).
- Change anything. It does not change your files, your domain controllers, or your directory.
- Read a log in a language other than English when the log is a CSV export. The CSV readers need English header names and message labels.

## What must be audited

toledot reads events. An event exists only if auditing was on when the change happened. A change made while auditing was off leaves no event, and toledot cannot recover it. The account is only as complete as your audit policy was.

Turn on **Success** auditing for these advanced audit policy subcategories on every domain controller before you need the account:

| To see | Events | Subcategory |
| --- | --- | --- |
| Directory objects created, modified, moved, deleted, or restored | 5137, 5136, 5139, 5141, 5138 | Audit Directory Service Changes |
| User accounts created, changed, enabled, turned off, deleted, locked, unlocked, and password changes | 4720, 4722 to 4726, 4738, 4740, 4765, 4767, 4780, 4781 | Audit User Account Management |
| Computer accounts created, changed, or deleted | 4741, 4742, 4743 | Audit Computer Account Management |
| Security groups created, changed, or deleted, and their members added or removed | 4727 to 4735, 4737, 4754 to 4758, 4764 | Audit Security Group Management |
| Where a session came from | 4624 | Audit Logon |
| When a session ended | 4634, 4647 | Audit Logoff |
| When Windows started, so logon IDs may repeat | 4608 | Audit Security State Change |

Microsoft documents each subcategory:

- [Audit Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes)
- [Audit User Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management)
- [Audit Computer Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-computer-account-management)
- [Audit Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [Audit Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon)
- [Audit Logoff](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logoff)

Microsoft has archived these pages, so check current guidance for your Windows version.

Directory service changes need more than the subcategory. Microsoft states that audit events are generated only for objects that have a system access control list (SACL), and only for accesses that match it. For event 5136, the modified object must have an entry that audits **Write** on the specific attributes. Without those entries, directory changes leave no event even when the subcategory is on. Microsoft also states that some objects and properties do not generate audit events, because of settings on the object class in the schema.

The audit policy and the SACLs are yours to set. toledot does not read them and does not check them. It can tell you only what the events in your logs say.

Other events in the catalog, such as the log cleared event 1102, need no setting.

## The event catalog

toledot understands 84 events: 83 in the Security log and event 104 (log cleared) in the System log. Run `toledot events` to list them.

- **Everything else is not described.** An event outside the catalog, such as a failed logon (4625), is counted in "Other events read" and not described. An event is likewise from another provider that reuses an event ID, and a permission or auditing event on a `File` or `Key` object.
- **Some entries are partly inferred.** Each catalog entry cites a Microsoft or standards page and carries a confirmed flag. When a detail could not be confirmed from a primary source, the flag is false, and the entry's note says which detail. `toledot events` marks these entries with `[partly inferred; see the catalog notes]`. At this release, 26 of the 84 entries are marked.
- **Where this matters.** A `.evtx`, XML, or collection file carries each event's own field names, so a doubtful catalog detail affects little. A JSON export names values by position from the catalog, and a CSV export names them by the labels the catalog maps. For those two, check any result built from an event marked partly inferred against the event in Event Viewer.
- **Codes.** A `%%NNNN` code in event data is decoded from the catalog. A meaning that Microsoft's documentation does not confirm is marked `[code meaning not documented by Microsoft]` in the report.

- **No affiliation.** toledot is not affiliated with or endorsed by Microsoft. The catalog uses event IDs and field names from Microsoft's public documentation and cites the page for each entry.

## How toledot links events

Each rule below is chosen so that toledot never says more than the events do.

- **One event is one change.** The exception is directory service changes (5136). Windows writes one event for each value, so toledot joins the events that share a correlation ID and an object on one computer. It pairs a deleted and an added value of one attribute as one change of that value. A 5136 event with no correlation ID, or with no object name, stands alone.
- **From where follows the logon ID.** A change names its actor's logon session. toledot looks for the latest logon event with that logon ID, on the same computer, at or before the change. If a logoff for that session comes after the logon and before the change, the logon no longer counts. The logon event gives the address, port, workstation name, and logon type.
- **Events with the same timestamp are ordered by record number, or not at all.** Event Viewer exports round times to the second, so a logon, a logoff, and a change can share a timestamp. Record numbers order them only within one log. When the order cannot be established and the possible orders would give different answers, the origin is `unordered` and no address is named. toledot never assumes that a logon came first or that a logoff came last.
- **A logon from before a restart is not used.** Microsoft documents logon IDs as unique only between reboots. When Windows started (4608) or the log service stopped (1100) on the computer between the logon and the change, the origin says so instead of naming the earlier logon. A restart that left neither event in the input cannot be seen, and then an old logon with a reused ID could still be linked.
- **Contradictory evidence gives no origin.** Two different logons for one session at the same moment, or a logon for a different account from the change's actor, give an origin that says why it is not known rather than a guess.
- **A logon on another controller is not linked.** toledot matches logon IDs within one computer. If the logon event is on another domain controller, the report says that the logon event is not in the input, even when you gave toledot that controller's log. Where it came from is then not known. toledot says so and does not guess.
- **A system session has no origin.** The sessions of the computer itself (SYSTEM, NETWORK SERVICE, and LOCAL SERVICE) have no logon event. The report says the computer's own system session made the change.
- **The address is what the logon recorded.** A proxy, a jump host, or network address translation can hide the real origin.
- **Names are shown only when every event agrees.** The report always shows the name the change event recorded. It adds "named X in other events" for a SID only when every event that names the SID gives the same X. If events disagree, it adds nothing.
- **Well-known relative identifiers are worded with care.** A relative identifier such as 512 means Domain Admins only under a domain SID. The same number under a computer's own SID is another account. toledot writes `well-known: Domain Admins, if this is a domain SID`. toledot knows 40 well-known SIDs and 21 well-known relative identifiers.
- **Old values exist only where Windows recorded them.** Directory service change events record the value that changed. Most other events record only the new value.
- **A lockout names the computer that recorded it.** Event 4740 is written by the domain controller, so the report words it as the controller's account recording that the account was locked out, and shows the caller computer (the computer the bad passwords came from) as its own detail. Microsoft's sample puts the caller computer in the field that other events use for the account's domain, so toledot does not show a domain for the locked account and does not learn names for the account from this event. That mapping is an inference and the entry is marked partly inferred.
- **Password events use the outcome the event records.** Windows logs events 4723, 4724, and 4794 for success and for failure. toledot reads the event's `Keywords` audit bits (Audit Success `0x0020000000000000`, Audit Failure `0x0010000000000000`, as in Microsoft's `StandardEventKeywords`). With exactly one bit set, the report says the password was changed or reset (`password-changed`, `password-reset`) or that the attempt was unsuccessful (`password-change-failed`, `password-reset-failed`). Event Viewer CSV has no mask, so its `Level` text (`Audit Success`, `Audit Failure`) is used. When the mask is absent, unreadable, or sets both or neither bit, the report words it as an attempt (`password-change-attempted`, `password-reset-attempted`) and does not guess. Get-WinEvent's `KeywordsDisplayNames` is not read; its numeric `Keywords` is. A failed attempt that Windows did not audit leaves no event. Event 4724 is not written when the caller is refused access, per Microsoft.
- **A failed SID history attempt is never an add.** Event 4766 means that an attempt to add SID history failed. The report words it as an unsuccessful attempt and counts it as `sid-history-failed`. Only event 4765 is worded and counted as SID history added.
- **Related changes are a hint.** Changes by one session, on one computer, within two seconds of each other are marked as related. They are probably parts of one administrative action. They may not be.
- **Times are UTC, as each computer's own clock recorded them.** toledot does not correct clocks that disagree. The order of changes on different computers is only as good as their clocks.
- **The same record is counted once.** A catalogued event that two inputs both hold counts once. Two copies of one record with different content are a problem, and toledot keeps both copies as separate changes so that neither is hidden.

## Size and memory

- **Memory grows with the number of changes.** The readers stream a file one record at a time, but toledot keeps every event it uses and every change it builds until the reports are written, and the JSON report is built whole before it is written. A test with 150,000 synthetic changes used about 1.5 GB at its peak, which is roughly 10 KB per change. A log with a million directory changes (event 5136 can be that numerous) would need about 10 GB. Use `--since` and `--until`, or collect shorter periods, when a log is large. Writing the reports in a streaming way is planned work, not done.

## Log overwrite and clearing

Windows logs are circular by default. When a log fills, Windows overwrites the oldest events. toledot cannot see events that no longer exist.

- **A collection records how far back the log reaches.** The collectors write the oldest record in each log into the file. When it is newer than the start of the period you asked for, the report says that earlier events had been overwritten and are missing. A log that was cleared or is new can look the same, and the report words it as overwritten. An export you made by hand has no such record. Check the first time in the coverage table against the period you meant to cover.
- **A cleared log hides everything before the clear.** Events 1102 (Security log) and 104 (System log) become warning notices, with the account that cleared the log as the event recorded it. Events from before the clear are gone from that log unless you have a copy or a forwarded copy. toledot cannot restore them.
- **An archived log is another file.** Event 1105 means Windows archived the log and started a new one. Give toledot the archive file as well.
- **Record numbers cannot prove nothing was removed.** A clean record-number check shows that no record is absent from a log. Someone who can rewrite a log can renumber it. See [Reports and output](output.md#what-complete-means).

## Filtered exports and record numbers

toledot checks record numbers to find missing events. That works for a whole log and fails for a filtered export, where gaps are expected.

- A collection file states whether it holds whole logs or chosen events only. A file from the collector's default query holds chosen events only, so its gaps are expected. A file written with `-All` or `--all` holds whole logs.
- For a native `.evtx`, XML, JSON, or CSV file, toledot cannot tell. It reports absent record numbers in the coverage table and calls the account not confirmed. It does not call it incomplete, because the gaps may be expected. Pass `--whole-logs` when every input is a whole log. See [Command reference](usage.md#whole-logs).
- An export with no record numbers cannot be checked at all. The account is not confirmed.

## Event Viewer CSV

Event Viewer's "Save All Events As" CSV keeps the least. See [Input formats](formats.md#event-viewer-save-all-events-as-csv).

- It has no record numbers, so toledot cannot check for missing events. The account is not confirmed.
- It has no computer name and no log name. toledot treats every such file as coming from one computer, so do not mix files from different computers in one run.
- Times have no UTC offset, so you must pass `--local-offset`, and `--date-order` for some dates. A fixed offset is wrong across a daylight saving change.
- The reader needs English header names and message text.
- It holds only the rendered message, so a value with line breaks can imitate labels. toledot refuses a message in which a mapped label or a section repeats, and reports the row as a problem. It cannot detect an imitated label that the real message does not carry. See [Input formats](formats.md#how-fields-are-recovered-from-the-message).

## Collectors

- **Collectors have not yet been run against a real domain controller or a real WinRM endpoint.** This is a known limitation of this release. The PowerShell collector and `toledot collect` are tested with a simulated PowerShell host and a simulated WinRM client only. Treat their first runs in your environment as a pilot, check the file they write with `toledot report`, and report anything unexpected.
- **Rights.** The rights `toledot collect` needs are those Microsoft documents for PowerShell remoting and for reading the Security log. toledot has not tested whether a just-enough-administration endpoint can be narrowed further for the script.
- **One controller per run.** A collector sees only the logs on the controller it runs on. Run it on every controller.
- **A compromised controller can lie.** The end line of a collection file shows that the file arrived whole. It does not show that the controller told the truth. See the [threat model](threat-model.md).
- **Kerberos on Linux and macOS.** `toledot collect` defaults to Kerberos. On those systems it needs support that the `live` extra does not install. See [Collecting events](collecting.md#prerequisites).

## How far this release has been tested

- The readers and the report writers are tested on synthetic files. The `.evtx` reader's tests use files built by a test writer from the published format documentation. No test in the repository reads a log that Windows wrote.
- The collectors are tested as stated earlier.
- The example and its sample reports are synthetic and are checked by a test.

## Limits of any file-based check

- toledot sees only what the inputs contain. It cannot detect records a source system did not export or did not write.
- A complete result means the supplied inputs give evidence that nothing is missing, and toledot found nothing that suggests otherwise. It is not proof that nothing is missing, and it says nothing about whether a change was right. A not confirmed result means the inputs cannot show either way.
- Results are only as current as the inputs. Every report shows when it was generated and the period it covers.
- Hashes in the reports and the collection file show that a file is consistent. They do not show who made it. A person who edits a file can recompute its hashes.
