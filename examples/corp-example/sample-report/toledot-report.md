# Account of changes

**15 changes described, but the account is incomplete: 1 notice, 1 log with missing events.**

Generated 2026-11-09T12:00:00Z by toledot 0.1.0. Period: everything in the input. All times are UTC.

## Completeness

**Incomplete.** 15 changes described, but the account is incomplete: 1 notice, 1 log with missing events.

These events bear on whether the log can be trusted to be whole (a cleared log, dropped events, a changed audit policy or a clock changed by a person):

- 2026-11-06T07:52:00Z on DC02.corp.example: log-cleared: The log was cleared. Events may be missing from this account around this time. By CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104). Evidence: event 1102, record 9102 (dc02-events.jsonl, line 3).

### What each log holds

| Computer | Log | Events | First | Last | Records | Continuity | Scope | Absent records | What it means |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DC01.corp.example | Security | 17 | 2026-11-02T08:05:00Z | 2026-11-05T07:40:00Z | 48211–48639 | gaps | filtered | 48227–48638 | 412 record numbers between the first and the last are absent. The input says it holds chosen events only, so this is expected and does not show whether any chosen event is missing. |
| DC02.corp.example | Security | 5 | 2026-11-06T07:50:00Z | 2026-11-06T13:40:00Z | 9101–9105 | complete | filtered | none | Every record number between the first and the last is present. Events before the first or after the last are outside this input. The collection asked for earlier events, but the log's oldest record is from 2026-11-05 08:00:00 UTC: earlier events had been overwritten and are missing. |

## Summary

15 changes, 1 warning notice, 0 routine log events, 0 problems. Events read: 17 in changes, 4 as context, 1 as notices, 0 not described, 0 duplicates, 0 outside the period.

First change 2026-11-02T08:06:00Z, last 2026-11-06T13:40:00Z.

| Category | Changes |
| --- | --- |
| user | 7 |
| group | 5 |
| directory | 2 |
| policy | 1 |

| Action | Changes |
| --- | --- |
| changed | 3 |
| member-added | 3 |
| created | 2 |
| password-reset-attempted | 2 |
| deleted | 1 |
| enabled | 1 |
| member-removed | 1 |
| policy-changed | 1 |
| unlocked | 1 |

| Actor | SID | Changes |
| --- | --- | --- |
| CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) | S-1-5-21-1111111111-2222222222-3333333333-1104 | 7 |
| CORP\\svc\_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) | S-1-5-21-1111111111-2222222222-3333333333-1150 | 5 |
| CORP\\helpdesk.sam (S-1-5-21-1111111111-2222222222-3333333333-1131) | S-1-5-21-1111111111-2222222222-3333333333-1131 | 3 |

## Changes on 2026-11-02 (UTC): 7

### C0001 · 08:06:00 UTC · CORP\\svc\_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) created the user account CORP\\dana.whitfield (S-1-5-21-1111111111-2222222222-3333333333-1207).

- Computer: DC01.corp.example. Kind: user, created.
- SAM account name: created as dana.whitfield \[attribute: SamAccountName\]
- display name: created as Dana Whitfield \[attribute: DisplayName\]
- user principal name: created as dana.whitfield@⁠corp.example \[attribute: UserPrincipalName\]
- password last set: created as %%1794 (meaning: \<never\> \[code meaning not documented by Microsoft\]) \[attribute: PasswordLastSet\]
- account expiry: created as %%1794 (meaning: \<never\> \[code meaning not documented by Microsoft\]) \[attribute: AccountExpires\]
- primary group RID: created as 513 \[attribute: PrimaryGroupId\]
- account control flags: 0x0 → 0x15 (meaning: turned on: USER\_ACCOUNT\_DISABLED, USER\_PASSWORD\_NOT\_REQUIRED, USER\_NORMAL\_ACCOUNT) \[attribute: OldUacValue/NewUacValue\]
- PrivilegeList: %%1793 (meaning: \<value not set\> \[code meaning not documented by Microsoft\]) \[attribute: PrivilegeList\]
- From where: Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731.
- Related changes: C0002, C0003, C0004
- Evidence: event 4720, record 48212 (dc01-events.jsonl, line 3)

### C0002 · 08:06:00 UTC · CORP\\svc\_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) attempted to reset the password of CORP\\dana.whitfield (S-1-5-21-1111111111-2222222222-3333333333-1207).

- Computer: DC01.corp.example. Kind: user, password-reset-attempted.
- From where: Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731.
- Related changes: C0001, C0003, C0004
- Evidence: event 4724, record 48213 (dc01-events.jsonl, line 4)

### C0003 · 08:06:01 UTC · CORP\\svc\_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) changed the user account CORP\\dana.whitfield (S-1-5-21-1111111111-2222222222-3333333333-1207).

- Computer: DC01.corp.example. Kind: user, changed.
- account control flags: 0x15 → 0x10 (meaning: turned off: USER\_ACCOUNT\_DISABLED, USER\_PASSWORD\_NOT\_REQUIRED) \[attribute: OldUacValue/NewUacValue\]
- From where: Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731.
- Related changes: C0001, C0002, C0004
- Evidence: event 4738, record 48214 (dc01-events.jsonl, line 5)

### C0004 · 08:06:01 UTC · CORP\\svc\_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) enabled the user account CORP\\dana.whitfield (S-1-5-21-1111111111-2222222222-3333333333-1207).

- Computer: DC01.corp.example. Kind: user, enabled.
- From where: Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731.
- Related changes: C0001, C0002, C0003
- Evidence: event 4722, record 48215 (dc01-events.jsonl, line 6)

### C0005 · 08:06:30 UTC · CORP\\svc\_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) added CN=Dana Whitfield,OU=Staff,DC=corp,DC=example (named CORP\\dana.whitfield in other events; S-1-5-21-1111111111-2222222222-3333333333-1207) to the group CORP\\Staff-All (S-1-5-21-1111111111-2222222222-3333333333-2101).

- Computer: DC01.corp.example. Kind: group, member-added.
- From where: Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731.
- Evidence: event 4728, record 48216 (dc01-events.jsonl, line 7)

### C0006 · 11:12:00 UTC · CORP\\helpdesk.sam (S-1-5-21-1111111111-2222222222-3333333333-1131) attempted to reset the password of CORP\\omar.reyes (S-1-5-21-1111111111-2222222222-3333333333-1188).

- Computer: DC01.corp.example. Kind: user, password-reset-attempted.
- From where: Session 0x3b7f02 began at 2026-11-02 11:10:00 UTC as Network from 192.0.2.61 port 49731.
- Evidence: event 4724, record 48218 (dc01-events.jsonl, line 9)

### C0007 · 11:12:12 UTC · CORP\\helpdesk.sam (S-1-5-21-1111111111-2222222222-3333333333-1131) unlocked the user account CORP\\omar.reyes (S-1-5-21-1111111111-2222222222-3333333333-1188).

- Computer: DC01.corp.example. Kind: user, unlocked.
- From where: Session 0x3b7f02 began at 2026-11-02 11:10:00 UTC as Network from 192.0.2.61 port 49731.
- Evidence: event 4767, record 48219 (dc01-events.jsonl, line 10)

## Changes on 2026-11-03 (UTC): 3

### C0008 · 09:07:00 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) changed the user object CN=Dana Whitfield,OU=Staff,DC=corp,DC=example.

- Computer: DC01.corp.example. Kind: directory, changed.
- title: Analyst → Finance Systems Lead \[attribute: title\]
- From where: Session 0x5f1a2 began at 2026-11-03 09:05:00 UTC as Network from 192.0.2.44 port 49731.
- Evidence: event 5136, record 48221 (dc01-events.jsonl, line 12); event 5136, record 48222 (dc01-events.jsonl, line 13)

### C0009 · 09:09:00 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) added CN=Dana Whitfield,OU=Staff,DC=corp,DC=example (named CORP\\dana.whitfield in other events; S-1-5-21-1111111111-2222222222-3333333333-1207) to the group CORP\\Domain Admins (well-known: Domain Admins, if this is a domain SID; S-1-5-21-1111111111-2222222222-3333333333-512).

- Computer: DC01.corp.example. Kind: group, member-added.
- From where: Session 0x5f1a2 began at 2026-11-03 09:05:00 UTC as Network from 192.0.2.44 port 49731.
- Evidence: event 4728, record 48223 (dc01-events.jsonl, line 14)

### C0010 · 09:09:24 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) changed the user object CN=Dana Whitfield,OU=Staff,DC=corp,DC=example.

- Computer: DC01.corp.example. Kind: directory, changed.
- userAccountControl: 512 → 66048 (meaning: turned on: DONT\_EXPIRE\_PASSWORD) \[attribute: userAccountControl\]
- From where: Session 0x5f1a2 began at 2026-11-03 09:05:00 UTC as Network from 192.0.2.44 port 49731.
- Evidence: event 5136, record 48224 (dc01-events.jsonl, line 15); event 5136, record 48225 (dc01-events.jsonl, line 16)

## Changes on 2026-11-04 (UTC): 1

### C0011 · 08:10:00 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) changed policy on DC01.corp.example (domain policy changed).

- Computer: DC01.corp.example. Kind: policy, policy-changed.
- policy that changed: set to Password Policy (earlier value not recorded) \[attribute: DomainPolicyChanged\]
- minimum password length: set to 8 (earlier value not recorded) \[attribute: MinPasswordLength\]
- password history length: set to 5 (earlier value not recorded) \[attribute: PasswordHistoryLength\]
- From where: Session 0x5f1a2 began at 2026-11-03 09:05:00 UTC as Network from 192.0.2.44 port 49731.
- Evidence: event 4739, record 48226 (dc01-events.jsonl, line 17)

## Changes on 2026-11-05 (UTC): 1

### C0012 · 07:40:00 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) removed CN=Dana Whitfield,OU=Staff,DC=corp,DC=example (named CORP\\dana.whitfield in other events; S-1-5-21-1111111111-2222222222-3333333333-1207) from the group CORP\\Domain Admins (well-known: Domain Admins, if this is a domain SID; S-1-5-21-1111111111-2222222222-3333333333-512).

- Computer: DC01.corp.example. Kind: group, member-removed.
- From where: Session 0x5f1a2 began at 2026-11-03 09:05:00 UTC as Network from 192.0.2.44 port 49731.
- Evidence: event 4729, record 48639 (dc01-events.jsonl, line 18)

## Changes on 2026-11-06 (UTC): 3

### C0013 · 08:00:00 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) created the group CORP\\Temp-Vendors (S-1-5-21-1111111111-2222222222-3333333333-2240).

- Computer: DC02.corp.example. Kind: group, created.
- SAM account name: created as Temp-Vendors \[attribute: SamAccountName\]
- From where: Session 0x77e310 began at 2026-11-06 07:50:00 UTC as RemoteInteractive from 192.0.2.44 port 49731, workstation name ADMIN-PC7.
- Evidence: event 4727, record 9103 (dc02-events.jsonl, line 4)

### C0014 · 08:01:00 UTC · CORP\\alice.admin (S-1-5-21-1111111111-2222222222-3333333333-1104) added S-1-5-21-1111111111-2222222222-3333333333-1188 (named CORP\\omar.reyes in other events) to the group CORP\\Temp-Vendors (S-1-5-21-1111111111-2222222222-3333333333-2240).

- Computer: DC02.corp.example. Kind: group, member-added.
- From where: Session 0x77e310 began at 2026-11-06 07:50:00 UTC as RemoteInteractive from 192.0.2.44 port 49731, workstation name ADMIN-PC7.
- Evidence: event 4728, record 9104 (dc02-events.jsonl, line 5)

### C0015 · 13:40:00 UTC · CORP\\helpdesk.sam (S-1-5-21-1111111111-2222222222-3333333333-1131) deleted the user account CORP\\old.contractor (S-1-5-21-1111111111-2222222222-3333333333-1099).

- Computer: DC02.corp.example. Kind: user, deleted.
- From where: The logon event for session 0x91c4d7 is not in the input, so where it came from is not known.
- Evidence: event 4726, record 9105 (dc02-events.jsonl, line 6)

## Inputs

| File | Format | Scope | Bytes | SHA-256 |
| --- | --- | --- | --- | --- |
| dc01-events.jsonl | collection | unknown | 13166 | eb388fee6542ded0cee9527c958ded99da375bde5df52b6204cdc8bfd69c2dc6 |
| dc02-events.jsonl | collection | unknown | 3894 | b55ce353dd0e62eeff4bb9babdb50869d7e5d80db04882dbeb09b7ac4eb7f2df |

## Limitations

- toledot reports what the events record. It cannot show a change that Windows did not audit, and it does not judge whether a change was authorized.
- "From where" is the source the logon session recorded. A proxy, a jump host, or network address translation can hide the real origin.
- Times are UTC, as recorded by each computer's own clock. Clocks that disagree are not corrected.
- Names that come from other events are shown apart from the names a change event recorded.
- Old values exist only where Windows recorded them: directory service change events (event 5136 and its relatives) record the value that changed, and most other events do not.
- A clean record-number check does not prove that nothing was removed. Someone able to rewrite the log can renumber it, and an export that was filtered cannot be checked at all.
