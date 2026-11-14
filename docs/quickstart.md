# Quickstart

This walk-through takes about ten minutes. It starts with synthetic data, so nothing here touches a real system. It then shows the three ways to get events from your own domain controllers.

## 1. Install

```shell
pipx install faithful-toledot
toledot --version
```

Until the first release is on PyPI, install the wheel attached to a [GitHub release](https://github.com/faithful-oversight/faithful-toledot/releases) instead:

```shell
pipx install ./faithful_toledot-0.1.0-py3-none-any.whl
```

toledot runs on Windows, macOS, and Linux with Python 3.11 or newer. Reading files needs nothing else. Remote collection needs an extra, which [Collecting events](collecting.md#remote-collection) explains.

## 2. Create the example

```shell
toledot example ./toledot-demo
```

This writes two collection files for a made-up domain, `corp.example`:

| File | What it is |
| --- | --- |
| `dc01-events.jsonl` | What the PowerShell collector would write on `DC01.corp.example`: a week of account work, a privileged group change, and a password policy change. |
| `dc02-events.jsonl` | What the collector would write on `DC02.corp.example`: a group created with a member added, a user deleted, and a Security log that was cleared. |

Every name and address is invented. Addresses come from the ranges reserved for documentation. The files use toledot's own [collection format](formats.md#the-toledot-collection-file), the same format a real collector writes.

## 3. Write the account

```shell
toledot report ./toledot-demo/dc01-events.jsonl ./toledot-demo/dc02-events.jsonl -o ./toledot-demo/report
```

On Windows PowerShell, put the command on one line.

The terminal shows a summary, then the files it wrote:

```text
toledot 0.1.0
15 changes described, but the account is incomplete: 1 notice, 1 log with missing events.
  user: 7
  group: 5
  directory: 2
  policy: 1
  first change 2026-11-02T08:06:00Z, last 2026-11-06T13:40:00Z
  See the Completeness section of the report before relying on this account.
Reports written to ./toledot-demo/report: toledot-report.json, toledot-report.md, toledot-report.html, toledot-changes.csv, toledot-manifest.json
```

toledot exits with code `1` because the account is incomplete. That is the expected result here. Add `--fail-on never` to see exit code `0`.

## 4. Read the report

Open `./toledot-demo/report/toledot-report.html` in a browser. The Markdown version, `toledot-report.md`, holds the same content.

Read the **Completeness** section first. It says whether the account is complete, not confirmed, or incomplete, and why. In the example it is incomplete, and it names two things:

- A notice: the Security log on `DC02.corp.example` was cleared at 2026-11-06T07:52:00Z, by `CORP\admin.example`. Events may be missing around that time.
- A table of what each log holds. For `DC02.corp.example`, the collection asked for events from before the log's oldest record, so earlier events had been overwritten and are missing. For `DC01.corp.example`, 412 record numbers are absent, but the collector says it kept chosen events only, so that is expected.

Then read the changes. Each change is one sentence, followed by what changed, where it came from, and the evidence:

- **What changed.** Values come from the event itself. Directory service change events (5136) record the old and the new value. Most other events record only the new value, and the report says `earlier value not recorded`.
- **From where.** toledot follows the logon ID of the actor's session to the logon event on the same computer. If that logon event is not in the input, the report says so. See [Limitations](limitations.md#how-toledot-links-events).
- **Evidence.** The event ID, the record number, and the file and line of every event the change is built from.

Look at change C0015, where `CORP\helpdesk.example` deleted a user account. Its logon event is not in the input, so the origin is not known. The report says that instead of guessing.

## 5. Use your own logs

You can get events from a domain controller in three ways. Use the first or second for the best account of what is missing. Use the third when you cannot run a script.

### Run the PowerShell collector on a domain controller

Write the script from the installed package:

```shell
toledot collector -o Collect-ToledotEvents.ps1
```

Copy it to the domain controller. Read it first: it is one plain-text file. Open an **elevated** PowerShell session on the controller and run it:

```powershell
.\Collect-ToledotEvents.ps1 -OutFile C:\Temp\dc01-events.jsonl -Days 30
```

The script reads the Security and System logs for the last 30 days. It reads only the events toledot understands. It prints nothing when it succeeds. Check that the file exists, then copy it to the machine where you run toledot.

If the execution policy blocks the script, run it for this one session only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Collect-ToledotEvents.ps1 -OutFile C:\Temp\dc01-events.jsonl -Days 30
```

Run the script on every domain controller. toledot reports only on the logs it is given. [Collecting events](collecting.md#on-each-domain-controller) has every parameter and the rights it needs.

### Collect remotely

`toledot collect` runs the same script on a controller over PowerShell remoting (WinRM), so you install nothing on it. It needs the `live` extra:

```shell
pipx install "faithful-toledot[live]"
export TOLEDOT_PASSWORD='...'
toledot collect --server dc01.corp.example --auth ntlm --username 'CORP\auditor' \
  --secret env:TOLEDOT_PASSWORD --ca-file corp-root-ca.pem --days 30 -o dc01-events.jsonl
```

With Kerberos and a current ticket, leave out `--username` and `--secret`:

```shell
toledot collect --server dc01.corp.example --days 30 -o dc01-events.jsonl
```

toledot connects over HTTPS on port 5986 and always verifies the certificate. See [Collecting events](collecting.md#remote-collection) for the requirements, every option, and why Basic and CredSSP authentication are not offered.

### Export the logs yourself

If you cannot run either collector, export the logs with Event Viewer, `wevtutil`, or `Get-WinEvent`. For example, on a domain controller, in an elevated session:

```shell
wevtutil epl Security C:\Temp\dc01-security.evtx
```

[Input formats](formats.md) gives an exact command for every format, and says what each one loses.

### Write the account

Pass every file to one run:

```shell
toledot report dc01-events.jsonl dc02-events.jsonl -o report
```

If a file is a complete log, such as the preceding export, add `--whole-logs`. Absent record numbers in a complete log mean events are missing. Without the option, toledot cannot tell that apart from a filtered export, and it reports the account as not confirmed when a log has absent record numbers. See [Command reference](usage.md#report).

## Next steps

- [Command reference](usage.md) for every command, option, and exit code.
- [Input formats](formats.md) for what each export keeps and loses.
- [Collecting events](collecting.md) for the collector, WinRM, and secrets.
- [Reports and output](output.md) for what each part of the report means.
- [Limitations](limitations.md) before you rely on an account as evidence.
