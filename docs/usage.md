# Command reference

```text
toledot [--version] COMMAND [options]
```

| Command | What it does |
| --- | --- |
| `report` | Read event files and write the account of changes. |
| `collect` | Collect events from a domain controller over PowerShell remoting. Needs the `live` extra. |
| `collector` | Write the PowerShell collector, to run on a domain controller yourself. |
| `events` | List the events toledot understands. |
| `schema` | Print a JSON Schema: `report`, `events`, or `manifest`. |
| `example` | Write synthetic event files to try toledot with. |

Run `toledot COMMAND --help` for the options of any command. Running `toledot` with no command prints the help and exits with code `2`.

## report

```shell
toledot report FILE [FILE ...] -o DIR [options]
```

| Option | Meaning |
| --- | --- |
| `FILE` | One or more event files. toledot detects the format of each file from its contents, not its name. See [Input formats](formats.md). |
| `-o`, `--output` | Folder for the reports. Required. Created if needed. |
| `-f`, `--format` | Comma-separated list of `json`, `md`, `html`, `csv`. Default: all four. The manifest is always written. |
| `--since` | Leave out changes and notices before this time. The time itself is included. |
| `--until` | Leave out changes and notices at or after this time. |
| `--whole-logs` | State that every file is a whole log, not a filtered export. Record numbers that are absent from a log then count as missing events. |
| `--local-offset` | The UTC offset of times in exports that carry none, such as Event Viewer CSV. Write it like `-06:00` or `+05:30`. |
| `--date-order` | `day-first` or `month-first`. How to read a date such as `03/04/2026` in exports that leave it open. |
| `--fail-on` | When to exit with code 1: `unconfirmed` (default), `incomplete`, or `never`. See [Exit code of report](#exit-code-of-report). |
| `--force` | Replace report files that already exist. Without it, toledot refuses. |

### Time format

A time must say its UTC offset, either `Z` for UTC or an offset such as `-06:00`:

```shell
toledot report dc01-events.jsonl -o report --since 2026-11-03T14:00:00Z --until 2026-11-04T08:00:00-06:00
```

A time with no offset, such as `2026-11-03T14:00:00` or a bare date, is refused with exit code `2`. Read on another computer, it would mean another moment. A time that falls outside the years 1 to 9999 once converted to UTC is refused the same way, also with exit code `2`. toledot converts every time to UTC. Every time in a report is UTC.

`--since` must be earlier than `--until`. Otherwise toledot stops with exit code `2`.

The window applies to changes and notices. Logon events from before `--since` are still used to say where a session came from.

### Whole logs

Some inputs are complete logs, such as a `wevtutil epl` export with no query. Others hold chosen events only, such as the file the collector writes by default. Record numbers in a complete log run without gaps, apart from the records that were overwritten before the first one. Record numbers in a filtered export have gaps by design.

toledot cannot tell the two apart from a native export or an XML, JSON, or CSV file. It marks such a file's scope `unknown` and reports the absent record numbers in the coverage table. It does not count them as missing events, but it cannot count them as expected either, so the account is not confirmed. A collection file states its own scope. A file written with `-All` holds whole logs, and a file written by default holds chosen events only.

Pass `--whole-logs` when you know that every input file is a whole log. toledot then marks every log from such a file `unfiltered`, and absent record numbers make the account incomplete. `--whole-logs` affects only inputs that do not state their scope. A collection file's own statement wins, so a file written by default stays `filtered` even with `--whole-logs`. See [Reports and output](output.md#coverage).

### Times without an offset

Event Viewer CSV and some `Get-WinEvent` CSV files write times in local time with no offset, for example `11/10/2026 8:15:03 PM`. toledot will not guess an offset. It stops with exit code `3` and says which option to pass.

```shell
toledot report viewer.csv -o report --local-offset -06:00 --date-order month-first
```

`--local-offset` takes a sign, hours, and minutes: `-06:00`, `+05:30`. The largest offset is `+14:00` or `-14:00`. toledot accepts a leading minus sign after the option name, so `--local-offset -06:00` works. The form `--local-offset=-06:00` works too.

`--date-order` is needed only when the first two numbers of a date are both 12 or less and differ, such as `03/04/2026`. toledot refuses to read such a date without it.

One fixed offset is wrong across a daylight saving change. If an export spans one, export again with ISO 8601 times. [Input formats](formats.md#csv) shows how.

### Input

toledot hashes and identifies every file before it reads any of them, so a file it cannot use stops the run early. It refuses:

- A file it cannot read, or an empty file. A filename that is not valid UTF-8 shows in messages and reports with escapes such as `\xff`.
- A file in none of the five [formats](formats.md).
- Two files with the same contents, even under different names. The error names both. Give each file once, so one event is not counted twice.
- Two files with the same name, even from different folders, such as `a/events.jsonl` and `b/events.jsonl`. A citation in the report names a file and a position, so the name has to identify one file. The error gives the name; rename one file and run again. The check compares the names as the report shows them, so a file whose name holds a byte that is not UTF-8 (shown as `\xff`) also clashes with a file whose name holds those four characters. The same goes for a name with an invisible character, such as a zero-width space, shown as `\u200b`.

A record that cannot be read does not stop the run. toledot lists it as a problem in the report, and the account is incomplete. A file that fails as a whole before its first record is an error and stops the run.

### Output files

`toledot report` writes the formats you choose with `--format`, then `toledot-manifest.json`, into the output folder:

| File | Format |
| --- | --- |
| `toledot-report.json` | Machine-readable report. See [Reports and output](output.md). |
| `toledot-report.md` | Markdown report for pull requests and tickets. |
| `toledot-report.html` | Self-contained web page. Open it in any browser. |
| `toledot-changes.csv` | One row per detail of each change. |
| `toledot-manifest.json` | The size and SHA-256 of every file listed and of every input. Written last. |

Files are written in that order whatever order you give to `--format`. They are readable only by your user account on Linux and macOS. Without `--force`, toledot never replaces an existing file, even one created while it runs. With or without `--force`, toledot refuses to write a report file that is the same file as one of the inputs, however the path is spelled and through any symbolic or hard link, and it changes nothing. With `--force`, it moves the old files aside first and puts them back if anything fails, so the folder holds either the old set or the new set.

Run one toledot at a time per output folder. Only a crash or power loss while writing can leave a partial file, a mix of old and new files, or `.toledot-old-*` backup files. The manifest lists the size and SHA-256 of every file from its run, so either case is detectable. See [Reports and output](output.md#manifest).

### Repeatable reports

A report records when it was generated. By default that is the clock. Set the environment variable `SOURCE_DATE_EPOCH` to a whole number of seconds since 1970-01-01 UTC, and toledot uses that time instead. The same inputs and options then give byte-for-byte identical files.

```shell
SOURCE_DATE_EPOCH=1793000000 toledot report dc01-events.jsonl -o report
```

A value that is not a whole number of seconds is ignored, and toledot uses the clock.

### Exit code of report

toledot checks how far the input shows the account to be whole. The result is one of three levels, and `--fail-on` says which levels make the exit code `1`. toledot writes the reports first.

| Level | Meaning |
| --- | --- |
| `complete` | The input gives evidence that nothing is missing. No notice, problem, or missing event is found, and every log can be checked. |
| `unconfirmed` | Nothing shows events missing, but the input cannot show that none are. For example, a log with absent record numbers and an unknown scope, or an export with no record numbers. |
| `incomplete` | Events are known or likely to be missing. |

| `--fail-on` | Exit code 1 when the account is |
| --- | --- |
| `unconfirmed` (default) | `unconfirmed` or `incomplete`. |
| `incomplete` | `incomplete` only. |
| `never` | Never. The run exits with `0` when it completes. |

The account is `incomplete` when any of these is true:

- A notice with severity `warning` exists: a cleared log, dropped events, a full log, a changed audit policy, or a clock change that is not routine. See [Notices](output.md#notices).
- A problem exists: a record or file that could not be read, or two copies of one record that disagree.
- A log with scope `unfiltered` has absent record numbers.
- A collector found that a log no longer reaches back as far as it asked.

[Reports and output](output.md#what-complete-means) has the full rules.

## collect

```shell
toledot collect --server SERVER -o FILE [options]
```

Runs the packaged collector on a domain controller over PowerShell remoting and writes the collection file. Needs the `live` extra. See [Collecting events](collecting.md#remote-collection) for requirements, security settings, and secret providers.

| Option | Meaning |
| --- | --- |
| `--server` | The controller's fully qualified DNS name, such as `dc01.corp.example`. Required. An IP address or a bare host name is refused. |
| `--auth` | `kerberos` (default), `negotiate`, or `ntlm`. No other method is offered. |
| `--username` | `DOMAIN\user` or `user@domain.example`. A name with no domain is refused. |
| `--secret` | A reference to where the password is kept: `env:NAME`, `file:PATH`, `keyring:SERVICE/USER`, `vault:MOUNT/PATH#FIELD`, `aws:SECRET_ID[#FIELD]`, or `azure:VAULT/NAME`. Never the password itself. |
| `--transport` | `https` (default) or `http`. HTTP is used only with message encryption. |
| `--port` | Default: 5986 for `https`, 5985 for `http`. |
| `--ca-file` | A PEM file of certificate authorities to verify the HTTPS certificate against. Applies to `https` only. |
| `--since`, `--until` | The period to collect, in the [time format](#time-format). |
| `--days` | Collect the last N days, from 1 to 3650. Default: 7. Ignored when `--since` is given. |
| `--channel` | A log to read. Repeat the option for more. Default: `Security` and `System`. |
| `--all` | Collect every event in the period, not only the ones toledot reads. The file then says it holds whole logs. |
| `--timeout` | Stop when the collector sends nothing for this many seconds, from 1 to 86400. Default: 600. |
| `-o`, `--output` | The collection file to write. Required. |
| `--force` | Replace an existing file. |

`--username` and `--secret` go together. Give both, or leave both out to use the current Kerberos ticket. `--auth ntlm` always needs both. toledot checks the server name, the user name, and these pairings before it reads the secret or makes a connection. A pairing that does not fit exits with code `2`.

A missing `live` extra, a failed connection, a failed login, an unreadable secret, a collection that does not match its end line, or an existing output file stops the run with exit code `3`. A log the collector could not read does not stop it. toledot prints each such gap as a `not read:` line, and the file records it. The command prints the `toledot report` command to run next.

## collector

```shell
toledot collector [-o FILE] [--force]
```

Writes `Collect-ToledotEvents.ps1`, the read-only PowerShell collector. The default output is `Collect-ToledotEvents.ps1` in the current folder. The command creates the folder if needed, never replaces an existing file unless you give `--force`, and prints the command that runs the script. See [Collecting events](collecting.md#on-each-domain-controller).

## events

```shell
toledot events
```

Lists every event toledot understands, one per line: the log, the event ID, the category, and the title. An event whose catalog entry could not be fully confirmed from Microsoft documentation ends with `[partly inferred; see the catalog notes]`. See [Limitations](limitations.md#the-event-catalog).

## schema

```shell
toledot schema {report|events|manifest}
```

Prints a JSON Schema for the installed version, with no network access. `report` is the report, `events` is the [collection file](formats.md#the-toledot-collection-file), and `manifest` is the manifest. See [Reports and output](output.md#json-schemas).

## example

```shell
toledot example DIR [--force]
```

Writes `dc01-events.jsonl` and `dc02-events.jsonl` into the folder, creating it if needed, and prints the `toledot report` command that uses them. The data is synthetic and describes the reserved domain `corp.example`. Without `--force`, toledot refuses to replace existing files.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `toledot report`, the account did not reach the `--fail-on` level, which for the default means it is complete. Also `--help` and `--version`. |
| `1` | `toledot report` wrote its reports, and the account reached the level that `--fail-on` names: by default, it is not shown to be complete. |
| `2` | The command was used incorrectly. For example, an option is unknown or missing, a format name is unknown, a time has no UTC offset, a time is outside the years 1 to 9999, `--since` is not before `--until`, options that must go together do not, or `toledot` is run with no command. |
| `3` | An input, output, or collection problem: a missing, empty, or unreadable file, a file in no known format, a duplicate input, a report file that already exists, or a failed collection. This includes a bad `--server` or `--username` for `toledot collect`. |
| `4` | An internal error in toledot. This is a bug. Please report it. |

Exit code `1` never means the tool failed. It means the account it wrote is not shown to be complete, so read its Completeness section.

## Use in a pipeline

`toledot report` needs no network access and no secrets, so it runs anywhere Python does.

PowerShell:

```powershell
toledot report .\dc01-events.jsonl .\dc02-events.jsonl -o .\report
switch ($LASTEXITCODE) {
    0 { "Account complete." }
    1 { Write-Warning "Account not shown to be complete; see .\report\toledot-report.html" }
    default { throw "toledot failed with exit code $LASTEXITCODE" }
}
```

Shell:

```shell
toledot report dc01-events.jsonl dc02-events.jsonl -o report || test $? -eq 1
```

Collect remotely on a schedule by giving `toledot collect` a secret reference that your scheduler or secret store fills in, for example `--secret env:TOLEDOT_PASSWORD`. Never put the password on the command line.
