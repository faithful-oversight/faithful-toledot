# Collecting events

toledot can read logs you export yourself. See [Input formats](formats.md). It also has two collectors that write its own [collection file](formats.md#the-toledot-collection-file). The file records facts about each log and what the collector could not read, so the account can say where it is incomplete.

| Collector | Runs | Best for |
| --- | --- | --- |
| PowerShell script | On each domain controller, in an elevated session | Controllers you can run a script on. Nothing but the script and its output file is involved. |
| `toledot collect` | Anywhere that can reach a controller over WinRM | A fast collection with nothing copied to the controller. Needs the `live` extra and a WinRM listener. |

Both run the same script, so there is one format to read and one script to review. Both only read: neither changes a setting, a log, or a directory object.

Run a collector on every domain controller. toledot reports only on the logs it is given, and it shows each computer and log in the [coverage table](output.md#coverage).

## On each domain controller

### What it reads

The script `Collect-ToledotEvents.ps1` reads event logs, nothing else:

- **The Security and System logs**, by default. Use `-Channel` to name other logs, but see the note below.
- **The events toledot understands.** That is the event IDs in toledot's catalog: 82 in the Security log and event 104 (log cleared) in the System log. Run `toledot events` to list them. The script asks for them in ranges, 20 terms to a query, because the event log service refuses a filter with too many terms. It checks every event ID again before it keeps the event.
- **Every event in the period**, with `-All`. The file then says it holds whole logs, so absent record numbers count as missing events.
- **Facts about each log** it reads, as the log stands at that moment: the oldest and newest record numbers, the time of the oldest record, the record count, the maximum size, and whether the log is circular, retained, or set to archive when full.
- **The computer's name and the account that ran the script**, for the file header.

The event IDs include logon, logoff, and authentication events (4624, 4634, 4647, 4648, 4672, 4768, 4769, and 4776). toledot uses the logon events (4624) and logoff events (4634 and 4647) to say where a session came from. It counts the others as context. These can be the most numerous events on a busy controller, so a long period can give a large file.

The catalog covers the Security and System logs only. A log you name with `-Channel` gives no events unless you also give `-All`.

The script looks up the computer's own host name, and the event log service answers its queries. It sends no event data anywhere, and it makes no other network connection.

### Required rights

Run the script in an elevated Windows PowerShell 5.1 or PowerShell 7 session on the controller, or as a member of the **Event Log Readers** group. The script's own help states this: reading the Security log needs an elevated session or membership of Event Log Readers.

The script needs no PowerShell modules beyond what Windows includes. It is pure ASCII, so Windows PowerShell 5.1 reads it the same as PowerShell 7 does.

If the account cannot read a log, the script does not fail. It records a gap. See [How it records facts and gaps](#how-it-records-facts-and-gaps).

### Run it

Write the script from the installed package, then copy it to the controller:

```shell
toledot collector -o Collect-ToledotEvents.ps1
```

On the controller:

```powershell
.\Collect-ToledotEvents.ps1 -OutFile C:\Temp\dc01-events.jsonl -Days 30
```

Read the script before you run it. It is one plain-text file, with its help text at the top. `Get-Help .\Collect-ToledotEvents.ps1 -Detailed` shows that help.

If the execution policy blocks the script, run it for one session only. This does not change the policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Collect-ToledotEvents.ps1 -OutFile C:\Temp\dc01-events.jsonl -Days 30
```

| Parameter | Meaning |
| --- | --- |
| `-OutFile` | The file to write. Required, unless you give `-ToPipeline`. |
| `-Since` | Collect events from this time. Default: `-Days` days ago. |
| `-Until` | Collect events before this time. Default: now. Must be later than `-Since`. |
| `-Days` | Collect the last N days when `-Since` is not given, from 1 to 3650. Default: 7. |
| `-Channel` | The logs to read, from 1 to 16. Default: `Security` and `System`. |
| `-All` | Collect every event in the period, not only the ones toledot understands. |
| `-Force` | Replace `-OutFile` if it exists. Works with `-OutFile` only. |
| `-ToPipeline` | Write the lines to the output stream instead of a file. `toledot collect` uses this. |
| `-Method` | `powershell` (default) or `psrp`. Recorded in the header, so the file says how it was collected. |

Give `-Since` and `-Until` with an offset, for example `-Since '2026-11-03T14:00:00Z'`. PowerShell reads a time with no offset as the computer's local time.

A relative `-OutFile` is resolved against the current PowerShell location, the folder shown at the prompt.

The script prints nothing when it succeeds. Copy the file to the machine where you run `toledot report`, and keep the original with your records.

### How the file is written

The script writes lines as UTF-8 with `\n` line ends to a new temporary file next to `-OutFile`, named `OutFile.RANDOM.part`. It keeps a running SHA-256 of what it writes, and writes the end line last, with the event count, and the hash. Only then does it move the temporary file to the `-OutFile` name.

- Without `-Force`, the move fails if the name is taken, even by a file that appeared after the script started. The script stops with an error and changes nothing.
- With `-Force`, the script replaces the existing file in one step where the file system allows. A failed run therefore never truncates a good file.
- If the script stops partway, no file appears under the `-OutFile` name. When the script fails, it deletes its temporary file, so no partial file is left.
- A file written to the pipeline with `-ToPipeline` has no temporary file. `toledot report` reads the events it holds and reports that the file was cut short. See [Input formats](formats.md#how-toledot-reads-it).

### Why it is read-only

- A test in the repository checks that the script calls only these commands: `Set-StrictMode`, `New-Object`, `Write-Output`, `Get-Date`, `Sort-Object`, `ForEach-Object`, and `Where-Object`. It checks that the script has no `Invoke-Expression`, `Start-Process`, `Remove-Item`, `Set-Content`, or `Out-File`.
- The script reads logs through the .NET event log reader classes (`EventLogConfiguration`, `EventLogSession`, `EventLogQuery`, and `EventLogReader`). Those classes only query.
- Its only write is the file you name.
- It reads each event's XML with DTD processing prohibited and no resolver, so a crafted event cannot make the script fetch or expand anything. A single event is limited to 16,777,216 characters.

### How it records facts and gaps

The header holds the facts about each log: the oldest record, the newest record, the record count, the maximum size, and the log mode. The header also records the period the script asked for.

toledot compares them. When the oldest record in a log is newer than the start of the period asked for, toledot reports that the log no longer reaches back as far as the collection asked. toledot words this as `earlier events had been overwritten and are missing`. A log whose oldest record is number 1 is never reported this way. A log that was cleared or is new can look the same as an overwritten one, because in each case the oldest record is recent. The collector names the computer from DNS, and events name it from the event log. toledot matches a log's facts to the events when the names share their first label and only one computer in the file has that label, so `DC01` and `DC01.corp.example` count as one. The account is incomplete either way.

A log the script cannot read becomes a gap in the end line, not a failure. The script records a gap, with a reason from Windows, when:

- It cannot read a log's size and oldest record.
- A query on a log fails. The script stops reading that log.
- Reading a log stops partway.
- One record cannot be decoded. The script records the record number and goes on to the next.

`toledot report` shows every gap as a problem, so the account is incomplete.

## Remote collection

`toledot collect` runs the same script on a controller over PowerShell remoting, which uses WinRM. toledot sends the script text to the controller, runs it with `-ToPipeline`, and streams the lines back. Nothing is installed on the controller.

```shell
toledot collect --server dc01.corp.example --auth ntlm --username 'CORP\auditor' \
  --secret env:TOLEDOT_PASSWORD --ca-file corp-root-ca.pem --days 30 -o dc01-events.jsonl
```

[Command reference](usage.md#collect) lists every option.

### Prerequisites

Install the `live` extra, which adds `pypsrp`:

```shell
pipx install "faithful-toledot[live]"
```

You also need:

- A WinRM listener on the controller that your machine can reach: TCP **5986** for HTTPS, or **5985** for HTTP with message encryption. toledot does not create or change a listener.
- For HTTPS, a controller certificate that chains to a root you trust and names the `--server` DNS name. Pass the certificate of your internal CA in PEM format with `--ca-file` when the system does not already trust it.
- An account that may open a PowerShell remoting session on the controller. By default, that is a member of Administrators or Remote Management Users.
- The same rights to read the logs as the local script: an administrator, or a member of Event Log Readers.

The account must hold both rights. Microsoft documents both groups. toledot does not ship a just-enough-administration (JEA) configuration, and running the collector through one has not been tested.

On Linux and macOS, Kerberos authentication needs support that the `live` extra does not install. `pypsrp` lists it as its optional `kerberos` extra, which adds `pyspnego[kerberos]`, and it needs the system Kerberos libraries. This has not been tested. If Kerberos fails on Linux or macOS, install that extra into the same environment, for example `pipx inject faithful-toledot "pyspnego[kerberos]"`.

### Security settings

toledot offers no insecure combination.

- **HTTPS is the default**, on port 5986. toledot always verifies the certificate. It must chain to a trusted root, which is the system's roots or the authorities in the `--ca-file` PEM file. No option turns verification off.
- **HTTP**, on port 5985, works only with message encryption required. `pypsrp` then wraps every message with Kerberos, Negotiate, or NTLM encryption. `--ca-file` with `--transport http` is refused.
- **`--server` must be a fully qualified DNS name**, such as `dc01.corp.example`. toledot verifies the certificate against that name, and Kerberos asks for a ticket for it. An IP address or a bare host name would fail verification or weaken it, so toledot refuses both.
- **Authentication is `kerberos` (the default), `negotiate`, or `ntlm`.** None of these sends the password to the server. toledot does not offer Basic or CredSSP. Basic sends the password itself. CredSSP hands the account's reusable credentials to the server, so a compromised controller could keep them. Prefer Kerberos.
- **Names are checked first.** toledot checks `--server`, `--username`, and the pairing of `--username` with `--secret` before it reads a secret or opens a connection. `--username` must be `DOMAIN\user` or `user@domain.example`, with the domain the account belongs to.

Use a dedicated account that has only the rights listed earlier. Prefer a Kerberos ticket or a secret manager to a stored password.

### Secret references

`--secret` takes a reference, never the password. toledot reads the secret when it starts and passes it to the authentication library. It never writes the secret to the output file or to a report.

| Provider | Reference | Extra | Notes |
| --- | --- | --- | --- |
| Environment | `env:NAME` | none | The variable must be set and not empty. |
| File | `file:PATH` | none | The first line of the file, read as UTF-8. A byte order mark is accepted. A file that is not UTF-8 is refused. Keep the file readable only by you. toledot does not check its permissions. |
| Keyring | `keyring:SERVICE/USERNAME` | `keyring` | The operating system keychain entry for that service and username. |
| HashiCorp Vault | `vault:MOUNT/PATH#FIELD` | `vault` | A KV version 2 secret. Uses `VAULT_ADDR` and `VAULT_TOKEN`. `#FIELD` is required. |
| AWS Secrets Manager | `aws:SECRET_ID` or `aws:SECRET_ID#FIELD` | `aws` | Uses the standard AWS credential chain. Without `#FIELD`, the whole secret string is the password. With it, the secret must be JSON and `FIELD` is one key. |
| Azure Key Vault | `azure:VAULT_NAME/SECRET_NAME` | `azure` | Reads `https://VAULT_NAME.vault.azure.net` with `DefaultAzureCredential`. |

A missing provider package produces an error that names the extra to install. An empty secret is refused.

Authentication libraries sometimes put the credential in their own error text. toledot remembers every secret it resolves and removes it, in its plain, URL-encoded, JSON-escaped, and quoted forms, from any error before it prints the error. Errors from Vault, AWS, and Azure name only the type of the exception.

### Timeouts

toledot waits up to 30 seconds to connect. After that, collection has no overall time limit. It has an idle limit instead: if the controller sends no line for `--timeout` seconds (default 600), toledot stops the remote script, deletes the partial file, and fails with exit code `3`.

A query on a very large log can take a while before its first event. If collection stops with an idle error on a healthy controller, raise `--timeout`.

### How the output file is written safely

The lines stream into a private temporary file in the same folder as the output, named `.NAME.RANDOM.part`. toledot checks each line as it arrives. A line must be one line of ASCII text, at most 8 MiB, and the first line must be a toledot header. Nothing may follow the end line.

When the script ends, toledot checks the end line against what arrived: the event count and the SHA-256 of every line before it must match. Only then does it publish the file.

- Without `--force`, toledot puts the file in place only if the name is free, so it never replaces a file, even one that appears while collection runs. toledot also checks at the start and refuses early if the file exists.
- With `--force`, it replaces the file. Where the file system has no hard links, such as FAT, exFAT, and some network shares, toledot creates the output name exclusively and copies the checked file into it. A failed copy removes what it created. A symbolic link at the output name is replaced, not followed.
- On any failure, toledot deletes the temporary file. A partial file is never left behind.
- On Linux and macOS, the file is readable only by your user account.

The check proves that the transfer was whole. It does not check the events. `toledot report` validates every line again, as it does for any file. Treat a file from a controller like any other untrusted input. See the [threat model](threat-model.md).

### What a collection cannot show

- Only the logs on the controller you collected from. Collect from every controller.
- Events that Windows did not audit, and events the log had already overwritten. See [Limitations](limitations.md).
- Anything a compromised controller chooses to hide or invent. The end line proves the file arrived whole, not that the controller told the truth.

## After collecting

```shell
toledot report dc01-events.jsonl dc02-events.jsonl -o report
```

Collection files hold account names, SIDs, and addresses. Treat them as sensitive.
