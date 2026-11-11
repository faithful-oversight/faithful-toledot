# toledot

**AD Change Narrative.** Turns exported Active Directory change events into a plain-language account of who changed what, when, and from where. It says plainly where that account is incomplete.

[![CI](https://github.com/faithful-oversight/faithful-toledot/actions/workflows/ci.yml/badge.svg)](https://github.com/faithful-oversight/faithful-toledot/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: first release.** toledot reads exported logs end to end and is tested on synthetic data. The two collectors, the PowerShell script and `toledot collect`, have not yet been run against a real domain controller or a real WinRM endpoint. Treat the first runs in your environment as a pilot. See [Limitations](docs/limitations.md).

## What it does

When someone asks `who added that account to Domain Admins?`, the answer sits in the Security logs of your domain controllers, spread over thousands of events. toledot reads those logs and writes the answer in sentences:

> CORP\svc_provision (S-1-5-21-1111111111-2222222222-3333333333-1150) created the user account CORP\dana.whitfield (S-1-5-21-1111111111-2222222222-3333333333-1207).
>
> Session 0x2a51c began at 2026-11-02 08:05:00 UTC as Network from 198.51.100.20 port 49731.

toledot:

- Reads event logs exported from domain controllers: native `.evtx` files, `wevtutil` and Event Viewer XML, `Get-WinEvent` JSON and CSV, and Event Viewer CSV.
- Turns each change event into one change with an actor, a target, the values that changed, and the logon session it came from. It joins the per-value directory events (5136) that belong to one modification.
- Links each change to the logon event of the session that made it, and says why when it cannot.
- Says how much to trust the account. It reports cleared logs, dropped events, record numbers that are absent from a log given as complete, and logs that no longer reach back as far as you asked. It also says when an input cannot show whether events are missing.
- Writes one report in four forms: JSON, Markdown, HTML, and CSV, plus a manifest with the SHA-256 of every file.
- Lists every input file with its SHA-256, and every change with the event record that proves it.

## What it will not do

- Monitor or alert in real time. toledot reads files after the fact.
- Judge whether a change was authorized. It reports what happened, not whether it should have.
- See what the logs did not record. A change that Windows did not audit is not in the account. See [Limitations](docs/limitations.md#what-must-be-audited).
- Change anything. toledot is read-only, on your files and on your domain controllers.

## About the name

*toledot* (toh-leh-DOHT). Hebrew: an account of what came from what, as in the genealogical records of Genesis.

## Install

toledot needs Python 3.11 or newer. Reading files needs no other packages.

```shell
pipx install faithful-toledot
```

Remote collection needs the `live` extra. Each secret provider has its own extra:

| Extra | Adds | Needed for |
| --- | --- | --- |
| `live` | `pypsrp` | `toledot collect` |
| `keyring` | `keyring` | `--secret keyring:...` |
| `vault` | `hvac` | `--secret vault:...` |
| `aws` | `boto3` | `--secret aws:...` |
| `azure` | `azure-identity`, `azure-keyvault-secrets` | `--secret azure:...` |

```shell
pipx install "faithful-toledot[live]"
pipx install "faithful-toledot[live,vault]"
```

Until the first release is on PyPI, install the wheel file from a release, or work from source as [CONTRIBUTING.md](CONTRIBUTING.md) describes.

## Quick start

```shell
pipx install faithful-toledot
toledot example ./toledot-demo
toledot report ./toledot-demo/dc01-events.jsonl ./toledot-demo/dc02-events.jsonl -o ./toledot-demo/report
```

Open `./toledot-demo/report/toledot-report.html` in any browser. The example describes a made-up domain, `corp.example`, with two domain controllers. It holds routine account work, a change to a privileged group, and a cleared log.

toledot exits with code `1` here, because the account is incomplete: one log was cleared and one log no longer reaches back as far as the collection asked. That is the expected result. Add `--fail-on never` to see exit code `0`. The same reports are committed in [examples/corp-example](examples/corp-example/).

The [Quickstart](docs/quickstart.md) walks through the output and then shows how to use your own logs.

## Get your logs

You can get events into toledot in three ways:

1. **Run the PowerShell collector on a domain controller.** `toledot collector -o Collect-ToledotEvents.ps1` writes a read-only script. Run it in an elevated session on the controller. It writes one collection file.
2. **Collect remotely.** `toledot collect` runs the same script on a controller over PowerShell remoting (WinRM) and writes the same file.
3. **Export the logs yourself** with Event Viewer, `wevtutil`, or `Get-WinEvent`.

The collectors record facts about each log, and what they could not read, so the account can say where it is incomplete. Exports made by hand carry less. [Input formats](docs/formats.md) shows what each one keeps and loses.

## Outputs

| File | For |
| --- | --- |
| `toledot-report.html` | People. One self-contained page that works offline, follows the light or dark setting, and prints cleanly. |
| `toledot-report.md` | Pull requests, tickets, and change records. |
| `toledot-report.json` | Automation. Follows a published, versioned [JSON Schema](src/faithful_toledot/schema/report-v1.schema.json). |
| `toledot-changes.csv` | Spreadsheets. One row per detail of each change. Protected against formula injection. |
| `toledot-manifest.json` | Evidence handling. The size and SHA-256 of every other file and of every input, written last. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, and the account is complete, or the level you chose with `--fail-on` was not reached. |
| `1` | `toledot report` wrote its reports, but the account is not shown to be complete. It is either incomplete (events are known or likely to be missing) or not confirmed (nothing shows events missing, but the input cannot show that none are). |
| `2` | The command was used incorrectly. |
| `3` | An input, output, or collection problem. |
| `4` | An internal error in toledot. This is a bug. |

## Design goals

- **Read-only.** The tool never changes the systems it examines. The collector only reads logs.
- **Offline first.** `toledot report` reads files and writes reports. It never touches the network. Only the optional `toledot collect` command uses the network, and only when you run it.
- **Explicit unknowns.** Every report states what the tool could not see or verify. A gap is never left out to make a report look clean.
- **Traceable findings.** Every change points back to its source records, by file and position, and every input file is recorded with its SHA-256.
- **Safe output.** Reports escape every input value, and the HTML page cannot run scripts or load anything.
- **Synthetic test data only.** Fixtures are hand-made or generated. No real organization's data is ever committed.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Command reference](docs/usage.md)
- [Input formats](docs/formats.md)
- [Collecting events](docs/collecting.md)
- [Reports and output](docs/output.md)
- [Limitations](docs/limitations.md)
- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md)
- [Releasing](docs/releasing.md) and [decision records](docs/adr/)

## Security

Please do not report security problems in public issues. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first.

## License

Copyright 2026 Faithful Oversight, LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
