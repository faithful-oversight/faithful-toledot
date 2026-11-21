# Architecture

toledot is a command-line tool and a Python library with the same core. Reading files needs one runtime dependency beyond the Python standard library: [faithful-core](https://github.com/faithful-oversight/faithful-core), the shared foundation library of the Faithful Oversight tools, pinned to an exact version. Remote collection and the secret providers use optional dependencies, installed as extras.

```text
domain controller ──► PowerShell collector ──┐
                                             ├──► collection file   header, events, trailer with SHA-256
WinRM ──► toledot collect ───────────────────┘
                                                        │
 .evtx, XML, JSON, CSV exports ─────────────────────────┤
                                                        ▼
                 formats       detect each file's format from its first bytes;
                               a reader yields Event, Problem, and LogFacts items
                                                        │
                                                        ▼
 events catalog ──► correlate  build the Account: changes, notices, coverage, problems
 (data/events.toml)                                     │
                                                        ▼
                 outputs       one report document, rendered as JSON, Markdown, HTML, CSV,
                               plus a manifest
                                                        │
                                                        ▼
                 cli           arguments, file writing, exit codes
```

Both collectors write the same collection file. Nothing after the readers knows which format an event came from.

## The pipeline

1. `pipeline.run` hashes every input file with SHA-256 and detects its format with `formats.detect`. It refuses a file it cannot read, a file in no known format, and two files with the same contents. It does this for every file before it parses any of them.
2. `formats.read` runs the reader for each format. A reader is a function from a file and the read options to a stream of items:
   - `Event`: one Windows event, with its values as text, and a `Source` that says the file and position.
   - `Problem`: a record or part of a file that could not be read. A problem never stops the rest of the file.
   - `LogFacts`: what a collector recorded about a log when it read it. Only the collection file reader yields these.
3. `correlate.build` consumes the streams. It looks each event up in the catalog, files logon events by computer and logon ID, keeps the other events, and counts what it read. It then joins events into changes, links each change to its logon session, and works out coverage. It returns an `Account`.
4. `outputs.build_report` turns the `Account` into one report document, a plain dictionary. The renderers for JSON, Markdown, HTML, and CSV read only that dictionary. `outputs.write_reports` writes the files and a manifest.
5. `cli` prints a summary and returns an exit code.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli` | The command-line interface, exit codes, and the `report`, `events`, `schema`, and `example` commands. |
| `errors` | `ToledotError`, which is faithful-core's `FaithfulError`, and the error classes toledot uses: `InputError`, `CollectionError`, `UsageError`, and `OutputError`. |
| `events` | The one shape every format is read into: `Event`, `Problem`, `LogFacts`, `Source`, and `ReadOptions`. |
| `formats` | One reader for each input format: `evtx`, `xml`, `json`, `csv`, and `bundle` (the collection file). `detect` picks between them. |
| `catalog` | Load and strictly validate `data/events.toml`. It says what each event means: field names, roles, labels, `%%` codes, logon types, account control flags, and well-known SIDs. |
| `pipeline` | Hash and detect each file, then read them all and build the account. |
| `correlate` | Turn events into the `Account`. No file access and no output. |
| `changes` | The records `correlate` builds: `Account`, `Change`, `Party`, `Origin`, `Detail`, `Notice`, and `Coverage`. |
| `narrative` | The plain sentences for changes, origins, and coverage. |
| `outputs` | Build the report document, render each format, and write the files all together. |
| `collect` | `toledot collect` and `toledot collector`: the collection file's line checks, the script's parameters, and the commands. |
| `example` | The synthetic collection files for the `example` command and tests. |
| `data` | The event catalog `events.toml` and the PowerShell collector `Collect-ToledotEvents.ps1`. |
| `schema` | JSON Schemas for the report, the collection file, and the manifest. |

## The event catalog

`data/events.toml` is the one place that knows what an event means. It holds each event's field names for each schema version, which fields play which role (who did it, to what, from where), the label and kind of each changed attribute, and the labels the English message text uses. It also holds the `%%NNNN` codes, the logon types, both account control flag layouts, and the well-known SIDs and RIDs.

Every entry names a source page and carries a `confirmed` flag. `catalog` refuses a catalog that is malformed in any way. It never uses one partly, because a wrong field name in an audit tool is worse than a missing one.

Three things read the catalog:

- The JSON and CSV readers use it to name values that their formats lose, through `ReadOptions`.
- `correlate` uses it to find each role in an event and to word each detail.
- The PowerShell collector asks for exactly the events in the catalog. A test keeps the script's list in step with the catalog.

## The collect package

| Module | Responsibility |
| --- | --- |
| `collect.cli` | Registers `collect` and `collector` and checks their arguments. |
| `collect.remote` | Checks each line the controller sends, and its end line, in a private file. It also builds the script's parameters and the result, and hands the connection to faithful-core. |
| `collect.script` | Names the packaged PowerShell script and reads it through faithful-core. |

Both collection paths run the same script, so there is one format to read and one script to review. See [Collecting events](collecting.md).

## The shared library

faithful-core holds the code that every Faithful Oversight tool needs to behave the same way. toledot uses it for:

- the base error and the exit codes;
- making untrusted text safe for the terminal, CSV, Markdown, and HTML;
- the report time and the way times are written;
- printing that never changes an exit code;
- publishing a set of files all together, without replacing a file the tool reads;
- the checks on `--server` and `--username`, the secret providers, and the redaction of every resolved secret;
- the WinRM connection, its transport rules, and the loop that takes the controller's output.

The library's own pages describe how each of these works. toledot's tests cover them through the commands, and the library's tests cover them directly.

## Rules the design follows

- **Separation.** Readers handle input, `correlate` is logic, and `outputs` handles output. `correlate` never reads files or prints.
- **One shape.** Every format is read into the same `Event`, so nothing after the readers depends on the format.
- **A problem is a result.** A record that cannot be read becomes a `Problem` in the report, and the account is incomplete. It is never skipped silently.
- **Say no more than the events say.** When an event does not record something, the report says so and does not guess. An origin that cannot be linked is `not in the input`, never a guess.
- **One report document.** Every format is rendered from the same document, so the formats cannot disagree.
- **A versioned contract.** The report, the collection file, and the manifest follow published JSON Schemas. See [Reports and output](output.md#json-schemas) for the compatibility promise.
- **No prompts.** The tool never asks questions interactively, so it runs unchanged in scripts and pipelines.
- **Structured exit codes.** `0` success and a complete account, `1` an account not shown to be complete, `2` usage error, `3` input, output, or collection error, and `4` internal error. Any exception that is not a `ToledotError` ends in exit code `4`, with a message that says it is a bug. This keeps a crash apart from a result.
- **Careful output.** Report files are complete before they appear, are never overwritten without `--force`, and are swapped in with rollback on failure. A manifest of file hashes, written last, makes any partial or mixed set detectable.
- **Read-only.** The collector reads event logs and writes only its own file. The tool does not change the systems it examines.
- **Offline analysis.** `toledot report` reads files and writes reports. It never touches the network. Only `toledot collect` does, and only when you run it. [ADR 5](adr/0005-remote-collection.md) records that exception.

## Packaging

- Python package on PyPI: `faithful-toledot`, with the command `toledot`. Its one runtime dependency is `faithful-core`, pinned to an exact version.
- Extras: `live` (`pypsrp`), `keyring`, `vault`, `aws`, and `azure`. See the [README](https://github.com/faithful-oversight/faithful-toledot#install).
- Further formats, such as a standalone executable or a container image, are added only when a decision record justifies them.

## Decisions

Significant decisions are recorded in [architecture decision records](adr/index.md).
