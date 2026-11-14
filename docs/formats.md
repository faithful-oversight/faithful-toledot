# Input formats

toledot reads five formats. It picks the format from the first bytes of each file, never from its name. A file named `events.csv` that holds XML is read as XML.

| Format | How you get it | Record numbers | Computer and log | Field names | Times |
| --- | --- | --- | --- | --- | --- |
| [Native `.evtx`](#native-evtx) | `wevtutil epl` | Yes | Yes | Yes | UTC, to 100 ns |
| [Event XML](#event-xml) | `wevtutil qe /f:xml`, Event Viewer, `Get-WinEvent ... ToXml()` | Yes | Yes | Yes | UTC, to 100 ns |
| [Get-WinEvent JSON](#get-winevent-json) | `Get-WinEvent \| ConvertTo-Json` | If exported | Yes | From toledot's catalog, by position | As exported |
| [CSV](#csv) | `Get-WinEvent \| Export-Csv`, Event Viewer "Save as CSV" | `Export-Csv` only | `Export-Csv` only | Recovered from the English message text | `Export-Csv`: as exported. Event Viewer: local, no offset |
| [toledot collection file](#the-toledot-collection-file) | `toledot collector`, `toledot collect` | Yes | Yes | Yes | UTC, to 100 ns |

Use the native `.evtx` file or the collection file when you can. They keep everything the event log holds. The other formats are conveniences, and each one loses something, as the sections below say.

Run the examples below on a domain controller in an elevated session. Reading the Security log needs an elevated session or membership of the **Event Log Readers** group, as the collector's own help text says.

## Complete logs and filtered exports

toledot checks record numbers to find missing events. That works only for a whole log. A filtered export has gaps by design. toledot cannot see from the file whether a native export, XML, JSON, or CSV file is whole or filtered. If you give it a whole log, add `--whole-logs`. See [Command reference](usage.md#whole-logs).

A collection file states its own scope, so toledot knows. For an input of unknown scope with absent record numbers, toledot calls the account not confirmed.

## Native evtx

The log in its own binary form. toledot reads it with the Python standard library only. It decodes each record's binary XML itself and does not use Windows.

Export a whole log:

```shell
wevtutil epl Security C:\Temp\dc01-security.evtx
```

Export chosen events with a query. The result is a filtered export:

```shell
wevtutil epl Security C:\Temp\dc01-groups.evtx "/q:*[System[(EventID=4728 or EventID=4729)]]"
```

Do not copy `Security.evtx` from `C:\Windows\System32\winevt\Logs` while Windows is running. Windows is still writing to it. toledot still reads the records of such a copy, but it reports a checksum problem, and the account is incomplete.

**What it loses.** Nothing the event holds. Every field, record number, computer name, and time is kept.

**What toledot checks.** toledot checks every size and offset before it uses it. It reports each of these as a problem and keeps reading where it can:

- A file header or chunk header checksum that does not match, a chunk with a bad header, or a record that cannot be decoded.
- A log that was not closed cleanly (the dirty flag), a chunk count that differs from the chunks present, or a file that ends in a partial chunk.
- A chunk that holds a different number of records than its header says.
- An empty chunk in the middle of the log, which means something zeroed part of it.

A file that is not an `.evtx` file, or has an impossible header, is refused with exit code `3`.

## Event XML

Windows event XML in the standard event schema. These shapes work:

- `wevtutil qe Security /f:xml`: a bare sequence of `<Event>` elements with no root element.
- `wevtutil qe Security /f:xml /e:Events`: the same inside an `<Events>` root.
- Event Viewer, **Save All Events As**, with the type XML. The `RenderingInfo` inside each event is ignored.
- `Get-WinEvent | ForEach-Object { $_.ToXml() }`, one event per line or joined together.

Export a whole log:

```shell
wevtutil qe Security /f:xml /e:Events > C:\Temp\dc01-security.xml
```

Export chosen events from PowerShell:

```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4728 or EventID=4729)]]' |
  ForEach-Object { $_.ToXml() } |
  Set-Content -Encoding UTF8 C:\Temp\dc01-groups.xml
```

toledot reads UTF-8, with or without a byte order mark, and UTF-16 with a byte order mark. It decodes strictly. A file in another encoding stops with the error `is not valid UTF-8 text`. If that happens, export again as `.evtx`, or write the file with `-Encoding UTF8`.

**What it loses.** Nothing the event holds, apart from Event Viewer's rendered text. Times in Windows XML are UTC.

**What toledot refuses.** A `DOCTYPE` or an entity declaration anywhere in the file is an error, in any encoding. A second XML declaration in the middle of the file, as from two exports appended together, stops the read there, and toledot reports it as a problem. Pass two exports as two files.

**Problems.** A file that stops being well-formed after its first event, such as a truncated export, yields one problem, and keeps the events before it. An event with no `EventID`, time, computer, channel, or provider name is a problem for that event only.

## Get-WinEvent JSON

A JSON array of event objects, one event object, or JSON Lines with one event object per line.

Export a whole log as one array:

```powershell
Get-WinEvent -LogName Security | ConvertTo-Json -Depth 4 |
  Set-Content -Encoding UTF8 C:\Temp\dc01-security.json
```

Export as JSON Lines, which streams and has no size limit:

```powershell
Get-WinEvent -LogName Security |
  ForEach-Object { $_ | ConvertTo-Json -Depth 4 -Compress } |
  Set-Content -Encoding UTF8 C:\Temp\dc01-security.jsonl
```

Pass `-Depth 4` at least. With too little depth, PowerShell replaces nested values with their text.

A single JSON document larger than 256 MiB is refused. toledot advises JSON Lines or `.evtx` instead.

toledot accepts two shapes of event object, told apart by their keys: a PowerShell `EventLogRecord` as `ConvertTo-Json` writes it, and a "named data" shape with an `EventData` object, for other exporters. The module documentation of `faithful_toledot.formats.json` lists every accepted key. An event with two spellings of one field, or with neither shape, is a problem for that record. If the very first record matches neither shape, the file is refused.

**What it loses.**

- **Field names.** `Get-WinEvent` JSON holds the values as a list with no names. toledot names them by position from its [event catalog](limitations.md#the-event-catalog), using the event ID, the event version, and the number of values. For an event the catalog does not know, or when the count does not fit, the values are named `param1`, `param2`, and so on, and toledot cannot describe the event. A wrong count makes the event a problem.
- **Hex values.** JSON keeps the value, not how Windows wrote it. A logon ID such as `0x3e7` arrives as the decimal number `999`. toledot understands both forms when it links sessions, but the report shows the logon ID as it came, in decimal.
- **Time precision.** Windows PowerShell 5.1 writes times as `\/Date(1762740903123)\/`, which keeps milliseconds. The 100 ns ticks of the original event are lost. PowerShell 7 writes ISO 8601 strings.
- **Record numbers** are present only if the export includes `RecordId`, which `Get-WinEvent` does.

toledot refuses an ISO 8601 time with no offset unless you pass `--local-offset`.

## CSV

Two layouts. Both keep the rendered English message and not the event's fields, so toledot recovers the fields from the message text. Header names are English and exact. An export from a machine with another display language is refused with a message that says so.

### Get-WinEvent and Export-CSV

```powershell
Get-WinEvent -LogName Security |
  Select-Object Id, Version, RecordId, ProviderName, LogName, MachineName, Message,
    @{ Name = 'TimeCreated'; Expression = { $_.TimeCreated.ToString('o') } } |
  Export-Csv -Path C:\Temp\dc01-security.csv -NoTypeInformation -Encoding UTF8
```

The header must have `Message`, `Id`, `ProviderName`, `LogName`, `MachineName`, and `TimeCreated`. `Version` and `RecordId` are used when present. Other columns are ignored. A first line that starts with `#TYPE`, which Windows PowerShell 5.1 writes without `-NoTypeInformation`, is skipped.

The command writes `TimeCreated` as an ISO 8601 string with an offset, so toledot needs no `--local-offset`. Without the calculated property, `Export-Csv` writes a local time with no offset, and toledot stops and asks for `--local-offset`. One fixed offset is wrong across a daylight saving change, which is why the preceding command avoids it.

### Event Viewer: Save All Events As CSV

Open the log in Event Viewer, choose **Save All Events As**, and choose CSV. The file has the columns `Level`, `Date and Time`, `Source`, `Event ID`, and `Task Category`, then the message.

```shell
toledot report viewer.csv -o report --local-offset -06:00 --date-order month-first
```

**What it loses.**

- **No record numbers.** toledot cannot check for missing events. The coverage table shows the log as `unnumbered`, and the account is not confirmed.
- **No computer name and no log name.** Both are empty. toledot treats every Event Viewer CSV file as coming from one computer, so do not mix files from different computers in one run. toledot cannot tell their sessions apart.
- **Display text only.** `Source` holds the provider's display text, such as `Microsoft Windows security auditing.`, not the provider name. toledot matches it to the provider name for the events it knows.
- **Times with no offset.** The file writes local times such as `11/10/2026 8:15:03 PM`. You must pass `--local-offset`. When the first two numbers of a date are both 12 or less and differ, you must also pass `--date-order`. A fixed offset is wrong across a daylight saving change. The times carry whole seconds only.

### How fields are recovered from the message

Windows security messages hold a label and a value on each line, grouped in sections such as `Subject:` and `Member:`. toledot reads an unindented line that ends in a colon as a section. It reads an indented line as a field, with the label before the first colon. A deeper-indented line directly after a field continues its value, so a list of privileges becomes one value.

toledot maps `Section/Label`, such as `Subject/Security ID`, to the event's field name using its catalog. A label with no mapping keeps the `Section/Label` text as its name, so nothing is lost. A message with no field lines at all, for example because the tabs were lost in the export, is a problem for that row.

A genuine Windows message never repeats a label inside a section, or a section header. When a mapped `Section/Label` or a section header appears twice in one message, toledot makes that row a problem ("the message is ambiguous") and uses none of its fields. It does not choose the first or the last copy. A directory attribute such as `info` or `description` can hold line breaks, so a value can imitate the message's own labels and sections. A message-only CSV is therefore weaker evidence than `.evtx`, XML, JSON, or a collection file, which keep each field apart. toledot cannot detect an imitated label that the genuine message does not carry at all. Prefer the other formats when the log may hold values written by someone you do not trust.

Because of this recovery, a change built from a CSV can show some details under a label such as `Subject/Logon ID` where an XML export shows the field name. The facts are the same.

### CSV limits

A field is at most 131,072 characters, a physical line at most 4 MiB, a header at most 256 columns, and a message at most 4,096 lines. A NUL character is refused. A duplicate header name stops the read. A bad row, such as one with the wrong number of fields, is a problem and toledot reads the next row. Broken quoting stops the read with one problem, because the rows after it cannot be told apart.

## The toledot collection file

The PowerShell collector and `toledot collect` write this format. Its filename ends in `.jsonl` by convention. toledot detects it by its first bytes, so the name does not matter. `toledot schema events` prints its JSON Schema. Every line of the file matches that schema.

A collection file is JSON Lines in UTF-8, with `\n` line ends. It has three kinds of line, in this order:

1. One **header** line.
2. Zero or more **event** lines.
3. One **trailer** line.

The PowerShell collector writes pure ASCII. It escapes every character outside printable ASCII as `\uXXXX`, so the file reads the same whatever code page a tool assumes.

### Header

The first line starts, byte for byte, with `{"toledot_events":`. That marker is how toledot knows the file. Here is a header, shown on several lines for reading. In the file it is one line. The `event_ids` list is shortened here. A real header lists every event ID toledot asks for.

```json
{
  "toledot_events": 1,
  "collector": {"name": "Collect-ToledotEvents.ps1", "version": "0.1.0", "method": "powershell"},
  "collected_at": "2026-11-09T08:00:00.0000000Z",
  "computer": "DC01.corp.example",
  "operator": "CORP\\auditor",
  "query": {
    "channels": ["Security"],
    "event_ids": [4720, 4728, 5136],
    "since": "2026-11-02T00:00:00.0000000Z",
    "until": null
  },
  "logs": [
    {
      "channel": "Security",
      "oldest_record_id": 48211,
      "oldest_time": "2026-10-25T08:00:00.0000000Z",
      "newest_record_id": 48700,
      "record_count": 490,
      "max_size_bytes": 134217728,
      "mode": "circular"
    }
  ]
}
```

| Property | Meaning |
| --- | --- |
| `toledot_events` | The format version. Always `1`. |
| `collector` | The `name` and `version` of the collector, and its `method`: `powershell` for a script run on the controller, or `psrp` for a run through `toledot collect`. |
| `collected_at` | When the collector ran. A UTC time. |
| `computer` | The computer's name. |
| `operator` | The account that ran the collector. Optional. |
| `query.channels` | The logs the collector read. At most 16. |
| `query.event_ids` | The event IDs the collector asked for. An empty list means every event in the period, so the file holds whole logs. A non-empty list means chosen events only. |
| `query.since`, `query.until` | The period asked for, or `null`. |
| `logs` | Each log as it stood when it was read. At most 16. |

Each entry in `logs` has the log's `channel`, the `oldest_record_id` and `oldest_time` of the oldest record still in the log, the `newest_record_id`, the `record_count`, the `max_size_bytes`, and the `mode`: `circular`, `retain`, `autobackup`, or `unknown`. A value the collector could not read is `null`. toledot uses the oldest record to say when a log no longer reaches back as far as the collection asked. See [Reports and output](output.md#coverage).

A time in a collection file is a UTC time with a `Z` suffix and up to seven fraction digits: `2026-11-03T14:00:00.1234567Z`.

### Event lines

Each event is one line with exactly these properties:

```json
{"record_id":48212,"event_id":4720,"version":0,"time":"2026-11-02T08:06:00.0000000Z","computer":"DC01.corp.example","channel":"Security","provider":"Microsoft-Windows-Security-Auditing","system":{},"data":{"TargetUserName":"dana.whitfield","TargetDomainName":"CORP"}}
```

| Property | Meaning |
| --- | --- |
| `record_id` | The log's record number. |
| `event_id` | The event ID, 0 to 65535. |
| `version` | The event's schema version, 0 to 255. |
| `time` | When the event was recorded. A UTC time. |
| `computer`, `channel`, `provider` | As Windows recorded them. |
| `system` | Other `System` fields, by name, as text: `Keywords`, `Level`, `Task`, `Opcode`, `ActivityID`, `ProcessID`, `ThreadID`, and `UserID`. |
| `data` | The `EventData` (or `UserData`) fields, in order, each exactly as the event's XML holds it, as text. `%%1794` stays `%%1794` and a SID stays a SID. |

A repeated field name keeps the first under its name and stores later ones as `name#2`, `name#3`. A `Data` element with no name is called `param` followed by its position among all `Data` elements of the event, named or not (`param2` is the second one). The native, XML, and collection readers all number them this way. The collector does not copy the `RelatedActivityID` attribute that the XML and native readers keep in `system`; toledot does not use it.

### Trailer

The last line says the file is whole:

```json
{"end":true,"events":5,"sha256":"cd029eaa63a443d4d53705a0b713c1683372bc67cbcb2cedf88a2cbbdcfda3c3","gaps":[]}
```

| Property | Meaning |
| --- | --- |
| `end` | Always `true`. |
| `events` | How many event lines the file holds. |
| `sha256` | The SHA-256 of every byte before the trailer line. That is the header line and every event line, each with its `\n`. |
| `gaps` | What the collector could not read, and why. Each gap has an `area` and a `reason`. |

A gap is a sentence the collector wrote, such as the area `the Security log` and a reason from Windows. The collector records a log it cannot read as a gap and carries on. It does not fail. The list holds at most 1000 gaps. If more fail, the collector ends the list with one gap that counts the rest, and a reader that meets a longer list keeps the first 1000, reports the rest as one problem, and still checks the count and the hash.

The hash detects a file that was cut short or damaged. It does not prove who wrote the file. Anyone who edits a file can recompute the hash. See the [threat model](threat-model.md).

### How toledot reads it

toledot reads the file line by line, but it keeps every change it builds in memory until the reports are written, so memory grows with the number of changes (see [Size limits](limitations.md#size-and-memory)). It reports each of these as a problem, and the account is incomplete:

- A file that ends without its trailer. It was cut short, or collection did not finish. Every event before the cut is still read.
- A trailer whose event count or SHA-256 does not match what toledot read.
- A line that is not a valid event. toledot skips it and reads the next line.
- A line longer than 8 MiB. toledot stops reading there.
- Anything after the trailer.
- Every entry in `gaps`, worded as `The collector could not read AREA: REASON`.

A first line that is not a valid header stops the run with exit code `3`.

toledot is strict about what a line holds: a repeated property name, `NaN`, an unpaired surrogate, nesting deeper than 8 levels, or more than 256 fields is refused. A name is at most 255 characters, and a value at most 1 MiB.

[ADR 4](adr/0004-collection-file.md) records why the format looks this way.
