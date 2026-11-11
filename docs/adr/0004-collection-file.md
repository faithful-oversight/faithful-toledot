# 4. A JSON Lines collection file with a header and a hash trailer

- Status: accepted
- Date: 2026-11-11

## Context

toledot has two collectors. A PowerShell script runs on a domain controller. A remote command runs the same script over the network. Both must feed the same analysis, and both must work on a Security log that holds millions of events.

The file they write has to meet five needs:

- It must stream. A collector cannot hold a month of events in memory, and neither can the reader.
- It must show whether it is whole. A collection that stops at event 400,000 of 900,000 must not look like a complete one.
- It must carry facts about the logs it read, such as the oldest record, so the account can say that a log no longer reached back as far as the collection asked.
- It must record what the collector could not read, so a failure is a gap in the account and not silence.
- It must keep each event as Windows wrote it, field names and values both, because the PowerShell collector runs where Python is not installed and cannot be trusted with interpretation.

Options considered:

- **A native `.evtx` copy.** It keeps everything, but a collector would have to export a log with `wevtutil` and could not add log facts, gaps, or a hash. Copying a live log also gives a file with a failed checksum.
- **A single JSON document.** The reader must hold it whole, and a document cut short is not valid JSON, so every event in it is lost.
- **CSV.** It keeps the rendered message and not the fields, and has no place for log facts or gaps.
- **Windows event XML.** It is verbose, and it has no place for log facts, gaps, or a hash.
- **JSON Lines with a header and a trailer.** Each line stands alone, so a cut file still yields every complete line.

## Decision

- The collection file is JSON Lines in UTF-8, with `\n` line ends. It has one header line, one line for each event, and one trailer line.
- The header starts, byte for byte, with `{"toledot_events":`, so the format is detected from the first bytes and the filename does not matter. It names the collector and its method (`powershell` or `psrp`), says when and on which computer the collection ran, and records the query: the logs, the event IDs asked for, and the period. An empty list of event IDs means the collection holds whole logs. The header also records each log's facts: the oldest and newest record, the time of the oldest record, the record count, the maximum size, and the mode.
- Each event line holds the record number, event ID, version, UTC time, computer, log, and provider, the other `System` fields, and the data fields in order. Every value is text, exactly as the event's XML holds it. The file holds field names, so the readers need no help from the catalog for it.
- The trailer holds the event count, the SHA-256 of every byte before the trailer line, and the gaps: each an `area` and a `reason`. The collector writes the trailer last. A log it cannot read becomes a gap, and collection goes on.
- The PowerShell collector writes pure ASCII. It escapes every character outside printable ASCII as `\uXXXX`, so Windows PowerShell 5.1 and PowerShell 7 write the same bytes whatever the code page.
- The reader checks each line strictly: it refuses repeated property names, `NaN`, unpaired surrogates, nesting deeper than 8 levels, and more than 256 fields. A line is at most 8 MiB. A line that breaks the rules is a problem, and reading goes on at the next line.
- A file that ends without its trailer, a trailer whose count or hash does not match, and every gap in the trailer are problems in the report. The events read before the fault are kept. The account is incomplete.
- The file follows a published, versioned JSON Schema, `events-v1.schema.json`. `toledot schema events` prints it.
- The Python writer in `formats.bundle` exists for the bundled example and for tests. It is the reference for what the collectors emit. The collectors do not use it.

## Consequences

The reader streams, so a file's size is not limited by memory. A file cut short by a full disk, a dropped connection, or a stopped script is detected and still yields its events. A collector that cannot read a log reports a gap that the report shows as a problem.

The PowerShell script and the Python reader are two implementations of one format. Tests keep them in step: the script's JSON writer is compared with Python's JSON parser, its reading of event XML with toledot's XML reader, and a whole collection with the collection reader. A change to the shape needs a new schema version.

The hash detects a file that was cut short or damaged. It does not show who wrote the file, because anyone who edits the file can recompute it. Authenticity stays the job of the system that stores the file. The [threat model](../threat-model.md) says so.

The collector writes the lines to a temporary file and writes the trailer last. It moves the file to its final name only after the trailer is written, so a failed run leaves no file under that name. A file that is cut short in some other way has no trailer, which the reader reports as cut short. The remote collector adds a second check before it publishes the file. See [ADR 5](0005-remote-collection.md).
