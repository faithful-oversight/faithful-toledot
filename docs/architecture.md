# Architecture

> **Status: planned.** This page describes the intended design. It changes as the design is decided and recorded in [architecture decision records](adr/index.md).

## Shape of the tool

toledot is a command-line tool and a Python library with the same core.

```text
inputs (exported Windows event logs and event records)
        |
        v
  adapters   -> read one input format each, and record what they could not read
        |
        v
  model      -> typed, validated records with a link back to each source record
        |
        v
  analysis   -> pure functions: records in, findings out, no input or output
        |
        v
  reporters  -> Markdown, HTML, CSV, and JSON output
```

## Rules the design follows

- **Separation.** Adapters handle input, analysis is pure logic, and reporters handle output. Analysis never reads files or prints.
- **A versioned contract.** Machine-readable output follows a published JSON Schema with a version number. Breaking changes to the schema require a major release.
- **No prompts.** The tool never asks questions interactively, so it runs unchanged in scripts and pipelines.
- **Structured exit codes.** `0` means success with no findings, `1` means findings were reported, `2` means the command was used incorrectly, and `3` means the input could not be processed.
- **Unknowns are results.** When the tool cannot verify something, it reports *unknown* with the reason, never *passed*.
- **Read-only and offline.** The tool does not change the systems it examines and does not need network access.

## Packaging

- Python package on PyPI: `faithful-toledot`, with the command `toledot`.
- Further formats, such as a standalone executable or a container image, are added only when a decision record justifies them.
