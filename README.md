# toledot

**AD Change Narrative.** Turns exported Active Directory change events into a plain-language account of who changed what, when, and from where.

[![CI](https://github.com/faithful-oversight/faithful-toledot/actions/workflows/ci.yml/badge.svg)](https://github.com/faithful-oversight/faithful-toledot/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: pre-release.** The repository holds the project foundation only. No feature is implemented yet, and nothing here is ready for production use.

## About the name

*toledot* (toh-leh-DOHT). Hebrew: an account of what came from what, as in the genealogical records of Genesis.

## What it will do

- Parse exported directory change and account management events.
- Group related events into single changes with actor, target, old value, and new value.
- Produce a readable digest and structured output for review and evidence.
- Report gaps, such as event ranges that are missing or events that could not be parsed.

## What it will not do

- Monitor or alert in real time.
- Collect events from domain controllers in the first release. Inputs are exported files.
- Judge whether a change was authorized.

See [docs/limitations.md](docs/limitations.md) for the full list.

## Design goals

- **Read-only.** The tool will never change the systems it examines.
- **Offline first.** Inputs will be exported files, with no network access required.
- **Explicit unknowns.** Every report will state what the tool could not see or verify.
- **Traceable findings.** Every finding will point back to its source record and the rule that produced it.
- **Synthetic test data only.** Fixtures are hand-made or generated. No real organization's data is ever committed.

## Installation

Not yet published. Once released, the package will install with:

```shell
pipx install faithful-toledot
```

To work from source, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

```shell
toledot --version
```

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Limitations](docs/limitations.md)
- [Releasing](docs/releasing.md)
- [Architecture decision records](docs/adr/)

## Security

Please do not report security problems in public issues. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first.

## License

Copyright 2026 Faithful Oversight, LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
