# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The source archive's own tests now run in the build check: it unpacks the archive outside the checkout and runs the whole suite there, instead of only collecting the tests.
- Editing a pull request title now reruns the title check, so a corrected title clears the required check.
- The dependency audit writes its export to a private temporary directory, so a planted link or a second run at the same time cannot interfere.
- The DCO check now fails when it cannot list the commits to check, instead of reporting success.
- The release script now treats only a clean "not found" answer as an absent tag; an authentication, rate-limit, network, or malformed answer stops the release.
- The dependency audit always includes every optional extra, and a new check fails it when a package named by an extra is missing from the audited export.
- The release evidence is now one SBOM per scope: `sbom-base.cdx.json` for the base install, and `sbom-all-extras.cdx.json` when the project defines optional extras. Each states its scope, and tests check what each one holds.

## [0.1.0] - 2026-11-11

First release.

### Added

- Project foundation: license, documentation, contribution and security policies, continuous integration, and release pipeline.
- `toledot report` reads Windows event logs and writes an account of changes in Active Directory. It reads `.evtx`, XML, JSON, and CSV exports, and collection files. It writes JSON, Markdown, HTML, and CSV reports and a manifest with SHA-256 hashes. The CSV ends with an `account_completeness` column, so the caveat stays with the change list. Two input files that show the same name are refused, so every citation names one file.
- A catalog of 84 events with plain-English meanings, 40 well-known SIDs, and 21 well-known relative identifiers.
- Origin of each change: the logon session, address, and workstation behind it, with a status that says how far the link holds.
- Three completeness levels, `complete`, `unconfirmed`, and `incomplete`, based on record numbers, notices, problems, and what each input states about its scope. The `--fail-on` option sets when the exit code is `1`.
- `toledot events`, `toledot schema`, and `toledot example` commands, with JSON Schemas for the report, events, and manifest.
- `Collect-ToledotEvents.ps1`, a read-only PowerShell collector that writes a collection file, a JSON Lines file with a hash trailer, and records gaps instead of failing.
- `toledot collect`, which runs the collector on a domain controller over WinRM, with the optional `live` extra. HTTPS always verifies the certificate. Passwords come from `env`, `file`, `keyring`, `vault`, `aws`, or `azure` references.
- Architecture decision records 4 and 5, and user documentation: quickstart, usage, formats, collecting, output, limitations, threat model, and architecture.
