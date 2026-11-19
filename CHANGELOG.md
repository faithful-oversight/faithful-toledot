# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-14

### Fixed

- A failed SID history attempt (event 4766) is no longer worded or counted as SID history added. It has its own action, `sid-history-failed`, and reads "attempted, unsuccessfully, to add SID history".
- Password change, password reset, and DSRM password events (4723, 4724, 4794) are worded and counted as changed, reset, or an unsuccessful attempt by the event's Audit Success or Audit Failure keyword bit, in every format that carries it, and as an attempt only when the bit is absent or unreadable.
- A lockout (event 4740) now shows the caller computer as its own detail and no longer shows it as the account's domain, and it no longer changes the name other events give the same account.
- A message-only CSV row whose labels or sections repeat, which a directory value with line breaks can cause, is now a problem instead of letting the forged text win.
- A collection that lists more than 1000 gaps keeps its gaps, still checks the event count and hash, and `toledot collect` publishes it instead of discarding the transfer. The PowerShell collector now caps the list itself.
- A closed pipe, or an output that cannot show a non-ASCII path, no longer turns a finished run into exit code 4. The exit code is decided before the summary is printed.
- Linking changes to logon sessions no longer slows down quadratically when one logon ID repeats many times.
- A logon or logoff that shares a change's timestamp now counts only when its record number, in the same log, is lower than the change's, for logoffs as well as logons. A change made at the same second as a logon or logoff of its session that cannot be ordered gets the origin status `unordered` and no address, instead of an address from a logon that may have come later or a session that had already ended.
- A log in which any event has no record number is now never `checked` and never `complete`, even when the numbered events are continuous: the report's coverage says `partly-numbered` and counts the unnumbered events (new `unnumbered` property in the JSON report), the account is `unconfirmed`, and `--fail-on unconfirmed` exits 1. Before, one numbered subset with no gaps made the whole log read as complete and the gate exit 0.
- A collection file's header is now checked against every constraint of the published `events-v1` schema, in the file reader and in `toledot collect`. A header with `toledot_events` set to 2, to text, or to `false`, or with a `collector` that is not an object, a bad `method`, a malformed `query`, or an incomplete `logs` entry, is refused instead of read as version 1.
- Two copies of one password event (4723, 4724, 4794) that say different outcomes, one Audit Success and one Audit Failure, are no longer merged silently with whichever input came first. They are reported as a problem and the event is worded as an attempt, in either input order. A copy that carries no outcome evidence never overrides a copy that does.
- `toledot report` no longer replaces an input with a report. An output file that is the same file as an input, by the same path, a `..` path, a symbolic link, or a hard link, is refused with or without `--force`, and nothing is written. `toledot collect` likewise refuses an output that is its `--ca-file` or `file:` secret file.
- The `.evtx` reader numbers unnamed `Data` elements by position among all of them, as the XML reader does.
- `toledot collect --help` shows the Vault form `vault:MOUNT/PATH#FIELD`.
- Errors about an unreadable input name the path as you typed it.
- The look-alike space and negative-number fixes in CSV and text output (shared output safety code).
- The source archive's own tests now run in the build check: it unpacks the archive outside the checkout and runs the whole suite there, instead of only collecting the tests.
- Editing a pull request title now reruns the title check, so a corrected title clears the required check.
- The dependency audit writes its export to a private temporary directory, so a planted link or a second run at the same time cannot interfere.
- The DCO check now fails when it cannot list the commits to check, instead of reporting success.
- The release script now treats only a clean "not found" answer as an absent tag; an authentication, rate-limit, network, or malformed answer stops the release.
- The dependency audit always includes every optional extra, and a new check fails it when a package named by an extra is missing from the audited export.
- The release evidence is now one SBOM per scope: `sbom-base.cdx.json` for the base install, and `sbom-all-extras.cdx.json` when the project defines optional extras. Each states its scope, and tests check what each one holds.
- The sign-off check no longer lets a commit skip sign-off by claiming Dependabot as its author. Dependabot is exempt only on its own pull requests.
- The required "All checks passed" check now fails if a CI job is missing, and a skipped title or sign-off check no longer counts as a pass on a pull request.
- `scripts/check.sh workflows` prints a clear message instead of a stack trace when GitHub rejects the token.
- `SECURITY.md` no longer says that no release has been published. It says the latest release is supported.
- The PowerShell syntax check now fails in CI when PowerShell is missing, instead of skipping.
- On Windows, a closed pipe (reported there as an invalid-argument error rather than a broken pipe) also stops the printing and keeps the real exit code, instead of ending with an internal error or exit 120.
- A file name, report folder, collection path, or error message that contains a line break can no longer add a line to what toledot prints. Previously a value such as `d\nNo changes found in the input.` put a convincing line of its own under toledot's output. These values now print on one line, with the line break shown as `\n`.

### Changed

- Install instructions use `pipx install git+https://github.com/faithful-oversight/faithful-toledot` until a PyPI release exists, and the missing-extra errors give pipx and pip commands that work.
- The README states the status, how toledot differs from other approaches, and shows an excerpt of the example report, and the docs say that the project is not affiliated with Microsoft.
- The example uses obviously synthetic names, and its sample reports were regenerated.
- The docs now say that a conflicting duplicate record keeps both copies, that memory grows with the number of changes, and that a message-only CSV can be forged.
- The collector script is version 0.1.1.
- Dependabot groups minor and patch updates of runtime dependencies into one pull request.
- `CONTRIBUTING.md` lists every tool a clean machine needs and which checks need network access or a token.
- The releasing guide covers the first PyPI publish, a failed PyPI step, scheduled checks that stop after 60 idle days, both SBOM files, and the pinned tools.
- CI on a private repository tests Python 3.11 and 3.14 on pull requests and runs macOS only on schedule and before releases, to save metered Actions minutes; a public repository keeps the full matrix.

### Security

- A release now stops with a clear message when the `FO_PUBLIC` setting disagrees with whether the repository is public, so a public release cannot skip provenance and PyPI by mistake.
- Release jobs check the built files against `SHA256SUMS` before attesting, uploading or publishing.
- uv and the Vale style packages used in CI are pinned to exact versions, and the style packages are checked against a SHA-256 before use.
- Khmer and Mongolian marks that draw nothing (U+17B4, U+17B5, U+180B to U+180D, U+180F) now print as visible escapes, and an issue reference such as `#123` from the input is no longer turned into a link in the Markdown report.
- The dependency audit now covers every locked package and version, including Windows-only packages and versions only another Python installs, and fails if the auditor leaves any out. The license check now reads the license of such packages from their exact locked artifact, checked against the sha256 in `uv.lock`, and fails if it cannot, instead of skipping them. The docs theme is limited to Python 3.11.5 and later, so the lock no longer pulls in a `soupsieve` with known advisories.

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
