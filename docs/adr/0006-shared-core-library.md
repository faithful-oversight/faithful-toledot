# 6. One shared core library for the Faithful Oversight tools

- Status: accepted
- Date: 2026-11-21

## Context

toledot carried its own copies of modules that every Faithful Oversight tool needs: safe output for the terminal, CSV, Markdown, and HTML, printing that never changes an exit code, atomic publishing of output files, the checks on server and account names, the secret providers, and the WinRM transport. The other tools carried copies of the same modules. The copies drifted apart. A fix in one tool did not reach the others, and each tool tested the same code in its own way.

The project had a second rule that this decision changes. [ADR 5](0005-remote-collection.md) says the file readers have no runtime dependencies. A shared library is a runtime dependency, so the rule needs a record.

Options considered:

- **Keep the copies.** Nothing changes for users, but every fix must be made and reviewed once for each tool, and the copies keep drifting.
- **Vendor the shared code with a script.** The copies stay in each repository, so each tool still carries and reviews the same code, and a sync step has to be kept honest.
- **Depend on a shared library.** One copy, one test suite, and one place to fix.

## Decision

- Depend on [faithful-core](https://github.com/faithful-oversight/faithful-core) for the code that must behave the same in every tool. toledot keeps its own logic: the readers, the correlation, the report content and manifest, the command-line options, the collection file's line checks, and the PowerShell collector.
- Pin an exact version in `pyproject.toml` (`faithful-core==X.Y.Z`), and lock it, with hashes, in `uv.lock`.
- Take a new version only through a pull request that changes the pin and the lock. That pull request runs toledot's own checks, so a change in the library reaches users only after toledot's tests pass against it.
- faithful-core's own checks run toledot's tests against every change to the library, so a change that breaks toledot is found before the library is released.
- faithful-core uses only the Python standard library and has no dependencies of its own. It is licensed Apache-2.0, which is on the allow list in `scripts/check_licenses.py`. It is released from the `faithful-oversight/faithful-core` repository by trusted publishing, with provenance attestations, so the files on PyPI can be traced to that repository's release workflow.
- `pypsrp` stays an optional extra of toledot. faithful-core imports it only when remote collection runs.
- Messages from the library name no product. Where the old copies worded a message differently, toledot now shows the library's wording.

## Consequences

A fix and its tests live in one place, and one release of the library reaches every tool through one pull request each. The shared code has a single, larger test suite than any copy had.

toledot now has one runtime dependency. A compromise of faithful-core would reach every user of toledot. The exact pin, the locked hashes, the vulnerability and license checks, the release provenance, and the review of each version change are the controls. The [threat model](../threat-model.md) records the risk.

A bug in the library can break toledot. Pinning an exact version means toledot does not pick up a broken release by itself, and a fix needs a new release of the library and a pull request that takes it.

A few messages changed wording where the library unified them. The changelog lists each one. Messages are for people, and the library's documentation says not to match on their wording.
