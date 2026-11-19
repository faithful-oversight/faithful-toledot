# Contributing

Thank you for helping. This guide explains how to set up the project, what every change must pass, and how changes are reviewed.

## Ground rules

- **Synthetic data only.** Never commit real directory exports, logs, account names, hostnames, or any other data from a real organization, including in issues, tests, or screenshots.
- **Your own work only.** Contribute only code and text you have the right to submit. Do not contribute anything that belongs to an employer or client.
- **One change per pull request.** Small, focused pull requests are reviewed faster.

## Developer Certificate of Origin

Every commit must be signed off to certify the [Developer Certificate of Origin](https://developercertificate.org/). Add the sign-off with `git commit -s`, which appends a line like this:

```text
Signed-off-by: Your Name <you@example.com>
```

The name and email must match the commit author. Continuous integration rejects commits without a valid sign-off. Merge commits are not checked, because pull requests are squash-merged and merge commits never reach `main`. Resolve conflicts by rebasing rather than merging when you can.

Dependabot's own commits are exempt, but only on pull requests that Dependabot opened. A commit that merely names Dependabot as its author is checked like any other.

Because pull requests are squash-merged, the check runs on the commits of the pull request itself. Their sign-offs stay in the pull request history; the single squashed commit on `main` is not checked again.

## Set up

Requirements for a clean machine:

- [uv](https://docs.astral.sh/uv/) and Git. If the Python version in `.python-version` is not installed, uv downloads it, which needs network access.
- A full clone, not a shallow one (`--depth`). The `secrets` stage and the sign-off check read the whole history.
- Bash 4 or newer for `scripts/check.sh`, and `curl`, `tar`, `sha256sum`, `xargs`, and `diff`. Linux has all of these. macOS ships Bash 3.2 and has no `sha256sum`, so install a newer Bash and the GNU core utilities (for example with Homebrew). On Windows, use WSL or Git Bash. CI runs only the `test` stage on Windows and macOS, so the other stages are checked on Linux only.
- [Gitleaks](https://github.com/gitleaks/gitleaks) on your `PATH`, for the `secrets` stage and the pre-commit hook. On Linux x64, `scripts/install_gitleaks.sh [directory]` downloads the pinned release from github.com, checks its SHA-256, and installs it into `~/.local/bin` or the directory you give. It needs `curl`, `tar`, `sha256sum`, and `install`. Make sure that directory is on your `PATH`. On other platforms, install Gitleaks yourself.
- PowerShell 7 (`pwsh`) for the PowerShell tests and for the PowerShell syntax check in the `config` stage. Locally both skip with a note when `pwsh` is missing. CI sets `TOLEDOT_REQUIRE_PWSH=1`, which turns a missing `pwsh` into a failure; set it yourself to get the same result.
- The optional extras that CI installs (`--extra live` with `uv sync --locked`), for the tests that exercise the real remote transport. Without them those tests skip. CI sets `TOLEDOT_REQUIRE_LIVE=1`, which turns that skip into a failure.
- Network access for the stages marked in the table below. Vale and every other check tool come from the project environment, so there is nothing else to install. The link check runs in CI only.

```shell
git clone https://github.com/faithful-oversight/faithful-toledot.git
cd faithful-toledot
uv sync --locked
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

## Run the checks

Continuous integration runs the same script you run locally:

```shell
scripts/check.sh all
```

Run one stage at a time with `scripts/check.sh <stage>`:

| Stage | What it checks | Also needs |
| --- | --- | --- |
| `format` | Code formatting (Ruff) | Nothing |
| `lint` | Code lint rules, including security rules (Ruff) | Nothing |
| `types` | Strict static typing (mypy) | Nothing |
| `test` | Unit and property-based tests, with at least 95% combined line and branch coverage (pytest, Hypothesis) | `pwsh` and the extras, for the tests that need them (see the requirements) |
| `docs` | Markdown structure (PyMarkdown), spelling (codespell), and wording (Vale) | Network: downloads the pinned Vale styles from github.com |
| `site` | Documentation site build, with warnings treated as errors (Sphinx) | Nothing |
| `config` | YAML style (yamllint), workflow correctness (actionlint), and shell scripts (ShellCheck) | `pwsh`, for the PowerShell syntax check |
| `workflows` | Workflow security (zizmor) | Optional GitHub token, see below |
| `secrets` | Committed secrets across the full history (Gitleaks) | Gitleaks on `PATH`; full history |
| `deps` | Known vulnerabilities in every locked package, whatever its platform or Python version (pip-audit) | Network: queries the vulnerability database |
| `licenses` | Licenses of the installed runtime dependencies against the allow list | Installs the optional extras, so network on the first run |
| `reuse` | Copyright and license information on every file (REUSE) | Nothing |
| `build` | Package build with the pinned backend, metadata check, and an end-to-end test of the built wheel (uv, twine) | Network on the first run, for the pinned build backend; full history, because the reproducible build reads the commit time |

"Nothing" means nothing beyond the project environment from `uv sync --locked`, which needs network access once.

The `workflows` stage uses a GitHub token if `GH_TOKEN`, `GITHUB_TOKEN`, or `ZIZMOR_GITHUB_TOKEN` is set, which lets zizmor run its online audits (for example, known-vulnerable actions). With none set, it runs the offline audits only. If GitHub rejects the token, for example because it expired, the stage stops with a message instead of a stack trace. Fix the token, or unset `GH_TOKEN` and `GITHUB_TOKEN`, to continue.

The `deps` stage audits every package and version in `uv.lock`, not only the ones the machine running it would install. `pip-audit` drops a requirement whose environment marker is false on its own host, such as a Windows-only package or the version only another Python installs, so the stage rewrites the lock export as marker-free requirement files (one version of each package per file) and audits those. It then reads pip-audit's own JSON results and fails unless every locked package was reported, none skipped, and it prints each vulnerability found. It also fails if `uv.lock` and the export disagree.

The `licenses` stage reads licenses from installed packages, so it cannot read a package that is locked only for another platform or Python version. It names each one as not checked and says so in its success message. A reviewed exception for that exact version in `scripts/license_exceptions.toml` settles it. The vulnerability audit has no such limit.

The pre-commit hooks use the project environment and Gitleaks, and download nothing.

## Commit messages and pull request titles

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `revert`, `security`.

```text
fix(parser): keep leading zeros in identifier columns
```

Pull requests are squash-merged, so the pull request title becomes the commit message on `main`. Continuous integration checks the title format.

## Code standards

- Python 3.11 or newer, fully type-annotated, passing mypy in strict mode.
- Parse untrusted input defensively: refuse DTDs and entity declarations in XML (the XML reader does this with the standard library's expat parser), never evaluate input, and treat every field as text until validated.
- Neutralize spreadsheet formula injection in every CSV or spreadsheet output.
- Escape all values in HTML output.
- No network access except `toledot collect`, which connects only to the domain controller the operator names (see [ADR 5](docs/adr/0005-remote-collection.md)). No telemetry, and no writes outside the output path the operator chooses.
- New behavior needs tests. Parsers need property-based tests.
- Every source file starts with SPDX copyright and license lines.

## Documentation standards

- Write in plain, direct language. Vale enforces the project style.
- Update the docs, the changelog `Unreleased` section, and the threat model when behavior changes.
- Record significant design decisions as architecture decision records in `docs/adr/`.

## Review

All changes reach `main` through a pull request. A pull request can merge only when every required check passes and every review conversation is resolved. The maintainer reviews each pull request before merging.

A pull request runs its own copy of the workflows and of the scripts in `scripts/`, including the script that decides whether **All checks passed** is green. The maintainer therefore reads every change to `.github/`, `scripts/`, `zizmor.yml`, `pyproject.toml`, and `uv.lock` line by line, and approves the workflow runs of outside contributors before they start.

## License

By contributing, you agree that your contributions are licensed under the [Apache License, Version 2.0](LICENSE).
