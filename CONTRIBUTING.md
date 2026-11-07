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

The name and email must match the commit author. Continuous integration rejects commits without a valid sign-off.

## Set up

Requirements:

- [uv](https://docs.astral.sh/uv/) and Git.
- Bash 4 or newer. macOS ships Bash 3.2, so install a newer Bash with Homebrew.
- [Gitleaks](https://github.com/gitleaks/gitleaks) for the `secrets` stage. On Linux x64, `scripts/install_gitleaks.sh` installs the pinned version.
- Network access for the first run of the `docs` stage (it downloads the Vale styles) and for the `deps` stage (it queries the vulnerability database).

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

| Stage | What it checks |
| --- | --- |
| `format` | Code formatting (Ruff) |
| `lint` | Code lint rules, including security rules (Ruff) |
| `types` | Strict static typing (mypy) |
| `test` | Unit and property-based tests, with a coverage threshold (pytest, Hypothesis) |
| `docs` | Markdown structure (PyMarkdown), spelling (codespell), and wording (Vale) |
| `config` | YAML style (yamllint), workflow correctness (actionlint), and shell scripts (ShellCheck) |
| `workflows` | Workflow security (zizmor) |
| `secrets` | Committed secrets across the full history (Gitleaks) |
| `deps` | Known vulnerabilities in locked dependencies (pip-audit) |
| `licenses` | Dependency licenses against the allow list |
| `reuse` | Copyright and license information on every file (REUSE) |
| `build` | Package build and metadata (uv, twine) |

## Commit messages and pull request titles

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `revert`, `security`.

```text
fix(parser): keep leading zeros in identifier columns
```

Pull requests are squash-merged, so the pull request title becomes the commit message on `main`. Continuous integration checks the title format.

## Code standards

- Python 3.11 or newer, fully type-annotated, passing mypy in strict mode.
- Parse untrusted input defensively: use `defusedxml` for XML, never evaluate input, and treat every field as text until validated.
- Neutralize spreadsheet formula injection in every CSV or spreadsheet output.
- Escape all values in HTML output.
- No network access, no telemetry, and no writes outside the output path the operator chooses.
- New behavior needs tests. Parsers need property-based tests.
- Every source file starts with SPDX copyright and license lines.

## Documentation standards

- Write in plain, direct language. Vale enforces the project style.
- Update the docs, the changelog `Unreleased` section, and the threat model when behavior changes.
- Record significant design decisions as architecture decision records in `docs/adr/`.

## Review

All changes reach `main` through a pull request. A pull request can merge only when every required check passes and every review conversation is resolved. The maintainer reviews each pull request before merging.

## License

By contributing, you agree that your contributions are licensed under the [Apache License, Version 2.0](LICENSE).
