# Rules for AI coding agents

These rules apply to every AI assistant working in this repository. Human contributors follow [CONTRIBUTING.md](CONTRIBUTING.md), which also applies to agents.

## Workflow

1. Fetch `main` before starting. Work from the latest version, never a stale copy.
2. Work on a branch named `<agent>/<topic>`, for example `claude/csv-parser`. Never push to `main`.
3. Sign off every commit (`git commit -s`) and end the message with a `Co-Authored-By` trailer naming the model actually used.
4. Run `scripts/check.sh all` and fix every failure before opening a pull request.
5. Open a pull request with a Conventional Commits title. Fill in every section of the pull request template.

## Hard rules

- Never commit secrets, real organization data, or anything derived from an employer's or client's code, data, or methods.
- Fixtures are synthetic. Use example domains such as `example.com` and `corp.example`.
- Never weaken a check to make it pass: no lowering the coverage threshold, no broad lint ignores, no skipped tests, and no unpinned actions. If a rule is wrong, change it in its own pull request and explain why.
- Never add a dependency without stating why in the pull request. Runtime dependencies must use a license on the allow list in `scripts/check_licenses.py`.
- Keep the tool read-only and offline unless an architecture decision record says otherwise.
- Update `CHANGELOG.md`, the docs, and the threat model in the same pull request as the behavior change.
- State what you did not verify. Do not claim a feature works without a test that proves it.
