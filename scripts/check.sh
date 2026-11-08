#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Run the project's quality gates. Continuous integration calls this same
# script, so a local pass means the same checks pass in CI.
#
# Usage: scripts/check.sh <stage> [<stage> ...]
#        scripts/check.sh all

set -euo pipefail
cd "$(dirname "$0")/.."

run() { uv run --locked --no-sync "$@"; }

stage_format()    { run ruff format --check --diff .; }
stage_lint()      { run ruff check --no-fix .; }
stage_types()     { run mypy; }
stage_test()      { run pytest --cov-fail-under=95; }
stage_docs() {
  local -a docs
  # Generated sample reports are checked by tests, not by the prose linters.
  mapfile -t docs < <(git ls-files '*.md' ':!:examples/*/sample-report/*')
  run pymarkdown --config .pymarkdown.json scan "${docs[@]}"
  git ls-files -z | xargs -0 uv run --locked --no-sync codespell --
  run vale sync >/dev/null
  run vale --minAlertLevel=warning "${docs[@]}"
}
stage_site() {
  rm -rf build/docs
  run sphinx-build --fail-on-warning --keep-going --nitpicky --quiet --builder html docs build/docs
}
stage_config() {
  run yamllint --strict .
  run actionlint
  git ls-files -z '*.sh' | xargs -0 uv run --locked --no-sync shellcheck --
}
stage_workflows() {
  # Online audits need a GitHub token; without one, run the offline audits only.
  local -a mode=()
  [[ -n "${GH_TOKEN:-}" ]] || mode=(--offline)
  run zizmor "${mode[@]}" --persona=auditor --min-severity=low .github/workflows
}
stage_secrets()   { gitleaks git --redact --no-banner --exit-code 1 .; }
stage_deps() {
  uv export --color never --locked --all-groups --no-emit-project --format requirements-txt \
    > "${TMPDIR:-/tmp}/requirements-audit.txt"
  run pip-audit --strict --requirement "${TMPDIR:-/tmp}/requirements-audit.txt" --disable-pip
}
stage_licenses()  { run python scripts/check_licenses.py; }
stage_reuse()     { run reuse lint; }
stage_build() {
  rm -rf dist
  # Build with the pinned, hash-verified backend in requirements-build.txt.
  uv build --build-constraint requirements-build.txt --require-hashes
  run twine check --strict dist/*
  scripts/smoke_test.sh dist
  scripts/release_evidence.sh dist
  # A rerun of the release workflow rebuilds everything, and can resume a staged
  # draft only if every byte comes out the same. Prove that on every change.
  local again=build/rebuild
  rm -rf "$again"
  uv build --quiet --build-constraint requirements-build.txt --require-hashes --out-dir "$again"
  scripts/release_evidence.sh "$again"
  if ! diff dist/SHA256SUMS "$again/SHA256SUMS" >&2; then
    echo "a second build gave different bytes; releases could not resume" >&2
    return 1
  fi
}

ALL=(format lint types test docs site config workflows secrets deps licenses reuse build)

[[ $# -gt 0 ]] || { echo "usage: $0 <stage>... | all (stages: ${ALL[*]})" >&2; exit 2; }
[[ "$1" == "all" ]] && set -- "${ALL[@]}"

for stage in "$@"; do
  if ! declare -F "stage_${stage}" >/dev/null; then
    echo "unknown stage: ${stage}" >&2
    exit 2
  fi
  echo "::group::${stage}"
  "stage_${stage}"
  echo "::endgroup::"
done
