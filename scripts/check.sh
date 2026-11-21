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
  # Pinned, checksum-verified styles. `vale sync` would fetch the newest release unchecked.
  scripts/install_vale_styles.sh >/dev/null
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
  check_powershell
}
check_powershell() {
  # Parse every PowerShell script with the real PowerShell parser. GitHub's runners
  # include pwsh. Elsewhere the check is skipped with a note, unless TOLEDOT_REQUIRE_PWSH=1
  # (set in CI), which makes a missing pwsh a failure.
  if ! command -v pwsh >/dev/null; then
    if [[ "${TOLEDOT_REQUIRE_PWSH:-}" == "1" ]]; then
      echo "TOLEDOT_REQUIRE_PWSH is set but pwsh is not installed" >&2
      return 1
    fi
    echo "pwsh not found; skipping the PowerShell syntax check" >&2
    return 0
  fi
  local script
  while IFS= read -r -d '' script; do
    # -Command does not pass extra arguments to the command as $args, so the path goes
    # through the environment.
    # shellcheck disable=SC2016 # $errors and $env: are PowerShell syntax
    POWERSHELL_TELEMETRY_OPTOUT=1 PS_PARSE_PATH="$script" pwsh -NoProfile -NonInteractive -Command '
      $errors = $null
      $path = (Resolve-Path -LiteralPath $env:PS_PARSE_PATH).Path
      [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
      foreach ($e in $errors) {
        $line = "{0}:{1}:{2}: {3}" -f $env:PS_PARSE_PATH, $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message
        [Console]::Error.WriteLine($line)
      }
      if ($errors) { exit 1 }'
  done < <(git ls-files -z '*.ps1')
}
stage_workflows() {
  # Online audits (known-vulnerable actions, for example) need a valid GitHub
  # token, which zizmor reads from any of three variables. Without one, run the
  # offline audits only, and remove the variables: zizmor rejects an empty one
  # even with --offline.
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-${ZIZMOR_GITHUB_TOKEN:-}}}"
  local -a mode=()
  local out rc=0
  [[ -n "$token" ]] || mode=(--offline)
  out="$(mktemp)"
  (
    [[ -n "$token" ]] || unset GH_TOKEN GITHUB_TOKEN ZIZMOR_GITHUB_TOKEN
    RUST_BACKTRACE=0 run zizmor ${mode[@]+"${mode[@]}"} --persona=auditor --min-severity=low \
      .github/workflows
  ) > "$out" 2>&1 || rc=$?
  if [[ $rc -eq 1 ]]; then
    # Exit code 1 means zizmor could not finish; findings use higher codes. Show
    # the cause without the Rust stack trace, and say what to do.
    sed '/^Stack backtrace:/,$d' "$out" >&2
    {
      echo "workflows: zizmor could not finish its online audits. The usual cause is a GH_TOKEN"
      echo "(or GITHUB_TOKEN) that GitHub rejects, such as an expired token, or no route to"
      echo "github.com. Fix the token, or unset GH_TOKEN and GITHUB_TOKEN to run only the"
      echo "offline audits."
    } >&2
  else
    cat "$out"
  fi
  rm -f "$out"
  return "$rc"
}
stage_secrets()   { gitleaks git --redact --no-banner --exit-code 1 .; }
stage_deps() {
  # A private directory for every run. A fixed path in a shared temporary
  # directory could be a symlink planted beforehand, and two checks running at
  # the same time would overwrite each other's input.
  local work inputs input n rc=0
  work="$(mktemp -d)"
  inputs="$work/audit"
  # --all-extras puts every optional extra in the audit; without it their pins would never
  # be checked. The export keeps environment markers, and pip-audit would drop every pin
  # whose marker is false on this host (a Windows-only package, or the version that only
  # another Python installs). So the pins are rewritten as marker-free files, one version
  # of each package per file, and every identity in uv.lock is audited on any host.
  uv export --color never --locked --all-groups --all-extras --no-emit-project \
    --format requirements-txt > "$work/export.txt" || rc=$?
  if [[ $rc -eq 0 ]]; then
    run python scripts/check_audit_inventory.py split "$work/export.txt" "$inputs" \
      --lock uv.lock || rc=$?
  fi
  if [[ $rc -eq 0 ]]; then
    for input in "$inputs"/requirements-audit-*.txt; do
      [[ -e "$input" ]] || continue
      n="${input##*requirements-audit-}"
      n="${n%.txt}"
      run pip-audit --strict --requirement "$input" --disable-pip --progress-spinner off \
        --format json --output "$inputs/audit-$n.json" || rc=$?
    done
    # Read what the auditor reported, not what was sent: every locked identity must be in
    # its results, none skipped. This also prints each vulnerability found.
    run python scripts/check_audit_inventory.py verify "$work/export.txt" "$inputs" \
      --lock uv.lock || rc=$?
  fi
  rm -rf "$work"
  return "$rc"
}
stage_licenses() {
  # Optional extras are dependencies too; install them so their licenses can be read.
  uv sync --quiet --locked --all-extras
  run python scripts/check_licenses.py
}
stage_reuse()     { run reuse lint; }
stage_build() {
  rm -rf dist
  # Build with the pinned, hash-verified backend in requirements-build.txt.
  # uv writes dist/.gitignore by default; SHA256SUMS names only the release files,
  # and verify_artifacts.sh rejects any file it does not name.
  uv build --no-create-gitignore --build-constraint requirements-build.txt --require-hashes
  run twine check --strict dist/*
  scripts/smoke_test.sh dist
  # The source distribution must carry everything its own tests need. Unpack it
  # outside the checkout and run those tests there, against the unpacked source.
  local unpacked py rc=0
  unpacked="$(mktemp -d)"
  tar -xzf dist/*.tar.gz -C "$unpacked"
  py="$(run python -c 'import sys; print(sys.executable)')"
  (cd "$unpacked"/*/ && PYTHONPATH="$PWD/src" "$py" -m pytest --no-cov -q -p no:cacheprovider) || rc=$?
  rm -rf "$unpacked"
  [[ $rc -eq 0 ]] || { echo "tests failed in the unpacked source distribution" >&2; return 1; }
  scripts/release_evidence.sh dist
  # A rerun of the release workflow rebuilds everything, and can resume a staged
  # draft only if every byte comes out the same. Prove that on every change.
  local again=build/rebuild
  rm -rf "$again"
  uv build --quiet --no-create-gitignore --build-constraint requirements-build.txt --require-hashes --out-dir "$again"
  scripts/release_evidence.sh "$again"
  if ! diff dist/SHA256SUMS "$again/SHA256SUMS" >&2; then
    echo "a second build gave different bytes; releases could not resume" >&2
    return 1
  fi
  # The release jobs check dist with this script before they attest, upload, or
  # publish. Run the same check on every build so a failure shows on the PR.
  scripts/verify_artifacts.sh dist
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
