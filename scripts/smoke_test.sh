#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install the exact wheel in a directory into a clean environment and run it.
# CI and the release workflow both run this on the files they publish.
#
# Usage: scripts/smoke_test.sh <dist-directory>
#
# Products extend the marked section to run their real workflow end to end on
# synthetic data, so a broken package cannot be released.

set -euo pipefail

dist="${1:?dist directory required}"
shopt -s nullglob
wheels=("$dist"/*.whl)
[[ ${#wheels[@]} -eq 1 ]] || { echo "expected exactly one wheel in $dist" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

uv venv --quiet "$work/venv"
uv pip install --quiet --python "$work/venv" --no-deps "${wheels[0]}"
if [[ -x "$work/venv/bin/toledot" ]]; then
  tool="$work/venv/bin/toledot"
  python="$work/venv/bin/python"
else
  tool="$work/venv/Scripts/toledot"
  python="$work/venv/Scripts/python"
fi

"$tool" --version
"$tool" --help > /dev/null
# Product end to end: the synthetic example through the installed wheel.
"$tool" example "$work/demo" > /dev/null
demo=("$work"/demo/*.jsonl)
[[ ${#demo[@]} -ge 1 && -e "${demo[0]}" ]] || { echo "toledot example wrote no event files" >&2; exit 1; }
status=0
"$tool" report "${demo[@]}" -o "$work/demo/out" > /dev/null || status=$?
# The example account is incomplete on purpose, so the report exits 1, not 0 or an error.
[[ "$status" -eq 1 ]] || { echo "expected exit code 1 (incomplete), got $status" >&2; exit 1; }
outputs=(toledot-report.json toledot-report.md toledot-report.html toledot-changes.csv
  toledot-manifest.json)
for name in "${outputs[@]}"; do
  [[ -s "$work/demo/out/$name" ]] || { echo "missing $name" >&2; exit 1; }
done
# The manifest must list the four reports (it cannot list itself).
"$python" - "$work/demo/out" "${outputs[@]:0:4}" <<'PY'
import json
import sys

folder, *expected = sys.argv[1:]
with open(f"{folder}/toledot-manifest.json", encoding="utf-8") as handle:
    listed = sorted(item["name"] for item in json.load(handle)["files"])
if listed != sorted(expected):
    sys.exit(f"the manifest lists {listed}, not {sorted(expected)}")
PY

echo "smoke test passed: ${wheels[0]}"
