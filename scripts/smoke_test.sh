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
else
  tool="$work/venv/Scripts/toledot"
fi

"$tool" --version
"$tool" --help > /dev/null
# --- Product end-to-end run goes here. ---

echo "smoke test passed: ${wheels[0]}"
