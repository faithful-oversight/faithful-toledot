#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Check a downloaded release directory against its SHA256SUMS: every listed
# file must match, and no file may be present that the list does not name.
# Jobs that attest, upload, or publish run this right after downloading the
# artifact, so they act on the bytes the build job wrote.
#
# Usage: scripts/verify_artifacts.sh <dist-directory>

set -euo pipefail
export LC_ALL=C

dist="${1:?dist directory required}"
[[ -f "$dist/SHA256SUMS" ]] || { echo "::error::$dist/SHA256SUMS is missing" >&2; exit 1; }

(cd "$dist" && sha256sum --check --strict SHA256SUMS) ||
  { echo "::error::files in $dist do not match SHA256SUMS" >&2; exit 1; }

# SHA256SUMS lines are "<digest>  <name>"; names carry no spaces or directories.
listed="$(cut -c 67- "$dist/SHA256SUMS" | sort)"
present="$(
  cd "$dist"
  shopt -s dotglob nullglob
  for name in *; do
    [[ "$name" == SHA256SUMS ]] || printf '%s\n' "$name"
  done | sort
)"
if [[ "$listed" != "$present" ]]; then
  echo "::error::files in $dist differ from the files SHA256SUMS lists" >&2
  diff <(echo "$listed") <(echo "$present") >&2 || true
  exit 1
fi
echo "verified $(echo "$listed" | wc -l) files against SHA256SUMS"
