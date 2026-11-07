#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Verify that every commit in a range carries a Developer Certificate of
# Origin sign-off matching its author.
#
# Usage: scripts/check_dco.sh <base-sha> <head-sha>

set -euo pipefail

base="${1:?base commit required}"
head="${2:?head commit required}"
status=0

while read -r sha; do
  author="$(git show -s --format='%an <%ae>' "$sha")"
  # Dependabot cannot sign off; its commits are generated, not authored.
  if [[ "$author" == "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>" ]]; then
    continue
  fi
  if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qxF "$author"; then
    echo "::error::commit ${sha} has no 'Signed-off-by: ${author}' trailer"
    status=1
  fi
done < <(git rev-list --no-merges "${base}..${head}")

[[ $status -eq 0 ]] && echo "every commit is signed off"
exit "$status"
