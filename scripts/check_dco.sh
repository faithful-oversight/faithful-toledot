#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Verify that every commit in a range carries a Developer Certificate of
# Origin sign-off matching its author.
#
# Dependabot's commits are generated and cannot be signed off, so they are
# exempt, but only on a pull request that Dependabot itself opened. The commit
# author is text any contributor can set, so it is never enough on its own:
# set PR_AUTHOR to the login of the pull request's author
# (github.event.pull_request.user.login). Unset, empty, or any other value
# means there is no exemption at all.
#
# Usage: PR_AUTHOR=<login> scripts/check_dco.sh <base-sha> <head-sha>

set -euo pipefail

base="${1:?base commit required}"
head="${2:?head commit required}"
pr_author="${PR_AUTHOR:-}"
dependabot_author="dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
status=0

# List the range first. An error inside a process substitution would not stop
# the loop below, and an unreadable range would then count as "all signed off".
if ! commits="$(git rev-list --no-merges "${base}..${head}")"; then
  echo "::error::cannot list the commits in ${base}..${head}" >&2
  exit 1
fi

if [[ -z "$commits" ]]; then
  echo "no commits to check"
  exit 0
fi

while read -r sha; do
  author="$(git show -s --format='%an <%ae>' "$sha")"
  # Dependabot cannot sign off; its commits are generated, not authored. The
  # exemption needs the pull request itself to be Dependabot's, because anyone
  # can write that author on a commit of their own.
  if [[ "$pr_author" == "dependabot[bot]" && "$author" == "$dependabot_author" ]]; then
    continue
  fi
  if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qxF "$author"; then
    echo "::error::commit ${sha} has no 'Signed-off-by: ${author}' trailer"
    status=1
  fi
done <<< "$commits"

[[ $status -eq 0 ]] && echo "every commit is signed off"
exit "$status"
