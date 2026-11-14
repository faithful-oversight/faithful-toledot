#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Decide from the repository's real visibility whether this release is public,
# and stop if the FO_PUBLIC variable disagrees. Public releases get build
# provenance attestations and a PyPI upload. Trusting the variable alone would
# let a public repository release with neither, and a green run.
#
# Prints public=true or public=false to $GITHUB_OUTPUT (stdout when unset).
#
# Usage: FO_PUBLIC=<value> scripts/check_visibility.sh <owner/repo>
# Needs the gh CLI with a token that can read the repository.

set -euo pipefail

repo="${1:?owner/repo required}"
declared="${FO_PUBLIC:-}"

if ! private="$(gh api "repos/${repo}" --jq '.private')"; then
  echo "::error::cannot read the visibility of ${repo}, so the release cannot tell whether it is public" >&2
  exit 1
fi
case "$private" in
  false) actual=true ;;
  true) actual=false ;;
  *)
    echo "::error::unexpected visibility answer for ${repo}: '${private}'" >&2
    exit 1
    ;;
esac

declared_public=false
[[ "$declared" == "true" ]] && declared_public=true

if [[ "$declared_public" != "$actual" ]]; then
  if [[ "$actual" == "true" ]]; then
    echo "::error::${repo} is public but the FO_PUBLIC variable is '${declared}', not 'true'. A release now would skip build provenance and PyPI. Set FO_PUBLIC to true under Settings, Secrets and variables, Actions, Variables, then run the release again."
  else
    echo "::error::${repo} is private but the FO_PUBLIC variable is 'true'. Provenance attestations need a public repository on this plan. Set FO_PUBLIC to false, or make the repository public first, then run the release again."
  fi
  exit 1
fi

echo "${repo} is $([[ "$actual" == "true" ]] && echo public || echo private); FO_PUBLIC agrees."
echo "public=${actual}" >> "${GITHUB_OUTPUT:-/dev/stdout}"
