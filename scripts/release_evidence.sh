#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Write the release evidence next to the built packages: a CycloneDX software
# bill of materials (sbom.cdx.json) and SHA256SUMS for every file.
#
# The output is reproducible. The SBOM timestamp is the commit time, and it has
# no random serial number, so the same commit always gives the same bytes. A
# rerun of the release workflow therefore matches a draft it staged earlier.
#
# Usage: scripts/release_evidence.sh <dist-directory>
#
# The directory should hold only the built packages: SHA256SUMS covers every
# file in it. Set SOURCE_DATE_EPOCH, or run inside a git checkout.

set -euo pipefail
export LC_ALL=C

dist="${1:?dist directory required}"
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" ||
    { echo "set SOURCE_DATE_EPOCH or run inside a git checkout" >&2; exit 1; }
fi
export SOURCE_DATE_EPOCH

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

rm -f -- "$dist/sbom.cdx.json" "$dist/SHA256SUMS"
uv export --quiet --locked --no-dev --no-emit-project --no-hashes \
  --format requirements-txt --output-file "$work/runtime-requirements.txt"
uv run --no-sync cyclonedx-py requirements "$work/runtime-requirements.txt" \
  --pyproject pyproject.toml --mc-type application --output-reproducible \
  --output-format JSON --output-file "$dist/sbom.cdx.json"
(cd "$dist" && sha256sum -- * > SHA256SUMS)
