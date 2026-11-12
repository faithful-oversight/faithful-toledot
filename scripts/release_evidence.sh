#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Write the release evidence next to the built packages: two CycloneDX software
# bills of materials and SHA256SUMS for every file.
#
#   sbom-base.cdx.json        what `pip install faithful-toledot` installs: the
#                             analyzer, which has no runtime dependencies
#   sbom-all-extras.cdx.json  everything every optional extra can add: remote
#                             collection (pypsrp) and the keyring, Vault, AWS,
#                             and Azure secret sources
#
# Each SBOM states its scope in metadata.properties.
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

rm -f -- "$dist"/sbom*.cdx.json "$dist/SHA256SUMS"

# sbom <name> <scope> [uv export options...]
sbom() {
  local name="$1" scope="$2"
  shift 2
  uv export --quiet --locked --no-dev --no-emit-project --no-hashes "$@" \
    --format requirements-txt --output-file "$work/$name.txt"
  uv run --no-sync cyclonedx-py requirements "$work/$name.txt" \
    --pyproject pyproject.toml --mc-type application --output-reproducible \
    --output-format JSON --output-file "$work/$name.cdx.json"
  uv run --no-sync python - "$work/$name.cdx.json" "$dist/$name.cdx.json" "$scope" <<'PY'
import json
import sys

source, target, scope = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    document = json.load(handle)
document["metadata"].setdefault("properties", []).append(
    {"name": "faithful-toledot:sbom-scope", "value": scope}
)
with open(target, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(document, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
PY
}

sbom sbom-base "base install: pip install faithful-toledot"
sbom sbom-all-extras "every optional extra: pip install faithful-toledot[live,keyring,vault,aws,azure]" \
  --all-extras
(cd "$dist" && sha256sum -- * > SHA256SUMS)
