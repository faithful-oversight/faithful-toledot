#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install the Vale style packages pinned in scripts/vale-styles.lock. Each zip
# must match its SHA-256 before it is unpacked, and a mismatch stops the check.
# An existing copy of a package is replaced, so no file from an earlier or
# unpinned install stays behind.
#
# Usage: scripts/install_vale_styles.sh [<lock-file> [<styles-directory>]]
# Needs curl, sha256sum, and uv (which finds the Python that unpacks the zip).

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
lock="${1:-$root/scripts/vale-styles.lock}"
dest="${2:-$root/.vale/styles}"

[[ -f "$lock" ]] || { echo "::error::lock file $lock not found" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$dest"

count=0
while read -r name url sha256 extra; do
  case "$name" in "" | \#*) continue ;; esac
  if [[ -z "$url" || ! "$sha256" =~ ^[0-9a-f]{64}$ || -n "$extra" || ! "$name" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "::error::bad line in $lock for '$name'; expected: <name> <url> <sha256>" >&2
    exit 1
  fi
  zip="$tmp/$name.zip"
  if ! curl --fail --silent --show-error --location --proto '=https,file' --tlsv1.2 \
    --output "$zip" "$url"; then
    echo "::error::cannot download Vale package $name from $url" >&2
    exit 1
  fi
  if ! echo "$sha256  $zip" | sha256sum --check --strict --status -; then
    echo "::error::Vale package $name does not match its pinned SHA-256 ($url)" >&2
    exit 1
  fi
  mkdir "$tmp/$name.dir"
  uv run --no-project python -m zipfile -e "$zip" "$tmp/$name.dir"
  if [[ ! -d "$tmp/$name.dir/$name" ]]; then
    echo "::error::Vale package $name does not contain a $name directory" >&2
    exit 1
  fi
  rm -rf "${dest:?}/$name"
  mv "$tmp/$name.dir/$name" "$dest/$name"
  count=$((count + 1))
done < "$lock"

[[ $count -gt 0 ]] || { echo "::error::$lock lists no packages" >&2; exit 1; }
echo "installed $count Vale packages into $dest"
