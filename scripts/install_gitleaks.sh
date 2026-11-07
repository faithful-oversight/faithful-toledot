#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install a pinned Gitleaks release on Linux x64 and verify its checksum.
# Update the version and checksum together.

set -euo pipefail

VERSION="8.30.1"
SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
DEST="${1:-${HOME}/.local/bin}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

archive="gitleaks_${VERSION}_linux_x64.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "${tmp}/${archive}" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${archive}"
echo "${SHA256}  ${tmp}/${archive}" | sha256sum --check --strict -
tar --extract --gzip --file "${tmp}/${archive}" --directory "$tmp" gitleaks
mkdir -p "$DEST"
install -m 0755 "${tmp}/gitleaks" "${DEST}/gitleaks"
"${DEST}/gitleaks" version
