# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail if any runtime dependency uses a license outside the allow list.

Runtime dependencies ship to users, so their licenses must be compatible with
Apache-2.0 distribution. Development tools are not distributed and are not
checked here.
"""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import PackageNotFoundError, metadata

# Keep in sync with allow-licenses in .github/workflows/ci.yml.
ALLOWED = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
}
CLASSIFIER_MAP = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}


def runtime_requirements() -> list[str]:
    """Return the names of locked runtime dependencies."""
    out = subprocess.run(
        [  # noqa: S607 - uv is resolved from PATH by design
            "uv",
            "export",
            "--color",
            "never",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--no-hashes",
            "--format",
            "requirements-txt",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names = []
    for raw in out.splitlines():
        line = raw.strip()
        if line and not line.startswith(("#", "-")):
            names.append(line.split("==")[0].split(";")[0].strip())
    return names


def licenses_for(name: str) -> set[str]:
    """Return SPDX identifiers declared by an installed distribution."""
    meta = metadata(name)
    expressions = meta.get_all("License-Expression") or []
    if expressions:
        expression = expressions[0]
        return {part.strip("() ") for part in expression.replace(" OR ", " AND ").split(" AND ")}
    found = {CLASSIFIER_MAP[c] for c in meta.get_all("Classifier") or [] if c in CLASSIFIER_MAP}
    return found or {"UNKNOWN"}


def main() -> int:
    """Check every runtime dependency and report violations."""
    failures = []
    for name in runtime_requirements():
        try:
            found = licenses_for(name)
        except PackageNotFoundError:
            failures.append(f"{name}: not installed, cannot read license")
            continue
        if not found <= ALLOWED:
            failures.append(f"{name}: {', '.join(sorted(found))}")
    for failure in failures:
        print(f"license not allowed: {failure}", file=sys.stderr)  # noqa: T201
    if not failures:
        print("all runtime dependency licenses are allowed")  # noqa: T201
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
