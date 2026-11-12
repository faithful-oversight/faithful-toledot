# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail if any runtime dependency uses a license outside the allow list.

Runtime dependencies ship to users, so their licenses must be compatible with
Apache-2.0 distribution. Development tools are not distributed and are not
checked here. This script is the same in every Faithful Oversight product; each
repository keeps its own reviewed exceptions in ``license_exceptions.toml``.

A license is taken from the first source that establishes it:

1. A reviewed exception for that exact package version.
2. The ``License-Expression`` field, which must be a valid SPDX expression.
3. A ``License`` field that is a valid SPDX expression, of any length, or one of
   a few exact, unambiguous names such as ``MIT License``. Any other short text is
   not guessed at; it fails until someone reads the license and records an exception.
4. Only when no ``License`` field names a license (it is empty or holds the
   license text itself): classifiers that name one license. The generic BSD and
   Apache classifiers do not say which version or how many clauses, so they fail
   until reviewed. License text that mentions the GNU licenses always fails.

An explicit license is never replaced by a classifier, so ``License: BSD-4-Clause``
with a generic BSD classifier fails rather than passing as BSD-3-Clause.

Some identifiers are allowed only through a reviewed exception (``REVIEW_ONLY``):
public domain dedications vary, so metadata alone does not establish one.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, metadata, version
from pathlib import Path
from typing import Any, Protocol

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.markers import Marker


class Metadata(Protocol):
    """The part of package metadata the gate reads."""

    def get_all(self, name: str, failobj: Any = None) -> list[Any] | None: ...  # noqa: D102


EXCEPTIONS_FILE = Path(__file__).with_name("license_exceptions.toml")
MAX_SPDX_FIELD = 40
"""The longest License field read as a license name; longer text is a license body."""

# Keep in sync with allow-licenses in .github/workflows/ci.yml.
ALLOWED = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "LicenseRef-Public-Domain",  # only through a reviewed exception; see REVIEW_ONLY
    "MIT",
    "MIT-0",
    "MPL-2.0",  # file-level copyleft; allowed for unmodified dependencies
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
}
REVIEW_ONLY = {"LicenseRef-Public-Domain"}
NAMES = {
    # Exact License field values that name one license without ambiguity.
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "isc license": "ISC",
    "mit license": "MIT",
}
CLASSIFIERS = {
    # Classifiers that name exactly one license.
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
}
COPYLEFT_TEXT = ("gnu general public", "gnu lesser general public", "gnu affero")


def identifiers(expression: str) -> set[str]:
    """Return the license identifiers in a valid SPDX expression, or raise ValueError."""
    try:
        canonical = canonicalize_license_expression(expression)
    except InvalidLicenseExpression as exc:
        raise ValueError(expression) from exc
    words = canonical.replace("(", " ").replace(")", " ").split()
    return {word for word in words if word not in {"AND", "OR", "WITH"}}


def load_exceptions(path: Path = EXCEPTIONS_FILE) -> dict[tuple[str, str], str]:
    """Return reviewed licenses keyed by (normalized package name, exact version)."""
    if not path.exists():
        return {}
    entries = tomllib.loads(path.read_text(encoding="utf-8")).get("exception", [])
    found = {}
    for entry in entries:
        for key in ("package", "version", "license", "evidence"):
            if not str(entry.get(key, "")).strip():
                msg = f"{path.name}: every exception needs {key}"
                raise ValueError(msg)
        found[(normalize(entry["package"]), entry["version"])] = entry["license"]
    return found


def normalize(name: str) -> str:
    """Return a package name in its normalized form (PEP 503)."""
    return "-".join(name.lower().replace("_", "-").replace(".", "-").split("-"))


def licenses_from(meta: Metadata) -> set[str]:
    """Return the licenses package metadata establishes, as the module docstring describes."""
    return _unreviewed(_from_fields(meta))


def _unreviewed(found: set[str]) -> set[str]:
    """Mark identifiers that only a reviewed exception may establish."""
    return {
        f"{name} (needs a reviewed exception)" if name in REVIEW_ONLY else name for name in found
    }


def _from_fields(meta: Metadata) -> set[str]:
    expressions = meta.get_all("License-Expression") or []
    if expressions:
        try:
            return identifiers(expressions[0])
        except ValueError:
            return {f"invalid License-Expression {expressions[0]!r}"}
    declared = ((meta.get_all("License") or [""])[0] or "").strip()
    if declared and "\n" not in declared:
        # An SPDX expression is explicit whatever its length; try it before any
        # guess that long text is a license body.
        try:
            return identifiers(declared)
        except ValueError:
            pass
        if len(declared) < MAX_SPDX_FIELD:
            return _named(declared)
    if any(marker in declared.casefold() for marker in COPYLEFT_TEXT):
        return {"GNU license text in the License field"}
    classifiers = [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    named = {CLASSIFIERS.get(c, f"classifier {c!r} does not name one license") for c in classifiers}
    return named or {"no license in the metadata; read the license and record an exception"}


def _named(declared: str) -> set[str]:
    """Return the license a short License field names, without guessing."""
    if declared.casefold() in NAMES:
        return {NAMES[declared.casefold()]}
    return {f"unrecognized License {declared!r}; read the license and record an exception"}


def licenses_for(name: str, exceptions: dict[tuple[str, str], str]) -> set[str]:
    """Return the licenses of an installed distribution."""
    reviewed = exceptions.get((normalize(name), version(name)))
    if reviewed is not None:
        return identifiers(reviewed)
    return licenses_from(metadata(name))


def runtime_requirements() -> list[str]:
    """Return the names of locked runtime dependencies, with every optional extra."""
    out = subprocess.run(
        [  # noqa: S607 - uv is resolved from PATH by design
            "uv",
            "export",
            "--color",
            "never",
            "--locked",
            "--all-extras",
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
        if not line or line.startswith(("#", "-")):
            continue
        requirement, _, marker = line.partition(";")
        # Skip dependencies for other platforms or Python versions, which are not installed here.
        if marker.strip() and not Marker(marker.strip()).evaluate():
            continue
        names.append(requirement.split("==")[0].strip())
    return names


def main() -> int:
    """Check every runtime dependency and report violations."""
    exceptions = load_exceptions()
    failures = []
    for name in runtime_requirements():
        try:
            found = licenses_for(name, exceptions)
        except PackageNotFoundError:
            failures.append(f"{name}: not installed, cannot read license")
            continue
        if not found <= ALLOWED:
            failures.append(f"{name} {version(name)}: {', '.join(sorted(found - ALLOWED))}")
    for failure in failures:
        print(f"license not allowed: {failure}", file=sys.stderr)  # noqa: T201
    if not failures:
        print("all runtime dependency licenses are allowed")  # noqa: T201
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
