# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Check that the vulnerability audit covers the optional dependencies.

``scripts/check.sh deps`` exports the locked dependencies to a requirements file and
audits that file. An export without ``--all-extras`` leaves out every optional extra, so a
vulnerable pin in one of them would pass unseen. This script reads the export and fails,
naming what is missing, unless every package that an extra in ``pyproject.toml`` names is in
it. A project with no extras has nothing to check and passes.

Usage: scripts/check_audit_inventory.py <requirements-file> [pyproject.toml]
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

ALSO_REQUIRED: tuple[str, ...] = ("pyspnego",)
"""Packages to require besides the ones the extras name. ``pypsrp`` pulls in ``pyspnego``."""

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==", re.MULTILINE)
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalise(name: str) -> str:
    """Return a package name in the form pip uses to compare names."""
    return re.sub(r"[-_.]+", "-", name).lower()


def audited(text: str) -> set[str]:
    """Return the normalised names of the packages a requirements export pins."""
    return {normalise(name) for name in _PIN.findall(text)}


def required(pyproject: Path, also: Sequence[str] | None = None) -> list[str]:
    """Return the packages the extras of a project name, then ``also``, in order.

    ``also`` defaults to ``ALSO_REQUIRED``.
    """
    project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    own = normalise(str(project.get("name", "")))
    names: list[str] = []
    for requirements in project.get("optional-dependencies", {}).values():
        for requirement in requirements:
            found = _NAME.match(str(requirement))
            name = normalise(found.group(1)) if found else ""
            if name and name != own and name not in names:
                names.append(name)
    extra = ALSO_REQUIRED if also is None else also
    names.extend(normalise(name) for name in extra if normalise(name) not in names)
    return names


def missing(text: str, pyproject: Path, also: Sequence[str] | None = None) -> list[str]:
    """Return the required packages the export does not hold, in ``required`` order."""
    present = audited(text)
    return [name for name in required(pyproject, also) if name not in present]


def main(argv: list[str]) -> int:
    """Check the export named in ``argv``; print what is missing and return 1 if any is."""
    if len(argv) not in {1, 2}:
        print(  # noqa: T201
            "usage: check_audit_inventory.py <requirements-file> [pyproject.toml]", file=sys.stderr
        )
        return 2
    pyproject = Path(argv[1]) if len(argv) == 2 else Path("pyproject.toml")  # noqa: PLR2004
    absent = missing(Path(argv[0]).read_text(encoding="utf-8"), pyproject)
    if absent:
        print(  # noqa: T201
            "the vulnerability audit does not cover the optional dependencies: "
            f"{', '.join(absent)} missing from the export. "
            "Export with --all-extras so every extra is audited.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
