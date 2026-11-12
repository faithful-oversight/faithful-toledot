# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Check that the vulnerability audit covers the optional product dependencies.

``scripts/check.sh deps`` exports the locked dependencies to a requirements file and
audits that file. An export without ``--all-extras`` leaves out remote collection and
the secret sources, so a vulnerable pin in them would pass unseen. This script reads the
export and fails, naming what is missing, unless every package in ``REQUIRED`` is in it.

Usage: scripts/check_audit_inventory.py <requirements-file>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REQUIRED = ("pypsrp", "pyspnego", "hvac", "boto3", "azure-identity", "keyring")
"""One package from each optional extra, and ``pyspnego``, which ``pypsrp`` pulls in."""

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==", re.MULTILINE)


def audited(text: str) -> set[str]:
    """Return the normalised names of the packages a requirements export pins."""
    return {re.sub(r"[-_.]+", "-", name).lower() for name in _PIN.findall(text)}


def missing(text: str) -> list[str]:
    """Return the required packages the export does not hold, in ``REQUIRED`` order."""
    present = audited(text)
    return [name for name in REQUIRED if name not in present]


def main(argv: list[str]) -> int:
    """Check the export named in ``argv``; print what is missing and return 1 if any is."""
    if len(argv) != 1:
        print("usage: check_audit_inventory.py <requirements-file>", file=sys.stderr)  # noqa: T201
        return 2
    absent = missing(Path(argv[0]).read_text(encoding="utf-8"))
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
