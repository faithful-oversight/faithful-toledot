# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Validate release preconditions and write the release notes.

Prints the version on success. Exits non-zero with a reason on failure.

Usage: python scripts/release_preflight.py <notes-output-path>
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def fail(message: str) -> int:
    """Report a failed precondition."""
    print(f"::error::{message}", file=sys.stderr)  # noqa: T201
    return 1


def changelog_section(text: str, version: str) -> str | None:
    """Return the body of the changelog section for a version, if it is dated."""
    heading = re.compile(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", re.MULTILINE)
    match = heading.search(text)
    if not match:
        return None
    rest = text[match.end() :]
    following = re.search(r"^## ", rest, re.MULTILINE)
    return (rest[: following.start()] if following else rest).strip()


def git(*args: str) -> str:
    """Run a fixed git command and return its output."""
    return subprocess.run(  # noqa: S603 - arguments are fixed, not user input
        ["git", *args],  # noqa: S607 - git is resolved from PATH by design
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def tag_is_free_or_here(tag: str) -> bool:
    """Return True if the tag does not exist or already points at HEAD.

    The second case lets a release that failed partway be run again.
    """
    if not git("tag", "--list", tag):
        return True
    return git("rev-list", "-n", "1", tag) == git("rev-parse", "HEAD")


def main() -> int:
    """Check the version, the changelog, and the tag, then write release notes."""
    if len(sys.argv) != 2:  # noqa: PLR2004
        return fail("usage: release_preflight.py <notes-output-path>")
    version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if not SEMVER.match(version) or version == "0.0.0":
        return fail(f"version {version!r} is not a releasable X.Y.Z version")
    notes = changelog_section(Path("CHANGELOG.md").read_text(encoding="utf-8"), version)
    if not notes:
        return fail(f"CHANGELOG.md has no dated section for {version}")
    if not tag_is_free_or_here(f"v{version}"):
        return fail(f"tag v{version} already exists on a different commit")
    Path(sys.argv[1]).write_text(notes + "\n", encoding="utf-8")
    print(version)  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
