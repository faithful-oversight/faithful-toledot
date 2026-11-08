# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Decide whether the CI aggregate check passes.

Reads the ``needs`` context as JSON from the ``NEEDS`` environment variable.
Core jobs must succeed. Only the jobs in ``MAY_SKIP`` may also be skipped,
because they run only in some situations.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

MAY_SKIP = {
    "pull-request": "runs on pull requests only",
    "dependency-review": "needs a public repository",
}


def failures(needs: dict[str, Any]) -> list[str]:
    """Return the jobs that block the aggregate, with their results."""
    bad = []
    for job, info in sorted(needs.items()):
        result = info.get("result")
        allowed = {"success", "skipped"} if job in MAY_SKIP else {"success"}
        if result not in allowed:
            bad.append(f"{job} ({result})")
    return bad


def main() -> int:
    """Print each job's result and fail if any required job did not pass."""
    needs = json.loads(os.environ["NEEDS"])
    for job, info in sorted(needs.items()):
        print(f"{job}: {info.get('result')}")  # noqa: T201
    bad = failures(needs)
    if bad:
        print("::error::required jobs did not pass: " + ", ".join(bad))  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
