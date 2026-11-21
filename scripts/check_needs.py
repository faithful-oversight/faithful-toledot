# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Decide whether the CI aggregate check passes.

Reads the ``needs`` context as JSON from the ``NEEDS`` environment variable, the
triggering event from ``EVENT``, and the repository visibility from
``REPO_PRIVATE`` (``true`` or ``false``).

Every job in ``EXPECTED`` must appear in ``needs`` and must succeed. A job that
is missing from ``needs`` fails the aggregate, so dropping a job from the
workflow cannot go unnoticed. Two jobs may be skipped, and only where the
workflow itself skips them:

* ``pull-request`` runs on pull requests only.
* ``dependency-review`` runs on pull requests in a public repository.

Unknown values never excuse a skip. An empty or unrecognized ``EVENT``, or a
``REPO_PRIVATE`` other than ``true``, means the job was expected to run.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

EXPECTED = frozenset(
    {"static", "test", "docs", "links", "security", "build", "pull-request", "dependency-review"}
)
"""The jobs the aggregate waits for. Keep in sync with ``needs`` in ci.yml; a test checks it."""

PULL_REQUEST = "pull_request"
OTHER_EVENTS = frozenset({"push", "merge_group", "schedule", "workflow_dispatch"})
"""Events on which pull-request jobs do not apply. ``workflow_call`` reports its caller's event."""


def may_skip(job: str, event: str, private: str) -> bool:
    """Return True if the workflow legitimately skips this job for this event."""
    if job == "pull-request":
        return event in OTHER_EVENTS
    if job == "dependency-review":
        return event in OTHER_EVENTS or (event == PULL_REQUEST and private == "true")
    return False


def failures(needs: dict[str, Any], event: str = "", private: str = "") -> list[str]:
    """Return the jobs that block the aggregate, with their results."""
    bad = [f"{job} (missing from needs)" for job in sorted(EXPECTED - needs.keys())]
    for job, info in sorted(needs.items()):
        result = info.get("result")
        if result == "success" or (result == "skipped" and may_skip(job, event, private)):
            continue
        bad.append(f"{job} ({result})")
    return bad


def main() -> int:
    """Print each job's result and fail if any required job did not pass."""
    try:
        needs = json.loads(os.environ["NEEDS"])
    except (KeyError, json.JSONDecodeError):
        print("::error::NEEDS must hold the needs context as JSON")  # noqa: T201
        return 1
    event = os.environ.get("EVENT", "")
    private = os.environ.get("REPO_PRIVATE", "")
    print(f"event: {event or '(unset)'}; repository private: {private or '(unset)'}")  # noqa: T201
    for job, info in sorted(needs.items()):
        print(f"{job}: {info.get('result')}")  # noqa: T201
    bad = failures(needs, event, private)
    if bad:
        print("::error::required jobs did not pass: " + ", ".join(bad))  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
