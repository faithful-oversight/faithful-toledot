# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CI aggregate decision."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_needs.py"
_spec = importlib.util.spec_from_file_location("check_needs", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
check_needs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_needs)

CORE = ("static", "test", "docs", "links", "security", "build")


def needs(**overrides: str) -> dict[str, dict[str, str]]:
    results = dict.fromkeys(CORE, "success") | {
        "pull-request": "success",
        "dependency-review": "skipped",
    }
    results |= {k.replace("_", "-"): v for k, v in overrides.items()}
    return {job: {"result": result} for job, result in results.items()}


def test_all_success_passes() -> None:
    assert check_needs.failures(needs()) == []


def test_intended_skips_pass() -> None:
    assert check_needs.failures(needs(pull_request="skipped")) == []


@pytest.mark.parametrize("job", CORE)
@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled"])
def test_core_jobs_must_succeed(job: str, result: str) -> None:
    assert check_needs.failures(needs(**{job: result})) == [f"{job} ({result})"]


def test_optional_jobs_still_cannot_fail() -> None:
    assert check_needs.failures(needs(dependency_review="failure")) == [
        "dependency-review (failure)"
    ]


def test_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("NEEDS", json.dumps(needs()))
    assert check_needs.main() == 0
    monkeypatch.setenv("NEEDS", json.dumps(needs(build="skipped")))
    assert check_needs.main() == 1
    assert "build (skipped)" in capsys.readouterr().out
