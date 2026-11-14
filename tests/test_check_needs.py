# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CI aggregate decision."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_needs.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
_spec = importlib.util.spec_from_file_location("check_needs", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
check_needs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_needs)

CORE = ("static", "test", "docs", "links", "security", "build")
NON_PULL_REQUEST_EVENTS = ("push", "merge_group", "schedule", "workflow_dispatch")


def needs(**overrides: str) -> dict[str, dict[str, str]]:
    results = dict.fromkeys(CORE, "success") | {
        "pull-request": "success",
        "dependency-review": "success",
    }
    results |= {k.replace("_", "-"): v for k, v in overrides.items()}
    return {job: {"result": result} for job, result in results.items()}


def test_all_success_passes() -> None:
    assert check_needs.failures(needs(), "pull_request", "false") == []


@pytest.mark.parametrize("event", NON_PULL_REQUEST_EVENTS)
def test_pull_request_jobs_may_skip_on_other_events(event: str) -> None:
    skipped = needs(pull_request="skipped", dependency_review="skipped")
    assert check_needs.failures(skipped, event, "false") == []


@pytest.mark.parametrize("job", ["pull-request", "dependency-review"])
@pytest.mark.parametrize("private", ["false", "", "unknown"])
def test_pull_request_jobs_cannot_skip_on_a_public_pull_request(job: str, private: str) -> None:
    """A skipped title and sign-off check must not read as a pass on a pull request."""
    skipped = needs(**{job: "skipped"})
    assert check_needs.failures(skipped, "pull_request", private) == [f"{job} (skipped)"]


def test_dependency_review_may_skip_on_a_private_pull_request() -> None:
    assert check_needs.failures(needs(dependency_review="skipped"), "pull_request", "true") == []


def test_title_and_sign_off_check_cannot_skip_on_a_private_pull_request() -> None:
    skipped = needs(pull_request="skipped")
    assert check_needs.failures(skipped, "pull_request", "true") == ["pull-request (skipped)"]


@pytest.mark.parametrize("event", ["", "release", "pull_request_target"])
def test_an_unknown_event_excuses_nothing(event: str) -> None:
    skipped = needs(pull_request="skipped", dependency_review="skipped")
    assert check_needs.failures(skipped, event, "true") == [
        "dependency-review (skipped)",
        "pull-request (skipped)",
    ]


@pytest.mark.parametrize("job", CORE)
@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled", None])
@pytest.mark.parametrize("event", ["pull_request", "push"])
def test_core_jobs_must_succeed(job: str, result: str | None, event: str) -> None:
    changed = needs()
    changed[job] = {} if result is None else {"result": result}
    assert check_needs.failures(changed, event, "false") == [f"{job} ({result})"]


@pytest.mark.parametrize("job", sorted(check_needs.EXPECTED))
def test_a_job_missing_from_needs_fails(job: str) -> None:
    """Dropping a job from ``needs`` in the workflow must not leave the aggregate green."""
    remaining = {k: v for k, v in needs().items() if k != job}
    assert check_needs.failures(remaining, "push", "false") == [f"{job} (missing from needs)"]
    assert check_needs.failures({}, "push", "false") != []


def test_optional_jobs_still_cannot_fail() -> None:
    changed = needs(dependency_review="failure")
    assert check_needs.failures(changed, "pull_request", "false") == ["dependency-review (failure)"]


def test_an_extra_job_must_succeed() -> None:
    changed = needs() | {"new-job": {"result": "skipped"}}
    assert check_needs.failures(changed, "push", "false") == ["new-job (skipped)"]


def test_the_expected_jobs_match_the_workflow() -> None:
    if not CI.exists():
        pytest.skip("workflows are not part of the source distribution")
    text = CI.read_text(encoding="utf-8")
    jobs = set(re.findall(r"^  ([a-z][a-z-]*):\n", text.split("\njobs:\n", 1)[1], re.MULTILINE))
    match = re.search(r"^    needs: \[([^\]]*)\]", text, re.MULTILINE)
    assert match is not None, "the aggregate job must list its needs"
    listed = {name.strip() for name in match.group(1).split(",")}
    assert listed == check_needs.EXPECTED
    assert jobs - {"all-checks-passed"} == check_needs.EXPECTED


def test_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("NEEDS", json.dumps(needs()))
    monkeypatch.setenv("EVENT", "pull_request")
    monkeypatch.setenv("REPO_PRIVATE", "false")
    assert check_needs.main() == 0
    monkeypatch.setenv("NEEDS", json.dumps(needs(build="skipped")))
    assert check_needs.main() == 1
    assert "build (skipped)" in capsys.readouterr().out


def test_main_without_event_and_visibility_excuses_no_skip(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NEEDS", json.dumps(needs(pull_request="skipped")))
    monkeypatch.delenv("EVENT", raising=False)
    monkeypatch.delenv("REPO_PRIVATE", raising=False)
    assert check_needs.main() == 1
    assert "pull-request (skipped)" in capsys.readouterr().out


@pytest.mark.parametrize("value", [None, "not json"])
def test_main_reports_unreadable_needs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("NEEDS", raising=False)
    else:
        monkeypatch.setenv("NEEDS", value)
    assert check_needs.main() == 1
    assert "NEEDS must hold" in capsys.readouterr().out
