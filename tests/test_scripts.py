# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the check scripts and the packaging and workflow settings they rely on."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "scripts" / "check.sh"
DCO = ROOT / "scripts" / "check_dco.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"

needs_bash = pytest.mark.skipif(
    os.name != "posix" or shutil.which("bash") is None or shutil.which("git") is None,
    reason="the check scripts run under bash with git",
)


def _env(home: Path, **extra: str) -> dict[str, str]:
    """A clean environment: no user or system git configuration."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env |= {
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test Author",
        "GIT_AUTHOR_EMAIL": "author@example.com",
        "GIT_COMMITTER_NAME": "Test Author",
        "GIT_COMMITTER_EMAIL": "author@example.com",
    }
    return env | extra


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed git command in a temporary repository
        ["git", *args],  # noqa: S607 - git is looked up on PATH on purpose
        cwd=repo,
        env=_env(repo.parent),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    (path / "file.txt").write_text("base\n", encoding="utf-8")
    _git(path, "add", "file.txt")
    _git(path, "commit", "-q", "-s", "-m", "base")
    return path


def _dco(repo: Path, base: str, head: str, **extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed script path, no shell
        ["bash", str(DCO), base, head],  # noqa: S607 - bash is looked up on PATH on purpose
        cwd=repo,
        env=_env(repo.parent, **extra),
        check=False,
        capture_output=True,
        text=True,
    )


@needs_bash
def test_dco_accepts_a_signed_commit(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "file.txt").write_text("change\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-a", "-s", "-m", "signed")
    result = _dco(repo, base, "HEAD")
    assert result.returncode == 0
    assert "every commit is signed off" in result.stdout


@needs_bash
def test_dco_rejects_an_unsigned_commit(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "file.txt").write_text("change\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-a", "-m", "unsigned")
    result = _dco(repo, base, "HEAD")
    assert result.returncode == 1
    assert "no 'Signed-off-by" in result.stdout
    assert "every commit is signed off" not in result.stdout


@needs_bash
@pytest.mark.parametrize("bad", ["invalid-base", "0" * 40])
def test_dco_fails_when_the_range_cannot_be_listed(repo: Path, bad: str) -> None:
    """An unreadable range must never read as "every commit is signed off"."""
    result = _dco(repo, bad, "invalid-head")
    assert result.returncode != 0
    assert "every commit is signed off" not in result.stdout
    assert "cannot list the commits" in result.stderr


@needs_bash
def test_dco_says_so_when_there_is_nothing_to_check(repo: Path) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    result = _dco(repo, head, head)
    assert result.returncode == 0
    assert "no commits to check" in result.stdout


DEPENDABOT = "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"


def _unsigned_commit(repo: Path, author: str | None = None) -> str:
    """Add an unsigned commit, optionally with a chosen author, and return the base before it."""
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "file.txt").write_text("change\n", encoding="utf-8")
    extra = ["--author", author] if author else []
    _git(repo, "commit", "-q", "-a", *extra, "-m", "unsigned")
    return base


@needs_bash
@pytest.mark.parametrize("pr_author", [None, "", "someone-else", "dependabot", "dependabot[bot]x"])
def test_dco_does_not_exempt_a_forged_dependabot_author(repo: Path, pr_author: str | None) -> None:
    """A commit author is only text; without Dependabot's own pull request it earns no exemption."""
    base = _unsigned_commit(repo, DEPENDABOT)
    extra = {} if pr_author is None else {"PR_AUTHOR": pr_author}
    result = _dco(repo, base, "HEAD", **extra)
    assert result.returncode == 1
    assert "no 'Signed-off-by" in result.stdout
    assert "every commit is signed off" not in result.stdout


@needs_bash
def test_dco_exempts_dependabot_on_its_own_pull_request(repo: Path) -> None:
    base = _unsigned_commit(repo, DEPENDABOT)
    result = _dco(repo, base, "HEAD", PR_AUTHOR="dependabot[bot]")
    assert result.returncode == 0
    assert "every commit is signed off" in result.stdout


@needs_bash
def test_dco_still_checks_other_authors_on_a_dependabot_pull_request(repo: Path) -> None:
    """The exemption is for Dependabot's own commits, not for the whole pull request."""
    base = _unsigned_commit(repo)
    result = _dco(repo, base, "HEAD", PR_AUTHOR="dependabot[bot]")
    assert result.returncode == 1
    assert "no 'Signed-off-by: Test Author <author@example.com>'" in result.stdout


FAKE_UV = """#!/usr/bin/env bash
case "$1" in
  export) echo "example==1.0" ;;
  run) printf '%s\\n' "$*" >> "$UV_LOG"; sleep "${UV_SLEEP:-0}"; exit "${UV_RUN_EXIT:-0}" ;;
esac
"""


def _deps(
    tmp_path: Path, shared_tmp: Path, name: str = "uv", **extra: str
) -> tuple[int, list[str]]:
    """Run the deps stage with a fake uv. Return the exit code and the audit file paths used."""
    bin_dir = tmp_path / f"bin-{name}"
    bin_dir.mkdir(exist_ok=True)
    uv = bin_dir / "uv"
    uv.write_text(FAKE_UV, encoding="utf-8")
    uv.chmod(0o755)
    log = tmp_path / f"{name}.log"
    env = _env(
        tmp_path,
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        TMPDIR=str(shared_tmp),
        UV_LOG=str(log),
        **extra,
    )
    result = subprocess.run(  # noqa: S603 - fixed script path, no shell
        ["bash", str(CHECK), "deps"],  # noqa: S607 - bash is looked up on PATH on purpose
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    paths = [
        m.group(1) for line in lines if (m := re.search(r"(\S+requirements-audit\.txt)", line))
    ]
    return result.returncode, paths


@needs_bash
def test_dependency_audit_uses_a_private_file_and_leaves_planted_links_alone(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep me\n", encoding="utf-8")
    (shared / "requirements-audit.txt").symlink_to(sentinel)
    code, first = _deps(tmp_path, shared)
    assert code == 0
    assert sentinel.read_text(encoding="utf-8") == "keep me\n"
    assert first
    assert first[0] != str(shared / "requirements-audit.txt")
    assert not Path(first[0]).exists()
    assert not Path(first[0]).parent.exists()


@needs_bash
def test_concurrent_dependency_audits_do_not_share_a_path(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs = [pool.submit(_deps, tmp_path, shared, name, UV_SLEEP="1") for name in ("a", "b")]
        (code_a, paths_a), (code_b, paths_b) = (run.result() for run in runs)
    assert code_a == code_b == 0
    assert paths_a[0] != paths_b[0]


@needs_bash
def test_a_failing_dependency_audit_still_fails_and_cleans_up(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    code, paths = _deps(tmp_path, shared, UV_RUN_EXIT="1")
    assert code != 0
    assert not Path(paths[0]).parent.exists()
    assert list(shared.iterdir()) == []


def test_source_distribution_carries_the_scripts_its_tests_load() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    included = config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert "scripts" in included
    assert "tests" in included


def test_pull_request_checks_rerun_when_the_title_is_edited() -> None:
    if not CI.exists():
        pytest.skip("workflows are not part of the source distribution")
    text = CI.read_text(encoding="utf-8")
    match = re.search(
        r"^  pull_request:\n(?:    #.*\n)*    types: \[([^\]]*)\]", text, re.MULTILINE
    )
    assert match is not None, "pull_request must list its activity types"
    types = {t.strip() for t in match.group(1).split(",")}
    assert {"opened", "synchronize", "reopened", "edited"} <= types
