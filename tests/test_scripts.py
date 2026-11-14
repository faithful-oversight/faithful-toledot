# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the check scripts and the packaging and workflow settings they rely on."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tomllib
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "scripts" / "check.sh"
DCO = ROOT / "scripts" / "check_dco.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
VISIBILITY = ROOT / "scripts" / "check_visibility.sh"
VERIFY = ROOT / "scripts" / "verify_artifacts.sh"
VALE_INSTALL = ROOT / "scripts" / "install_vale_styles.sh"
VALE_LOCK = ROOT / "scripts" / "vale-styles.lock"

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


def _run_script(
    script: Path, *args: str, home: Path, **extra: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed script path, no shell
        ["bash", str(script), *args],  # noqa: S607 - bash is looked up on PATH on purpose
        env=_env(home, **extra),
        check=False,
        capture_output=True,
        text=True,
    )


def _fake_gh(tmp_path: Path, answer: str, exit_code: int = 0) -> str:
    """Return a PATH whose gh prints ``answer`` and exits with ``exit_code``."""
    bin_dir = tmp_path / "gh-bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(f"#!/usr/bin/env bash\necho '{answer}'\nexit {exit_code}\n", encoding="utf-8")
    gh.chmod(0o755)
    return f"{bin_dir}{os.pathsep}{os.environ['PATH']}"


def _visibility(
    tmp_path: Path, private: str, public_variable: str | None, gh_exit: int = 0
) -> tuple[subprocess.CompletedProcess[str], str]:
    out = tmp_path / "github-output"
    out.write_text("", encoding="utf-8")
    extra = {"PATH": _fake_gh(tmp_path, private, gh_exit), "GITHUB_OUTPUT": str(out)}
    if public_variable is not None:
        extra["FO_PUBLIC"] = public_variable
    result = _run_script(VISIBILITY, "faithful-oversight/example", home=tmp_path, **extra)
    return result, out.read_text(encoding="utf-8")


@needs_bash
@pytest.mark.parametrize(
    ("private", "variable", "expected"),
    [
        ("false", "true", "public=true"),
        ("true", "false", "public=false"),
        ("true", None, "public=false"),
    ],
)
def test_visibility_accepts_a_variable_that_matches_the_repository(
    tmp_path: Path, private: str, variable: str | None, expected: str
) -> None:
    result, output = _visibility(tmp_path, private, variable)
    assert result.returncode == 0, result.stderr + result.stdout
    assert output.strip() == expected


@needs_bash
@pytest.mark.parametrize("variable", [None, "", "false", "True", "yes"])
def test_a_public_repository_with_the_variable_off_cannot_release(
    tmp_path: Path, variable: str | None
) -> None:
    """Releasing then would skip provenance and PyPI and still finish green (CI-06)."""
    result, output = _visibility(tmp_path, "false", variable)
    assert result.returncode == 1
    assert "is public but the FO_PUBLIC variable is" in result.stdout
    assert "public=" not in output


@needs_bash
def test_a_private_repository_with_the_variable_on_cannot_release(tmp_path: Path) -> None:
    result, output = _visibility(tmp_path, "true", "true")
    assert result.returncode == 1
    assert "is private but the FO_PUBLIC variable is 'true'" in result.stdout
    assert "public=" not in output


@needs_bash
def test_visibility_fails_when_the_repository_cannot_be_read(tmp_path: Path) -> None:
    result, output = _visibility(tmp_path, "", "true", gh_exit=1)
    assert result.returncode == 1
    assert "cannot read the visibility" in result.stderr
    assert "public=" not in output


@needs_bash
@pytest.mark.parametrize("answer", ["", "null", "maybe"])
def test_visibility_fails_on_an_answer_it_does_not_understand(tmp_path: Path, answer: str) -> None:
    result, output = _visibility(tmp_path, answer, "true")
    assert result.returncode == 1
    assert "unexpected visibility answer" in result.stderr
    assert "public=" not in output


def _release_jobs() -> dict[str, str]:
    """Split release.yml into its jobs, keyed by job id."""
    text = RELEASE.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z][a-z-]*):\n", text, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_the_release_decides_public_status_from_the_repository_not_the_variable() -> None:
    if not RELEASE.exists():
        pytest.skip("workflows are not part of the source distribution")
    jobs = _release_jobs()
    uses_variable = [job for job, body in jobs.items() if "vars.FO_PUBLIC" in body]
    assert uses_variable == ["preflight"], "only the visibility check may read the variable"
    assert "scripts/check_visibility.sh" in jobs["preflight"]
    for job in ("github-draft", "pypi", "github-publish"):
        assert "needs.preflight.outputs.public" in jobs[job]
    assert "needs.pypi.result == 'skipped' && needs.preflight.outputs.public != 'true'" in re.sub(
        r"\s+", " ", jobs["github-publish"]
    )


def test_every_release_job_verifies_the_downloaded_artifact_before_using_it() -> None:
    if not RELEASE.exists():
        pytest.skip("workflows are not part of the source distribution")
    consumers = ("attest-build-provenance", "publish_release.py", "gh-action-pypi-publish", "cp ")
    checked = 0
    for job, body in _release_jobs().items():
        if "actions/download-artifact" not in body:
            continue
        download = body.index("actions/download-artifact")
        verify = body.find("scripts/verify_artifacts.sh release/dist", download)
        assert verify != -1, f"{job} downloads the artifact without verifying it"
        for marker in consumers:
            use = body.find(marker, download)
            assert use == -1 or verify < use, f"{job} uses the artifact ({marker}) before verifying"
        checked += 1
    assert checked == 3  # github-draft, pypi, github-publish


def _dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "pkg-1.0-py3-none-any.whl").write_bytes(b"wheel")
    (dist / "pkg-1.0.tar.gz").write_bytes(b"sdist")
    (dist / "sbom-base.cdx.json").write_bytes(b"{}")
    sums = subprocess.run(  # noqa: S603 - fixed command in a temporary directory
        ["sha256sum", "--", *sorted(p.name for p in dist.iterdir())],  # noqa: S607
        cwd=dist,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (dist / "SHA256SUMS").write_text(sums, encoding="utf-8")
    return dist


def _verify(tmp_path: Path, dist: Path) -> subprocess.CompletedProcess[str]:
    return _run_script(VERIFY, str(dist), home=tmp_path)


@needs_bash
@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="needs sha256sum")
class TestVerifyArtifacts:
    """The release jobs act only on the bytes the build wrote."""

    def test_accepts_an_intact_directory(self, tmp_path: Path) -> None:
        result = _verify(tmp_path, _dist(tmp_path))
        assert result.returncode == 0, result.stderr
        assert "verified 3 files" in result.stdout

    def test_rejects_a_changed_file(self, tmp_path: Path) -> None:
        dist = _dist(tmp_path)
        (dist / "pkg-1.0-py3-none-any.whl").write_bytes(b"tampered")
        result = _verify(tmp_path, dist)
        assert result.returncode == 1
        assert "do not match SHA256SUMS" in result.stderr

    def test_rejects_a_missing_file(self, tmp_path: Path) -> None:
        dist = _dist(tmp_path)
        (dist / "pkg-1.0.tar.gz").unlink()
        assert _verify(tmp_path, dist).returncode == 1

    def test_rejects_a_file_the_list_does_not_name(self, tmp_path: Path) -> None:
        dist = _dist(tmp_path)
        (dist / "extra-1.0-py3-none-any.whl").write_bytes(b"not built here")
        result = _verify(tmp_path, dist)
        assert result.returncode == 1
        assert "differ from the files SHA256SUMS lists" in result.stderr

    def test_rejects_a_directory_without_checksums(self, tmp_path: Path) -> None:
        dist = _dist(tmp_path)
        (dist / "SHA256SUMS").unlink()
        result = _verify(tmp_path, dist)
        assert result.returncode == 1
        assert "SHA256SUMS is missing" in result.stderr


def _style_zip(path: Path, package: str, files: dict[str, str]) -> str:
    """Write a style package zip and return its SHA-256."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in files.items():
            archive.writestr(f"{package}/{name}", text)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _install_styles(
    tmp_path: Path, lock_text: str, dest: Path | None = None
) -> subprocess.CompletedProcess[str]:
    lock = tmp_path / "styles.lock"
    lock.write_text(lock_text, encoding="utf-8")
    return _run_script(VALE_INSTALL, str(lock), str(dest or tmp_path / "styles"), home=tmp_path)


@needs_bash
@pytest.mark.skipif(shutil.which("curl") is None, reason="needs curl")
class TestInstallValeStyles:
    """Vale styles come from pinned releases whose digest is checked before unpacking."""

    def test_installs_a_package_that_matches_its_digest(self, tmp_path: Path) -> None:
        digest = _style_zip(tmp_path / "Demo.zip", "Demo", {"Rule.yml": "extends: existence\n"})
        result = _install_styles(
            tmp_path, f"# comment\n\nDemo {(tmp_path / 'Demo.zip').as_uri()} {digest}\n"
        )
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "styles" / "Demo" / "Rule.yml").read_text(encoding="utf-8") == (
            "extends: existence\n"
        )

    def test_replaces_an_existing_copy_without_leaving_stale_files(self, tmp_path: Path) -> None:
        digest = _style_zip(tmp_path / "Demo.zip", "Demo", {"New.yml": "new\n"})
        stale = tmp_path / "styles" / "Demo"
        stale.mkdir(parents=True)
        (stale / "Old.yml").write_text("from an unpinned sync\n", encoding="utf-8")
        result = _install_styles(tmp_path, f"Demo {(tmp_path / 'Demo.zip').as_uri()} {digest}\n")
        assert result.returncode == 0, result.stderr
        assert sorted(p.name for p in stale.iterdir()) == ["New.yml"]

    def test_rejects_a_package_that_does_not_match_its_digest(self, tmp_path: Path) -> None:
        _style_zip(tmp_path / "Demo.zip", "Demo", {"Rule.yml": "changed upstream\n"})
        result = _install_styles(tmp_path, f"Demo {(tmp_path / 'Demo.zip').as_uri()} {'0' * 64}\n")
        assert result.returncode == 1
        assert "does not match its pinned SHA-256" in result.stderr
        assert not (tmp_path / "styles" / "Demo").exists()

    def test_rejects_a_package_that_cannot_be_downloaded(self, tmp_path: Path) -> None:
        missing = (tmp_path / "missing.zip").as_uri()
        result = _install_styles(tmp_path, f"Demo {missing} {'0' * 64}\n")
        assert result.returncode == 1
        assert "cannot download Vale package Demo" in result.stderr

    def test_rejects_a_zip_without_the_package_directory(self, tmp_path: Path) -> None:
        digest = _style_zip(tmp_path / "Demo.zip", "Other", {"Rule.yml": "x\n"})
        result = _install_styles(tmp_path, f"Demo {(tmp_path / 'Demo.zip').as_uri()} {digest}\n")
        assert result.returncode == 1
        assert "does not contain a Demo directory" in result.stderr

    @pytest.mark.parametrize(
        "line",
        [
            "Demo https://example.com/Demo.zip",
            "Demo https://example.com/Demo.zip nothex",
            "../x u " + "0" * 64,
        ],
    )
    def test_rejects_a_malformed_line(self, tmp_path: Path, line: str) -> None:
        result = _install_styles(tmp_path, line + "\n")
        assert result.returncode == 1
        assert "bad line" in result.stderr

    def test_rejects_a_lock_file_with_no_packages(self, tmp_path: Path) -> None:
        result = _install_styles(tmp_path, "# nothing pinned\n")
        assert result.returncode == 1
        assert "lists no packages" in result.stderr


def test_the_docs_check_installs_pinned_styles_and_never_syncs() -> None:
    assert "vale sync" not in CHECK.read_text(encoding="utf-8").replace("`vale sync`", "")
    assert "scripts/install_vale_styles.sh" in CHECK.read_text(encoding="utf-8")
    entries = [
        line.split()
        for line in VALE_LOCK.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert {name for name, _, _ in entries} >= {"Google", "write-good"}
    for name, url, digest in entries:
        assert re.fullmatch(
            r"https://github\.com/errata-ai/[\w-]+/releases/download/v\d+\.\d+\.\d+/"
            + re.escape(name)
            + r"\.zip",
            url,
        ), f"{name} must name one release"
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_one_uv_version_is_pinned_for_every_workflow() -> None:
    workflows = ROOT / ".github" / "workflows"
    if not workflows.exists():
        pytest.skip("workflows are not part of the source distribution")
    versions = set()
    for path in sorted(workflows.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        steps = re.findall(
            r"uses: astral-sh/setup-uv@\S+ # \S+\n        with:\n          version: (.+)\n", text
        )
        assert text.count("uses: astral-sh/setup-uv@") == len(steps), (
            f"{path.name}: every setup-uv step needs the pinned version"
        )
        if steps:
            assert set(steps) == {"${{ env.FO_UV_VERSION }}"}
            match = re.search(r'^  FO_UV_VERSION: "(\d+\.\d+\.\d+)"$', text, re.MULTILINE)
            assert match is not None, f"{path.name} must define FO_UV_VERSION"
            versions.add(match.group(1))
    assert len(versions) == 1, f"workflows pin different uv versions: {sorted(versions)}"


FAKE_ZIZMOR_UV = """#!/usr/bin/env bash
[[ "$1" == run ]] || exit 0
{
  printf 'args: %s\\n' "$*"
  printf 'GH_TOKEN=%s GITHUB_TOKEN=%s ZIZMOR_GITHUB_TOKEN=%s\\n' \
    "${GH_TOKEN-unset}" "${GITHUB_TOKEN-unset}" "${ZIZMOR_GITHUB_TOKEN-unset}"
} >> "$UV_LOG"
cat "$ZIZMOR_OUTPUT"
exit "${ZIZMOR_EXIT:-0}"
"""

ZIZMOR_FATAL_OUTPUT = """ INFO zizmor: zizmor v1.32.0
fatal: no audit was performed
'artipacked' audit failed on file://.github/workflows/ci.yml

Caused by:
    0: error in 'artipacked' audit
    1: couldn't list tags for actions/checkout
    2: request error while accessing GitHub API
    3: HTTP status client error (401 Unauthorized) for url (https://github.com/x.git/git-upload-pack)

Stack backtrace:
   0: <anyhow::Error as core::convert::From<zizmor::Error>>::from
   1: zizmor::main
"""


def _workflows(
    tmp_path: Path, output: str, exit_code: int, env: dict[str, str]
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the workflows stage against a fake zizmor and return its log lines."""
    bin_dir = tmp_path / "bin-zizmor"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(FAKE_ZIZMOR_UV, encoding="utf-8")
    uv.chmod(0o755)
    canned = tmp_path / "zizmor-output.txt"
    canned.write_text(output, encoding="utf-8")
    log = tmp_path / "zizmor.log"
    # Start from an environment with no token of the machine this runs on.
    base = {k: v for k, v in _env(tmp_path).items() if k not in TOKEN_VARIABLES}
    base["PATH"] = f"{bin_dir}{os.pathsep}{base['PATH']}"
    base |= {"UV_LOG": str(log), "ZIZMOR_OUTPUT": str(canned), "ZIZMOR_EXIT": str(exit_code)}
    result = subprocess.run(  # noqa: S603 - fixed script path, no shell
        ["bash", str(CHECK), "workflows"],  # noqa: S607 - bash is looked up on PATH on purpose
        env=base | env,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, log.read_text(encoding="utf-8").splitlines() if log.exists() else []


TOKEN_VARIABLES = ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN")


@needs_bash
def test_a_rejected_github_token_gets_a_clear_message_not_a_stack_trace(tmp_path: Path) -> None:
    result, log = _workflows(tmp_path, ZIZMOR_FATAL_OUTPUT, 1, {"GH_TOKEN": "expired"})
    assert result.returncode == 1
    assert "401 Unauthorized" in result.stderr
    assert "GH_TOKEN" in result.stderr
    assert "unset GH_TOKEN and GITHUB_TOKEN" in result.stderr
    assert "Stack backtrace" not in result.stderr + result.stdout
    assert "--offline" not in log[0], "a set token must not silently drop the online audits"


@needs_bash
@pytest.mark.parametrize("variable", TOKEN_VARIABLES)
def test_any_zizmor_token_variable_keeps_the_online_audits(tmp_path: Path, variable: str) -> None:
    result, log = _workflows(tmp_path, "No findings\n", 0, {variable: "valid"})
    assert result.returncode == 0
    assert "--offline" not in log[0]


@needs_bash
@pytest.mark.parametrize("empty", [{}, {"GH_TOKEN": ""}, {"GITHUB_TOKEN": "", "GH_TOKEN": ""}])
def test_without_a_token_zizmor_runs_offline_and_never_sees_an_empty_one(
    tmp_path: Path, empty: dict[str, str]
) -> None:
    """Zizmor rejects an empty GH_TOKEN even with --offline, so the variables must be gone."""
    result, log = _workflows(tmp_path, "No findings\n", 0, empty)
    assert result.returncode == 0
    assert "--offline" in log[0]
    assert log[1] == "GH_TOKEN=unset GITHUB_TOKEN=unset ZIZMOR_GITHUB_TOKEN=unset"


@needs_bash
def test_workflow_findings_keep_their_exit_code_and_output(tmp_path: Path) -> None:
    result, _ = _workflows(
        tmp_path, "warning[artipacked]: credential persistence\n", 14, {"GH_TOKEN": "valid"}
    )
    assert result.returncode == 14
    assert "credential persistence" in result.stdout
    assert "could not finish" not in result.stderr
