# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the release publishing script, against a simulated GitHub."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "publish_release.py"
EVIDENCE = ROOT / "scripts" / "release_evidence.sh"
_spec = importlib.util.spec_from_file_location("publish_release", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
pr = importlib.util.module_from_spec(_spec)
sys.modules["publish_release"] = pr
_spec.loader.exec_module(pr)

REPO = "faithful-oversight/faithful-toledot"
TAG = "v0.1.0"
SHA = "a" * 40
REF = pr.ReleaseRef(REPO, TAG, SHA)


class FakeGitHub:
    """An in-memory GitHub with just enough behavior for the script."""

    def __init__(self) -> None:
        self.release_list: list[dict[str, Any]] = []
        self.tags: dict[str, str] = {}
        self.uploads: list[str] = []
        self.fail_upload: str | None = None

    def releases(self, repo: str) -> list[dict[str, Any]]:
        return self.release_list

    def create_draft(self, repo: str, tag: str, target: str, notes: str) -> dict[str, Any]:
        release = {"id": 1, "tag_name": tag, "target_commitish": target, "draft": True}
        release |= {"body": notes, "assets": []}
        self.release_list.append(release)
        return release

    def upload(self, repo: str, tag: str, path: Path) -> None:
        if path.name == self.fail_upload:
            raise pr.ReleaseError("network error")
        release = next(r for r in self.release_list if r["tag_name"] == tag)
        if any(a["name"] == path.name for a in release["assets"]):
            raise pr.ReleaseError("already exists")
        release["assets"].append({"name": path.name, "digest": "sha256:" + pr.sha256(path)})
        self.uploads.append(path.name)

    def publish(self, repo: str, release_id: int) -> None:
        release = next(r for r in self.release_list if r["id"] == release_id)
        release["draft"] = False
        self.tags[release["tag_name"]] = release["target_commitish"]

    def tag_commit(self, repo: str, tag: str) -> str | None:
        return self.tags.get(tag)


@pytest.fixture
def assets(tmp_path: Path) -> list[Path]:
    paths = []
    for name, content in (("a.whl", b"wheel"), ("a.tar.gz", b"sdist"), ("SHA256SUMS", b"sums")):
        path = tmp_path / name
        path.write_bytes(content)
        paths.append(path)
    return paths


def test_fresh_release_is_staged_then_published(assets: list[Path]) -> None:
    gh = FakeGitHub()
    pr.stage(gh, REF, "notes", assets)
    assert gh.release_list[0]["draft"]
    assert sorted(gh.uploads) == sorted(p.name for p in assets)
    pr.publish(gh, REF, assets)
    assert not gh.release_list[0]["draft"]
    assert gh.tags[TAG] == SHA


def test_partial_draft_resumes_only_missing_uploads(assets: list[Path]) -> None:
    gh = FakeGitHub()
    gh.fail_upload = "a.tar.gz"
    with pytest.raises(pr.ReleaseError, match="network error"):
        pr.stage(gh, REF, "notes", assets)
    gh.fail_upload = None
    gh.uploads.clear()
    pr.stage(gh, REF, "notes", assets)
    assert "a.tar.gz" in gh.uploads
    assert len(gh.release_list) == 1
    pr.publish(gh, REF, assets)


def test_rerun_with_rebuilt_evidence_resumes(assets: list[Path], tmp_path: Path) -> None:
    """A rerun rebuilds every file in a new place; identical bytes resume the draft.

    Resuming depends on the rebuild giving identical bytes, which
    test_release_evidence_is_reproducible and scripts/check.sh build check.
    Different bytes stop the rerun instead.
    """
    gh = FakeGitHub()
    gh.fail_upload = "SHA256SUMS"
    with pytest.raises(pr.ReleaseError, match="network error"):
        pr.stage(gh, REF, "notes", assets)
    first_run = set(gh.uploads)
    rebuilt_dir = tmp_path / "rerun"
    rebuilt_dir.mkdir()
    rebuilt = []
    for path in assets:
        copy = rebuilt_dir / path.name
        copy.write_bytes(path.read_bytes())
        rebuilt.append(copy)
    gh.fail_upload = None
    gh.uploads.clear()
    pr.stage(gh, REF, "notes", rebuilt)
    assert set(gh.uploads) == {p.name for p in assets} - first_run
    assert "SHA256SUMS" in gh.uploads
    pr.publish(gh, REF, rebuilt)
    (rebuilt_dir / "SHA256SUMS").write_bytes(b"different sums")
    with pytest.raises(pr.ReleaseError, match="SHA256SUMS"):
        pr.stage(gh, REF, "notes", rebuilt)


def test_incomplete_release_is_never_published(assets: list[Path]) -> None:
    gh = FakeGitHub()
    gh.create_draft(REPO, TAG, SHA, "notes")
    with pytest.raises(pr.ReleaseError, match="missing"):
        pr.publish(gh, REF, assets)
    assert gh.release_list[0]["draft"] is True


def test_partial_published_release_is_not_treated_as_done(assets: list[Path]) -> None:
    gh = FakeGitHub()
    gh.create_draft(REPO, TAG, SHA, "notes")
    gh.upload(REPO, TAG, assets[0])
    gh.publish(REPO, 1)
    with pytest.raises(pr.ReleaseError, match="missing"):
        pr.publish(gh, REF, assets)
    pr.stage(gh, REF, "notes", assets)
    pr.publish(gh, REF, assets)


def test_complete_release_rerun_changes_nothing(
    assets: list[Path], capsys: pytest.CaptureFixture[str]
) -> None:
    gh = FakeGitHub()
    pr.stage(gh, REF, "notes", assets)
    pr.publish(gh, REF, assets)
    gh.uploads.clear()
    pr.stage(gh, REF, "notes", assets)
    pr.publish(gh, REF, assets)
    assert gh.uploads == []
    assert "already published and complete" in capsys.readouterr().out


def test_conflicting_bytes_stop_the_release(assets: list[Path]) -> None:
    gh = FakeGitHub()
    pr.stage(gh, REF, "notes", assets)
    assets[0].write_bytes(b"rebuilt differently")
    with pytest.raises(pr.ReleaseError, match="different bytes"):
        pr.stage(gh, REF, "notes", assets)
    with pytest.raises(pr.ReleaseError, match="different bytes"):
        pr.publish(gh, REF, assets)


def test_unexpected_or_unverifiable_assets_stop_the_release(assets: list[Path]) -> None:
    gh = FakeGitHub()
    gh.create_draft(REPO, TAG, SHA, "notes")
    gh.release_list[0]["assets"].append({"name": "extra.zip", "digest": "sha256:00"})
    with pytest.raises(pr.ReleaseError, match="not part of this build"):
        pr.stage(gh, REF, "notes", assets)
    gh.release_list[0]["assets"] = [{"name": "a.whl", "digest": None}]
    with pytest.raises(pr.ReleaseError, match="no recorded digest"):
        pr.stage(gh, REF, "notes", assets)


def test_wrong_commit_stops_the_release(assets: list[Path]) -> None:
    gh = FakeGitHub()
    gh.create_draft(REPO, TAG, "b" * 40, "notes")
    with pytest.raises(pr.ReleaseError, match="targets"):
        pr.stage(gh, REF, "notes", assets)
    gh.tags[TAG] = "c" * 40
    with pytest.raises(pr.ReleaseError, match="points at"):
        pr.publish(gh, REF, assets)


def test_duplicate_releases_for_a_tag_stop_the_release(assets: list[Path]) -> None:
    gh = FakeGitHub()
    gh.create_draft(REPO, TAG, SHA, "notes")
    gh.create_draft(REPO, TAG, SHA, "notes")
    with pytest.raises(pr.ReleaseError, match="2 releases"):
        pr.stage(gh, REF, "notes", assets)


def test_publish_needs_a_staged_release(assets: list[Path]) -> None:
    with pytest.raises(pr.ReleaseError, match="run the stage step"):
        pr.publish(FakeGitHub(), REF, assets)


def test_verify_pypi(assets: list[Path]) -> None:
    dists = assets[:2]
    urls: list[dict[str, Any]] = [
        {"filename": p.name, "digests": {"sha256": pr.sha256(p)}} for p in dists
    ]
    data = {"urls": urls}
    pr.verify_pypi("faithful-toledot", "0.1.0", dists, fetch=lambda _: data)
    urls[0]["digests"] = {"sha256": "0" * 64}
    with pytest.raises(pr.ReleaseError, match="different bytes"):
        pr.verify_pypi("faithful-toledot", "0.1.0", dists, fetch=lambda _: data)
    with pytest.raises(pr.ReleaseError, match="differ from this build"):
        pr.verify_pypi("faithful-toledot", "0.1.0", dists, fetch=lambda _: {"urls": []})


def test_main_reports_errors_and_runs_steps(
    assets: list[Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gh = FakeGitHub()
    notes = tmp_path / "notes.md"
    notes.write_text("notes", encoding="utf-8")
    base = ["--repo", REPO, "--tag", TAG, "--target", SHA]
    assert pr.main(["publish", *base, *map(str, assets)], api=gh) == 1
    assert "::error::" in capsys.readouterr().err
    assert pr.main(["stage", *base, "--notes", str(notes), *map(str, assets)], api=gh) == 0
    assert pr.main(["publish", *base, *map(str, assets)], api=gh) == 0


@pytest.mark.skipif(
    os.name != "posix" or shutil.which("git") is None or shutil.which("uv") is None,
    reason="release evidence is built on Linux, with git and uv",
)
def test_release_evidence_is_reproducible(tmp_path: Path) -> None:
    """Two runs of scripts/release_evidence.sh give the same SBOM and SHA256SUMS."""
    outputs = []
    for run in ("first", "second"):
        dist = tmp_path / run
        dist.mkdir()
        (dist / "package.whl").write_bytes(b"wheel")
        subprocess.run(  # noqa: S603 - fixed script path, no shell
            [str(EVIDENCE), str(dist)], cwd=ROOT, check=True, capture_output=True
        )
        outputs.append({p.name: p.read_bytes() for p in dist.iterdir()})
    assert outputs[0] == outputs[1]
    assert sorted(outputs[0]) == ["SHA256SUMS", "package.whl", "sbom.cdx.json"]
    sbom = json.loads(outputs[0]["sbom.cdx.json"])
    assert "serialNumber" not in sbom
