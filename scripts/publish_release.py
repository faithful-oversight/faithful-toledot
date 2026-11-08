# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Publish a GitHub release safely, and resume a release that failed partway.

A release is never treated as done just because it exists. Every step checks the
actual state first:

``stage``
    Create a draft release for the tag, or reuse the existing one. Upload any
    missing assets. An asset that already exists must have the same SHA-256 as
    the local file; different bytes stop the run. An asset that is not part of
    this build also stops the run.
``publish``
    Check that the release targets the expected commit and holds exactly the
    expected assets with matching digests, then publish the draft. A release
    that is already published and complete is left as it is.
``verify-pypi``
    Check that every distribution on PyPI for this version has the same SHA-256
    as the local file.

Usage:
    publish_release.py stage --repo OWNER/NAME --tag vX.Y.Z --target SHA --notes FILE ASSET...
    publish_release.py publish --repo OWNER/NAME --tag vX.Y.Z --target SHA ASSET...
    publish_release.py verify-pypi --project NAME --version X.Y.Z ASSET...

The GitHub calls use the ``gh`` command, authenticated with ``GH_TOKEN``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class ReleaseRef:
    """Which release to work on: repository, tag, and the commit it must point at."""

    repo: str
    tag: str
    target: str


class ReleaseError(Exception):
    """The release is in a state this script will not change automatically."""


class Api(Protocol):
    """The GitHub operations this script needs."""

    def releases(self, repo: str) -> list[dict[str, Any]]:
        """Return all releases, including drafts."""

    def create_draft(self, repo: str, tag: str, target: str, notes: str) -> dict[str, Any]:
        """Create a draft release and return it."""

    def upload(self, repo: str, tag: str, path: Path) -> None:
        """Upload one asset to the release for a tag, failing if it already exists."""

    def publish(self, repo: str, release_id: int) -> None:
        """Turn a draft release into a published release."""

    def tag_commit(self, repo: str, tag: str) -> str | None:
        """Return the commit a tag points to, or None if the tag does not exist."""


def sha256(path: Path) -> str:
    """Return the hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def find_release(api: Api, repo: str, tag: str) -> dict[str, Any] | None:
    """Return the release for a tag, draft or published."""
    matches = [r for r in api.releases(repo) if r.get("tag_name") == tag]
    if len(matches) > 1:
        msg = f"{len(matches)} releases use tag {tag}; resolve this by hand"
        raise ReleaseError(msg)
    return matches[0] if matches else None


def check_assets(release: dict[str, Any], local: dict[str, str]) -> list[str]:
    """Compare release assets with local files. Return the names still missing."""
    remote: dict[str, str | None] = {}
    for asset in release.get("assets", []):
        digest = asset.get("digest")
        remote[asset["name"]] = digest.removeprefix("sha256:") if digest else None
    unexpected = sorted(set(remote) - set(local))
    if unexpected:
        msg = f"release has assets that are not part of this build: {', '.join(unexpected)}"
        raise ReleaseError(msg)
    for name, digest in remote.items():
        if digest is None:
            msg = f"release asset {name} has no recorded digest; verify it by hand"
            raise ReleaseError(msg)
        if digest != local[name]:
            msg = f"release asset {name} has different bytes from this build"
            raise ReleaseError(msg)
    return sorted(set(local) - set(remote))


def check_target(api: Api, repo: str, release: dict[str, Any], tag: str, target: str) -> None:
    """Make sure the release, and its tag if it exists, point at the expected commit."""
    tagged = api.tag_commit(repo, tag)
    if tagged is not None and tagged != target:
        msg = f"tag {tag} points at {tagged}, not {target}"
        raise ReleaseError(msg)
    if tagged is None and release.get("target_commitish") != target:
        msg = f"draft release for {tag} targets {release.get('target_commitish')}, not {target}"
        raise ReleaseError(msg)


def stage(api: Api, release_ref: ReleaseRef, notes: str, assets: list[Path]) -> None:
    """Create or resume a draft release and upload any missing assets."""
    repo, tag, target = release_ref.repo, release_ref.tag, release_ref.target
    local = {p.name: sha256(p) for p in assets}
    release = find_release(api, repo, tag)
    if release is None:
        release = api.create_draft(repo, tag, target, notes)
        print(f"created draft release for {tag}")  # noqa: T201
    else:
        check_target(api, repo, release, tag, target)
    by_name = {p.name: p for p in assets}
    for name in check_assets(release, local):
        api.upload(repo, tag, by_name[name])
        print(f"uploaded {name}")  # noqa: T201
    final = find_release(api, repo, tag)
    if final is None or check_assets(final, local):
        msg = f"release for {tag} is still missing assets after upload"
        raise ReleaseError(msg)
    print(f"release for {tag} has every asset with matching digests")  # noqa: T201


def publish(api: Api, release_ref: ReleaseRef, assets: list[Path]) -> None:
    """Publish a complete draft release, after checking it."""
    repo, tag, target = release_ref.repo, release_ref.tag, release_ref.target
    local = {p.name: sha256(p) for p in assets}
    release = find_release(api, repo, tag)
    if release is None:
        msg = f"no release for {tag}; run the stage step first"
        raise ReleaseError(msg)
    check_target(api, repo, release, tag, target)
    missing = check_assets(release, local)
    if missing:
        msg = f"release for {tag} is missing {', '.join(missing)}"
        raise ReleaseError(msg)
    if release.get("draft"):
        api.publish(repo, int(release["id"]))
        print(f"published release {tag}")  # noqa: T201
    else:
        print(f"release {tag} is already published and complete")  # noqa: T201
    if api.tag_commit(repo, tag) != target:
        msg = f"tag {tag} does not point at {target} after publishing"
        raise ReleaseError(msg)


def verify_pypi(project: str, version: str, assets: list[Path], fetch: Any = None) -> None:
    """Check that PyPI holds exactly these distributions for the version."""
    fetch = fetch or _fetch_json
    data = fetch(f"https://pypi.org/pypi/{project}/{version}/json")
    remote = {u["filename"]: u["digests"]["sha256"] for u in data.get("urls", [])}
    local = {p.name: sha256(p) for p in assets}
    if set(remote) != set(local):
        msg = f"PyPI files {sorted(remote)} differ from this build {sorted(local)}"
        raise ReleaseError(msg)
    for name, digest in local.items():
        if remote[name] != digest:
            msg = f"PyPI file {name} has different bytes from this build"
            raise ReleaseError(msg)
    print(f"PyPI files for {project} {version} match this build")  # noqa: T201


def _fetch_json(url: str) -> Any:  # pragma: no cover - network
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return json.load(response)


@dataclass
class GhApi:  # pragma: no cover - thin wrapper over the gh command, exercised in CI
    """GitHub operations through the ``gh`` command."""

    calls: list[list[str]] = field(default_factory=list)

    def _gh(self, *args: str, data: str | None = None) -> Any:
        command = ["gh", "api", *args]
        self.calls.append(command)
        result = subprocess.run(  # noqa: S603 - fixed command, arguments are not shell-parsed
            command, input=data, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            msg = f"gh api {' '.join(args[:2])} failed: {result.stderr.strip()}"
            raise ReleaseError(msg)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def releases(self, repo: str) -> list[dict[str, Any]]:
        """Return all releases, including drafts."""
        pages = self._gh("--paginate", "--slurp", f"repos/{repo}/releases?per_page=100")
        return [r for page in pages for r in page]

    def create_draft(self, repo: str, tag: str, target: str, notes: str) -> dict[str, Any]:
        """Create a draft release and return it."""
        body: dict[str, object] = {
            "tag_name": tag,
            "target_commitish": target,
            "name": tag,
            "body": notes,
        }
        body |= {"draft": True}
        result: dict[str, Any] = self._gh(
            "-X", "POST", f"repos/{repo}/releases", "--input", "-", data=json.dumps(body)
        )
        return result

    def upload(self, repo: str, tag: str, path: Path) -> None:
        """Upload one asset. gh finds drafts by tag and refuses to replace an asset."""
        # gh finds draft releases by tag, and without --clobber refuses to replace.
        command = ["gh", "release", "upload", tag, str(path), "--repo", repo]
        self.calls.append(command)
        result = subprocess.run(  # noqa: S603 - fixed command, arguments are not shell-parsed
            command, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            msg = f"uploading {path.name} failed: {result.stderr.strip()}"
            raise ReleaseError(msg)

    def publish(self, repo: str, release_id: int) -> None:
        """Turn a draft release into a published release."""
        self._gh("-X", "PATCH", f"repos/{repo}/releases/{release_id}", "-F", "draft=false")

    def tag_commit(self, repo: str, tag: str) -> str | None:
        """Return the commit a tag points to, or None if the tag does not exist."""
        command = ["gh", "api", f"repos/{repo}/commits/{tag}", "--jq", ".sha"]
        result = subprocess.run(  # noqa: S603 - fixed command, arguments are not shell-parsed
            command, capture_output=True, text=True, check=False
        )
        return result.stdout.strip() or None if result.returncode == 0 else None


def main(argv: list[str] | None = None, api: Api | None = None) -> int:
    """Run one step and return an exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="step", required=True)
    for name in ("stage", "publish"):
        step = sub.add_parser(name)
        step.add_argument("--repo", required=True)
        step.add_argument("--tag", required=True)
        step.add_argument("--target", required=True)
        if name == "stage":
            step.add_argument("--notes", type=Path, required=True)
        step.add_argument("assets", nargs="+", type=Path)
    pypi = sub.add_parser("verify-pypi")
    pypi.add_argument("--project", required=True)
    pypi.add_argument("--version", required=True)
    pypi.add_argument("assets", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.step == "verify-pypi":
            verify_pypi(args.project, args.version, args.assets)
            return 0
        client = api or GhApi()
        if args.step == "stage":
            notes = args.notes.read_text(encoding="utf-8")
            ref = ReleaseRef(args.repo, args.tag, args.target)
            stage(client, ref, notes, args.assets)
        else:
            publish(client, ReleaseRef(args.repo, args.tag, args.target), args.assets)
    except ReleaseError as exc:
        print(f"::error::{exc}", file=sys.stderr)  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
