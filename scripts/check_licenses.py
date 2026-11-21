# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail if any runtime dependency uses a license outside the allow list.

Runtime dependencies ship to users, so their licenses must be compatible with
Apache-2.0 distribution. Development tools are not distributed and are not
checked here. This script is the same in every Faithful Oversight product; each
repository keeps its own reviewed exceptions in ``license_exceptions.toml``.

A license is taken from the first source that establishes it:

1. A reviewed exception for that exact package version.
2. The ``License-Expression`` field, which must be a valid SPDX expression.
3. A ``License`` field that is a valid SPDX expression, of any length, or one of
   a few exact, unambiguous names such as ``MIT License``. Any other short text is
   not guessed at; it fails until someone reads the license and records an exception.
4. Only when no ``License`` field names a license (it is empty or holds the
   license text itself): classifiers that name one license. The generic BSD and
   Apache classifiers do not say which version or how many clauses, so they fail
   until reviewed. License text that mentions the GNU licenses always fails.

An explicit license is never replaced by a classifier, so ``License: BSD-4-Clause``
with a generic BSD classifier fails rather than passing as BSD-3-Clause.

A dependency locked only for another platform or Python version is not installed here, so
its installed metadata cannot be read. Its license is then read from the exact locked
artifact: the wheel (else the source distribution) that ``uv.lock`` names by URL, downloaded
over HTTPS, checked against the sha256 in ``uv.lock``, and read for ``METADATA`` or
``PKG-INFO`` only, never unpacked or executed. The same rules above then apply. A download
that fails, a hash that differs, metadata that is missing or names another package or
version, or a license that is not allowed, fails the check, unless a reviewed exception
names that exact version.

Some identifiers are allowed only through a reviewed exception (``REVIEW_ONLY``):
public domain dedications vary, so metadata alone does not establish one.
"""

from __future__ import annotations

import email.parser
import hashlib
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import zipfile
from importlib.metadata import PackageNotFoundError, metadata, version
from pathlib import Path
from typing import IO, Any, NamedTuple, Protocol

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.markers import Marker


class Metadata(Protocol):
    """The part of package metadata the gate reads."""

    def get_all(self, name: str, failobj: Any = None) -> list[Any] | None: ...  # noqa: D102


EXCEPTIONS_FILE = Path(__file__).with_name("license_exceptions.toml")
MAX_SPDX_FIELD = 40
"""The longest License field read as a license name; longer text is a license body."""

# Keep in sync with allow-licenses in .github/workflows/ci.yml.
ALLOWED = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "LicenseRef-Public-Domain",  # only through a reviewed exception; see REVIEW_ONLY
    "MIT",
    "MIT-0",
    "MPL-2.0",  # file-level copyleft; allowed for unmodified dependencies
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
}
REVIEW_ONLY = {"LicenseRef-Public-Domain"}
NAMES = {
    # Exact License field values that name one license without ambiguity.
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "isc license": "ISC",
    "mit license": "MIT",
}
CLASSIFIERS = {
    # Classifiers that name exactly one license.
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
}
COPYLEFT_TEXT = ("gnu general public", "gnu lesser general public", "gnu affero")


def identifiers(expression: str) -> set[str]:
    """Return the license identifiers in a valid SPDX expression, or raise ValueError."""
    try:
        canonical = canonicalize_license_expression(expression)
    except InvalidLicenseExpression as exc:
        raise ValueError(expression) from exc
    words = canonical.replace("(", " ").replace(")", " ").split()
    return {word for word in words if word not in {"AND", "OR", "WITH"}}


def load_exceptions(path: Path = EXCEPTIONS_FILE) -> dict[tuple[str, str], str]:
    """Return reviewed licenses keyed by (normalized package name, exact version)."""
    if not path.exists():
        return {}
    entries = tomllib.loads(path.read_text(encoding="utf-8")).get("exception", [])
    found = {}
    for entry in entries:
        for key in ("package", "version", "license", "evidence"):
            if not str(entry.get(key, "")).strip():
                msg = f"{path.name}: every exception needs {key}"
                raise ValueError(msg)
        found[(normalize(entry["package"]), entry["version"])] = entry["license"]
    return found


def normalize(name: str) -> str:
    """Return a package name in its normalized form (PEP 503)."""
    return "-".join(name.lower().replace("_", "-").replace(".", "-").split("-"))


def licenses_from(meta: Metadata) -> set[str]:
    """Return the licenses package metadata establishes, as the module docstring describes."""
    return _unreviewed(_from_fields(meta))


def _unreviewed(found: set[str]) -> set[str]:
    """Mark identifiers that only a reviewed exception may establish."""
    return {
        f"{name} (needs a reviewed exception)" if name in REVIEW_ONLY else name for name in found
    }


def _from_fields(meta: Metadata) -> set[str]:
    expressions = meta.get_all("License-Expression") or []
    if expressions:
        try:
            return identifiers(expressions[0])
        except ValueError:
            return {f"invalid License-Expression {expressions[0]!r}"}
    declared = ((meta.get_all("License") or [""])[0] or "").strip()
    if declared and "\n" not in declared:
        # An SPDX expression is explicit whatever its length; try it before any
        # guess that long text is a license body.
        try:
            return identifiers(declared)
        except ValueError:
            pass
        if len(declared) < MAX_SPDX_FIELD:
            return _named(declared)
    if any(marker in declared.casefold() for marker in COPYLEFT_TEXT):
        return {"GNU license text in the License field"}
    classifiers = [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    named = {CLASSIFIERS.get(c, f"classifier {c!r} does not name one license") for c in classifiers}
    return named or {"no license in the metadata; read the license and record an exception"}


def _named(declared: str) -> set[str]:
    """Return the license a short License field names, without guessing."""
    if declared.casefold() in NAMES:
        return {NAMES[declared.casefold()]}
    return {f"unrecognized License {declared!r}; read the license and record an exception"}


def licenses_for(name: str, exceptions: dict[tuple[str, str], str]) -> set[str]:
    """Return the licenses of an installed distribution."""
    reviewed = exceptions.get((normalize(name), version(name)))
    if reviewed is not None:
        return identifiers(reviewed)
    return licenses_from(metadata(name))


class Locked(NamedTuple):
    """A locked runtime package, and whether its environment marker holds on this host."""

    name: str
    version: str
    here: bool


def locked_runtime() -> list[Locked]:
    """Return every locked runtime (name, version), with every optional extra.

    Markers are evaluated only to say whether the package is installed here, never to leave
    a package out: its license can be read from the installed copy only when it is.
    """
    out = subprocess.run(
        [  # noqa: S607 - uv is resolved from PATH by design
            "uv",
            "export",
            "--color",
            "never",
            "--locked",
            "--all-extras",
            "--no-dev",
            "--no-emit-project",
            "--no-hashes",
            "--format",
            "requirements-txt",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    found: dict[tuple[str, str], bool] = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        requirement, _, marker = line.partition(";")
        name, _, pinned = requirement.partition("==")
        if not pinned.strip():
            msg = f"cannot read this locked requirement as name==version: {line!r}"
            raise ValueError(msg)
        applies = not marker.strip() or Marker(marker.strip()).evaluate()
        key = (name.strip(), pinned.strip())
        found[key] = found.get(key, False) or applies
    return [Locked(name, ver, here) for (name, ver), here in found.items()]


def runtime_requirements() -> list[str]:
    """Return the names of locked runtime dependencies installed on this host."""
    names: list[str] = []
    for item in locked_runtime():
        if item.here and item.name not in names:
            names.append(item.name)
    return names


LOCK_FILE = Path(__file__).resolve().parent.parent / "uv.lock"
MAX_ARTIFACT = 256 * 1024 * 1024
"""The largest artifact downloaded to read one package's metadata."""
MAX_METADATA = 4 * 1024 * 1024
"""The most bytes read from the metadata file inside an artifact."""
TIMEOUT = 60


class ArtifactError(Exception):
    """A locked artifact could not be fetched, verified or read."""


class Artifact(NamedTuple):
    """A file uv.lock names for a package version, with the sha256 it must have."""

    url: str
    sha256: str
    wheel: bool
    size: int


def locked_artifacts(lock: Path = LOCK_FILE) -> dict[tuple[str, str], list[Artifact]]:
    """Return the artifacts uv.lock names, keyed by (normalized name, exact version)."""
    found: dict[tuple[str, str], list[Artifact]] = {}
    for package in tomllib.loads(lock.read_text(encoding="utf-8")).get("package", []):
        files = [(entry, True) for entry in package.get("wheels", [])]
        if package.get("sdist"):
            files.append((package["sdist"], False))
        artifacts = []
        for entry, wheel in files:
            digest = str(entry.get("hash", ""))
            if entry.get("url") and digest.startswith("sha256:"):
                artifacts.append(
                    Artifact(
                        entry["url"], digest.removeprefix("sha256:"), wheel, entry.get("size", 0)
                    )
                )
        key = (normalize(str(package.get("name", ""))), str(package.get("version", "")))
        found.setdefault(key, []).extend(artifacts)
    return found


def _open(url: str) -> IO[bytes]:
    """Open an HTTPS URL for reading."""
    if not url.startswith("https://"):
        msg = f"refusing to download {url!r}: not an https URL"
        raise ArtifactError(msg)
    request = urllib.request.Request(url, headers={"User-Agent": "faithful-license-check"})  # noqa: S310
    return urllib.request.urlopen(request, timeout=TIMEOUT)  # type: ignore[no-any-return]  # noqa: S310


def download(artifact: Artifact, cache: Path) -> Path:
    """Fetch an artifact into ``cache``, verified against its locked sha256, and return it."""
    target = cache / artifact.sha256
    if target.exists():
        return target
    digest = hashlib.sha256()
    partial = cache / f"{artifact.sha256}.partial"
    try:
        with _open(artifact.url) as source, partial.open("wb") as out:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                if out.tell() + len(chunk) > MAX_ARTIFACT:
                    msg = f"{artifact.url} is larger than {MAX_ARTIFACT} bytes"
                    raise ArtifactError(msg)
                out.write(chunk)
    except OSError as exc:
        msg = f"could not download {artifact.url}: {type(exc).__name__}"
        raise ArtifactError(msg) from exc
    if digest.hexdigest() != artifact.sha256:
        partial.unlink(missing_ok=True)
        msg = f"{artifact.url} does not match the sha256 in uv.lock"
        raise ArtifactError(msg)
    partial.rename(target)
    return target


def _read_member(opened: Any, label: str) -> bytes:
    data: bytes = opened.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        msg = f"{label} is larger than {MAX_METADATA} bytes"
        raise ArtifactError(msg)
    return data


def read_metadata(path: Path, wheel: bool) -> Metadata:  # noqa: FBT001
    """Return the package metadata inside an artifact, reading one file and nothing else."""
    pattern = re.compile(r"^[^/]+\.dist-info/METADATA$" if wheel else r"^[^/]+/PKG-INFO$")
    try:
        if wheel:
            with zipfile.ZipFile(path) as archive:
                names = [n for n in archive.namelist() if pattern.match(n)]
                if len(names) != 1:
                    msg = "no single METADATA file in the wheel"
                    raise ArtifactError(msg)
                with archive.open(names[0]) as opened:
                    data = _read_member(opened, "METADATA")
        else:
            with tarfile.open(path, "r:gz") as tar:
                members = [m for m in tar if m.isfile() and pattern.match(m.name)]
                if len(members) != 1:
                    msg = "no single PKG-INFO file in the source distribution"
                    raise ArtifactError(msg)
                member = tar.extractfile(members[0])
                if member is None:
                    msg = "PKG-INFO cannot be read"
                    raise ArtifactError(msg)
                data = _read_member(member, "PKG-INFO")
    except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        msg = f"cannot open the artifact ({type(exc).__name__})"
        raise ArtifactError(msg) from exc
    return email.parser.BytesParser().parsebytes(data, headersonly=True)


def licenses_from_artifact(
    item: Locked, artifacts: dict[tuple[str, str], list[Artifact]], cache: Path
) -> set[str]:
    """Return the licenses of a locked package, read from its exact locked artifact."""
    candidates = sorted(
        artifacts.get((normalize(item.name), item.version), []), key=lambda a: (not a.wheel, a.size)
    )
    if not candidates:
        msg = "uv.lock names no wheel or source distribution with a sha256 for it"
        raise ArtifactError(msg)
    chosen = candidates[0]
    meta = read_metadata(download(chosen, cache), wheel=chosen.wheel)
    said_name = (meta.get_all("Name") or [""])[0] or ""
    said_version = (meta.get_all("Version") or [""])[0] or ""
    if normalize(said_name) != normalize(item.name) or said_version != item.version:
        msg = f"the artifact says it is {said_name} {said_version}, not {item.name} {item.version}"
        raise ArtifactError(msg)
    return licenses_from(meta)


def _decide(
    item: Locked,
    exceptions: dict[tuple[str, str], str],
    artifacts: dict[tuple[str, str], list[Artifact]],
    cache: Path,
) -> tuple[str, str]:
    """Return ("ok" | "failed", detail) for one locked runtime package."""
    if item.here:
        try:
            found = licenses_for(item.name, exceptions)
        except PackageNotFoundError:
            return "failed", f"{item.name}: not installed, cannot read license"
        name = f"{item.name} {version(item.name)}"
    else:
        # Not installed here, so there is no installed metadata. A reviewed exception for
        # this exact version decides it; otherwise read the locked artifact itself.
        name = f"{item.name} {item.version}"
        reviewed = exceptions.get((normalize(item.name), item.version))
        if reviewed is not None:
            found = identifiers(reviewed)
        else:
            try:
                found = licenses_from_artifact(item, artifacts, cache)
            except ArtifactError as exc:
                return "failed", f"{name}: cannot read its license from the locked artifact: {exc}"
    if found <= ALLOWED:
        return "ok", name
    return "failed", f"{name}: {', '.join(sorted(found - ALLOWED))}"


def main() -> int:
    """Check every runtime dependency and report violations."""
    exceptions = load_exceptions()
    locked = locked_runtime()
    artifacts = locked_artifacts(LOCK_FILE) if not all(item.here for item in locked) else {}
    with tempfile.TemporaryDirectory(prefix="licenses-") as cache:
        results = [_decide(item, exceptions, artifacts, Path(cache)) for item in locked]
    failures = [detail for status, detail in results if status == "failed"]
    for failure in failures:
        print(f"license not allowed: {failure}", file=sys.stderr)  # noqa: T201
    if not failures:
        elsewhere = sum(1 for item in locked if not item.here)
        note = (
            f" ({elsewhere} for other platforms read from their locked artifacts)"
            if elsewhere
            else ""
        )
        print(f"all runtime dependency licenses are allowed{note}")  # noqa: T201
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
