# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The license gate decides from metadata that establishes a license, never a guess."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tarfile
import zipfile
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from types import ModuleType

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_licenses.py"
BSD = "License :: OSI Approved :: BSD License"
MIT = "License :: OSI Approved :: MIT License"
APACHE = "License :: OSI Approved :: Apache Software License"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_licenses", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_licenses"] = module
    spec.loader.exec_module(module)
    return module


def meta(expression: str = "", license_field: str = "", *classifiers: str) -> Message:
    message = Message()
    if expression:
        message["License-Expression"] = expression
    if license_field:
        message["License"] = license_field
    for classifier in classifiers:
        message["Classifier"] = classifier
    return message


@pytest.mark.parametrize(
    ("data", "expected", "allowed"),
    [
        # The reviewed counterexamples: an explicit license outside policy stays itself.
        (meta("", "BSD-4-Clause", BSD), {"BSD-4-Clause"}, False),
        (meta("", "GPL-3.0-only", MIT), {"GPL-3.0-only"}, False),
        (meta("", "GPL", MIT), None, False),
        # Long explicit expressions are still explicit, whatever the classifiers say.
        (
            meta("", "MIT AND GPL-3.0-only AND Apache-2.0 AND BSD-3-Clause", MIT),
            {"MIT", "GPL-3.0-only", "Apache-2.0", "BSD-3-Clause"},
            False,
        ),
        (
            meta("", "MIT AND Apache-2.0 AND BSD-3-Clause AND BSD-2-Clause AND ISC", MIT),
            {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"},
            True,
        ),
        (
            meta("", "Permission is hereby granted, free of charge, to any person obtaining", MIT),
            {"MIT"},
            True,
        ),
        # Public domain only through a reviewed exception.
        (meta("LicenseRef-Public-Domain"), None, False),
        (meta("", "MIT AND LicenseRef-Public-Domain"), None, False),
        (meta("", "LGPL", MIT), None, False),
        # License-Expression wins, and must be valid SPDX.
        (meta("MIT", "GPL-3.0-only"), {"MIT"}, True),
        (meta("Apache-2.0 OR BSD-3-Clause"), {"Apache-2.0", "BSD-3-Clause"}, True),
        (meta("GPL-2.0-only OR MIT"), {"GPL-2.0-only", "MIT"}, False),
        (meta("not a license"), None, False),
        # Short License fields: SPDX, or an exact unambiguous name.
        (meta("", "MPL-2.0 AND MIT"), {"MPL-2.0", "MIT"}, True),
        (meta("", "mit"), {"MIT"}, True),
        (meta("", "MIT License", MIT), {"MIT"}, True),
        (meta("", "Apache License 2.0", APACHE), {"Apache-2.0"}, True),
        (meta("", "BSD", BSD), None, False),
        (meta("", "Dual License", BSD, APACHE), None, False),
        # Classifiers only when no License field names a license.
        (meta("", "", MIT), {"MIT"}, True),
        (meta("", "", BSD), None, False),  # 2, 3 or 4 clauses: not established
        (meta("", "", APACHE), None, False),  # 1.1 or 2.0: not established
        (meta("", "", MIT, BSD), None, False),
        (meta("", "Copyright (c) 2026 Example\n\nRedistribution and use ...", MIT), {"MIT"}, True),
        (meta("", "x" * 200 + " GNU General Public License ...", MIT), None, False),
        (meta(), None, False),
    ],
)
def test_licenses_come_only_from_metadata_that_establishes_them(
    gate: Any, data: Message, expected: set[str] | None, *, allowed: bool
) -> None:
    found = gate.licenses_from(data)
    if expected is not None:
        assert found == expected
    assert (found <= gate.ALLOWED) is allowed


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "license_exceptions.toml"
    path.write_text(text, encoding="utf-8")
    return path


ENTRY = """
[[exception]]
package = "Some_Package"
version = "1.2.3"
license = "BSD-3-Clause"
evidence = "LICENSE in the wheel: three-clause BSD text"
"""


def test_an_exception_applies_only_to_the_version_reviewed(
    gate: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exceptions = gate.load_exceptions(write(tmp_path, ENTRY))
    assert exceptions == {("some-package", "1.2.3"): "BSD-3-Clause"}
    monkeypatch.setattr(gate, "metadata", lambda _: meta("", "", BSD))
    monkeypatch.setattr(gate, "version", lambda _: "1.2.3")
    assert gate.licenses_for("some.package", exceptions) == {"BSD-3-Clause"}
    monkeypatch.setattr(gate, "version", lambda _: "1.2.4")
    assert not gate.licenses_for("some.package", exceptions) <= gate.ALLOWED


@pytest.mark.parametrize("missing", ["package", "version", "license", "evidence"])
def test_every_exception_records_its_evidence(gate: Any, tmp_path: Path, missing: str) -> None:
    text = "\n".join(line for line in ENTRY.splitlines() if not line.startswith(missing))
    with pytest.raises(ValueError, match=f"needs {missing}"):
        gate.load_exceptions(write(tmp_path, text))


def test_public_domain_passes_with_an_exception_for_that_version(
    gate: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = ENTRY.replace('"BSD-3-Clause"', '"BSD-2-Clause AND LicenseRef-Public-Domain"')
    exceptions = gate.load_exceptions(write(tmp_path, entry))
    monkeypatch.setattr(gate, "metadata", lambda _: meta("LicenseRef-Public-Domain"))
    monkeypatch.setattr(gate, "version", lambda _: "1.2.3")
    assert gate.licenses_for("some-package", exceptions) <= gate.ALLOWED
    assert not gate.licenses_for("other-package", exceptions) <= gate.ALLOWED


def test_no_exceptions_file_means_no_exceptions(gate: Any, tmp_path: Path) -> None:
    assert gate.load_exceptions(tmp_path / "absent.toml") == {}


def test_this_repository_exceptions_are_valid(gate: Any) -> None:
    for expression in gate.load_exceptions().values():
        assert gate.identifiers(expression) <= gate.ALLOWED


def test_main_reports_each_failure(
    gate: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    packages = {"good": meta("MIT"), "bad": meta("", "BSD-4-Clause", BSD)}

    def lookup(name: str) -> Message:
        if name == "gone":
            raise gate.PackageNotFoundError(name)
        return packages[name]

    locked = [gate.Locked(name, "1.0", here=True) for name in ("good", "bad", "gone")]
    monkeypatch.setattr(gate, "locked_runtime", lambda: locked)
    monkeypatch.setattr(gate, "load_exceptions", dict)
    monkeypatch.setattr(gate, "metadata", lookup)
    monkeypatch.setattr(gate, "version", lambda _: "1.0")
    assert gate.main() == 1
    err = capsys.readouterr().err
    assert "bad 1.0: BSD-4-Clause" in err
    assert "gone: not installed" in err
    monkeypatch.setattr(gate, "locked_runtime", lambda: locked[:1])
    assert gate.main() == 0


EXPORT = """\
good==1.0
winonly==2.0 ; sys_platform == 'never-an-os'
old==1.0 ; python_full_version < '3.0'
old==2.0 ; python_full_version >= '3.0'
"""


def _uv_export(gate: Any, monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    class Done:
        stdout = text

    monkeypatch.setattr(gate.subprocess, "run", lambda *_a, **_k: Done())


def test_locked_runtime_keeps_every_identity_and_marks_the_ones_not_installed_here(
    gate: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _uv_export(gate, monkeypatch, EXPORT)
    assert gate.locked_runtime() == [
        gate.Locked("good", "1.0", here=True),
        gate.Locked("winonly", "2.0", here=False),
        gate.Locked("old", "1.0", here=False),
        gate.Locked("old", "2.0", here=True),
    ]
    assert gate.runtime_requirements() == ["good", "old"]


def test_an_unreadable_locked_requirement_is_an_error(
    gate: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _uv_export(gate, monkeypatch, "pkg @ https://example.com/pkg.tgz\n")
    with pytest.raises(ValueError, match="cannot read this locked requirement"):
        gate.locked_runtime()


def _wheel(name: str, ver: str, header: str, *, member: str = "METADATA") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr(f"{name}-{ver}.dist-info/{member}", header)
        archive.writestr(f"{name}/__init__.py", "raise SystemExit('never executed')\n")
    return out.getvalue()


def _sdist(name: str, ver: str, header: str) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        data = header.encode()
        info = tarfile.TarInfo(f"{name}-{ver}/PKG-INFO")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _header(name: str, ver: str, license_line: str = "License-Expression: MIT") -> str:
    return f"Metadata-Version: 2.4\nName: {name}\nVersion: {ver}\n{license_line}\n"


class Served:
    """Fake artifacts, served by URL, with a count of downloads."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.opened: list[str] = []

    def __call__(self, url: str) -> io.BytesIO:
        self.opened.append(url)
        if url not in self.files:
            raise OSError(url)
        return io.BytesIO(self.files[url])


def _lock(tmp_path: Path, *entries: tuple[str, str, bytes | None, bytes | None]) -> Path:
    """Write a uv.lock with a wheel and/or sdist (given as bytes) for each package."""

    def file_entry(url: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        return f'{{ url = "{url}", hash = "sha256:{digest}", size = {len(data)} }}'

    text = ""
    for name, ver, wheel, sdist in entries:
        text += f'[[package]]\nname = "{name}"\nversion = "{ver}"\n'
        if sdist is not None:
            text += f"sdist = {file_entry(f'https://files.example/{name}-{ver}.tar.gz', sdist)}\n"
        if wheel is not None:
            url = f"https://files.example/{name}-{ver}-py3-none-any.whl"
            text += f"wheels = [{file_entry(url, wheel)}]\n"
        text += "\n"
    path = tmp_path / "uv.lock"
    path.write_text(text, encoding="utf-8")
    return path


def _off_host(gate: Any, monkeypatch: pytest.MonkeyPatch, served: Served, lock: Path) -> None:
    monkeypatch.setattr(gate, "_open", served)
    monkeypatch.setattr(gate, "LOCK_FILE", lock)
    monkeypatch.setattr(gate, "load_exceptions", dict)
    monkeypatch.setattr(gate, "locked_runtime", lambda: [gate.Locked("winonly", "2.0", here=False)])


def _run(
    gate: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    built: tuple[bytes | None, bytes | None],
    serve: dict[str, bytes] | None = None,
) -> tuple[int, str, Served]:
    wheel, sdist = built
    lock = _lock(tmp_path, ("winonly", "2.0", wheel, sdist))
    files = {}
    if wheel is not None:
        files["https://files.example/winonly-2.0-py3-none-any.whl"] = wheel
    if sdist is not None:
        files["https://files.example/winonly-2.0.tar.gz"] = sdist
    served = Served(serve if serve is not None else files)
    _off_host(gate, monkeypatch, served, lock)
    return gate.main(), "", served


def test_locked_artifacts_reads_urls_hashes_and_kinds(gate: Any, tmp_path: Path) -> None:
    wheel, sdist = _wheel("winonly", "2.0", "x"), _sdist("winonly", "2.0", "x")
    found = gate.locked_artifacts(_lock(tmp_path, ("Win_Only", "2.0", wheel, sdist)))
    wheel_artifact, sdist_artifact = sorted(found[("win-only", "2.0")], key=lambda a: not a.wheel)
    assert wheel_artifact.wheel
    assert wheel_artifact.sha256 == hashlib.sha256(wheel).hexdigest()
    assert not sdist_artifact.wheel


def test_a_package_for_another_platform_is_read_from_its_locked_wheel(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0"))
    code, _, served = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 0
    assert served.opened == ["https://files.example/winonly-2.0-py3-none-any.whl"]
    assert "1 for other platforms read from their locked artifacts" in capsys.readouterr().out


def test_the_wheel_is_preferred_and_the_sdist_is_the_fallback(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0"))
    sdist = _sdist("winonly", "2.0", _header("winonly", "2.0"))
    _, _, served = _run(gate, monkeypatch, tmp_path, (wheel, sdist))
    assert served.opened == ["https://files.example/winonly-2.0-py3-none-any.whl"]
    other = tmp_path / "other"
    other.mkdir()
    code, _, served = _run(gate, monkeypatch, other, (None, sdist))
    assert code == 0
    assert served.opened == ["https://files.example/winonly-2.0.tar.gz"]


def test_a_disallowed_license_in_the_locked_artifact_fails(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    header = _header("winonly", "2.0", "License-Expression: GPL-3.0-only")
    wheel = _wheel("winonly", "2.0", header)
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 1
    assert "winonly 2.0: GPL-3.0-only" in capsys.readouterr().err


def test_an_artifact_without_license_metadata_fails(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0", ""))
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 1
    assert "no license in the metadata" in capsys.readouterr().err


def test_a_wheel_without_a_metadata_file_fails(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _wheel("winonly", "2.0", "x", member="RECORD")
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 1
    assert "no single METADATA file" in capsys.readouterr().err


def test_a_hash_that_differs_from_the_lock_fails_and_is_not_cached(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0"))
    tampered = _wheel("winonly", "2.0", _header("winonly", "2.0", "License-Expression: MIT\nX: y"))
    url = "https://files.example/winonly-2.0-py3-none-any.whl"
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None), {url: tampered})
    assert code == 1
    assert "does not match the sha256 in uv.lock" in capsys.readouterr().err


def test_an_artifact_for_another_package_or_version_fails(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _wheel("winonly", "2.0", _header("evil", "2.0"))
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 1
    assert "says it is evil 2.0, not winonly 2.0" in capsys.readouterr().err


def test_a_package_with_no_locked_artifact_or_a_failed_download_fails(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, _ = _run(gate, monkeypatch, tmp_path, (None, None))
    assert code == 1
    assert "names no wheel or source distribution" in capsys.readouterr().err
    other = tmp_path / "other"
    other.mkdir()
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0"))
    code, _, _ = _run(gate, monkeypatch, other, (wheel, None), {})
    assert code == 1
    assert "could not download" in capsys.readouterr().err


def test_only_https_artifacts_are_downloaded(gate: Any) -> None:
    with pytest.raises(gate.ArtifactError, match="not an https URL"):
        gate._open("http://files.example/x.whl")  # noqa: SLF001


def test_an_oversized_metadata_file_fails(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(gate, "MAX_METADATA", 100)
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0") + "x" * 500)
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 1
    assert "is larger than" in capsys.readouterr().err


def test_a_reviewed_exception_decides_a_package_without_any_download(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    served = Served({})
    _off_host(gate, monkeypatch, served, _lock(tmp_path))
    reviewed = {("winonly", "2.0"): "MIT"}
    monkeypatch.setattr(gate, "load_exceptions", lambda: reviewed)
    assert gate.main() == 0
    assert served.opened == []
    reviewed[("winonly", "2.0")] = "GPL-3.0-only"
    assert gate.main() == 1
    assert "winonly 2.0: GPL-3.0-only" in capsys.readouterr().err


def test_the_artifact_is_never_executed_or_unpacked(
    gate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The wheel's __init__.py raises SystemExit if run; main() must still return normally.
    wheel = _wheel("winonly", "2.0", _header("winonly", "2.0"))
    code, _, _ = _run(gate, monkeypatch, tmp_path, (wheel, None))
    assert code == 0
    assert not list(tmp_path.glob("winonly*"))


def test_locked_runtime_marks_the_ones_not_installed_here(
    gate: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _uv_export(gate, monkeypatch, EXPORT)
    assert [i.here for i in gate.locked_runtime()] == [True, False, False, True]
