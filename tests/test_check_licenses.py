# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The license gate decides from metadata that establishes a license, never a guess."""

from __future__ import annotations

import importlib.util
import sys
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


def test_licenses_for_other_platforms_are_reported_as_not_checked(
    gate: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _uv_export(gate, monkeypatch, EXPORT)
    monkeypatch.setattr(gate, "load_exceptions", dict)
    monkeypatch.setattr(gate, "metadata", lambda _: meta("MIT"))
    monkeypatch.setattr(gate, "version", lambda _: "1.0")
    assert gate.main() == 0
    captured = capsys.readouterr()
    assert "NOT checked on this host" in captured.err
    assert "old==1.0, winonly==2.0" in captured.err
    assert "all runtime dependency licenses" not in captured.out
    assert "2 locked for other platforms or Python versions were not checked" in captured.out


def test_a_reviewed_exception_decides_a_package_not_installed_here(
    gate: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _uv_export(gate, monkeypatch, EXPORT)
    monkeypatch.setattr(gate, "metadata", lambda _: meta("MIT"))
    monkeypatch.setattr(gate, "version", lambda _: "1.0")
    reviewed = {("winonly", "2.0"): "MIT", ("old", "1.0"): "MIT"}
    monkeypatch.setattr(gate, "load_exceptions", lambda: reviewed)
    assert gate.main() == 0
    captured = capsys.readouterr()
    assert "NOT checked" not in captured.err
    assert "all runtime dependency licenses are allowed" in captured.out
    reviewed[("winonly", "2.0")] = "GPL-3.0-only"
    assert gate.main() == 1
    assert "winonly 2.0: GPL-3.0-only" in capsys.readouterr().err
