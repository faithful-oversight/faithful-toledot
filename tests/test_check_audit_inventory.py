# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the check that the vulnerability audit includes the optional extras."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_audit_inventory.py"
_spec = importlib.util.spec_from_file_location("check_audit_inventory", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)

PYPROJECT = """\
[project]
name = "example-tool"
version = "1.0"

[project.optional-dependencies]
live = ["pypsrp>=0.8", "Azure_Identity[extra]>=1.19; python_version >= '3.11'"]
vault = ["hvac>=2.3", "example-tool[live]"]
"""
EVERY = (
    "pypsrp==0.8.1 \\\n    --hash=sha256:" + "0" * 64 + "\n"
    "azure-identity[extra]==1.19.0\nHVAC==2.3.0\nruff==0.8.0\n"
)


@pytest.fixture
def pyproject(tmp_path: Path) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text(PYPROJECT, encoding="utf-8")
    return path


def test_the_required_packages_come_from_the_extras_in_order(pyproject: Path) -> None:
    assert inventory.required(pyproject, also=()) == ["pypsrp", "azure-identity", "hvac"]


def test_a_project_without_extras_requires_nothing(tmp_path: Path) -> None:
    bare = tmp_path / "pyproject.toml"
    bare.write_text('[project]\nname = "x"\nversion = "1"\n', encoding="utf-8")
    assert inventory.required(bare, also=()) == []
    assert inventory.missing("", bare, also=()) == []


def test_an_export_with_every_optional_package_passes(pyproject: Path) -> None:
    assert inventory.missing(EVERY, pyproject, also=()) == []
    assert {"pypsrp", "azure-identity", "hvac"} <= inventory.audited(EVERY)


def test_missing_packages_are_named_in_order(pyproject: Path) -> None:
    export = "ruff==0.8.0\nhvac==2.3.0\n# pypsrp==0.8.1 is only a comment\n"
    assert inventory.missing(export, pyproject, also=()) == ["pypsrp", "azure-identity"]


def test_a_longer_name_does_not_stand_in_for_a_shorter_one(pyproject: Path) -> None:
    assert "hvac" in inventory.missing("hvac-stubs==1.0\n", pyproject, also=())


def test_a_project_can_require_a_package_an_extra_pulls_in(
    pyproject: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    also = ("PySPNEGO", "hvac")
    assert inventory.required(pyproject, also) == ["pypsrp", "azure-identity", "hvac", "pyspnego"]
    assert inventory.missing(EVERY, pyproject, also) == ["pyspnego"]
    monkeypatch.setattr(inventory, "ALSO_REQUIRED", also)
    assert inventory.required(pyproject) == ["pypsrp", "azure-identity", "hvac", "pyspnego"]


def test_main_reports_what_is_missing(
    tmp_path: Path,
    pyproject: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(inventory, "ALSO_REQUIRED", ())
    export = tmp_path / "requirements.txt"
    export.write_text("ruff==0.8.0\n", encoding="utf-8")
    assert inventory.main([str(export), str(pyproject)]) == 1
    err = capsys.readouterr().err
    assert "pypsrp, azure-identity, hvac missing" in err
    assert "--all-extras" in err
    export.write_text(EVERY, encoding="utf-8")
    assert inventory.main([str(export), str(pyproject)]) == 0


def test_main_wants_one_or_two_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert inventory.main([]) == 2
    assert inventory.main(["a", "b", "c"]) == 2
    assert "usage:" in capsys.readouterr().err


def test_main_reads_pyproject_from_the_working_directory_by_default(
    tmp_path: Path, pyproject: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(inventory, "ALSO_REQUIRED", ())
    export = tmp_path / "requirements.txt"
    export.write_text("ruff==0.8.0\n", encoding="utf-8")
    monkeypatch.chdir(pyproject.parent)
    assert inventory.main([str(export)]) == 1


def test_the_deps_stage_exports_every_extra_and_checks_the_inventory() -> None:
    stage = re.search(
        r"stage_deps\(\) \{.*?\n\}", (ROOT / "scripts/check.sh").read_text(), re.DOTALL
    )
    assert stage is not None
    text = stage.group()
    assert "uv export" in text
    assert "--all-extras" in text
    assert text.index("check_audit_inventory.py") < text.index("pip-audit")


@pytest.mark.skipif(
    os.name != "posix" or shutil.which("uv") is None or not (ROOT / "uv.lock").exists(),
    reason="needs uv, a POSIX shell, and the lock file (the source distribution has none)",
)
def test_the_locked_all_extras_export_holds_every_package_an_extra_names(
    tmp_path: Path,
) -> None:
    export = tmp_path / "requirements.txt"
    command = [
        "uv", "export", "--color", "never", "--locked", "--all-groups", "--all-extras",
        "--no-emit-project", "--format", "requirements-txt", "--output-file", str(export),
    ]  # fmt: skip
    subprocess.run(command, cwd=ROOT, check=True, capture_output=True)  # noqa: S603
    pyproject = ROOT / "pyproject.toml"
    assert inventory.missing(export.read_text(encoding="utf-8"), pyproject) == []
    if inventory.required(pyproject):
        # The export without extras is what the audit used to read, and it is missing them.
        plain = [part for part in command if part != "--all-extras"]
        plain[-1] = str(tmp_path / "plain.txt")
        subprocess.run(plain, cwd=ROOT, check=True, capture_output=True)  # noqa: S603
        assert inventory.missing((tmp_path / "plain.txt").read_text(encoding="utf-8"), pyproject)
