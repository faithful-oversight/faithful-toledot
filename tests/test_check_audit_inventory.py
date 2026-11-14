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

EVERY = (
    "pypsrp==0.8.1 \\\n    --hash=sha256:" + "0" * 64 + "\n"
    "PySPNEGO==0.11.2\nhvac==2.3.0\nboto3[crt]==1.35.0\nazure_identity==1.19.0\nkeyring==25.0.0\n"
    "ruff==0.8.0\n"
)


def test_an_export_with_every_optional_package_passes() -> None:
    assert inventory.missing(EVERY) == []
    assert {"pypsrp", "pyspnego", "azure-identity", "boto3"} <= inventory.audited(EVERY)


def test_missing_packages_are_named_in_order() -> None:
    export = "ruff==0.8.0\nkeyring==25.0.0\n# pypsrp==0.8.1 is only a comment\n"
    assert inventory.missing(export) == ["pypsrp", "pyspnego", "hvac", "boto3", "azure-identity"]


def test_a_longer_name_does_not_stand_in_for_a_shorter_one() -> None:
    assert "boto3" in inventory.missing("boto3-stubs==1.0\n")


def test_main_reports_what_is_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    export = tmp_path / "requirements.txt"
    export.write_text("ruff==0.8.0\n", encoding="utf-8")
    assert inventory.main([str(export)]) == 1
    err = capsys.readouterr().err
    assert "pypsrp, pyspnego, hvac, boto3, azure-identity, keyring missing" in err
    assert "--all-extras" in err
    export.write_text(EVERY, encoding="utf-8")
    assert inventory.main([str(export)]) == 0


def test_main_wants_one_file(capsys: pytest.CaptureFixture[str]) -> None:
    assert inventory.main([]) == 2
    assert "usage:" in capsys.readouterr().err


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
def test_the_locked_all_extras_export_holds_every_required_package(tmp_path: Path) -> None:
    export = tmp_path / "requirements.txt"
    command = [
        "uv", "export", "--color", "never", "--locked", "--all-groups", "--all-extras",
        "--no-emit-project", "--format", "requirements-txt", "--output-file", str(export),
    ]  # fmt: skip
    subprocess.run(command, cwd=ROOT, check=True, capture_output=True)  # noqa: S603
    assert inventory.missing(export.read_text(encoding="utf-8")) == []
    # The export without extras is what the audit used to read, and it is missing them.
    plain = [part for part in command if part != "--all-extras"]
    plain[-1] = str(tmp_path / "plain.txt")
    subprocess.run(plain, cwd=ROOT, check=True, capture_output=True)  # noqa: S603
    assert inventory.missing((tmp_path / "plain.txt").read_text(encoding="utf-8")) != []
