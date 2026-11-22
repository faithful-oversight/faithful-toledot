# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The committed example in examples/ is exactly what the current code produces."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_core.exitcodes import ExitCode

from faithful_toledot.cli import main
from faithful_toledot.outputs import MANIFEST_NAME

if TYPE_CHECKING:
    import pytest

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "corp-example"
SAMPLE_DIR = EXAMPLE_DIR / "sample-report"
INPUTS = [EXAMPLE_DIR / "dc01-events.jsonl", EXAMPLE_DIR / "dc02-events.jsonl"]
GENERATED = "1794225600"  # 2026-11-09T12:00:00Z, the SOURCE_DATE_EPOCH the sample used
REPORTS = ["toledot-report.json", "toledot-report.md", "toledot-report.html", "toledot-changes.csv"]
REGENERATE = (
    "is out of date. Regenerate it as examples/README.md shows, review the difference, "
    "and commit it"
)


def stable(directory: Path, name: str) -> str:
    """Read an output with the tool version, which changes every release, replaced."""
    report = json.loads((directory / "toledot-report.json").read_text(encoding="utf-8"))
    version = re.escape(report["tool"]["version"])
    text = (directory / name).read_bytes().decode("utf-8")
    return re.sub(rf'(toledot |"version": "){version}', r"\1<version>", text)


def test_the_example_command_writes_the_committed_inputs(tmp_path: Path) -> None:
    assert main(["example", str(tmp_path)]) == ExitCode.OK
    assert sorted(p.name for p in tmp_path.iterdir()) == [p.name for p in INPUTS]
    for path in INPUTS:
        assert (tmp_path / path.name).read_bytes() == path.read_bytes(), f"{path.name} {REGENERATE}"


def test_the_sample_reports_are_what_the_code_produces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", GENERATED)
    assert main(["report", *map(str, INPUTS), "-o", str(tmp_path)]) == ExitCode.FINDINGS
    for name in REPORTS:
        assert stable(tmp_path, name) == stable(SAMPLE_DIR, name), f"{name} {REGENERATE}"
    for directory in (tmp_path, SAMPLE_DIR):
        manifest = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
        for entry in manifest["files"]:
            data = (directory / entry["name"]).read_bytes()
            assert (len(data), hashlib.sha256(data).hexdigest()) == (entry["size"], entry["sha256"])
        for entry, path in zip(manifest["inputs"], INPUTS, strict=True):
            assert entry["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        listed = {entry["name"] for entry in manifest["files"]} | {MANIFEST_NAME}
        assert {path.name for path in directory.iterdir()} == listed
