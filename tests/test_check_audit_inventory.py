# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the check that the vulnerability audit includes the optional extras."""

from __future__ import annotations

import importlib.util
import json
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
    # Split before the audit, verify after it, and read the auditor's own JSON result.
    assert text.index("check_audit_inventory.py split") < text.index("run pip-audit")
    assert text.index("run pip-audit") < text.index("check_audit_inventory.py verify")
    assert "--format json" in text
    assert "--lock uv.lock" in text
    assert '--requirement "$input"' in text
    assert '--requirement "$work/export.txt"' not in text, "the raw export keeps markers"


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


# --- Coverage of every locked identity, whatever its environment markers -------------------


def _pin(name: str, version: str, marker: str = "") -> str:
    digest = (name + version).encode().hex().ljust(64, "0")[:64]
    suffix = f" ; {marker}" if marker else ""
    return f"{name}=={version}{suffix} \\\n    --hash=sha256:{digest}\n    # via example\n"


# A Windows-only pin, two Python-specific versions of one package, and an ordinary pin. The
# markers are the ones uv writes, so they are exactly what pip-audit would evaluate.
MARKED_EXPORT = (
    "# This file was autogenerated by uv\n"
    + _pin("colorama", "0.4.6", "sys_platform == 'win32'")
    + _pin("sphinx", "9.0.4", "python_full_version < '3.12'")
    + _pin("sphinx", "9.2.0", "python_full_version >= '3.12'")
    + _pin("zipp", "3.23.0")
)
EVERY_IDENTITY = {
    ("colorama", "0.4.6"),
    ("sphinx", "9.0.4"),
    ("sphinx", "9.2.0"),
    ("zipp", "3.23.0"),
}


def _collected(path: Path) -> set[tuple[str, str]]:
    """The identities the real pip-audit requirement collector keeps from a file."""
    module = importlib.import_module("pip_audit._dependency_source.requirement")
    source = module.RequirementSource([path], disable_pip=True)
    return {(inventory.normalise(dep.name), str(dep.version)) for dep in source.collect()}


def test_the_raw_export_loses_pins_to_the_hosts_markers(tmp_path: Path) -> None:
    # The defect this fixes: the auditor evaluates markers on its own host. On any host at
    # least one of the two sphinx pins is false, and on Linux or macOS so is colorama.
    raw = tmp_path / "raw.txt"
    raw.write_text(MARKED_EXPORT, encoding="utf-8")
    assert _collected(raw) < EVERY_IDENTITY


def test_every_identity_is_read_whatever_its_markers() -> None:
    assert inventory.identities(MARKED_EXPORT) == EVERY_IDENTITY
    assert inventory.audited(MARKED_EXPORT) == {"colorama", "sphinx", "zipp"}


def test_the_split_inputs_hold_every_identity_without_markers() -> None:
    texts = inventory.render_inputs(MARKED_EXPORT)
    assert len(texts) == 2  # sphinx has two versions, so two files
    for text in texts:
        assert ";" not in text.replace("\\", "")
        names = [name for name, _ in inventory.identities(text)]
        assert len(names) == len(set(names)), "one version of each package per file"
    assert set().union(*(inventory.identities(text) for text in texts)) == EVERY_IDENTITY
    assert all("--hash=sha256:" in text for text in texts)


def test_the_real_collector_keeps_every_split_identity(tmp_path: Path) -> None:
    seen: set[tuple[str, str]] = set()
    for index, text in enumerate(inventory.render_inputs(MARKED_EXPORT)):
        path = tmp_path / f"in-{index}.txt"
        path.write_text(text, encoding="utf-8")
        collected = _collected(path)
        assert collected == inventory.identities(text), "the collector dropped a pin"
        seen |= collected
    assert seen == EVERY_IDENTITY


def test_three_versions_of_one_package_make_three_files() -> None:
    export = "".join(
        _pin("pkg", version, f"python_full_version == '3.{minor}.*'")
        for minor, version in ((11, "1.0"), (12, "1.10"), (13, "1.9"))
    )
    texts = inventory.render_inputs(export)
    assert [sorted(inventory.identities(text)) for text in texts] == [
        [("pkg", "1.0")],
        [("pkg", "1.9")],
        [("pkg", "1.10")],
    ], "versions sort as versions, not as text"


@pytest.mark.parametrize(
    "line",
    [
        "pkg @ https://example.com/pkg-1.0.tgz",
        "pkg>=1.0",
        "-e .",
        "--index-url https://example.com/simple",
    ],
)
def test_a_line_that_is_not_a_pin_is_an_error_not_a_skip(line: str) -> None:
    with pytest.raises(inventory.AuditInputError):
        inventory.parse(line + "\n")


def test_a_pin_without_a_hash_is_an_error() -> None:
    with pytest.raises(inventory.AuditInputError, match=r"no hash for pkg==1\.0"):
        inventory.render_inputs("pkg==1.0\n")


def _lock(tmp_path: Path, ids: set[tuple[str, str]]) -> Path:
    body = '[[package]]\nname = "example-tool"\nversion = "1.0"\nsource = { editable = "." }\n'
    for name, version in sorted(ids):
        body += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
    path = tmp_path / "uv.lock"
    path.write_text(body, encoding="utf-8")
    return path


def _results(directory: Path, drop: tuple[str, ...] = (), vuln: str = "", skip: str = "") -> None:
    """Write what a faithful auditor would report for each input file in ``directory``."""
    for path in directory.glob("requirements-audit-*.txt"):
        number = re.search(r"(\d+)", path.name)
        assert number is not None
        deps: list[dict[str, object]] = []
        for name, version in sorted(inventory.identities(path.read_text(encoding="utf-8"))):
            if name in drop:
                continue
            if name == skip:
                deps.append({"name": name, "skip_reason": "marker evaluated false"})
                continue
            vulns = [{"id": "PYSEC-0", "fix_versions": ["9.9"]}] if name == vuln else []
            deps.append({"name": name, "version": version, "vulns": vulns})
        out = directory / f"audit-{number.group(1)}.json"
        out.write_text(json.dumps({"dependencies": deps, "fixes": []}), encoding="utf-8")


@pytest.fixture
def split_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path, Path]:
    monkeypatch.setattr(inventory, "ALSO_REQUIRED", ())
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "example-tool"\nversion = "1.0"\n'
        '[project.optional-dependencies]\nlive = ["zipp>=3"]\n',
        encoding="utf-8",
    )
    export = tmp_path / "export.txt"
    export.write_text(MARKED_EXPORT, encoding="utf-8")
    lock = _lock(tmp_path, EVERY_IDENTITY)
    directory = tmp_path / "audit"
    args = [
        "split",
        str(export),
        str(directory),
        "--pyproject",
        str(pyproject),
        "--lock",
        str(lock),
    ]
    assert inventory.main(args) == 0
    return export, directory, lock, pyproject


def _verify(parts: tuple[Path, Path, Path, Path]) -> int:
    export, directory, lock, pyproject = parts
    args = [
        "verify",
        str(export),
        str(directory),
        "--pyproject",
        str(pyproject),
        "--lock",
        str(lock),
    ]
    return int(inventory.main(args))


def test_verify_passes_when_the_auditor_reported_every_identity(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    _results(split_dir[1])
    assert _verify(split_dir) == 0
    assert "audited 4 locked packages" in capsys.readouterr().out


def test_verify_fails_when_the_auditor_dropped_a_windows_only_pin(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    _results(split_dir[1], drop=("colorama",))
    assert _verify(split_dir) == 1
    assert "colorama==0.4.6" in capsys.readouterr().err


def test_verify_fails_when_a_pin_was_skipped(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    _results(split_dir[1], skip="zipp")
    assert _verify(split_dir) == 1
    assert "skipped zipp" in capsys.readouterr().err


def test_verify_fails_and_names_a_vulnerability(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    _results(split_dir[1], vuln="sphinx")
    assert _verify(split_dir) == 1
    assert "vulnerable: sphinx==9.0.4: PYSEC-0 (fixed in: 9.9)" in capsys.readouterr().err


def test_verify_fails_when_a_result_is_missing_or_unreadable(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert _verify(split_dir) == 1, "no results at all"
    _results(split_dir[1])
    (split_dir[1] / "audit-2.json").write_text("not json", encoding="utf-8")
    assert _verify(split_dir) == 1
    assert "not a pip-audit result" in capsys.readouterr().err


def test_verify_fails_when_the_auditor_reports_something_that_was_not_sent(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    _results(split_dir[1])
    out = split_dir[1] / "audit-1.json"
    data = json.loads(out.read_text(encoding="utf-8"))
    data["dependencies"][0]["version"] = "0.0.1"
    out.write_text(json.dumps(data), encoding="utf-8")
    assert _verify(split_dir) == 1
    assert "did not audit what requirements-audit-1.txt holds" in capsys.readouterr().err


def test_verify_fails_when_an_input_regained_a_marker(
    split_dir: tuple[Path, Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    _results(split_dir[1])
    first = split_dir[1] / "requirements-audit-1.txt"
    first.write_text(
        first.read_text(encoding="utf-8").replace(
            "colorama==0.4.6", "colorama==0.4.6 ; os_name == 'nt'"
        ),
        encoding="utf-8",
    )
    assert _verify(split_dir) == 1
    assert "still has environment markers" in capsys.readouterr().err


def test_split_refuses_an_export_that_differs_from_the_lock(
    tmp_path: Path, pyproject: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export = tmp_path / "export.txt"
    export.write_text(MARKED_EXPORT, encoding="utf-8")
    lock = _lock(tmp_path, EVERY_IDENTITY | {("only-in-lock", "1.0")})
    args = [
        "split",
        str(export),
        str(tmp_path / "a"),
        "--pyproject",
        str(pyproject),
        "--lock",
        str(lock),
    ]
    assert inventory.main(args) == 1
    assert "locked but not exported, so not audited: only-in-lock==1.0" in capsys.readouterr().err
    lock = _lock(tmp_path, EVERY_IDENTITY - {("zipp", "3.23.0")})
    args = [
        "split",
        str(export),
        str(tmp_path / "b"),
        "--pyproject",
        str(pyproject),
        "--lock",
        str(lock),
    ]
    assert inventory.main(args) == 1
    assert "exported but not in uv.lock: zipp==3.23.0" in capsys.readouterr().err


def test_split_refuses_an_export_without_the_extras_or_packages(
    tmp_path: Path, pyproject: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export = tmp_path / "export.txt"
    export.write_text(MARKED_EXPORT, encoding="utf-8")
    args = ["split", str(export), str(tmp_path / "a"), "--pyproject", str(pyproject)]
    assert inventory.main(args) == 1
    assert "--all-extras" in capsys.readouterr().err
    export.write_text("# nothing\n", encoding="utf-8")
    assert (
        inventory.main(["split", str(export), str(tmp_path / "b"), "--pyproject", str(pyproject)])
        == 1
    )
    assert "lists no packages" in capsys.readouterr().err


def test_unreadable_input_is_an_exit_code_not_a_traceback(
    tmp_path: Path, pyproject: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export = tmp_path / "export.txt"
    export.write_text("pkg @ https://example.com/pkg.tgz\n", encoding="utf-8")
    args = ["split", str(export), str(tmp_path / "a"), "--pyproject", str(pyproject)]
    assert inventory.main(args) == 1
    assert "cannot read this requirement" in capsys.readouterr().err
    assert inventory.main(["verify", "--bogus"]) == 2


def test_the_real_lock_matches_its_export_and_is_split_without_loss(tmp_path: Path) -> None:
    if shutil.which("uv") is None or not (ROOT / "uv.lock").exists():
        pytest.skip("needs uv and the lock file (the source distribution has none)")
    export = tmp_path / "export.txt"
    command = [
        "uv", "export", "--color", "never", "--locked", "--all-groups", "--all-extras",
        "--no-emit-project", "--format", "requirements-txt", "--output-file", str(export),
    ]  # fmt: skip
    subprocess.run(command, cwd=ROOT, check=True, capture_output=True)  # noqa: S603
    directory = tmp_path / "audit"
    args = ["split", str(export), str(directory), "--lock", str(ROOT / "uv.lock")]
    args += ["--pyproject", str(ROOT / "pyproject.toml")]
    assert inventory.main(args) == 0
    submitted: set[tuple[str, str]] = set()
    for path in directory.glob("requirements-audit-*.txt"):
        assert _collected(path) == inventory.identities(path.read_text(encoding="utf-8"))
        submitted |= inventory.identities(path.read_text(encoding="utf-8"))
    assert submitted == inventory.lock_identities(ROOT / "uv.lock")
