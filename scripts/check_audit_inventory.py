# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Make the vulnerability audit cover every locked package, and prove it did.

``scripts/check.sh deps`` exports the lock to a requirements file. That export keeps
environment markers (``colorama==0.4.6 ; sys_platform == 'win32'``), and ``pip-audit``
evaluates a marker on the machine it runs on and silently drops every pin that is false
there. An audit on Linux would never look at a Windows-only package or at the version of
a package that only another Python version installs, yet it would report a clean result.

This script closes that gap in three steps, all of them failing closed:

``split EXPORT DIR``
    Reads every (name, version) identity from the export, whatever its markers, and writes
    marker-free requirement files that pip-audit cannot filter. One file holds one version
    of each package; a package the lock pins at several versions gets one version per
    file, so no file conflicts with itself. It also checks the identities against
    ``uv.lock`` and checks that every package an extra names is among them.

``verify EXPORT DIR``
    Run after pip-audit. For each input file it reads pip-audit's own JSON result and
    requires that the auditor reported exactly the identities in that file, none skipped.
    It then requires the union of what the auditor reported to equal the lock, so a
    package the auditor dropped is a failure and not a clean pass. It prints every
    vulnerability found and fails if there is one.

``EXPORT [pyproject.toml]``
    The older check alone: fail unless every package an extra names is in the export.

Usage: scripts/check_audit_inventory.py split EXPORT DIR [--pyproject FILE] [--lock FILE]
       scripts/check_audit_inventory.py verify EXPORT DIR [--pyproject FILE] [--lock FILE]
       scripts/check_audit_inventory.py EXPORT [pyproject.toml]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from packaging.version import InvalidVersion, Version

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

ALSO_REQUIRED: tuple[str, ...] = ("pyspnego",)
"""Packages to require besides the ones the extras name. ``pypsrp`` pulls in ``pyspnego``."""

INPUT_NAME = "requirements-audit-{}.txt"
RESULT_NAME = "audit-{}.json"
_INPUT = re.compile(r"^requirements-audit-(\d+)\.txt$")

_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(?P<version>[^\s;\\]+)"
    r"\s*(?:;(?P<marker>.*))?$"
)
_HASH = re.compile(r"--hash=(sha256:[0-9a-f]{64})")
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

Identity = tuple[str, str]
"""A package as the auditor sees it: (normalised name, exact version)."""


class AuditInputError(ValueError):
    """The export, the lock, or an audit file is not something the audit can rely on."""


class Pin(NamedTuple):
    """One pinned requirement line of an export."""

    name: str
    version: str
    marker: str
    hashes: frozenset[str]


def normalise(name: str) -> str:
    """Return a package name in the form pip uses to compare names."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations, as a requirements file does."""
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        lines.append((pending + line).strip())
        pending = ""
    if pending.strip():
        lines.append(pending.strip())
    return lines


def parse(text: str) -> list[Pin]:
    """Return every pin in a requirements export, or raise if a line cannot be read.

    A line this cannot read as ``name==version`` (a URL, a range, an option) is an error:
    skipping it would leave a package out of the audit without saying so.
    """
    pins: list[Pin] = []
    for line in _logical_lines(text):
        if not line or line.startswith("#"):
            continue
        hashes = frozenset(_HASH.findall(line))
        bare = _HASH.sub("", line).strip()
        found = _LINE.match(bare)
        if found is None:
            msg = f"cannot read this requirement as name==version: {line[:120]!r}"
            raise AuditInputError(msg)
        pins.append(
            Pin(
                name=normalise(found.group("name")),
                version=found.group("version"),
                marker=(found.group("marker") or "").strip(),
                hashes=hashes,
            )
        )
    return pins


def identities(text: str) -> set[Identity]:
    """Return every (name, version) an export pins, whatever its environment markers."""
    return {(pin.name, pin.version) for pin in parse(text)}


def audited(text: str) -> set[str]:
    """Return the normalised names of the packages a requirements export pins."""
    return {name for name, _ in identities(text)}


def _version_key(version: str) -> tuple[int, Version | str]:
    try:
        return (0, Version(version))
    except InvalidVersion:
        return (1, version)


def render_inputs(text: str) -> list[str]:
    """Return marker-free requirement files, as texts, that together hold every identity.

    File ``n`` holds the ``n``-th lowest version of every package that has that many, so a
    package locked at three versions appears in three files, once in each.
    """
    pins = parse(text)
    hashes: dict[Identity, set[str]] = {}
    for pin in pins:
        hashes.setdefault((pin.name, pin.version), set()).update(pin.hashes)
    unhashed = sorted(f"{n}=={v}" for (n, v), found in hashes.items() if not found)
    if unhashed:
        msg = f"the export carries no hash for {', '.join(unhashed)}; export with hashes"
        raise AuditInputError(msg)
    versions: dict[str, list[str]] = {}
    for name, version in hashes:
        versions.setdefault(name, []).append(version)
    rounds = max((len(found) for found in versions.values()), default=0)
    texts = []
    for index in range(rounds):
        lines = [
            "# Generated by scripts/check_audit_inventory.py: one version of each package, no",
            "# environment markers, so the auditor cannot drop a pin this host would not install.",
        ]
        for name in sorted(versions):
            ordered = sorted(versions[name], key=_version_key)
            if index < len(ordered):
                version = ordered[index]
                lines.append(f"{name}=={version} \\")
                found = sorted(hashes[(name, version)])
                lines.extend(
                    f"    --hash={digest}" + (" \\" if i < len(found) - 1 else "")
                    for i, digest in enumerate(found)
                )
        texts.append("\n".join(lines) + "\n")
    return texts


def lock_identities(lock: Path) -> set[Identity]:
    """Return every (name, version) the lock file pins, apart from the project itself."""
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    found: set[Identity] = set()
    for package in data.get("package", []):
        source = package.get("source", {})
        if source.get("editable") == "." or source.get("virtual") == ".":
            continue
        name, version = package.get("name"), package.get("version")
        if not name or not version:
            msg = f"{lock.name} has a package without a name and version: {package!r}"
            raise AuditInputError(msg)
        found.add((normalise(str(name)), str(version)))
    return found


def _show(ids: Iterable[Identity]) -> str:
    return ", ".join(f"{name}=={version}" for name, version in sorted(ids))


def required(pyproject: Path, also: Sequence[str] | None = None) -> list[str]:
    """Return the packages the extras of a project name, then ``also``, in order.

    ``also`` defaults to ``ALSO_REQUIRED``.
    """
    project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    own = normalise(str(project.get("name", "")))
    names: list[str] = []
    for requirements in project.get("optional-dependencies", {}).values():
        for requirement in requirements:
            found = _NAME.match(str(requirement))
            name = normalise(found.group(1)) if found else ""
            if name and name != own and name not in names:
                names.append(name)
    extra = ALSO_REQUIRED if also is None else also
    names.extend(normalise(name) for name in extra if normalise(name) not in names)
    return names


def missing(text: str, pyproject: Path, also: Sequence[str] | None = None) -> list[str]:
    """Return the required packages the export does not hold, in ``required`` order."""
    present = audited(text)
    return [name for name in required(pyproject, also) if name not in present]


def _absent_names(names: Iterable[str], pyproject: Path) -> list[str]:
    present = set(names)
    return [name for name in required(pyproject) if name not in present]


def _problems_with_sources(export: str, pyproject: Path, lock: Path | None) -> list[str]:
    """Return what is wrong with the export as the source of the audit, or nothing."""
    problems: list[str] = []
    exported = identities(export)
    if not exported:
        problems.append("the export lists no packages, so nothing would be audited")
    absent = _absent_names((name for name, _ in exported), pyproject)
    if absent:
        problems.append(
            "the vulnerability audit does not cover the optional dependencies: "
            f"{', '.join(absent)} missing from the export. "
            "Export with --all-extras so every extra is audited."
        )
    if lock is not None:
        locked = lock_identities(lock)
        if locked - exported:
            problems.append(f"locked but not exported, so not audited: {_show(locked - exported)}")
        if exported - locked:
            problems.append(f"exported but not in {lock.name}: {_show(exported - locked)}")
    return problems


def split(export: Path, directory: Path, pyproject: Path, lock: Path | None) -> int:
    """Write the marker-free audit inputs for ``export`` into ``directory``."""
    text = export.read_text(encoding="utf-8")
    problems = _problems_with_sources(text, pyproject, lock)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)  # noqa: T201
        return 1
    directory.mkdir(parents=True, exist_ok=True)
    for index, content in enumerate(render_inputs(text), start=1):
        (directory / INPUT_NAME.format(index)).write_text(content, encoding="utf-8")
    return 0


def _read_input(path: Path) -> set[Identity]:
    pins = parse(path.read_text(encoding="utf-8"))
    marked = sorted(f"{pin.name}=={pin.version}" for pin in pins if pin.marker)
    if marked:
        msg = f"{path.name} still has environment markers on {', '.join(marked)}"
        raise AuditInputError(msg)
    found = [(pin.name, pin.version) for pin in pins]
    if len(found) != len(set(found)) or len({name for name, _ in found}) != len(found):
        msg = f"{path.name} names a package more than once"
        raise AuditInputError(msg)
    return set(found)


def _reported(path: Path) -> tuple[set[Identity], list[str]]:
    """Return the identities pip-audit audited, and its vulnerability lines."""
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        entries = list(data["dependencies"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        kind = type(exc).__name__
        msg = f"{path.name} is not a pip-audit result ({kind}); the audit did not finish"
        raise AuditInputError(msg) from exc
    done: set[Identity] = set()
    skipped: list[str] = []
    vulnerable: list[str] = []
    for entry in entries:
        name = normalise(str(entry.get("name", "")))
        if "skip_reason" in entry or not entry.get("version"):
            skipped.append(f"{name} ({entry.get('skip_reason', 'no version')})")
            continue
        version = str(entry["version"])
        done.add((name, version))
        for vuln in entry.get("vulns", []):
            fixes = ", ".join(vuln.get("fix_versions", [])) or "no fix known"
            vulnerable.append(f"{name}=={version}: {vuln.get('id', '?')} (fixed in: {fixes})")
    if skipped:
        msg = f"{path.name}: pip-audit skipped {', '.join(sorted(skipped))}"
        raise AuditInputError(msg)
    return done, vulnerable


def _problems_with_results(directory: Path) -> tuple[set[Identity], list[str], list[str]]:
    """Return the identities the auditor reported, its vulnerabilities, and any problems."""
    submitted: set[Identity] = set()
    vulnerable: list[str] = []
    problems: list[str] = []
    inputs = sorted(
        (int(m.group(1)), p) for p in directory.iterdir() if (m := _INPUT.match(p.name)) is not None
    )
    if not inputs:
        problems.append(f"{directory} holds no audit input, so nothing was submitted")
    for index, path in inputs:
        try:
            wanted = _read_input(path)
            result = directory / RESULT_NAME.format(index)
            if not result.exists():
                msg = (
                    f"no pip-audit result for {path.name}; the audit did not run or did not finish"
                )
                raise AuditInputError(msg)  # noqa: TRY301
            done, found = _reported(result)
        except AuditInputError as exc:
            problems.append(str(exc))
            continue
        vulnerable.extend(found)
        if done != wanted:
            problems.append(
                f"pip-audit did not audit what {path.name} holds; "
                f"dropped: {_show(wanted - done) or 'none'}; "
                f"unexpected: {_show(done - wanted) or 'none'}"
            )
        submitted |= done
    return submitted, vulnerable, problems


def verify(export: Path, directory: Path, pyproject: Path, lock: Path | None) -> int:
    """Check that the auditor audited every identity of the export, and report its findings."""
    problems = _problems_with_sources(export.read_text(encoding="utf-8"), pyproject, lock)
    submitted, vulnerable, found = _problems_with_results(directory)
    problems.extend(found)
    wanted = identities(export.read_text(encoding="utf-8"))
    if lock is not None:
        wanted |= lock_identities(lock)
    if not found and wanted - submitted:
        problems.append(f"the audit never saw {_show(wanted - submitted)}")
    for line in vulnerable:
        print(f"vulnerable: {line}", file=sys.stderr)  # noqa: T201
    for problem in problems:
        print(f"audit coverage: {problem}", file=sys.stderr)  # noqa: T201
    if problems or vulnerable:
        return 1
    print(f"audited {len(submitted)} locked packages, whatever their platform or Python version")  # noqa: T201
    return 0


def _legacy(argv: list[str]) -> int:
    pyproject = Path(argv[1]) if len(argv) == 2 else Path("pyproject.toml")  # noqa: PLR2004
    try:
        absent = missing(Path(argv[0]).read_text(encoding="utf-8"), pyproject)
    except AuditInputError as exc:
        print(exc, file=sys.stderr)  # noqa: T201
        return 1
    if absent:
        print(  # noqa: T201
            "the vulnerability audit does not cover the optional dependencies: "
            f"{', '.join(absent)} missing from the export. "
            "Export with --all-extras so every extra is audited.",
            file=sys.stderr,
        )
        return 1
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="check_audit_inventory.py")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("split", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("export", type=Path)
        sub.add_argument("directory", type=Path)
        sub.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
        sub.add_argument("--lock", type=Path, default=None)
    return parser


def main(argv: list[str]) -> int:
    """Run a subcommand, or the older single-file check; return the exit code."""
    if argv and argv[0] in {"split", "verify"}:
        try:
            args = _parser().parse_args(argv)
        except SystemExit:
            return 2
        run = split if args.command == "split" else verify
        try:
            return run(args.export, args.directory, args.pyproject, args.lock)
        except (AuditInputError, OSError, tomllib.TOMLDecodeError) as exc:
            print(f"audit coverage: {exc}", file=sys.stderr)  # noqa: T201
            return 1
    if len(argv) not in {1, 2}:
        print(  # noqa: T201
            "usage: check_audit_inventory.py split|verify EXPORT DIR [--pyproject FILE] "
            "[--lock FILE]\n       check_audit_inventory.py EXPORT [pyproject.toml]",
            file=sys.stderr,
        )
        return 2
    return _legacy(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
