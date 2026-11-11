# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for publishing report files on file systems without hard links."""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

import pytest

from faithful_toledot.errors import ToledotError
from faithful_toledot.outputs.files import write_files

if TYPE_CHECKING:
    from collections.abc import Callable

FILES = {"a.txt": "first file\n" * 100, "b.txt": "second file\n" * 100}


class FlakyHandle:
    """A real file handle that fails at one chosen point."""

    def __init__(self, handle: IO[bytes], fail: str) -> None:
        self.handle = handle
        self.fail = fail

    def __enter__(self) -> FlakyHandle:
        """Enter like the real handle."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the real handle, then fail if asked to fail on close."""
        self.handle.close()
        if self.fail == "close":
            raise OSError(5, "Input/output error")

    def write(self, data: bytes) -> int:
        if self.fail == "write":
            self.handle.write(data[: len(data) // 2])
            self.handle.flush()
            raise OSError(28, "No space left on device")
        return self.handle.write(data)

    def flush(self) -> None:
        self.handle.flush()

    def fileno(self) -> int:
        return self.handle.fileno()


@pytest.fixture
def no_hard_links(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    """Make hard links unsupported; return a switch that injects one failure in the copy."""
    copying = {"on": False}
    fail = {"at": ""}
    real_fdopen = os.fdopen
    real_read = Path.read_bytes

    def no_links(*_: object) -> None:
        copying["on"] = True
        raise OSError(1, "Operation not permitted")

    def fdopen(fd: int, *args: Any, **kwargs: Any) -> object:
        if copying["on"] and fail["at"] == "fdopen":
            raise OSError(24, "Too many open files")
        handle = real_fdopen(fd, *args, **kwargs)
        return FlakyHandle(handle, fail["at"]) if copying["on"] else handle

    def read_bytes(self: Path) -> bytes:
        if copying["on"] and fail["at"] == "read":
            raise OSError(5, "Input/output error")
        return real_read(self)

    monkeypatch.setattr(os, "link", no_links)
    monkeypatch.setattr(os, "fdopen", fdopen)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)

    def inject(point: str) -> None:
        fail["at"] = point

    return inject


def test_copy_fallback_publishes_complete_private_files(
    tmp_path: Path, no_hard_links: Callable[[str], None]
) -> None:
    no_hard_links("")
    written = write_files(tmp_path, FILES, force=False)
    assert [p.name for p in written] == list(FILES)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(FILES)
    for path in written:
        assert path.read_text(encoding="utf-8") == FILES[path.name]
        if os.name == "posix":
            assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("point", ["read", "fdopen", "write", "close"])
def test_copy_fallback_failure_leaves_no_partial_file(
    tmp_path: Path, no_hard_links: Callable[[str], None], point: str
) -> None:
    """A read, partial write, or close failure removes the file the fallback created."""
    no_hard_links(point)
    with pytest.raises(ToledotError, match="the directory is unchanged"):
        write_files(tmp_path, FILES, force=False)
    assert list(tmp_path.iterdir()) == []


def test_copy_fallback_never_removes_a_file_it_did_not_create(
    tmp_path: Path, no_hard_links: Callable[[str], None]
) -> None:
    """A name taken by someone else before the exclusive create is left alone."""
    no_hard_links("")
    real_open = os.open

    def racing_open(path: str, flags: int, mode: int = 0o777) -> int:
        if str(path).endswith("b.txt"):
            Path(path).write_text("someone else", encoding="utf-8")
        return real_open(path, flags, mode)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "open", racing_open)
        with pytest.raises(ToledotError, match="appeared while writing"):
            write_files(tmp_path, FILES, force=False)
    assert [p.name for p in tmp_path.iterdir()] == ["b.txt"]
    assert (tmp_path / "b.txt").read_text(encoding="utf-8") == "someone else"
