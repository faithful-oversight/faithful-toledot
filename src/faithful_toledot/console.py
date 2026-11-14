# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Printing that never changes an exit code.

The reports are written before the closing summary is printed. A closed pipe or a
stream that cannot encode the text must not turn a finished run into an internal error,
so every line the commands print goes through :func:`say`.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys

_state = {"stdout_closed": False}


def harden_streams() -> None:
    r"""Make stdout and stderr unable to fail on a character they cannot encode.

    Text the stream's encoding cannot hold prints as an escape such as ``\xe9``.
    Streams that cannot be reconfigured, such as a test double, are left alone.
    """
    _state["stdout_closed"] = False
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(errors="backslashreplace")


def stop_stdout() -> None:
    """Stop printing and point stdout at the null device where the stream has a descriptor.

    This is the pattern the Python documentation gives for a closed pipe: the pipe is
    replaced, so shutting down the interpreter does not fail a second time.
    """
    _state["stdout_closed"] = True
    with contextlib.suppress(Exception):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
    # Nothing is written after this point (see say), so an in-memory sink holds nothing.
    sys.stdout = io.StringIO()


def say(text: str, *, error: bool = False, end: str = "\n") -> None:
    """Print one piece of text to stdout, or to stderr with ``error``.

    A closed stdout stops all further output without an error. Any other failure to
    print is also dropped: the caller has already decided the exit code.
    """
    if error:
        with contextlib.suppress(Exception):
            sys.stderr.write(text + end)
            sys.stderr.flush()
        return
    if _state["stdout_closed"]:
        return
    try:
        sys.stdout.write(text + end)
        sys.stdout.flush()
    except BrokenPipeError:
        stop_stdout()
    except (OSError, ValueError, UnicodeError):
        # A stream that is closed, full or cannot take the text: stop printing quietly.
        _state["stdout_closed"] = True
