# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Make untrusted values safe and honest for each output format.

Input files can contain characters that change how text looks rather than what
it says: control characters, terminal escape sequences, and bidirectional
formatting marks that reorder text on screen. People-facing outputs show these
as visible escapes, so a reader always sees what the data really contains. The
JSON report keeps exact values.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess

FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n", "\uff1d", "\uff0b", "\uff0d", "\uff20")
"""Leading characters that spreadsheet programs may treat as the start of a formula.

Includes the full-width forms, which some spreadsheet programs also accept.
"""

_INVISIBLE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"  # control characters, except tab and line breaks
    "\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"  # bidirectional formatting
    "\ud800-\udfff]"  # lone surrogates, which cannot be encoded
)
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&])")
_AUTOLINK = re.compile(r"(?i)(://|www\.|@)")
_WORD_JOINER = "\u2060"


def visible(value: str) -> str:
    r"""Replace invisible and reordering characters with visible escapes like ``\u202e``."""
    return _INVISIBLE.sub(lambda m: f"\\u{ord(m.group()):04x}", value)


def neutralize_formula(value: str) -> str:
    """Stop a spreadsheet from treating a cell as a formula.

    A value that starts with a formula trigger gets a leading apostrophe, which
    spreadsheets display as plain text. Applying this twice changes nothing more.
    """
    if value.startswith(FORMULA_TRIGGERS):
        return "'" + value
    return value


def csv_cell(value: str) -> str:
    """Make a value safe for a spreadsheet cell."""
    return neutralize_formula(visible(value))


def escape_markdown(value: str) -> str:
    """Escape text for a Markdown table cell or paragraph.

    Backslash-escapes the characters that can change meaning inside a table cell
    or after a list marker: emphasis, code, links, table pipes, entities, and
    ``<`` and ``>`` so the text cannot open an HTML tag. A word joiner after
    ``://``, ``www.``, and ``@`` stops automatic linking of URLs and email
    addresses from the input. Line breaks become a visible arrow, so a value
    cannot start a new block.
    """
    value = visible(value)
    value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " \u21b5 ")
    value = _MD_SPECIAL.sub(r"\\\1", value)
    return _AUTOLINK.sub(lambda m: m.group() + _WORD_JOINER, value)


def terminal(value: str) -> str:
    """Make a value safe to print to a terminal."""
    return visible(value)


def command_line(*parts: str) -> str:
    """Quote a command for copying into this platform's usual shell.

    Paths with spaces or shell characters stay one argument when pasted. The caller
    still passes the result through :func:`terminal` before printing it.
    """
    if os.name == "nt":
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)
