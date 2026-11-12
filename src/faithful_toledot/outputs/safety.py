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
import unicodedata

FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n", "\uff1d", "\uff0b", "\uff0d", "\uff20")
"""Leading characters that spreadsheet programs may treat as the start of a formula.

Includes the full-width forms, which some spreadsheet programs also accept.
"""

_CANDIDATE = re.compile("[^\x20-\x7e\t\n\r]")
"""Every character that might need escaping; printable ASCII, tab, and line breaks never do."""
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
"""Controls, format characters (zero width, bidirectional, joiners, soft hyphen, BOM),
lone surrogates, and the line and paragraph separators."""
_FILLERS = frozenset({0x034F, 0x115F, 0x1160, 0x180E, 0x3164, 0xFFA0})
"""Characters that draw nothing but are not in the categories above (U+180E was one
until Unicode 6.3, so it is listed in case the running Unicode data is older)."""
_RANGES = ((0xE0000, 0xE007F), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
"""The tag block, and the variation selectors, which change how a neighbour is drawn."""
_BMP_MAX = 0xFFFF
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&])")
_AUTOLINK = re.compile(r"(?i)(://|www\.|@)")
_WORD_JOINER = "\u2060"


def _hidden(char: str) -> bool:
    code = ord(char)
    return (
        unicodedata.category(char) in _HIDDEN_CATEGORIES
        or code in _FILLERS
        or any(low <= code <= high for low, high in _RANGES)
    )


def _escape(match: re.Match[str]) -> str:
    char = match.group()
    if not _hidden(char):
        return char
    code = ord(char)
    return f"\\u{code:04x}" if code <= _BMP_MAX else f"\\U{code:08x}"


def visible(value: str) -> str:
    r"""Replace invisible and reordering characters with visible escapes.

    Characters in the Basic Multilingual Plane become ``\u202e``; others become
    ``\U000e0041`` with eight digits, so the escape cannot be misread. Tab and line
    breaks are kept: the callers that cannot allow them handle them.
    """
    return _CANDIDATE.sub(_escape, value)


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
    """Make text safe to print to a terminal.

    Line feeds are kept, because callers print several lines at once. A carriage
    return and a tab become visible escapes: a carriage return in a file name could
    otherwise move the cursor back and print over the start of the line.
    """
    return visible(value).replace("\r", "\\r").replace("\t", "\\t")


def command_line(*parts: str) -> str:
    """Quote a command for copying into this platform's usual shell.

    Paths with spaces or shell characters stay one argument when pasted. The caller
    still passes the result through :func:`terminal` before printing it.
    """
    if os.name == "nt":
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)
