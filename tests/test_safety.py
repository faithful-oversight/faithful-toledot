# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the escaping of invisible characters."""

from __future__ import annotations

import unicodedata

import pytest

from faithful_toledot.outputs.safety import (
    csv_cell,
    escape_markdown,
    neutralize_formula,
    terminal,
    visible,
)

BMP_INVISIBLE = [
    0x00, 0x08, 0x0B, 0x0C, 0x1B, 0x7F, 0x85, 0x9F,  # controls
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x180E,  # soft hyphen, fillers
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029,  # zero width, separators
    0x202A, 0x202E, 0x2060, 0x2066, 0x2069,  # bidirectional, word joiner
    0x3164, 0xFE00, 0xFE0F, 0xFEFF, 0xFFA0,  # fillers, variation selectors, BOM
    0xFFF9, 0xFFFB,  # interlinear annotation
]  # fmt: skip
OUTSIDE_THE_BMP = [0xE0000, 0xE0001, 0xE0020, 0xE0041, 0xE007F, 0xE0100, 0xE01EF, 0x1D173, 0x110BD]


@pytest.mark.parametrize("code", BMP_INVISIBLE)
def test_invisible_characters_in_the_bmp_are_escaped_with_four_digits(code: int) -> None:
    assert visible(f"a{chr(code)}b") == f"a\\u{code:04x}b"


@pytest.mark.parametrize("code", OUTSIDE_THE_BMP)
def test_invisible_characters_outside_the_bmp_use_eight_digits(code: int) -> None:
    assert visible(f"a{chr(code)}b") == f"a\\U{code:08x}b"


def test_lone_surrogates_are_escaped() -> None:
    assert visible("a\udc80b") == "a\\udc80b"


@pytest.mark.parametrize("text", ["plain text", "tab\there", "line\nbreak\r\n", "", " ~"])
def test_ascii_text_tabs_and_line_breaks_pass_through(text: str) -> None:
    assert visible(text) == text


ORDINARY = [
    "na" + chr(0xEF) + "ve " + chr(0xFC) + "ber",  # accented Latin
    chr(0x65E5) + chr(0x672C),  # CJK
    chr(0x41F) + chr(0x440),  # Cyrillic
    chr(0x1F600),  # an emoji without joiners
]


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_non_ascii_text_passes_through(text: str) -> None:
    assert visible(text) == text


def test_every_format_character_and_separator_is_escaped() -> None:
    missed = [
        hex(code)
        for code in range(0x110000)
        if unicodedata.category(chr(code)) in {"Cf", "Zl", "Zp"} and visible(chr(code)) == chr(code)
    ]
    assert missed == []


def test_escapes_are_unambiguous_next_to_hex_digits() -> None:
    assert visible("\U000e0041" + "42") == "\\U000e004142"
    assert visible(chr(0x200B) + "42") == "\\u200b42"


def test_terminal_text_cannot_return_the_cursor_or_hide_in_tabs() -> None:
    assert terminal("evil\rtoledot: 0 problems\tx\nnext") == "evil\\rtoledot: 0 problems\\tx\nnext"


@pytest.mark.parametrize(
    "code",
    [0x00A0, 0x1680, 0x2000, 0x2003, 0x200A, 0x202F, 0x205F, 0x2800, 0x3000],
)
def test_look_alike_spaces_are_escaped(code: int) -> None:
    assert visible(f"admin{chr(code)}") == f"admin\\u{code:04x}"


def test_every_space_separator_except_the_ascii_space_is_escaped() -> None:
    spaces = [chr(code) for code in range(0x110000) if unicodedata.category(chr(code)) == "Zs"]
    assert " " in spaces
    for char in spaces:
        assert (visible(char) == char) is (char == " ")


def test_a_look_alike_space_cannot_hide_a_formula() -> None:
    assert csv_cell("\u00a0=1+1") == "\\u00a0=1+1"
    assert not csv_cell("\u00a0=1+1").startswith(("=", "+", "-", "@"))


@pytest.mark.parametrize("value", ["-1", "-42", "-0.5", "-1000000"])
def test_a_plain_negative_number_stays_a_number(value: str) -> None:
    assert neutralize_formula(value) == value
    assert csv_cell(value) == value


@pytest.mark.parametrize(
    "value", ["-1+1", "-cmd|x", "--1", "-", "-1e5", "-1,5", "-\u0661", "- 1", "-1\n", "=-1"]
)
def test_anything_else_starting_with_a_minus_is_still_neutralized(value: str) -> None:
    assert neutralize_formula(value) == "'" + value


@pytest.mark.parametrize("code", [0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F])
def test_khmer_and_mongolian_invisible_marks_are_escaped(code: int) -> None:
    assert visible(f"admin{chr(code)}") == f"admin\\u{code:04x}"


def test_an_issue_reference_from_the_input_is_not_linked() -> None:
    joiner = "\u2060"
    assert escape_markdown("see #123") == f"see #{joiner}123"
    assert escape_markdown("owner/repo#7") == f"owner/repo#{joiner}7"
    assert escape_markdown("item #a") == "item #a"
