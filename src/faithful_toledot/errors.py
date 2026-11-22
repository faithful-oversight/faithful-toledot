# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by toledot.

The classes come from faithful-core. ``ToledotError`` is its ``FaithfulError``, so
one ``except ToledotError`` also catches an error raised inside the library.
"""

from faithful_core.errors import (
    CollectionError,
    FaithfulError,
    InputError,
    OutputError,
    UsageError,
)

__all__ = [
    "CollectionError",
    "InputError",
    "OutputError",
    "ToledotError",
    "UsageError",
]

ToledotError = FaithfulError
"""Base class for errors toledot reports to the user."""
