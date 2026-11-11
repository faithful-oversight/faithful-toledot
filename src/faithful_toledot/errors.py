# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by toledot."""


class ToledotError(Exception):
    """Base class for errors toledot reports to the user."""


class InputError(ToledotError):
    """An input file or configuration cannot be read or has the wrong shape."""


class CollectionError(ToledotError):
    """Live collection could not connect, authenticate, or read what it needs."""
