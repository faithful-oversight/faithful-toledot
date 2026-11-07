# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""toledot: AD Change Narrative."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("faithful-toledot")
except PackageNotFoundError:  # pragma: no cover - only when run from an uninstalled tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
