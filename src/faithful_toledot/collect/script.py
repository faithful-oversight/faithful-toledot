# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The packaged PowerShell collector."""

from __future__ import annotations

from faithful_core.collect.script import ScriptResource

NAME = "Collect-ToledotEvents.ps1"
_COLLECTOR = ScriptResource("faithful_toledot", NAME, "collector")

text = _COLLECTOR.text
"""Return the collector script. It is pure ASCII."""
version = _COLLECTOR.version
"""Return the collector's own version, as it writes it into each file."""
