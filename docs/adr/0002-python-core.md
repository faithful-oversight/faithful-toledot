# 2. Python core with a versioned output contract

- Status: accepted
- Date: 2026-11-07

## Context

The tool must be easy to install for administrators and assessors, easy to read for reviewers, and usable from other languages and pipelines.

## Decision

- Write the core in Python 3.11 or newer, fully typed and checked with mypy in strict mode.
- Publish machine-readable output that follows a versioned JSON Schema, so other languages can consume results without a port.
- Keep runtime dependencies to a minimum. Each new runtime dependency needs a stated reason.
- Manage the environment and lock file with uv.

## Consequences

Other formats, such as a standalone executable or a PowerShell wrapper, can be built later around the same core and schema. A native port in another language would be separate code, checked against the same test fixtures.
