# Threat model

> **Status: initial.** This model covers the planned design. Review it whenever an input format, output format, or dependency changes.

## What the tool protects

- **The operator's data.** Inputs are exported Windows event logs and event records. They can hold sensitive account, group, and configuration details.
- **The integrity of results.** Reviewers and assessors rely on the output as evidence.
- **The operator's machine.** The tool processes files that may come from systems the operator does not fully trust.
- **The supply chain.** Users install release artifacts built by this project's pipeline.

## Trust boundaries

1. Input files enter the tool. They are untrusted.
2. Output files leave the tool and are opened in browsers, spreadsheets, and review systems.
3. Release artifacts leave the build pipeline and are installed by users.

## Threats and controls (STRIDE)

The **Status** column uses three values. **In place** means the repository enforces it today. **Planned** means it is a design requirement for features not yet built. **Needs settings** means it depends on repository settings applied outside the code.

| Category | Threat | Control | Status |
| --- | --- | --- | --- |
| Spoofing | A tampered release artifact is installed in place of the real one. | Releases are built only by the release workflow from a commit on `main`, with a published `SHA256SUMS` file and a software bill of materials. Build provenance attestations are added once the repository is public. | In place (attestations when public) |
| Tampering | A crafted input file changes results, for example by injecting duplicate keys or changing identifier types. | Strict validation, identifiers kept as text, duplicates and ambiguities reported as findings, and every finding linked to its source record. | Planned |
| Tampering | A malicious change enters the code base. | Pull requests only, a required passing check, resolved conversations, no force pushes to `main`, signed-off commits, and actions pinned to full commit hashes. | In place (branch rules need settings) |
| Repudiation | A user cannot show which inputs and rules produced a report. | Reports record the tool version, input file hashes, and the rules applied. | Planned |
| Information disclosure | Reports leak more data than needed, or test fixtures contain real data. | Reports include only the fields findings need. Fixtures are synthetic. Secret scanning runs on every change and across the full history. | Secret scanning in place; the rest planned |
| Information disclosure | The tool sends data over the network. | No network code and no telemetry. | In place |
| Denial of service | Oversized or deeply nested inputs exhaust memory or time. | Streaming parsers where possible, size limits, and `defusedxml` protection against XML entity expansion. | Planned |
| Elevation of privilege | Input content runs as code: XML external entities, formula injection in CSV output, or script injection in HTML output. | `defusedxml` for all XML, formula neutralization in all CSV and spreadsheet output, and escaping of all HTML output. No use of `eval`, `exec`, or `pickle` on input. | Planned; Ruff security rules in place |
| Elevation of privilege | A compromised dependency or build step runs with broad permissions. | Minimal runtime dependencies, locked versions, vulnerability and license scanning, least-privilege workflow tokens, and workflow security analysis with zizmor. | In place |

## Residual risks

- The tool cannot detect data that a source system never exported. Reports state this limit.
- Checksums and attestations protect users only if they verify them. [Releasing](releasing.md) shows how.
