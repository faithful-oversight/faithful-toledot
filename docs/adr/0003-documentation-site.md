# 3. Documentation as code, published with Sphinx

- Status: accepted
- Date: 2026-11-07

## Context

Users need searchable, navigable documentation. Reviewers need documentation changes to go through the same review and checks as code. Options considered: a GitHub wiki, Material for MkDocs, Zensical, and Sphinx.

- A GitHub wiki keeps its own Git history, but it is a separate repository edited outside pull request review, so wiki changes skip the checks that code and docs changes pass.
- Material for MkDocs is in maintenance mode, with critical fixes and security updates only until its end of life on 2027-05-05, as the 9.8.0 release notes state (checked 2026-11-07). An earlier announcement gave 2026-11-05.
- MkDocs itself has had no release since 2024.
- Zensical, the successor to Material for MkDocs, was at version 0.1 when this decision was made.
- Sphinx is mature and actively released, and is the generator behind the Python documentation.

## Decision

- `docs/` is the single source of truth, written in Markdown that also reads well on GitHub.
- Sphinx with the MyST Markdown parser and the Furo theme builds a documentation site.
- Every change builds the site with warnings treated as errors.
- The site is published to GitHub Pages only when the repository is public, because a Pages site from a private repository would be public.

## Consequences

Documentation is reviewed, tested, and versioned with the code. Because the source is plain Markdown, moving to another generator later means changing configuration, not content.
