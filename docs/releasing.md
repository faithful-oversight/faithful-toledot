# Releasing

Releases are made only by the release workflow. Nobody builds or uploads release artifacts by hand.

## Versioning

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The version lives in one place: `version` in `pyproject.toml`.

## Steps

1. Open a pull request titled `chore(release): X.Y.Z` that:
   - Sets `version = "X.Y.Z"` in `pyproject.toml`.
   - Renames the `Unreleased` section of `CHANGELOG.md` to `[X.Y.Z] - YYYY-MM-DD` and adds a new empty `Unreleased` section.
   - Runs `uv lock` so the lock file matches.
2. Merge the pull request after every check passes.
3. Run the **Release** workflow from the **Actions** tab on `main`.

## What the workflow does

1. **Preflight.** Confirms it runs on `main`, that the `FO_PUBLIC` variable matches the repository's real visibility (it stops with a message when they disagree, so a public repository cannot release without provenance and PyPI), that the version has a dated changelog section, that no tag for the version exists on another commit, and that the **All checks passed** check succeeded on the commit. If CI is still running, for example right after a merge, preflight waits for it, up to 20 minutes.
2. **Checks.** Runs the full check suite again. Its vulnerability audit covers every package in `uv.lock`, including ones locked only for Windows or for another Python version, and it fails if the audit leaves any of them out.
3. **Build.** Builds the wheel and source distribution once, with the pinned, hash-verified build backend in `requirements-build.txt`, then installs that exact wheel in a clean environment and runs the example end to end: `toledot example`, then `toledot report` on the files it wrote, expecting exit code 1 (the example account is incomplete) and checking that all five output files exist and that the manifest lists them. Every later step publishes these same bytes; nothing is rebuilt. Builds are reproducible, so the same commit gives the same bytes.
4. **Evidence.** Writes two CycloneDX software bills of materials and a `SHA256SUMS` file with `scripts/release_evidence.sh`. `sbom-base.cdx.json` covers a plain `pip install faithful-toledot`: the analyzer and its one runtime dependency, `faithful-core`. `sbom-all-extras.cdx.json` covers every optional extra: remote collection (`pypsrp`) and the keyring, Vault, AWS, and Azure secret sources. Each states its scope in `metadata.properties`. Both take their timestamp from the commit and have no random serial number. The check suite then builds everything a second time and stops unless every byte, both bills of materials included, matches. Because the output depends only on the commit, a rerun of the workflow produces the files a draft already holds.
5. **Draft.** Checks the downloaded build against `SHA256SUMS`, and every later job that downloads it does the same before it attests, uploads, or publishes. Creates a draft GitHub release, or reuses the existing draft, and uploads any missing assets. An asset that already exists must have the same SHA-256 as the build. When the repository is public, it also creates build provenance attestations.
6. **PyPI.** When the repository is public, publishes through trusted publishing, then checks that PyPI holds exactly these bytes.
7. **Publish.** Checks that the draft targets the release commit and holds every asset with matching digests, then publishes it, which creates the `vX.Y.Z` tag.

The steps that publish are in `scripts/publish_release.py`, which has its own tests.

## First publish to PyPI

This section is the procedure for a product's first PyPI release, kept as the template for new products. For toledot it is done: the first PyPI release, 0.1.1, was published on 2026-11-21, so the name is claimed and the warning below no longer applies here.

Until a product's first PyPI release exists, its package is not on PyPI and its name is unclaimed: anyone could register it. Set up trusted publishing, then release a new version, as soon as possible.

1. On the PyPI website, open **Your account**, then **Publishing**, and add a **pending publisher** with these fields. They must match `.github/workflows/release.yml` exactly.
   - PyPI project name: `faithful-toledot`
   - Owner: `faithful-oversight`
   - Repository name: `faithful-toledot`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. A pending publisher does **not** reserve the name. PyPI creates the project, and the name becomes yours, only when the first upload succeeds. Until then, someone else can still register it, and the pending publisher then stops working.
3. The first publish needs a version that has no tag yet. Preflight accepts an existing tag only when it points at the release commit, and `main` has moved past every earlier tag, so rerunning an old version cannot work. Open a release pull request for the next version (see Steps), merge it, and run **Release**.
4. The `pypi` environment has a required reviewer once the repository is public. Approve the run when it waits.

## If the PyPI step fails

PyPI trusted publishing cannot be checked before the upload, so a missing or mismatched publisher shows up in the **Publish to PyPI** job, after the build, the attestations, and the draft release. The sequence is:

1. Preflight, checks, and build pass. The draft release is staged and provenance attestations are issued.
2. The **Publish to PyPI** job waits for the `pypi` reviewer, then the upload fails with an invalid-publisher or authorization error.
3. **Publish GitHub release** is skipped, because it needs the PyPI job to succeed. No tag exists and the release stays a draft that only maintainers can see. Attestations exist for files that were never published; they describe the real build and do no harm.

Fix the publisher fields on PyPI, then run **Release** again on the same commit. The draft is reused, the attestations are issued again for identical files, and the upload and the PyPI digest check are safe to repeat.

## Scheduled checks stop on a quiet repository

GitHub disables scheduled workflows in a public repository after 60 days without repository activity. The weekly vulnerability audit and link check in `ci.yml`, the CodeQL schedule, and the Scorecard run all stop silently. Dependabot is separate and keeps running. After a quiet stretch, open the **Actions** tab, re-enable any workflow that is turned off, and start **CI** by hand with **Run workflow**.

## If a release fails partway

Run the workflow again on the same commit. Each step checks the real state rather than assuming it: missing uploads are added, existing files are verified against the build, and the release is published only when complete. If anything already published differs from the build, the workflow stops and says what differs. It never replaces or ignores a difference.

## Verifying a release

```shell
sha256sum --check SHA256SUMS
gh attestation verify faithful_toledot-X.Y.Z-py3-none-any.whl --repo faithful-oversight/faithful-toledot
```

The attestation check works for releases made after the repository became public.

## Pinned tools

Everything that runs in CI or the release is pinned, so a green `main` cannot turn red, and a rerun cannot produce different bytes, because an upstream project published something new. Dependabot updates the GitHub Actions (by commit SHA) and the Python packages in `uv.lock` and `requirements-build.txt`. It cannot update the tools below, so they change only in a reviewed pull request, and the maintainer checks them before each release.

| Tool | Where it is pinned | How to update |
| --- | --- | --- |
| uv | `FO_UV_VERSION` in `ci.yml`, `pages.yml`, and `release.yml`. The `setup-uv` action checks the download's checksum. | Change all three to the same version, then run CI. Find the newest version with `gh release view --repo astral-sh/uv --json tagName`. |
| Gitleaks | `VERSION` and `SHA256` in `scripts/install_gitleaks.sh` | Change both together, with the digest from the Gitleaks release page. Find the newest version with `gh release view --repo gitleaks/gitleaks --json tagName`. |
| Vale styles | `scripts/vale-styles.lock`: a release URL and a SHA-256 for each style | Download the new release zip, run `sha256sum` on it, change the URL and digest together, and run `scripts/check.sh docs`. The check installs these files and never runs `vale sync`. |
