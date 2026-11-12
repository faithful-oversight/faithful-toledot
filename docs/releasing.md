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

1. **Preflight.** Confirms it runs on `main`, that the version has a dated changelog section, that no tag for the version exists on another commit, and that the **All checks passed** check succeeded on the commit. If CI is still running, for example right after a merge, preflight waits for it, up to 20 minutes.
2. **Checks.** Runs the full check suite again.
3. **Build.** Builds the wheel and source distribution once, with the pinned, hash-verified build backend in `requirements-build.txt`, then installs that exact wheel in a clean environment and runs the example end to end: `toledot example`, then `toledot report` on the files it wrote, expecting exit code 1 (the example account is incomplete) and checking that all five output files exist and that the manifest lists them. Every later step publishes these same bytes; nothing is rebuilt. Builds are reproducible, so the same commit gives the same bytes.
4. **Evidence.** Writes two CycloneDX software bills of materials and a `SHA256SUMS` file with `scripts/release_evidence.sh`. `sbom-base.cdx.json` covers a plain `pip install faithful-toledot`: the analyzer, which has no runtime dependencies, so it lists no components. `sbom-all-extras.cdx.json` covers every optional extra: remote collection (`pypsrp`) and the keyring, Vault, AWS, and Azure secret sources. Each states its scope in `metadata.properties`. Both take their timestamp from the commit and have no random serial number. The check suite then builds everything a second time and stops unless every byte, both bills of materials included, matches. Because the output depends only on the commit, a rerun of the workflow produces the files a draft already holds.
5. **Draft.** Creates a draft GitHub release, or reuses the existing draft, and uploads any missing assets. An asset that already exists must have the same SHA-256 as the build. When the repository is public, it also creates build provenance attestations.
6. **PyPI.** When the repository is public, publishes through trusted publishing, then checks that PyPI holds exactly these bytes.
7. **Publish.** Checks that the draft targets the release commit and holds every asset with matching digests, then publishes it, which creates the `vX.Y.Z` tag.

The steps that publish are in `scripts/publish_release.py`, which has its own tests.

## If a release fails partway

Run the workflow again on the same commit. Each step checks the real state rather than assuming it: missing uploads are added, existing files are verified against the build, and the release is published only when complete. If anything already published differs from the build, the workflow stops and says what differs. It never replaces or ignores a difference.

## Verifying a release

```shell
sha256sum --check SHA256SUMS
gh attestation verify faithful_toledot-X.Y.Z-py3-none-any.whl --repo faithful-oversight/faithful-toledot
```

The attestation check works for releases made after the repository became public.
