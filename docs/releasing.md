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

1. Confirms it runs on `main`, that the version has a dated changelog section, that no tag for the version exists on another commit, and that the **All checks passed** check succeeded on the commit.
2. Runs the full check suite again.
3. Builds the wheel and source distribution.
4. Creates a CycloneDX software bill of materials and a `SHA256SUMS` file.
5. When the repository is public, publishes to PyPI through trusted publishing.
6. Creates the `vX.Y.Z` tag on the release commit and a GitHub release with the changelog section as release notes and all artifacts attached. When the repository is public, it also creates build provenance attestations.

## If a release fails partway

Run the workflow again on the same commit. Steps that already finished are skipped: PyPI ignores files it already has, and the tag and release are reused if they exist on that commit.

## Verifying a release

```shell
sha256sum --check SHA256SUMS
gh attestation verify faithful_toledot-X.Y.Z-py3-none-any.whl --repo faithful-oversight/faithful-toledot
```

The attestation check works for releases made after the repository became public.
