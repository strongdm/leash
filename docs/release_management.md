# Release Management

This guide supplements `docs/RELEASE.md` with npm distribution details, trusted publisher setup, and manual fallback procedures.

## npm Distribution Flow

The release workflow now includes two additional jobs after Goreleaser completes:

1. **`stage-npm`**  
   - Downloads the Goreleaser `dist/` artifact.  
   - Installs Node 22, `uv`, and runs `uv run ruff check build/npm` / `uv run ruff format --check build/npm`.  
   - Executes `uv run build/npm/collect_vendor_from_dist.py` to populate `dist/npm/vendor`.  
   - Builds `strongdm-leash-<version>.tgz` via `uv run build/npm/build_npm_package.py` and uploads it as a workflow artifact.
2. **`publish-npm`**  
   - Pulls the staged tarball.  
  - Derives the npm dist-tag (`alpha` if the semver contains `-alpha.`, otherwise `latest`).  
   - Executes `npm publish <tarball> --provenance --access public --tag <dist-tag>` using trusted publishing (OIDC).

The tarball name is deterministic (`strongdm-leash-<semver>.tgz`), enabling reuse in manual verification and GitHub release assets.

## Trusted Publisher Setup

1. Enable **Trusted Publishers** for the `@strongdm` npm scope and authorize the `strongdm/leash` GitHub repository.  
2. Grant `id-token: write` + `contents: read` permissions to release workflows (handled in `.github/workflows/release.yml`).  
3. Verify provenance once on npmjs.com’s package settings page after the first publish.

If you need to revoke or rotate the publisher, remove the association on npm, update settings in GitHub’s “Security → OIDC” panel, and rerun the release.

## Dist-tag Strategy

- **Stable tags (`vX.Y.Z`)** → publish with `--tag latest`.  
- **Alpha tags (`vX.Y.Z-alpha.N`)** → publish with `--tag alpha`.  
- Future prerelease channels can be added by extending the shell logic in `publish-npm`.

Consumers who require prereleases can install via `npm install @strongdm/leash@alpha`.

## First-publish Checklist

- Claim the `@strongdm/leash` package on npm (or create the scope if new).  
- Configure Trusted Publishing for `strongdm/leash` in npm settings.  
- Add at least two maintainers with 2FA enabled.  
- Trigger a tagged build (`vX.Y.Z`) and confirm:
  - `stage-npm` uploads `strongdm-leash-<version>.tgz`.  
  - `publish-npm` completes with `npm publish --provenance`.  
- Install locally for smoke testing:  
  ```bash
  npm install -g ./strongdm-leash-<version>.tgz
  leash --version
  ```

## Manual Fallback

If trusted publishing is unavailable:

1. Generate the package locally (ensure Goreleaser artifacts are available).
   ```bash
   timeout 135 uv run build/npm/collect_vendor_from_dist.py --dist dist --out dist/npm/vendor --force
   timeout 135 uv run build/npm/build_npm_package.py --version <semver> --vendor dist/npm/vendor --out dist/npm --stage dist/npm/stage --force
   ```
2. Authenticate with an npm token that has `publish` rights.
   ```bash
   npm login --scope=@strongdm
   ```
3. Publish with the same dist-tag rules:
   ```bash
   npm publish dist/npm/strongdm-leash-<semver>.tgz --access public --tag <alpha|latest>
   ```
4. Record the manual publish in the release notes and rerun CI to ensure the normal workflow succeeds next time.
