# Release Process

This document describes how we cut a Leash release, why the workflow looks the way it does, and how to dry-run everything locally before tagging `vX.Y.Z`.

For npm distribution specifics (trusted publishing, dist-tags, and manual fallbacks), see `docs/release_management.md`.

## Flow Overview

```mermaid
flowchart TD
    A[Engineer] --> B[Local Preflight]
    B --> C[git tag vX.Y.Z]
    C --> D[push tag to origin]
    D --> E[GitHub Actions: Verify job<br/>go test ./..., test_e2e.sh]
    E --> F[GitHub Actions: Release job<br/>Goreleaser + Buildx/QEMU]
    F --> G[Publish GitHub Release<br/>Attach tar.gz archives]
    F --> H[Push multi-arch images to ECR]
```

## Intentional Design Choices

- **Git tags drive releases** - We follow Go’s module versioning (`vX.Y.Z`) so that module consumers receive semantic guarantees, and CI has an unambiguous trigger for official builds.
- **CI builds the final artifacts** - GitHub Actions provides a reproducible environment with Buildx/QEMU configured for multi-architecture images, eliminating the need for engineers to manage emulation locally.
- **Goreleaser owns packaging** - One tool produces cross-platform binaries, tar.gz archives, and Docker images. This keeps the output identical whether run locally or in CI.

## Before You Tag

1. Ensure the tree is clean and tests pass:

```bash
go test ./... -count=1
./test_e2e.sh
```

2. Sanity-check your workspace:

```bash
git status --short              # should be empty
git describe --tags --exact-match  # should print vX.Y.Z (or fail if not tagged yet)
aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws  # ensure credentials exist before tagging
```
3. Optional: run the full Goreleaser dry run (builds all archives/images locally but skips publication):

```bash
./build/lsm-generate.sh     # runs docker-based LSM generation on non-Linux hosts
LSM_GENERATE_MODE=skip goreleaser release --snapshot --clean --skip=publish --skip=announce --skip=sign
```

*The first run regenerates Linux eBPF bindings; subsequent dry-runs can set `LSM_GENERATE_MODE=skip` to save time.*

## Cut the Release

1. Create an annotated tag following `vX.Y.Z`:

```bash
git tag -a v1.2.3 -m "Leash v1.2.3"
git push origin v1.2.3
```

2. GitHub Actions picks up the tag and executes:
   - **verify job** (Ubuntu runner): runs `go test ./...` and `./test_e2e.sh`.
    - **release job** (Ubuntu runner):
      - Sets up Go, QEMU, and Buildx.
      - Authenticates to ECR with the workflow token.
      - Runs `./build/lsm-generate.sh` to bake Linux eBPF bindings inside Docker.
      - Runs `goreleaser release --clean` to build darwin/linux binaries (amd64 & arm64) and tar.gz archives.
      - Runs `./build/publish-docker.sh vX.Y.Z` to build and push multi-arch Docker images (linux/amd64, linux/arm64).

## What You Get

- GitHub Release assets:
  - `leash_<version>_<os>_<arch>.tar.gz`
- Container registry:
  - Manifest lists for `public.ecr.aws/s5i7k8t3/strongdm/leash:{vX.Y.Z,latest}` (linux/amd64 & linux/arm64)
  - Manifest lists for `public.ecr.aws/s5i7k8t3/strongdm/coder:{vX.Y.Z,latest}`

If any step fails, the workflow halts and no release is published. Fix the issue (e.g., broken test, missing login) and re-push the tag once resolved.

---

## NPM Release Management

### npm Distribution Flow

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

### Trusted Publisher Setup

1. Enable **Trusted Publishers** for the `@strongdm` npm scope and authorize the `strongdm/leash` GitHub repository.
2. Grant `id-token: write` + `contents: read` permissions to release workflows (handled in `.github/workflows/release.yml`).
3. Verify provenance once on npmjs.com’s package settings page after the first publish.

If you need to revoke or rotate the publisher, remove the association on npm, update settings in GitHub’s “Security → OIDC” panel, and rerun the release.

### Dist-tag Strategy

- **Stable tags (`vX.Y.Z`)** → publish with `--tag latest`.
- **Alpha tags (`vX.Y.Z-alpha.N`)** → publish with `--tag alpha`.
- Future prerelease channels can be added by extending the shell logic in `publish-npm`.

Consumers who require prereleases can install via `npm install @strongdm/leash@alpha`.

### First-publish Checklist

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

### Manual Fallback

If trusted publishing is unavailable:

1. Generate the package locally (ensure Goreleaser artifacts are available).
```bash
uv run build/npm/collect_vendor_from_dist.py --dist dist --out dist/npm/vendor --force
uv run build/npm/build_npm_package.py --version <semver> --vendor dist/npm/vendor --out dist/npm --stage dist/npm/stage --force
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

