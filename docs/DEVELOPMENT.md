# Leash Developers Guide

## Requirements

- [Go](https://go.dev)
- Node.js and npm

## Clone and build Leash

```bash
git clone git@github.com:strongdm/leash.git
cd leash
make docker build

# Prefer Podman? Override the container runtime per invocation:
#   make DOCKER=podman docker build

# See also: make help
```

## Versioning

Version strings are resolved centrally by `build/versionator.py`. The helper looks for:

1. A `vX.Y.Z` git tag on the current commit.
2. Otherwise it falls back to a `dev-<shortSHA>[-dirty]` snapshot identifier.

The Makefile, release scripts, and Docker builds all shell out to this script, so running `./build/versionator.py <part>` shows the exact value those pipelines consume:

```bash
./build/versionator.py bin   # 1.2.3
./build/versionator.py tag   # v1.2.3 or dev-ab12cd3
./build/versionator.py minor # 2
```
