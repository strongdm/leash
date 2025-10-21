package ui

import "embed"

//go:generate bash -c "set -euo pipefail; cd ../../controlui/web && corepack enable && pnpm install --frozen-lockfile && node scripts/build-if-changed.mjs --out ../../internal/ui/dist"

//go:embed dist/**
var Dir embed.FS
