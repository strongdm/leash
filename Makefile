SHELL := /bin/bash

LEASH_IMAGE ?= ghcr.io/strongdm/leash:latest
TARGET_IMAGE ?= ghcr.io/strongdm/coder:latest
LEASH_ECR_LATEST ?= public.ecr.aws/s5i7k8t3/strongdm/leash:latest
TARGET_ECR_LATEST ?= public.ecr.aws/s5i7k8t3/strongdm/coder:latest
LSM_DOCKER_IMAGE ?= golang:1.25.3-bookworm
DOCKER ?= docker
#LEASH_PLATFORMS ?= darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
# TEMP: Disable multi-arch
LEASH_PLATFORMS ?= "$(shell uname -s | tr '[A-Z]' '[a-z]')/$(shell uname -m)"

VERSION_SCRIPT := ./build/versionator.py
DOCKER_TAG_SCRIPT := ./build/docker_tags.py
VERSION := $(strip $(shell $(VERSION_SCRIPT) bin))
ifeq ($(VERSION),)
$(error failed to resolve version via $(VERSION_SCRIPT))
endif
VERSION_TAG := $(strip $(shell $(VERSION_SCRIPT) tag))
ifeq ($(VERSION_TAG),)
$(error failed to resolve git/tag version via $(VERSION_SCRIPT))
endif
VERSION_MAJOR := $(strip $(shell $(VERSION_SCRIPT) major))
VERSION_MINOR := $(strip $(shell $(VERSION_SCRIPT) minor))
VERSION_PATCH := $(strip $(shell $(VERSION_SCRIPT) patch))
VERSION_MINOR_TAG := v$(VERSION_MAJOR).$(VERSION_MINOR)
VERSION_MAJOR_TAG := v$(VERSION_MAJOR)

GIT_REMOTE_URL := $(shell git config --get remote.origin.url 2>/dev/null || echo unknown)

# Docker caches for UI builds (override if desired)
PNPM_CACHE_VOLUME ?= leash_pnpm_store
COREPACK_CACHE_VOLUME ?= leash_corepack_cache
NEXT_CACHE_VOLUME ?= leash_next_cache
UI_CACHE_DIR ?= $(HOME)/.cache/leash/ui

.DEFAULT_GOAL := default

.PHONY: default
default: docker-ui docker-leash build ## Default Makefile task: builds UI, Docker images, and binaries

.PHONY: help
help: ## List common make targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nAvailable targets:\n\n"} /^[a-zA-Z0-9][^:]*:.*##/ {printf "  %-24s %s\n", $$1, $$2}' $(MAKEFILE_LIST); \
	printf '\n'

.PHONY: precommit
precommit: ## Configure git hooks for pre-commit guardrails
	@# Protect against committing large binary files.
	@git config --local core.hooksPath build/.hooks
	@chmod a+x build/.hooks/pre-commit
	@echo "git hooks path set to: $$(git config --get core.hooksPath)"

.PHONY: fmt
fmt: precommit ## Format Go sources with goimports
	@echo 'running goimports...'
	@command -v goimports >/dev/null 2>&1 || (echo 'installing goimports' && go install golang.org/x/tools/cmd/goimports@latest)
	@GOIMPORTS_BIN="$$(command -v goimports || echo "$$(go env GOPATH)/bin/goimports")"; \
	  FILES=$$(git ls-files '*.go' | grep -v '^\.scratch/'); \
	  if [ -n "$$FILES" ]; then $$GOIMPORTS_BIN -w $$FILES; fi

.PHONY: lsm-generate
lsm-generate: ## Generate LSM eBPF artifacts on the host system
	@set -euo pipefail; \
	if [ "$(shell uname -s)" = 'Linux' ]; then \
	  command -v clang >/dev/null 2>&1 || { echo 'clang is required to generate LSM eBPF bindings' >&2; exit 1; }; \
	  command -v llvm-strip >/dev/null 2>&1 || command -v llvm-objdump >/dev/null 2>&1 || echo 'warning: llvm tools not found; ensure LLVM is installed'; \
	  command -v bpf2go >/dev/null 2>&1 || { echo 'installing bpf2go...'; go install github.com/cilium/ebpf/cmd/bpf2go@v0.19.0; }; \
	  echo 'generating LSM BPF artifacts...'; \
	  GOOS=linux GOARCH=$$(go env GOARCH) go generate ./internal/lsm; \
	else \
	  $(MAKE) lsm-generate-docker; \
	fi

.PHONY: lsm-generate-docker
lsm-generate-docker: ## Generate LSM artifacts inside the Docker toolchain
	@echo "running lsm-generate inside $(LSM_DOCKER_IMAGE)..."
	@$(DOCKER) run --rm --platform=linux/amd64 \
	  -e CGO_ENABLED=1 -e GOWORK=off \
	  -v "$(CURDIR)":/workspace \
	  -w /workspace \
	  $(LSM_DOCKER_IMAGE) \
	  bash -lc 'set -euo pipefail; export PATH=$$PATH:/usr/local/go/bin:/go/bin; apt-get update >/dev/null; apt-get install -y --no-install-recommends clang llvm libbpf-dev pkg-config >/dev/null; go install github.com/cilium/ebpf/cmd/bpf2go@v0.19.0; make lsm-generate'

.PHONY: build-release
build-release: build ## Build release artifacts and retag docker images
	@$(MAKE) docker
	@set -euo pipefail; \
	  LEASH_DEFAULT="$(LEASH_IMAGE)"; \
	  LEASH_REPO="$${LEASH_DEFAULT%:*}"; \
	  if [ -z "$$LEASH_REPO" ] || [ "$$LEASH_REPO" = "$$LEASH_DEFAULT" ]; then LEASH_REPO="$$LEASH_DEFAULT"; fi; \
	  $(DOCKER) tag "$$LEASH_REPO:$(VERSION_TAG)" "$$LEASH_REPO:latest"; \
	  CODER_DEFAULT="$(TARGET_IMAGE)"; \
	  CODER_REPO="$${CODER_DEFAULT%:*}"; \
	  if [ -z "$$CODER_REPO" ] || [ "$$CODER_REPO" = "$$CODER_DEFAULT" ]; then CODER_REPO="$$CODER_DEFAULT"; fi; \
	  $(DOCKER) tag "$$CODER_REPO:$(VERSION_TAG)" "$$CODER_REPO:latest"

.PHONY: docker-base
docker-base: precommit ## Build cached Docker base images if missing
	@set -euo pipefail; \
	  if ! $(DOCKER) image inspect leash/build-base:latest >/dev/null 2>&1; then \
	    echo 'building leash/build-base:latest'; \
	    $(DOCKER) buildx build --load \
	      --target build-base \
	      -f Dockerfile.leash \
	      -t leash/build-base:latest .; \
	  else \
	    echo 'leash/build-base:latest already present; skipping'; \
	  fi; \
	  if ! $(DOCKER) image inspect leash/runtime-base:latest >/dev/null 2>&1; then \
	    echo 'building leash/runtime-base:latest'; \
	    $(DOCKER) buildx build --load \
	      --target runtime-base \
	      -f Dockerfile.leash \
	      -t leash/runtime-base:latest .; \
	  else \
	    echo 'leash/runtime-base:latest already present; skipping'; \
	  fi

.PHONY: docker-leash
docker-leash: precommit docker-base build-ui lsm-generate-docker ## Build Leash Docker image with channel tags
	@echo 'building leash image with channel tags'
	@set -euo pipefail; \
	  IMAGE="$(LEASH_IMAGE)"; \
	  VERSION_REF="$(VERSION_TAG)"; \
	  EXTRA_TAG_ARGS=""; \
	  if [ -n "$(strip $(LEASH_ECR_LATEST))" ]; then EXTRA_TAG_ARGS="--extra-tag $(LEASH_ECR_LATEST)"; fi; \
	  TAG_ENV=$$($(DOCKER_TAG_SCRIPT) --image "$$IMAGE" --version "$$VERSION_REF" $$EXTRA_TAG_ARGS); \
	  eval "$$TAG_ENV"; \
	  for TAG in $$TAG_LIST; do echo " - $$TAG"; done; \
	  IID_TMP="$$(mktemp)"; \
	  OUT_TMP="$$(mktemp "$(CURDIR)/.dev-docker-leash.XXXXXX")"; \
	  cleanup_dev() { rm -f "$$IID_TMP" "$$OUT_TMP"; }; \
	  trap cleanup_dev EXIT; \
	  DOCKER_BUILDKIT=1 $(DOCKER) build -f Dockerfile.leash \
	    --target final \
	    --build-arg COMMIT="$$COMMIT" \
	    --build-arg BUILD_DATE="$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	    --build-arg VERSION="$(VERSION)" \
	    --build-arg CHANNEL="$$CHANNEL_NAME" \
	    --build-arg VCS_URL="$(GIT_REMOTE_URL)" \
	    --iidfile "$$IID_TMP" \
	    $$TAG_ARGS .; \
	  IID_VALUE="$$(cat "$$IID_TMP")"; \
	  if [ -z "$$IID_VALUE" ]; then echo "failed to capture leash image ID" >&2; exit 1; fi; \
	  printf '%s\n' "$$IID_VALUE" > "$$OUT_TMP"; \
	  mv "$$OUT_TMP" "$(CURDIR)/.dev-docker-leash"; \
	  rm -f "$$IID_TMP"; \
	  trap - EXIT;

.PHONY: docker-leash-prebuilt
# Build runtime image using prebuilt UI assets in internal/ui/dist (skips Node stage)
docker-leash-prebuilt: precommit docker-base ## Build Docker image using prebuilt UI assets (part of release pipeline)
	@echo 'building leash image (prebuilt UI) with channel tags'
	@set -euo pipefail; \
	  IMAGE="$(LEASH_IMAGE)"; \
	  VERSION_REF="$(VERSION_TAG)"; \
	  EXTRA_TAG_ARGS=""; \
	  if [ -n "$(strip $(LEASH_ECR_LATEST))" ]; then EXTRA_TAG_ARGS="--extra-tag $(LEASH_ECR_LATEST)"; fi; \
	  TAG_ENV=$$($(DOCKER_TAG_SCRIPT) --image "$$IMAGE" --version "$$VERSION_REF" $$EXTRA_TAG_ARGS); \
	  eval "$$TAG_ENV"; \
	  for TAG in $$TAG_LIST; do echo " - $$TAG"; done; \
	  DOCKER_BUILDKIT=1 $(DOCKER) build -f Dockerfile.leash \
	    --target final-prebuilt \
	    --build-arg UI_SOURCE=ui-prebuilt \
	    --build-arg COMMIT="$$COMMIT" \
	    --build-arg BUILD_DATE="$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	    --build-arg VERSION="$(VERSION)" \
	    --build-arg CHANNEL="$$CHANNEL_NAME" \
	    --build-arg VCS_URL="$(GIT_REMOTE_URL)" \
	    $$TAG_ARGS .

.PHONY: docker-coder
docker-coder: precommit ## Build the coder docker image (includes all common coding agents)
	@echo 'building coder image with channel tags'
	@set -euo pipefail; \
	  IMAGE="$(TARGET_IMAGE)"; \
	  VERSION_REF="$(VERSION_TAG)"; \
	  EXTRA_TAG_ARGS=""; \
	  if [ -n "$(strip $(TARGET_ECR_LATEST))" ]; then EXTRA_TAG_ARGS="--extra-tag $(TARGET_ECR_LATEST)"; fi; \
	  TAG_ENV=$$($(DOCKER_TAG_SCRIPT) --image "$$IMAGE" --version "$$VERSION_REF" $$EXTRA_TAG_ARGS); \
	  eval "$$TAG_ENV"; \
	  for TAG in $$TAG_LIST; do echo " - $$TAG"; done; \
	  IID_TMP="$$(mktemp)"; \
	  OUT_TMP="$$(mktemp "$(CURDIR)/.dev-docker-coder.XXXXXX")"; \
	  cleanup_dev() { rm -f "$$IID_TMP" "$$OUT_TMP"; }; \
	  trap cleanup_dev EXIT; \
	  $(DOCKER) build -f Dockerfile.coder \
	    --build-arg COMMIT="$$COMMIT" \
	    --build-arg BUILD_DATE="$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	    --build-arg VERSION="$(VERSION)" \
	    --build-arg CHANNEL="$$CHANNEL_NAME" \
	    --build-arg VCS_URL="$(GIT_REMOTE_URL)" \
	    --iidfile "$$IID_TMP" \
	    $$TAG_ARGS .; \
	  IID_VALUE="$$(cat "$$IID_TMP")"; \
	  if [ -z "$$IID_VALUE" ]; then echo "failed to capture coder image ID" >&2; exit 1; fi; \
	  printf '%s\n' "$$IID_VALUE" > "$$OUT_TMP"; \
	  mv "$$OUT_TMP" "$(CURDIR)/.dev-docker-coder"; \
	  rm -f "$$IID_TMP"; \
	  trap - EXIT;

.PHONY: docker
docker: docker-leash docker-coder ## Build all project docker images

.PHONY: dev-ui
dev-ui: ## Start a development Control UI instance (ws:// points at: 127.0.0.1:18000)
	@cd controlui && make dev

.PHONY: docker-ui
docker-ui: precommit ## Build the Control UI using Docker
	@# n.b. Writes static assets to `internal/ui/dist` for embedding by Go.
	@echo 'building Control UI in Docker...'
	@mkdir -p internal/ui/dist "$(UI_CACHE_DIR)"
	@# n.b. re: CI=true:
	@#      pnpm install --frozen-lockfile wants to trash and recreate
	@#      node_modules. When the working tree lives on a bind-mounted volume
	@#      (our Docker run) and pnpm doesn’t see a TTY, it aborts with
	@#      ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY *UNLESS* the environment
	@#      indicates "I'm running unattended."  Setting CI=true is pnpm’s
	@#      way to silence interactive confirmation in headless environments.
	@#      With CI=true it proceeds non-interactively, avoiding the prompt that
	@#      otherwise kills the build.
	@$(DOCKER) run --rm \
	  -e CI=true \
	  -e PNPM_STORE_DIR=/pnpm/store \
	  -e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) \
	  -v "$(CURDIR)/controlui/web:/src:ro" \
	  -v "$(CURDIR)/internal/ui/dist:/out" \
	  -v "$(UI_CACHE_DIR):/cache" \
	  -v $(PNPM_CACHE_VOLUME):/pnpm/store \
	  -v $(COREPACK_CACHE_VOLUME):/root/.cache/node/corepack \
	  -v $(NEXT_CACHE_VOLUME):/work/.next/cache \
	  node:22-bookworm bash -lc \
	    'set -euo pipefail; mkdir -p /work /pnpm/store; corepack enable; cp -a /src/. /work; cd /work; pnpm config set store-dir $$PNPM_STORE_DIR; echo "Y" | pnpm install --frozen-lockfile --prefer-offline; node scripts/build-if-changed.mjs --out /out --hash /cache/controlui.buildhash; chown -R $$HOST_UID:$$HOST_GID /out'

.PHONY: build-ui
build-ui: precommit ## Build the Control UI. Uses local pnpm if available, otherwise falls back to Docker
	@set -e; \
	if command -v pnpm >/dev/null 2>&1; then \
	  echo 'building UI locally with pnpm (via `go generate`)'; \
	  cd controlui/web; \
	  corepack enable; \
	  pnpm install --frozen-lockfile && node scripts/build-if-changed.mjs --out ../../internal/ui/dist; \
	else \
	  echo 'pnpm not found; falling back to Docker'; \
      $(MAKE) docker-ui; \
	fi

.PHOME: generate-entrypoint-if-missing
generate-entrypoint-if-missing: ## Generate entrypoint artifacts only if not already present
	@set -e; \
	if ! [ -f internal/entrypoint/bundled_linux_amd64_gen.go ] || ! [ -f internal/entrypoint/bundled_linux_arm64_gen.go ]; then \
		go generate ./internal/entrypoint/...; \
	fi

.PHONY: build
build: precommit ## Build the leash binary
	@mkdir -p bin
	@set -e; \
	$(MAKE) generate-entrypoint-if-missing; \
	BASE=$$(git rev-parse --short=7 HEAD 2>/dev/null || true); \
	if [ -z "$$BASE" ]; then BASE=dev; fi; \
	DIRTY=''; \
	if [ -n "$$({ git status --porcelain 2>/dev/null || true; })" ]; then DIRTY="-dirty"; fi; \
	COMMIT="$$BASE$$DIRTY"; \
	BUILD_DATE="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	for cmd_dir in cmd/*; do \
	  if [ -d "$$cmd_dir" ] && ! [[ "$$cmd_dir" =~ leash-entry ]]; then \
	    name=$${cmd_dir##*/}; \
	    out="bin/$$name"; \
	    echo "building $${out}..."; \
	    CGO_ENABLED=0 go build -trimpath -ldflags "-X main.commit=$$COMMIT -X main.buildDate=$$BUILD_DATE" -o "$$out" "./$$cmd_dir" || exit $$?; \
	  fi; \
	done

.PHONY: test
test: test-unit test-e2e test-web ## Run entire test suite
	@echo 'all tests completed'

ifeq ($(filter 1 true True TRUE yes Yes YES on On ON,$(VERBOSE)),)
GO_TEST_FLAGS :=
else
GO_TEST_FLAGS := -v
endif

.PHONY: test-unit test-go
test-unit test-go: precommit ## Run Go unit tests (after UI build + LSM-generate steps)
	@echo 'running go tests...'
	@go test $(GO_TEST_FLAGS) ./...

# Runs JS/TS tests in Control UI if a test script exists; otherwise skips gracefully.
.PHONY: test-web
test-web: ## Run web frontend tests
	@echo 'checking for web tests...'
	@if [ -f controlui/web/package.json ] && grep -q '"test"\s*:' controlui/web/package.json; then \
	  echo 'installing web deps...'; \
	  command -v pnpm >/dev/null 2>&1 || (echo 'pnpm not found; install pnpm to run web tests' && exit 0); \
	  echo 'Y' | pnpm -C controlui/web install; \
	  echo 'running web tests...'; \
	  pnpm -C controlui/web test || exit 1; \
	else \
	  echo 'no web test script found; skipping'; \
	fi

.PHONY: test-deps
test-deps:
	@$(MAKE) build-ui >/dev/null
	@$(MAKE) generate-entrypoint-if-missing >/dev/null
	@$(MAKE) lsm-generate >/dev/null

.PHONY: test-e2e
test-e2e: test-deps ## Run integration tests via test_e2e.sh
	@echo 'running e2e tests...'
	@VERBOSE=$(VERBOSE) ./test_e2e.sh

.PHONY: clean-go
clean-go:
	@go clean -cache
	@# Go cache can get in a broken state, so.
	@go clean -cache
	@# Build artifacts.
	@rm -rf bin/*
	@rm -f .dev-docker-*
	@# Remove go:generate'd resources:
	@#     -> Embedded leash-entry binaries.
	@rm -rf internal/entrypoint/embed/*
	@rm -f internal/entrypoint/bundled_linux_*_gen.go
	@#     -> Intermediate eBPF files.
	@if [ "$(shell uname -s)" = 'Linux' ]; then rm -f internal/lsm/*_bpf*.go internal/lsm/*_bpf*.o; fi

.PHONY: clean-ui
clean-ui:
	@rm -rf controlui/web/.next/ controlui/web/out internal/ui/dist

.PHONY: clean-docker
clean-docker:
	@#     -> Cached Docker base images.
	@if command -v $(DOCKER) >/dev/null 2>&1; then \
	  $(DOCKER) image inspect leash/build-base:latest >/dev/null 2>&1 && $(DOCKER) image rm -f leash/build-base:latest >/dev/null 2>&1 || true; \
	  $(DOCKER) image inspect leash/runtime-base:latest >/dev/null 2>&1 && $(DOCKER) image rm -f leash/runtime-base:latest >/dev/null 2>&1 || true; \
	fi

.PHONY: clean
clean: clean-go clean-ui clean-docker ## Remove build artifacts
