# Control UI — Makefile
# Front-end only. Scaffolds and runs a Next.js + Tailwind + shadcn/ui app.

APP_DIR ?= web
PORT ?= 3000

# Detect a package manager once at parse time for help text; rules also guard at runtime.
PM := $(shell if command -v pnpm >/dev/null 2>&1; then echo pnpm; \
              elif command -v yarn >/dev/null 2>&1; then echo yarn; \
              else echo npm; fi)

.PHONY: help bootstrap deps ui-init ui-add-base icons dev build start lint format open check clean purge

help:
	@echo "Control UI — targets"
	@echo "  make bootstrap     # Scaffold Next.js app into ./$(APP_DIR) (one-time)"
	@echo "  make deps          # Install dependencies in ./$(APP_DIR)"
	@echo "  make ui-init       # Initialize shadcn/ui in the app"
	@echo "  make ui-add-base   # Add common shadcn/ui components"
	@echo "  make icons         # Install icon pack (lucide-react)"
	@echo "  make dev           # Run dev server on PORT=$(PORT)"
	@echo "  make build         # Build the production bundle"
	@echo "  make start         # Start the production server"
	@echo "  make lint          # Run linter (if configured)"
	@echo "  make format        # Run formatter (if configured)"
	@echo "  make open          # Open http://localhost:$(PORT) in a browser"
	@echo "  make check         # Print versions and PM in use"
	@echo "  make clean         # Remove .next cache"
	@echo "  make purge         # Remove ./$(APP_DIR) (CONFIRM=1 required)"

bootstrap:
	@if [ -f "$(APP_DIR)/package.json" ]; then \
	  echo "[bootstrap] $(APP_DIR) already initialized."; \
	else \
	  echo "[bootstrap] Creating Next.js app in ./$(APP_DIR) using $(PM)..."; \
	  if command -v pnpm >/dev/null 2>&1; then \
	    CI=1 pnpm dlx create-next-app@latest $(APP_DIR) --ts --tailwind --eslint --app --src-dir --import-alias @/* --turbopack; \
	  elif command -v yarn >/dev/null 2>&1; then \
	    CI=1 yarn create next-app $(APP_DIR) --typescript --tailwind --eslint --app --src-dir --import-alias @/* --turbopack; \
	  else \
	    CI=1 npx create-next-app@latest $(APP_DIR) --ts --tailwind --eslint --app --src-dir --import-alias @/* --turbopack; \
	  fi; \
	fi

deps:
	@echo "[deps] Installing dependencies in ./$(APP_DIR) with $(PM)"
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@if command -v pnpm >/dev/null 2>&1; then \
	  cd $(APP_DIR) && pnpm install; \
	elif command -v yarn >/dev/null 2>&1; then \
	  cd $(APP_DIR) && yarn install; \
	else \
	  cd $(APP_DIR) && npm install; \
	fi

ui-init: ## initialize shadcn/ui (idempotent)
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@echo "[ui-init] Initializing shadcn/ui in ./$(APP_DIR)"
	@cd $(APP_DIR) && ( \
	  if command -v shadcn >/dev/null 2>&1; then CLI=shadcn; \
	  elif command -v shadcn-ui >/dev/null 2>&1; then CLI=shadcn-ui; \
	  else CLI="npx shadcn@canary"; fi; \
	  $$CLI init --base-color neutral -y || $$CLI init --base-color neutral \
	)

ui-add-base:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@echo "[ui-add-base] Adding common shadcn/ui components"
	@cd $(APP_DIR) && ( \
	  if command -v shadcn >/dev/null 2>&1; then CLI=shadcn; \
	  elif command -v shadcn-ui >/dev/null 2>&1; then CLI=shadcn-ui; \
	  else CLI="npx shadcn@canary"; fi; \
	  $$CLI add button card table input label separator scroll-area tabs tooltip dropdown-menu navigation-menu badge avatar \
	)
	@$(MAKE) -s icons

icons:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@echo "[icons] Ensuring lucide-react is installed"
	@if command -v pnpm >/dev/null 2>&1; then \
	  cd $(APP_DIR) && pnpm add lucide-react; \
	elif command -v yarn >/dev/null 2>&1; then \
	  cd $(APP_DIR) && yarn add lucide-react; \
	else \
	  cd $(APP_DIR) && npm install lucide-react; \
	fi

dev:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@echo "[dev] Starting Next.js on http://localhost:$(PORT)"
	@cd $(APP_DIR) && \
	  if command -v pnpm >/dev/null 2>&1; then PORT=$(PORT) pnpm dev; \
	  elif command -v yarn >/dev/null 2>&1; then PORT=$(PORT) yarn dev; \
	  else PORT=$(PORT) npm run dev; fi

build:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@cd $(APP_DIR) && \
	  if command -v pnpm >/dev/null 2>&1; then pnpm build; \
	  elif command -v yarn >/dev/null 2>&1; then yarn build; \
	  else npm run build; fi

start:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@cd $(APP_DIR) && \
	  if command -v pnpm >/dev/null 2>&1; then PORT=$(PORT) pnpm start; \
	  elif command -v yarn >/dev/null 2>&1; then PORT=$(PORT) yarn start; \
	  else PORT=$(PORT) npm run start; fi

lint:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@cd $(APP_DIR) && \
	  if command -v pnpm >/dev/null 2>&1; then pnpm lint || true; \
	  elif command -v yarn >/dev/null 2>&1; then yarn lint || true; \
	  else npm run lint || true; fi

format:
	@if [ ! -f "$(APP_DIR)/package.json" ]; then echo "Run 'make bootstrap' first"; exit 1; fi
	@cd $(APP_DIR) && \
	  if command -v pnpm >/dev/null 2>&1; then pnpm format || true; \
	  elif command -v yarn >/dev/null 2>&1; then yarn format || true; \
	  else npm run format || true; fi

open:
	@echo "[open] Opening http://localhost:$(PORT)"
	@URL="http://localhost:$(PORT)"; \
	if command -v open >/dev/null 2>&1; then open $$URL; \
	elif command -v xdg-open >/dev/null 2>&1; then xdg-open $$URL; \
	else echo "Open $$URL in your browser"; fi

check:
	@echo "[check] Package manager: $(PM)"
	@echo "[check] Node: $$(node -v 2>/dev/null || echo 'not found')"
	@echo "[check] PNPM: $$(pnpm -v 2>/dev/null || echo 'not found')"
	@echo "[check] Yarn: $$(yarn -v 2>/dev/null || echo 'not found')"
	@echo "[check] NPM:  $$(npm -v 2>/dev/null || echo 'not found')"

clean:
	@echo "[clean] Removing .next cache in ./$(APP_DIR)"
	@rm -rf $(APP_DIR)/.next

purge:
	@if [ "$(CONFIRM)" != "1" ]; then echo "This will remove ./$(APP_DIR). Use: make purge CONFIRM=1"; exit 1; fi
	@echo "[purge] Removing ./$(APP_DIR)"
	@rm -rf $(APP_DIR)
