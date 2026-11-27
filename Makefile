GO ?= go
GOFMT ?= gofmt

.PHONY: fmt test test-postgres test-nginx test-management-browser build run

fmt:
	$(GOFMT) -w cmd internal

test:
	$(GO) test ./...

test-postgres:
	GO="$(GO)" sh scripts/test-postgres.sh

test-nginx:
	GO="$(GO)" sh scripts/test-nginx.sh

test-management-browser:
	node tests/e2e/management-isolation.mjs

build: frontend-auth frontend-config frontend-directory
	$(GO) build -trimpath -o bin/agp ./cmd/agp
	$(GO) build -trimpath -o bin/agpctl ./cmd/agpctl
	$(GO) build -trimpath -o bin/agp-security-journal ./cmd/agp-security-journal
	$(GO) build -trimpath -o bin/agp-edge-auth ./cmd/agp-edge-auth
	$(GO) build -trimpath -o bin/agp-agent ./cmd/agp-agent
	$(GO) build -trimpath -o bin/agp-helper ./cmd/agp-helper
	$(GO) build -trimpath -o bin/agp-issuer ./cmd/agp-issuer
	$(GO) build -trimpath -o bin/agp-agent-identity ./cmd/agp-agent-identity
	$(GO) build -trimpath -o bin/agp-agent-validate ./cmd/agp-agent-validate

run:
	$(GO) run ./cmd/agp

.PHONY: frontend-auth
frontend-auth:
	npm --prefix web/console-prototype run build:auth

.PHONY: test-s0-full
test-s0-full:
	GO="$(GO)" bash scripts/test-s0-full.sh

.PHONY: frontend-config test-s1-full
frontend-config:
	npm --prefix web/console-prototype run build:config

test-s1-full:
	GO="$(GO)" bash scripts/test-s1-full.sh

.PHONY: test-helper-foundation
test-helper-foundation:
	GO="$(GO)" bash scripts/test-helper-foundation.sh

.PHONY: test-plans-full
test-plans-full:
	GO="$(GO)" bash scripts/test-plans-full.sh

.PHONY: test-owned-tree
test-owned-tree:
	GO="$(GO)" bash scripts/test-owned-tree.sh

.PHONY: test-execution-wiring
test-execution-wiring:
	GO="$(GO)" bash scripts/test-execution-wiring.sh

.PHONY: frontend-directory package-release test-release-package test-install-update
frontend-directory:
	npm --prefix web/console-prototype run build:directory

package-release:
	bash scripts/build-release.sh --version "$(AGP_VERSION)" --output-dir "$(OUTPUT_DIR)"

test-release-package:
	python3 scripts/test-release-package.py

test-install-update:
	bash -n install.sh update.sh scripts/build-release.sh
	python3 scripts/test-release-install.py
	python3 scripts/test-release-package.py
