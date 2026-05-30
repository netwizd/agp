GO ?= go
GOFMT ?= gofmt

.PHONY: fmt test build run

fmt:
	$(GOFMT) -w cmd internal

test:
	$(GO) test ./...

build:
	$(GO) build -trimpath -o bin/agp ./cmd/agp
	$(GO) build -trimpath -o bin/agpctl ./cmd/agpctl

run:
	$(GO) run ./cmd/agp
