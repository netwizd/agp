#!/usr/bin/env sh
set -eu

go test ./...
go vet ./...
version="${AGP_VERSION:-$(cat VERSION 2>/dev/null || echo v1.0.0-dev)}"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ldflags="-X github.com/netwizd/agp/internal/version.Version=${version} -X github.com/netwizd/agp/internal/version.Commit=${commit} -X github.com/netwizd/agp/internal/version.BuiltAt=${built_at}"
go build -trimpath -ldflags "$ldflags" -o bin/agp ./cmd/agp
go build -trimpath -ldflags "$ldflags" -o bin/agpctl ./cmd/agpctl
node --check internal/frontend/static/app.js
git diff --check

if [ "${AGP_TEST_POSTGRES_DSN:-}" = "" ]; then
  echo "AGP_TEST_POSTGRES_DSN is required for v1.0 release checks" >&2
  exit 1
fi

AGP_TEST_POSTGRES_DSN="$AGP_TEST_POSTGRES_DSN" go test ./internal/storage/postgres
./bin/agp --version
./bin/agpctl version
