#!/usr/bin/env sh
set -eu

go test ./...
go vet ./...
go build -trimpath -o bin/agp ./cmd/agp
go build -trimpath -o bin/agpctl ./cmd/agpctl
node --check internal/frontend/static/app.js
git diff --check

if [ "${AGP_TEST_POSTGRES_DSN:-}" != "" ]; then
  AGP_TEST_POSTGRES_DSN="$AGP_TEST_POSTGRES_DSN" go test ./internal/storage/postgres
else
  echo "AGP_TEST_POSTGRES_DSN is not set; skipping live PostgreSQL integration profile"
fi
