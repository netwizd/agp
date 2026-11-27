#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
: "${AGP_TEST_NGINX_BIN:?select a verified native Nginx binary for mandatory release acceptance}"
: "${AGP_TEST_POSTGRES_DSN:?AGP_TEST_POSTGRES_DSN is required for release checks}"
python3 scripts/check-nginx-baseline.py --binary "$AGP_TEST_NGINX_BIN"
python3 scripts/test-nginx-baseline.py
# Ordinary go test permits optional native tests to skip. A release does not.
sh scripts/test-nginx.sh

commit="$(git rev-parse --verify HEAD 2>/dev/null)" || {
  echo 'Release checks require an identifiable Git commit; source metadata is unavailable' >&2
  exit 1
}
go test ./...
go vet ./...
version="${AGP_VERSION:-$(cat VERSION 2>/dev/null || echo v1.0.0-dev)}"
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ldflags="-X github.com/netwizd/agp/internal/version.Version=${version} -X github.com/netwizd/agp/internal/version.Commit=${commit} -X github.com/netwizd/agp/internal/version.BuiltAt=${built_at}"
for role in agp agpctl agp-security-journal agp-edge-auth agp-agent agp-helper agp-issuer agp-agent-identity agp-agent-validate; do
  go build -trimpath -ldflags "$ldflags" -o "bin/$role" "./cmd/$role"
done
node --check internal/frontend/static/app.js
git diff --check

AGP_TEST_POSTGRES_DSN="$AGP_TEST_POSTGRES_DSN" go test ./internal/storage/postgres
./bin/agp --version
./bin/agpctl version
