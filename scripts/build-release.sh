#!/usr/bin/env bash
# Build application bootstrap assets from an identifiable, tested Git release.
# This command never pushes, tags, signs or publishes.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
version=""
output=""
usage() {
  echo 'Usage: scripts/build-release.sh --version vX.Y.Z[-rc.N] --output-dir DIRECTORY'
  echo 'Requires clean tagged Git source, Go, npm, Python3, and release-check native/PG inputs.'
}
while (($#)); do
  case "$1" in
    --version|--output-dir)
      (($# >= 2)) || { usage >&2; exit 2; }
      if [[ "$1" == --version ]]; then version="$2"; else output="$2"; fi
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$version" && -n "$output" ]] || { usage >&2; exit 2; }
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || {
  echo 'Invalid immutable release version.' >&2; exit 2;
}
output="$(realpath -m -- "$output")"
cd "$repo_root"
[[ "$(git rev-parse --show-toplevel 2>/dev/null)" == "$repo_root" ]] || {
  echo 'Release build requires the actual Git checkout; this source snapshot has no release identity.' >&2
  exit 1
}
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || {
  echo 'Release build requires a clean source tree.' >&2; exit 1;
}
commit="$(git rev-parse --verify HEAD)"
tag_commit="$(git rev-parse --verify "refs/tags/$version^{commit}")"
[[ "$commit" == "$tag_commit" && "$(cat VERSION)" == "$version" ]] || {
  echo 'Release tag, VERSION and checked-out commit must agree.' >&2; exit 1;
}
epoch="$(git show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH="$epoch"
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
export GOTOOLCHAIN=local GOWORK=off
GO="${GO:-go}"
export PATH="$(dirname -- "$(command -v "$GO")"):$PATH"
# Mandatory real native/PG checks, without the ordinary optional-test skips.
bash scripts/release-check.sh
stage="$(mktemp -d "${TMPDIR:-/tmp}/agp-release-build.XXXXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/source" "$stage/bin"
git archive --format=tar HEAD | tar -xf - -C "$stage/source"
cd "$stage/source"
npm --prefix web/console-prototype ci --ignore-scripts --no-audit --no-fund
for app in auth config directory; do
  npm --prefix web/console-prototype run "build:$app"
done
built_at="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)"
ldflags="-X github.com/netwizd/agp/internal/version.Version=$version -X github.com/netwizd/agp/internal/version.Commit=$commit -X github.com/netwizd/agp/internal/version.BuiltAt=$built_at"
for role in agp agpctl agp-security-journal agp-edge-auth agp-agent agp-helper agp-issuer agp-agent-identity agp-agent-validate; do
  "$GO" build -buildvcs=false -trimpath -ldflags "$ldflags" -o "$stage/bin/$role" "./cmd/$role"
done
# Test the exact regenerated frontend that is embedded in these binaries.
"$GO" test ./internal/frontend
python3 "$repo_root/scripts/package-release.py" --source-dir "$stage/source" \
  --bin-dir "$stage/bin" --output-dir "$output" --version "$version" \
  --commit "$commit" --epoch "$epoch"
