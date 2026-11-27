#!/usr/bin/env sh
set -eu

fail() {
  echo "Nginx integration: $*" >&2
  exit 1
}

[ "$(id -u)" != 0 ] || fail "run the native suite as an unprivileged user"
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
binary="${AGP_TEST_NGINX_BIN:-}"
[ -n "$binary" ] || fail "set AGP_TEST_NGINX_BIN to an explicitly selected, verified native binary"
binary="$(command -v "$binary")" || fail "Nginx executable not found"
binary="$(CDPATH= cd -- "$(dirname -- "$binary")" && pwd)/$(basename -- "$binary")"
[ -x "$binary" ] || fail "Nginx binary is not executable: $binary"
python3 "$repo_root/scripts/check-nginx-baseline.py" --binary "$binary"
export AGP_TEST_NGINX_BIN="$binary"
go="${GO:-go}"
command -v "$go" >/dev/null 2>&1 || fail "Go executable not found: $go"
cd "$repo_root"
umask 077
workdir="$(mktemp -d /tmp/agp-test-nginx.XXXXXX)"
trap 'rm -rf -- "$workdir"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

test_result=0
"$go" test -count=1 -timeout=3m -v ./internal/reverseproxy/nginx >"$workdir/tests.log" 2>&1 || test_result="$?"
cat "$workdir/tests.log"
[ "$test_result" -eq 0 ] || exit "$test_result"
if ! awk '
  /^[[:space:]]*--- SKIP:/ { skipped = 1 }
  /^--- PASS: TestNativeIdentityHeaderSpoofing([[:space:]]|$)/ { native_passed = 1 }
  /^--- PASS: TestNativeManagementHostIsolation([[:space:]]|$)/ { management_passed = 1 }
  /^--- PASS: TestNativeEdgeAuthIsolation([[:space:]]|$)/ { edge_passed = 1 }
  END { exit (skipped || !native_passed || !management_passed || !edge_passed) }
' "$workdir/tests.log"; then
  fail "identity spoofing, management isolation and EdgeAuth native cases must all pass without SKIP"
fi
