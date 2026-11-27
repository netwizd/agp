#!/usr/bin/env bash
# Explicit root-supervisor qualification. No sudo, user namespace root fixture,
# infrastructure change or automatic privilege escalation is attempted here.
set -euo pipefail
: "${AGP_TEST_BWRAP_BIN:?set separately qualified bubblewrap path}"
: "${AGP_TEST_BWRAP_DIGEST:?set separately qualified sha256 digest}"
: "${AGP_TEST_EXECUTION_UID:?set the installed nonroot syntax UID}"
: "${AGP_TEST_EXECUTION_GID:?set the installed nonroot syntax GID}"
if [[ ${EUID} -ne 0 || $(id -ru) -ne 0 ]]; then
  echo 'Actual real/effective root is required; root bridge qualification remains OPEN.' >&2
  exit 1
fi
lab=$(mktemp -d /tmp/agp-bootstrap-root.XXXXXXXX)
trap 'rm -rf -- "$lab"' EXIT
chmod 0700 "$lab"
mkdir -m 0700 "$lab/cache" "$lab/work"
export GOCACHE="$lab/cache" GOTMPDIR="$lab/work"
export AGP_TEST_ROOT_BRIDGE_REQUIRED=1
# This is a standalone process and the native child sets its own rlimits. Race
# instrumentation is tested separately without the 4GiB address-space ceiling.
go test -count=1 -v -timeout=6m ./internal/nativesandbox -run '^TestRootBridgeNative$' >"$lab/bridge.log" 2>&1
cat "$lab/bridge.log"
if grep -Eq -- '--- SKIP:|--- FAIL:|^FAIL' "$lab/bridge.log"; then
  echo 'Mandatory root bridge coverage failed or skipped.' >&2
  exit 1
fi
grep -q -- '--- PASS: TestRootBridgeNative ' "$lab/bridge.log"
go test -count=1 -v ./cmd/agp-bootstrap-candidate
go vet ./cmd/agp-bootstrap-candidate ./internal/nativesandbox
echo 'PASS: root-owned source -> explicit nonroot isolated syntax bridge and CLI guards.'
echo 'Full CLI/journal/qualified-host/active-master/durable-backup qualification remains separate.'
