#!/usr/bin/env bash
set -euo pipefail
: "${AGP_TEST_BWRAP_BIN:?set the separately qualified bubblewrap installation path}"
: "${AGP_TEST_BWRAP_DIGEST:?set the separately qualified sha256 digest}"
if [[ ${EUID} -eq 0 ]]; then
  echo 'Run this test as the unprivileged syntax account.' >&2
  exit 1
fi
export AGP_TEST_NATIVE_REQUIRED=1
go test -count=1 -v -timeout=4m ./internal/nativesandbox -run '^TestNativeSandbox$'
