#!/usr/bin/env bash
set -euo pipefail

# Runtime bytes and the complete canonical []nativeactivation.RuntimeEntry
# descriptor are installed and pinned separately. This script does not install,
# rewrite, qualify, or chown them, and never changes the platform allowlist.
if [[ ${EUID} -ne 0 ]]; then
  echo 'Actual root is required for native activation acceptance.' >&2
  exit 1
fi
: "${AGP_TEST_NATIVE_RUNTIME_DIR:?set the root-installed qualified complete runtime directory}"
: "${AGP_TEST_NATIVE_RUNTIME_MANIFEST:?set its root-protected canonical complete RuntimeEntry JSON file}"
: "${AGP_TEST_NATIVE_RUNTIME_MANIFEST_DIGEST:?set the separately pinned descriptor sha256 digest}"
: "${AGP_TEST_NATIVE_QUALIFICATION_DIGEST:?set the supplied qualification report digest}"
: "${AGP_TEST_NATIVE_RELEASE_MANIFEST_DIGEST:?set the supplied release manifest digest}"
: "${AGP_TEST_BWRAP_BIN:?set the separately qualified bubblewrap executable}"
: "${AGP_TEST_BWRAP_DIGEST:?set the separately qualified bubblewrap sha256 digest}"
: "${AGP_TEST_EXECUTION_UID:?set the installed nonroot syntax/worker UID}"
: "${AGP_TEST_EXECUTION_GID:?set the installed nonroot syntax/worker GID}"
: "${AGP_TEST_NATIVE_CGROUP_PARENT:?set the actual writable cgroup v2 parent for one private child}"
export AGP_TEST_NATIVE_ROOT_REQUIRED=1
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo_root"
exec go test -count=1 -v -timeout=4m ./internal/nativeactivation -run '^TestNativeActivationRoot$'
