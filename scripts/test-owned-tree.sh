#!/usr/bin/env bash
# Local read-only filesystem evidence and admission guards, not runtime apply.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
[ "$(uname -s)" = Linux ] || { echo 'Owned-tree acceptance requires Linux statx and descriptor semantics.' >&2; exit 1; }
[ "$(id -u)" != 0 ] || { echo 'Run these self-owned fixtures as an unprivileged user.' >&2; exit 1; }
umask 077
work="$(mktemp -d /tmp/agp-owned-acceptance.XXXXXXXX)"
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$result" -ne 0 ]; then
    for log in tests boundary; do [ ! -f "$work/$log.log" ] || cat "$work/$log.log" >&2; done
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
"${GO:-go}" test -race -count=1 -timeout=4m -v ./internal/ownedtree ./cmd/agp-owned-tree >"$work/tests.log" 2>&1
cat "$work/tests.log"
if rg -q -- '--- (SKIP|FAIL):' "$work/tests.log"; then
  echo 'Owned-tree mandatory fixtures must not SKIP/FAIL.' >&2
  exit 1
fi
for required in \
  TestManifestClosedWire \
  TestManifestNormalizationAndBounds \
  TestOwnedTreeObservationAndDetachedMetadata \
  TestOwnedTreeOpenRejectsUnsafeFilesAndManifestMismatch \
  TestOwnedTreeDetectsPinnedTreeDrift \
  TestOwnedTreeMountIdentityProof \
  TestOwnedTreeRootCanSortAfterEntry \
  TestOwnedTreeCancellationAndConcurrentClose \
  TestOwnedTreeProtectedManifestLoader \
  TestCLILocalArgumentsAndRootBoundary \
  TestCLIHelpDoesNotRequireRoot \
  TestCLIProtectedManifestObservation \
  TestCLIDriftCancellationAndWrongPinHaveNoOutput \
  TestCLIOutputFailureIsNotSuccess
do
  rg -q -- "^--- PASS: $required \\(" "$work/tests.log" || { echo "Missing mandatory test: $required" >&2; exit 1; }
done
bash scripts/test-helper-foundation.sh
"${GO:-go}" build -trimpath -o "$work/agp-owned-tree" ./cmd/agp-owned-tree
"$work/agp-owned-tree" --help >"$work/help.log"
rg -q 'Read-only filesystem observation' "$work/help.log"
if "$work/agp-owned-tree" -manifest "$work/not-present.json" -ownership-digest 'sha256:0000000000000000000000000000000000000000000000000000000000000000' >"$work/stdout" 2>"$work/boundary.log"; then
  echo 'Unprivileged production CLI unexpectedly succeeded.' >&2
  exit 1
fi
[ ! -s "$work/stdout" ]
rg -qx 'owned_tree_local_root_required' "$work/boundary.log"
"${GO:-go}" vet ./internal/ownedtree ./internal/helper ./cmd/agp-owned-tree
echo 'Owned-tree and admission checks passed on self-owned Linux fixtures; privileged runtime baseline/apply remain unqualified.'
