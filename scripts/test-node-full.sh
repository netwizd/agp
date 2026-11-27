#!/usr/bin/env bash
# Disposable full pipeline, including owner-approved identity lifecycle and
# bounded local syntax validation. This does not install or apply to a node.
set -euo pipefail
if [ -n "${AGP_TEST_LOCAL_SYNTAX_TMPDIR:-}" ] && [ ! -d "$AGP_TEST_LOCAL_SYNTAX_TMPDIR" ]; then
  echo 'AGP_TEST_LOCAL_SYNTAX_TMPDIR must name an existing private native scratch directory' >&2
  exit 1
fi
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
export AGP_TEST_NODE_IDENTITY=1
bash scripts/test-fleet-full.sh
echo 'Full approved node enrollment, isolated issuer, renewal/revoke and local syntax acceptance passed.'
