#!/usr/bin/env bash
# S1 extends the actual two-cluster S0 lab; it never touches production.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
export AGP_TEST_S1=1
bash scripts/test-s0-full.sh
echo 'Full S1 authoring, CAS, immutable snapshots, HTTPS/browser, profile fences and controlled execution foundations passed; root deployment qualification remains separate.'
