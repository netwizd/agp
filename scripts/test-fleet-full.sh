#!/usr/bin/env bash
# Real read-only agent -> authenticated inventory -> trusted WAF desired revision.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
: "${AGP_TEST_AGENT_USERSPACE:?set the signed Ubuntu24/PRoot descriptor from prepare-waf-native.sh --agent-lab-only}"
export AGP_TEST_FLEET=1
bash scripts/test-waf-full.sh
echo 'Full read-only agent inventory and trusted WAF zone desired-revision acceptance passed.'
