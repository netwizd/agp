#!/usr/bin/env bash
# Full non-production WAF pipeline: real native corpus, verified test repository,
# PostgreSQL policy lifecycle and the existing real HTTPS/browser acceptance.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
[ "$(id -u)" != 0 ] || { echo 'Run as an unprivileged test user' >&2; exit 1; }
: "${AGP_TEST_WAF_BUNDLE:?set a prepared, pinned native Ubuntu24 bundle}"
: "${AGP_TEST_PG_BINDIR:?set native PostgreSQL binaries}"
python3 scripts/check-nginx-baseline.py --source-only
umask 077
# Keep the large native/browser closure on the workspace filesystem. /tmp may
# have a per-user quota even when df reports free space. A short basename also
# keeps EdgeAuth Unix socket paths below the platform limit.
work="$(mktemp -d "$repo_root/.waf.XXXXXX")"
export AGP_TEST_BROWSER_TMPDIR="$work"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export AGP_TEST_WAF_RENDERER="$work/agpctl"
export AGP_TEST_WAF_FIXTURE_BIN="$work/waf-repository-fixture"
export AGP_TEST_WAF_EVIDENCE="$work/native-evidence.json"
"${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_WAF_RENDERER" ./cmd/agpctl
"${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_WAF_FIXTURE_BIN" ./tests/waf-repository-fixture
if [ "${AGP_TEST_FLEET:-0}" = 1 ]; then
  export AGP_TEST_AGENT_BIN="$work/agp-agent"
  CGO_ENABLED=0 "${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_AGENT_BIN" ./cmd/agp-agent
fi
if [ "${AGP_TEST_NODE_IDENTITY:-0}" = 1 ]; then
  export AGP_TEST_ISSUER_BIN="$work/agp-issuer"
  export AGP_TEST_NODE_IDENTITY_BIN="$work/agp-agent-identity"
  export AGP_TEST_AGENT_VALIDATE_BIN="$work/agp-agent-validate"
  CGO_ENABLED=0 "${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_ISSUER_BIN" ./cmd/agp-issuer
  CGO_ENABLED=0 "${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_NODE_IDENTITY_BIN" ./cmd/agp-agent-identity
  CGO_ENABLED=0 "${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_AGENT_VALIDATE_BIN" ./cmd/agp-agent-validate
fi
bash scripts/test-waf-native.sh --bundle "$AGP_TEST_WAF_BUNDLE" --renderer "$AGP_TEST_WAF_RENDERER" --evidence "$AGP_TEST_WAF_EVIDENCE"
native_bundle="$(cd "$AGP_TEST_WAF_BUNDLE" && pwd)"
# The wrapper selects the qualified Ubuntu24 loader/lib closure explicitly.
# The actual Nginx/ELF objects are separately hashed and verified in native QA.
python3 - "$native_bundle" "$work/nginx" <<'PY'
from pathlib import Path
import shlex, sys
bundle, output = Path(sys.argv[1]), Path(sys.argv[2])
output.write_text('#!/bin/sh\nexec ' + shlex.quote(str(bundle/'lib/ld-linux-x86-64.so.2')) + ' --library-path ' + shlex.quote(str(bundle/'lib')) + ' ' + shlex.quote(str(bundle/'bin/nginx')) + ' "$@"\n')
output.chmod(0o500)
PY
export AGP_TEST_NGINX_BIN="$work/nginx"
python3 scripts/check-nginx-baseline.py --binary "$AGP_TEST_NGINX_BIN"
export AGP_TEST_WAF=1
bash scripts/test-s1-full.sh
echo 'Full verified WAF repository, native provider, policy publication and HTTPS/browser acceptance passed.'
