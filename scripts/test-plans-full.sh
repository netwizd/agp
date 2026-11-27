#!/usr/bin/env bash
# Disposable planning-review acceptance. Does not qualify or dispatch execution.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
[ "$(id -u)" != 0 ] || { echo 'Run planning acceptance as an unprivileged user.' >&2; exit 1; }
: "${AGP_TEST_PG_BINDIR:?set native PostgreSQL 17+ binaries}"
: "${AGP_TEST_PLAYWRIGHT_MODULE:?set Playwright module}"
: "${AGP_TEST_CHROMIUM_BIN:?set Chromium executable}"
pgbin="$(cd "$AGP_TEST_PG_BINDIR" && pwd)"
for binary in initdb pg_ctl postgres createdb; do
  [ -x "$pgbin/$binary" ] || { echo "Missing test tool: $binary" >&2; exit 1; }
done
unset AGP_DATABASE_DSN AGP_JOURNAL_DATABASE_DSN AGP_TEST_POSTGRES_DSN AGP_TEST_CONFIGURATION_DSN
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGPASSWORD PGSERVICE PGSERVICEFILE PGPASSFILE PGOPTIONS
umask 077
work="$(mktemp -d /tmp/agp-plans.XXXXXXXX)"
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ -f "$work/data/postmaster.pid" ]; then
    if ! "$pgbin/pg_ctl" -D "$work/data" -m immediate -w -t 30 stop >"$work/stop.log" 2>&1; then
      echo "Planning test cleanup failed; private lab retained: $work" >&2
      exit 1
    fi
  fi
  if [ "$result" -ne 0 ]; then
    for log in acceptance domain server; do [ ! -f "$work/$log.log" ] || cat "$work/$log.log" >&2; done
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$work/socket"
"$pgbin/initdb" -D "$work/data" -U planning_test --auth=trust --no-locale --encoding=UTF8 >"$work/initdb.log" 2>&1
cat >>"$work/data/postgresql.conf" <<CONFIG
listen_addresses = ''
unix_socket_directories = '$work/socket'
unix_socket_permissions = 0700
synchronous_commit = on
CONFIG
"$pgbin/pg_ctl" -D "$work/data" -l "$work/server.log" -w -t 30 start
"$pgbin/createdb" -h "$work/socket" -U planning_test planning
export AGP_TEST_CONFIGURATION_DSN="host=$work/socket port=5432 user=planning_test dbname=planning sslmode=disable connect_timeout=5"
"${GO:-go}" test -race -count=1 -timeout=6m -v ./internal/deploymentplan >"$work/domain.log" 2>&1
cat "$work/domain.log"
"${GO:-go}" test -race -count=1 -timeout=6m -v ./internal/configuration -run '^TestPlanProposals(SQLite|Postgres)$' >"$work/acceptance.log" 2>&1
cat "$work/acceptance.log"
if rg -q -- '--- (SKIP|FAIL):' "$work/domain.log" "$work/acceptance.log"; then
  echo 'Mandatory planning acceptance must not SKIP/FAIL.' >&2
  exit 1
fi
for required in TestPlanProposalsSQLite TestPlanProposalsPostgres; do
  rg -q -- "^--- PASS: $required \\(" "$work/acceptance.log" || { echo "Missing test: $required" >&2; exit 1; }
done
bash scripts/test-helper-foundation.sh
"${GO:-go}" test -race -count=1 -timeout=3m ./internal/config ./internal/runtime ./internal/httpapi -run '^TestPlan(Review|ProposalManagementHTTPBoundary)'
npm --prefix web/console-prototype run typecheck:config
npm --prefix web/console-prototype run build:config
npm --prefix web/console-prototype run test:config:browser
node web/console-prototype/fleet-browser-fixture.mjs
node web/console-prototype/node-identity-browser-fixture.mjs
npm --prefix web/console-prototype run test:plans:browser
"${GO:-go}" vet ./internal/deploymentplan ./internal/configuration ./internal/helper ./internal/httpapi ./internal/runtime ./internal/config
echo 'Planning review, signed-plan contracts and helper admission acceptance passed; execution is not qualified.'
