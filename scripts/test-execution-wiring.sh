#!/usr/bin/env bash
# Disposable code/transport acceptance; never installs or applies production.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
[ "$(uname -s)" = Linux ] || { echo "Execution wiring acceptance requires Linux." >&2; exit 1; }
[ "$(id -u)" != 0 ] || { echo "Run this disposable test lab as an unprivileged user." >&2; exit 1; }
: "${AGP_TEST_PG_BINDIR:?set native PostgreSQL 17+ binaries}"
unset AGP_DATABASE_DSN AGP_JOURNAL_DATABASE_DSN AGP_TEST_POSTGRES_DSN AGP_TEST_EXECUTION_DSN AGP_TEST_EXECUTION_SOURCES_DSN AGP_TEST_OIDC_HTTP_DSN AGP_TEST_JOURNAL_DSN PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGPASSWORD PGSERVICE PGSERVICEFILE PGPASSFILE PGOPTIONS
pgbin="$(cd "$AGP_TEST_PG_BINDIR" && pwd)"
for binary in initdb pg_ctl createdb; do
  [ -x "$pgbin/$binary" ] || { echo "Missing test binary: $binary" >&2; exit 1; }
done
umask 077
lab=$(mktemp -d /tmp/agp-sources-pg.XXXXXXXX)
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ -f "$lab/data/postmaster.pid" ]; then
    if ! "$pgbin/pg_ctl" -D "$lab/data" -m fast -w -t 30 stop >"$lab/stop.log" 2>&1; then
      echo "Execution test cleanup failed; private lab retained: $lab" >&2
      exit 1
    fi
  fi
  if [ "$result" -ne 0 ]; then
    for log in sources http native transport client agent journal runtime vet; do
      [ ! -f "$lab/$log.log" ] || cat "$lab/$log.log" >&2
    done
  fi
  rm -rf -- "$lab"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$lab/socket"
"$pgbin/initdb" -D "$lab/data" -U sources_test --auth=trust --no-locale --encoding=UTF8 >"$lab/initdb.log" 2>&1
cat >>"$lab/data/postgresql.conf" <<CONFIG
listen_addresses = ''
unix_socket_directories = '$lab/socket'
unix_socket_permissions = 0700
CONFIG
"$pgbin/pg_ctl" -D "$lab/data" -l "$lab/server.log" -w -t 30 start
"$pgbin/createdb" -h "$lab/socket" -U sources_test sources
"$pgbin/createdb" -h "$lab/socket" -U sources_test http
"$pgbin/createdb" -h "$lab/socket" -U sources_test inventory
export AGP_TEST_EXECUTION_SOURCES_DSN="host=$lab/socket port=5432 user=sources_test dbname=sources sslmode=disable connect_timeout=5"
export AGP_TEST_OIDC_HTTP_DSN="host=$lab/socket port=5432 user=sources_test dbname=http sslmode=disable connect_timeout=5"
export AGP_TEST_POSTGRES_DSN="host=$lab/socket port=5432 user=sources_test dbname=inventory sslmode=disable connect_timeout=5"
goexec="${GO:-go}"
"$goexec" test -race -count=1 -v -timeout 5m ./internal/executionsources | tee "$lab/sources.log"
"$goexec" test -race -count=1 -v -timeout 4m -run '^TestExecution' ./internal/httpapi | tee "$lab/http.log"
"$goexec" test -race -count=1 -timeout 3m ./internal/helper ./internal/nativeactivation ./internal/helperruntime | tee "$lab/native.log"
"$goexec" test -race -count=1 -v -timeout 2m ./internal/helpertransport ./cmd/agp-helper | tee "$lab/transport.log"
"$goexec" test -race -count=1 -v -timeout 2m -run '^TestExecution' ./internal/inventory | tee "$lab/client.log"
"$goexec" test -race -count=1 -v -timeout 2m ./internal/agentexecution | tee "$lab/agent.log"
"$goexec" test -race -count=1 -v -timeout 2m -run '^TestHeadWithChallenge' ./internal/securityjournal | tee "$lab/journal.log"
"$goexec" test -race -count=1 -v -timeout 2m -run '^TestExecution' ./internal/runtime | tee "$lab/runtime.log"
for required in TestSourcesSQLite TestSourcesPostgres TestSourceOutcomesSQLite TestSourceOutcomesPostgres TestUnknownInitialCaptureCannotBeResetSQLite TestUnknownInitialCaptureCannotBeResetPostgres; do
  rg -q -- "^--- PASS: $required \\(" "$lab/sources.log" || { echo "Missing source test: $required" >&2; exit 1; }
done
for required in TestExecutionHTTPBoundarySQLite TestExecutionHTTPBoundaryPostgres TestExecutionBaselineHTTPTransport; do
  rg -q -- "^--- PASS: $required \\(" "$lab/http.log" || { echo "Missing transport test: $required" >&2; exit 1; }
done
"$goexec" vet ./internal/executionsources ./internal/helperruntime ./internal/helpertransport ./internal/runtime ./internal/httpapi ./internal/securityjournal ./internal/agentexecution ./cmd/agp ./cmd/agp-helper ./cmd/agp-agent 2>&1 | tee "$lab/vet.log"
echo 'Execution wiring acceptance passed with synthetic qualification and controlled native adapters.'
echo 'OPEN: actual root/Nginx installation, production qualification, HA and performance. Root-only writer-lock lifecycle is explicitly skipped here.'
