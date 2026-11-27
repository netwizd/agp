#!/usr/bin/env sh
set -eu

# Always test an isolated native cluster; never use a caller's database DSN.
unset AGP_TEST_POSTGRES_DSN AGP_DATABASE_DSN
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGPASSWORD PGSERVICE PGSERVICEFILE PGPASSFILE PGOPTIONS

fail() {
  echo "PostgreSQL integration: $*" >&2
  exit 1
}

[ "$(id -u)" != 0 ] || fail "run as an unprivileged user (initdb cannot run as root)"

go="${GO:-go}"
command -v "$go" >/dev/null 2>&1 || fail "Go executable not found: $go"
if [ -n "${AGP_TEST_PG_BINDIR:-}" ]; then
  pg_bindir="$AGP_TEST_PG_BINDIR"
else
  initdb_path="$(command -v initdb 2>/dev/null || true)"
  [ -n "$initdb_path" ] || fail "native PostgreSQL is required; set AGP_TEST_PG_BINDIR to its bin directory"
  pg_bindir="$(dirname "$initdb_path")"
fi
# Resolve relative paths before changing to the repository root.
pg_bindir="$(cd "$pg_bindir" && pwd)" || fail "invalid AGP_TEST_PG_BINDIR"
for binary in initdb pg_ctl postgres psql; do
  [ -x "$pg_bindir/$binary" ] || fail "missing executable: $pg_bindir/$binary"
done

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
umask 077
# Keep the Unix socket path short and independent of the caller's TMPDIR.
workdir="$(mktemp -d /tmp/agp-test-pg.XXXXXX)"
data_dir="$workdir/data"
socket_dir="$workdir/socket"

cleanup() {
  result="$1"
  trap - 0 HUP INT TERM
  if [ -f "$data_dir/postmaster.pid" ]; then
    if ! "$pg_bindir/pg_ctl" -D "$data_dir" -m immediate -w -t 30 stop >"$workdir/stop.log" 2>&1; then
      cat "$workdir/stop.log" >&2
      echo "PostgreSQL integration: cleanup failed; cluster retained at $workdir" >&2
      exit 1
    fi
  fi
  if [ "$result" -ne 0 ] && [ -f "$workdir/server.log" ]; then
    cat "$workdir/server.log" >&2
  fi
  rm -rf -- "$workdir"
  exit "$result"
}
trap 'cleanup "$?"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$socket_dir"
if ! "$pg_bindir/initdb" -D "$data_dir" -U agp_test --auth=trust --no-locale --encoding=UTF8 >"$workdir/initdb.log" 2>&1; then
  cat "$workdir/initdb.log" >&2
  fail "initdb failed"
fi
cat >>"$data_dir/postgresql.conf" <<EOF
listen_addresses = ''
unix_socket_directories = '$socket_dir'
unix_socket_permissions = 0700
EOF
"$pg_bindir/pg_ctl" -D "$data_dir" -l "$workdir/server.log" -w -t 30 start
export AGP_TEST_POSTGRES_DSN="host=$socket_dir port=5432 user=agp_test dbname=postgres sslmode=disable connect_timeout=5"
"$pg_bindir/psql" -X -w "$AGP_TEST_POSTGRES_DSN" -v ON_ERROR_STOP=1 -c 'SELECT version();'

# Avoid pipelines hiding go test's exit status and disable cached test results.
test_result=0
"$go" test -count=1 -timeout=3m -v ./internal/storage ./internal/storage/postgres >"$workdir/tests.log" 2>&1 || test_result="$?"
cat "$workdir/tests.log"
[ "$test_result" -eq 0 ] || exit "$test_result"
if ! awk '
  /^[[:space:]]*--- SKIP:/ { skipped = 1 }
  /^--- PASS: TestStoreIntegration([[:space:]]|$)/ { integration_passed = 1 }
  /^[[:space:]]*--- PASS: TestIdentityMutationStorage\/postgres([[:space:]]|$)/ { identity_passed = 1 }
  /^[[:space:]]*--- PASS: TestSessionProfileStorage\/postgres([[:space:]]|$)/ { profile_passed = 1 }
  END { exit (skipped || !integration_passed || !identity_passed || !profile_passed) }
' "$workdir/tests.log"; then
  fail "the suite must pass TestStoreIntegration, TestIdentityMutationStorage/postgres and TestSessionProfileStorage/postgres and must not skip tests"
fi
