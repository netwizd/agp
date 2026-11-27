#!/usr/bin/env bash
# Native CP/journal acceptance uses two independent disposable PG clusters.
set -euo pipefail
fail() { echo "S0 acceptance: $*" >&2; exit 1; }
[ "$(id -u)" != 0 ] || fail 'run as an unprivileged user'
unset AGP_DATABASE_DSN AGP_JOURNAL_DATABASE_DSN AGP_TEST_POSTGRES_DSN AGP_TEST_JOURNAL_DSN AGP_TEST_S0_CP_DSN AGP_TEST_CONFIGURATION_DSN AGP_TEST_OIDC_HTTP_DSN
unset AGP_TEST_ROLE_SCOPE_DSN AGP_TEST_ROLE_SCOPE_DISPOSABLE
unset AGP_TEST_EXECUTION_DSN
unset AGP_WAF_TRUST_CONFIG AGP_WAF_REPOSITORY_DIR AGP_WAF_TEMP_DIR
unset AGP_AGENT_MTLS_ADDR AGP_AGENT_MTLS_CERT_FILE AGP_AGENT_MTLS_KEY_FILE AGP_AGENT_MTLS_CLIENT_CA_FILE AGP_AGENT_REGISTRY_FILE
unset AGP_NODE_IDENTITY_CONFIG AGP_ENROLLMENT_TLS_ADDR AGP_ENROLLMENT_TLS_CERT_FILE AGP_ENROLLMENT_TLS_KEY_FILE
unset AGP_EMAIL_CONFIG_FILE AGP_DIRECTORY_CONNECTOR_FILE AGP_OIDC_CONNECTOR_FILE
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGPASSWORD PGSERVICE PGSERVICEFILE PGPASSFILE PGOPTIONS
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
# Fleet/node browser acceptance needs its signed Ubuntu userspace descriptor.
# Fail before native compilation/databases when callers enable those stages.
if [ "${AGP_TEST_FLEET:-0}" = 1 ] || [ "${AGP_TEST_NODE_IDENTITY:-0}" = 1 ]; then
  [ -n "${AGP_TEST_AGENT_USERSPACE:-}" ] && [ -r "$AGP_TEST_AGENT_USERSPACE" ] || fail 'AGP_TEST_AGENT_USERSPACE must name the prepared Ubuntu24 agent userspace descriptor'
fi
pgbin="${AGP_TEST_PG_BINDIR:-}"
[ -n "$pgbin" ] || fail 'set AGP_TEST_PG_BINDIR to native PostgreSQL17+ binaries'
pgbin="$(cd "$pgbin" && pwd)"
for binary in initdb pg_ctl postgres psql createdb pg_dump pg_restore; do [ -x "$pgbin/$binary" ] || fail "missing $pgbin/$binary"; done
[ -x "${AGP_TEST_NGINX_BIN:-}" ] || fail 'AGP_TEST_NGINX_BIN must point to the qualified Nginx binary'
python3 scripts/check-nginx-baseline.py --binary "$AGP_TEST_NGINX_BIN"
python3 scripts/test-nginx-baseline.py
[ -n "${AGP_TEST_PLAYWRIGHT_MODULE:-}" ] || fail 'AGP_TEST_PLAYWRIGHT_MODULE is required for mandatory browser acceptance'
[ -x "${AGP_TEST_CHROMIUM_EXECUTABLE:-}" ] || fail 'AGP_TEST_CHROMIUM_EXECUTABLE must point to Chromium'
command -v "${AGP_TEST_NODE_BIN:-node}" >/dev/null || fail 'Node.js is required'
npm --prefix web/console-prototype run build:auth
npm --prefix web/console-prototype run build:directory
# These Chromium cases exercise production assets with deterministic API
# fixtures. The native HTTP/IdP/LDAP/SMTP tests and the real-process browser
# acceptance below separately prove backend composition.
export AGP_TEST_CHROMIUM_BIN="$AGP_TEST_CHROMIUM_EXECUTABLE"
for fixture in auth directory email oidc-auth oidc-management lifecycle-auth lifecycle-management roles; do
  "${AGP_TEST_NODE_BIN:-node}" "web/console-prototype/$fixture-browser-fixture.mjs"
done
if [ "${AGP_TEST_S1:-0}" = 1 ]; then
  npm --prefix web/console-prototype run build:config
  "${AGP_TEST_NODE_BIN:-node}" web/console-prototype/config-browser-fixture.mjs
  "${AGP_TEST_NODE_BIN:-node}" web/console-prototype/execution-browser-fixture.mjs
fi
umask 077
work="$(mktemp -d /tmp/agp-s0-full.XXXXXX)"
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  cleanup_failed=0
  for cluster in cp journal; do
    if [ -f "$work/$cluster/data/postmaster.pid" ]; then
      "$pgbin/pg_ctl" -D "$work/$cluster/data" -m immediate -w -t 30 stop >"$work/$cluster/stop.log" 2>&1 || { result=1; cleanup_failed=1; cat "$work/$cluster/stop.log" >&2; }
    fi
    if [ "$result" -ne 0 ] && [ -f "$work/$cluster/server.log" ]; then cat "$work/$cluster/server.log" >&2; fi
  done
  if [ "$cleanup_failed" -ne 0 ]; then echo "S0 cleanup failed; clusters retained at $work" >&2; exit 1; fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for cluster in cp journal; do
  mkdir -p "$work/$cluster/socket"
  "$pgbin/initdb" -D "$work/$cluster/data" -U "s0_$cluster" --auth=trust --no-locale --encoding=UTF8 >"$work/$cluster/initdb.log" 2>&1
  cat >>"$work/$cluster/data/postgresql.conf" <<CONFIG
listen_addresses = ''
unix_socket_directories = '$work/$cluster/socket'
unix_socket_permissions = 0700
synchronous_commit = on
CONFIG
  "$pgbin/pg_ctl" -D "$work/$cluster/data" -l "$work/$cluster/server.log" -w -t 30 start
  "$pgbin/createdb" -h "$work/$cluster/socket" -U "s0_$cluster" "agp_$cluster"
done
"$pgbin/createdb" -h "$work/cp/socket" -U s0_cp agp_identity
"$pgbin/createdb" -h "$work/cp/socket" -U s0_cp agp_oidc_http
"$pgbin/createdb" -h "$work/cp/socket" -U s0_cp agp_legacy
if [ "${AGP_TEST_S1:-0}" = 1 ]; then
  "$pgbin/createdb" -h "$work/cp/socket" -U s0_cp agp_configuration
  "$pgbin/createdb" -h "$work/cp/socket" -U s0_cp agp_role_scope
  "$pgbin/createdb" -h "$work/cp/socket" -U s0_cp agp_execution
  export AGP_TEST_CONFIGURATION_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_configuration sslmode=disable connect_timeout=5"
  export AGP_TEST_ROLE_SCOPE_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_role_scope sslmode=disable connect_timeout=5"
  export AGP_TEST_ROLE_SCOPE_DISPOSABLE=1
  export AGP_TEST_EXECUTION_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_execution sslmode=disable connect_timeout=5"
fi
export AGP_TEST_IDENTITY_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_identity sslmode=disable connect_timeout=5"
export AGP_TEST_OIDC_HTTP_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_oidc_http sslmode=disable connect_timeout=5"
export AGP_TEST_PG_BINDIR="$pgbin"
export AGP_TEST_S0_DISPOSABLE=1
export AGP_TEST_S0_CP_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_cp sslmode=disable connect_timeout=5"
export AGP_TEST_POSTGRES_DSN="host=$work/cp/socket port=5432 user=s0_cp dbname=agp_legacy sslmode=disable connect_timeout=5"
export AGP_TEST_JOURNAL_DSN="host=$work/journal/socket port=5432 user=s0_journal dbname=agp_journal sslmode=disable connect_timeout=5"
# Package-scoped integration avoids optional skips concealing a missing runtime.
native_packages=(./internal/securityjournal ./internal/securitystate ./internal/mailtransport ./internal/oidcclient ./internal/secretfiles ./internal/runtime ./internal/storage ./internal/storage/postgres ./tests/s0)
large_packages=(./internal/identity)
if [ "${AGP_TEST_S1:-0}" = 1 ]; then native_packages+=(./internal/configmodel ./internal/compiler ./internal/rolescope ./internal/helper ./internal/nativeactivation ./internal/rolloutexecution ./internal/inventory); large_packages+=(./internal/configuration ./internal/httpapi); fi
if [ "${AGP_TEST_WAF:-0}" = 1 ]; then native_packages+=(./internal/repository ./internal/wafnative); fi
if [ "${AGP_TEST_FLEET:-0}" = 1 ]; then
  if [ "${AGP_TEST_S1:-0}" != 1 ]; then native_packages+=(./internal/inventory); fi
  if [ "${AGP_TEST_S1:-0}" != 1 ]; then large_packages+=(./internal/httpapi); fi
fi
if [ "${AGP_TEST_NODE_IDENTITY:-0}" = 1 ]; then native_packages+=(./internal/nodeidentity ./internal/nodebootstrap); fi
"${GO:-go}" test -race -count=1 -timeout=10m -v "${native_packages[@]}" >"$work/acceptance.log" 2>&1 || { cat "$work/acceptance.log"; exit 1; }
# Every top-level test in the growing identity/configuration/HTTP packages is listed
# by the same race build, then run exactly once in bounded groups. This avoids
# a single package-wide deadline killing healthy sequential fixtures. There is
# no manually maintained exclusion list; new tests join acceptance automatically.
for package in "${large_packages[@]}"; do
  "${GO:-go}" test -race -list '^(Test|Example|Fuzz)' "$package" >"$work/test-list.log" 2>&1 || { cat "$work/test-list.log"; exit 1; }
  mapfile -t test_names < <(rg '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' "$work/test-list.log")
  [ "${#test_names[@]}" -gt 0 ] || fail "no native tests discovered in $package"
  for ((offset=0; offset<${#test_names[@]}; offset+=6)); do
    pattern=''
    for name in "${test_names[@]:offset:6}"; do
      pattern="${pattern:+$pattern|}$name"
    done
    echo "Native acceptance $package batch $((offset/6+1)): $pattern" >>"$work/acceptance.log"
    "${GO:-go}" test -race -count=1 -timeout=10m -v -run "^($pattern)$" "$package" >>"$work/acceptance.log" 2>&1 || { cat "$work/acceptance.log"; exit 1; }
  done
done
cat "$work/acceptance.log"
if rg -q -- '--- SKIP:' "$work/acceptance.log"; then fail 'mandatory native acceptance must not skip tests'; fi
for test in TestJournalNativeTransactions TestJournalNativeMTLSAndLostResponse TestNativeControlPlaneRestore TestLocalIdentityPostgres TestCentralEdgePostgres TestIdentityLeasePostgres TestStoreIntegration; do
  rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing required test $test"
done
for test in TestPrimaryAuthenticationTimePostgres TestEmailIdentityPostgres TestEmailLifecycleRacesPostgres TestEmailDirectorySourcePostgres TestEmailRecoveryConfirmationPostgres TestEmailSMTPWirePostgres TestEmailProtectedInstallationConfiguration TestPurposeBoundProtectedImmutableSecrets TestSecretManifestAndFileBoundary; do
  rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory identity/email acceptance $test"
done
for test in TestOIDCIdentityPostgres TestOIDCBoundariesPostgres TestOIDCFinalTimePostgres TestOIDCHistoricalPeoplePostgres TestOIDCStateKeySeparationAndProtectedFile TestOIDCProtectedInstallationConfiguration TestOIDCCodePKCEAndKeyRotation TestOIDCExchangeNoAutomaticRetryOrReplay TestOIDCDiscoveryEndpointPins TestOIDCPKCEVerifierEnforcedByIdP TestEmailRuntimeCancellationNeverRequeuesSubmission; do
  rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory OIDC/runtime acceptance $test"
done
for test in TestInvitationsSQLite TestInvitationsPostgres TestInvitationBoundariesSQLite TestInvitationBoundariesPostgres TestInvitationRestoreSQLite TestInvitationRestorePostgres TestInvitationADIssuerSQLite TestInvitationADIssuerPostgres TestInvitationSMTPWireSQLite TestInvitationSMTPWirePostgres TestRecoveryLifecycleSQLite TestRecoveryLifecyclePostgres TestRecoveryFaultSQLite TestRecoveryFaultPostgres TestRecoveryDirectoryWireSQLite TestRecoveryDirectoryWirePostgres TestLifecyclePendingUsernameSQLite TestLifecyclePendingUsernamePostgres TestLifecycleEphemeralCleanupSQLite TestLifecycleEphemeralCleanupPostgres TestEnrollmentFinalDeadlineSQLite TestEnrollmentFinalDeadlinePostgres TestLifecycleRuntimeCancelsAndJoinsSubmission; do
  rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory identity lifecycle acceptance $test"
done
if [ "${AGP_TEST_S1:-0}" = 1 ]; then
  for test in TestExecutionLifecyclePostgres TestExecutionHelperRoundtripPostgres TestExecutionHTTPBoundaryPostgres TestExecutionAgentIdentityPostgres TestExecutionAfterActivatingFsyncRequiresFreshLiveFence TestExecutionActivationCannotOutliveFreshProof TestExecutorRealFilesystemApplyThenExplicitRollbackReusesQualifiedContent TestExecutorRealFilesystemRecoveredApplyThenSameContentNewTask TestAuthorizationContextExpiresInsideLastPointerCheckpoint TestActualProcessCrashReconcilesOnlyProvedPendingPointer TestAbsentMasterStillContainsInstallerPinnedOrphanGroup; do
    rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory execution foundation acceptance $test"
  done
  for test in TestConfigurationPostgres TestScopedAuthoringPostgres TestZoneAuthoringPostgres TestAuthoringReviewsPostgres TestGatewayRecipientsPostgres TestGatewayRecipientsSiteIsolationPostgres TestGatewayScopedConfigurationPostgres TestGatewayScopedHTTPActualServicesPostgres TestResourceAuthorityPostgres TestGatewayRecipientsFleetPostgres TestResourceScopedConfigurationPostgres TestResourceScopedHistoryPostgres TestResourceScopedHTTPActualServicesPostgres; do
    rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory S1 PostgreSQL acceptance $test"
  done
fi
if [ "${AGP_TEST_WAF:-0}" = 1 ]; then
  for test in TestWafPoliciesPostgres TestNativeWAFProvider TestDirectoryWAFWirePostgres; do
    rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory WAF native acceptance $test"
  done
fi
if [ "${AGP_TEST_FLEET:-0}" = 1 ]; then
  for test in TestInventoryPostgres TestInventoryRealMTLSClient TestEdgeKeepAliveRejectsExpiredClientCertificate TestTrustedZonesPostgres TestOIDCHTTPWireSQLite TestOIDCHTTPWirePostgres TestOIDCManagementHTTPContractAndBoundaries TestOIDCCallbackHTTPRejectsUnboundOrAmbiguousBeforeProvider TestEmailContactsHTTPOriginCSRFCASAndFreshPrimary TestEmailConfirmationHTTPNeverIssuesSession; do
    rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory inventory/trusted-zone acceptance $test"
  done
  for test in TestInitialActivationHTTPStagedAndSessionless TestLifecycleInventoryHTTPReadOnlyAndPendingDenied TestPasswordResetHTTPUniformEmptyAcceptance; do
    rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory lifecycle HTTP acceptance $test"
  done
fi
if [ "${AGP_TEST_NODE_IDENTITY:-0}" = 1 ]; then
  for test in TestNodeIdentityPostgres TestIssuerRealMTLS TestIssuerJournalPostgres TestEnrollmentIssuanceAuthorizationHeadFence TestNodeRevokeStartupRecovery TestEnrollmentIngressRealTLSAndSourceLimits TestEnrollmentAdmissionBoundsBodyWork; do
    rg -q -- "--- PASS: $test( |$)" "$work/acceptance.log" || fail "missing mandatory node identity acceptance $test"
  done
  # Resource limits apply only to the isolated native worker. Race's virtual
  # address shadow mappings require a separate run of the concurrency suite.
  "${GO:-go}" test -race -count=1 -timeout=3m -run '^TestAgentLocalValidationPostgres$' -v ./internal/agentvalidation >"$work/local-syntax-pg.log" 2>&1 || { cat "$work/local-syntax-pg.log"; exit 1; }
  TMPDIR="${AGP_TEST_LOCAL_SYNTAX_TMPDIR:-${TMPDIR:-/tmp}}" "${GO:-go}" test -count=1 -timeout=3m -run '^TestActualSignedNativeSyntax$' -v ./internal/agentvalidation >"$work/local-syntax-native.log" 2>&1 || { cat "$work/local-syntax-native.log"; exit 1; }
  cat "$work/local-syntax-pg.log" "$work/local-syntax-native.log"
  for entry in 'local-syntax-pg:TestAgentLocalValidationPostgres' 'local-syntax-native:TestActualSignedNativeSyntax'; do
    log="${entry%%:*}"; test="${entry#*:}"
    rg -q -- '--- SKIP:|--- FAIL:' "$work/$log.log" && fail 'mandatory local syntax acceptance did not pass'
    rg -q -- "--- PASS: $test( |$)" "$work/$log.log" || fail "missing mandatory local syntax acceptance $test"
  done
fi
"${GO:-go}" test -race -count=1 -timeout=3m ./internal/edgeauth
"${GO:-go}" test -race -count=1 -timeout=3m ./internal/reverseproxy/nginx -run 'TestNativeEdgeAuthIsolation|TestNativeIdentityHeaderSpoofing|TestNativeManagementHostIsolation' -v >"$work/nginx.log" 2>&1 || { cat "$work/nginx.log"; exit 1; }
cat "$work/nginx.log"
if rg -q -- '--- SKIP:' "$work/nginx.log"; then fail 'mandatory Nginx integration must not skip'; fi
for test in TestNativeEdgeAuthIsolation TestNativeIdentityHeaderSpoofing TestNativeManagementHostIsolation; do
  rg -q -- "--- PASS: $test( |$)" "$work/nginx.log" || fail "missing required Nginx test $test"
done

# Compile the same source accepted above; all processes use disposable DBs/PKI.
export AGP_TEST_AGP_BIN="$work/agp"
export AGP_TEST_CTL_BIN="$work/agpctl"
export AGP_TEST_JOURNAL_BIN="$work/agp-security-journal"
export AGP_TEST_EDGE_BIN="$work/agp-edge-auth"
"${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_AGP_BIN" ./cmd/agp
"${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_CTL_BIN" ./cmd/agpctl
"${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_JOURNAL_BIN" ./cmd/agp-security-journal
"${GO:-go}" build -buildvcs=false -trimpath -o "$AGP_TEST_EDGE_BIN" ./cmd/agp-edge-auth
"${AGP_TEST_NODE_BIN:-node}" tests/e2e/s0-full.mjs
echo 'Full S0 native, HTTPS/browser, mTLS, EdgeAuth and restore acceptance passed.'
