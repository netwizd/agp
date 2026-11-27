package rolescope

import "testing"

func TestRoleScopeDisposableDatabaseBoundary(t *testing.T) {
	t.Setenv("AGP_TEST_ROLE_SCOPE_DISPOSABLE", "1")
	t.Setenv("AGP_TEST_S0_DISPOSABLE", "1")
	for _, tc := range []struct {
		dsn   string
		allow bool
	}{
		{"host=/tmp/agp-role-root-pg.synthetic/socket dbname=scopes", true},
		{"host=/tmp/agp-s0-full.synthetic/cp/socket dbname=agp_role_scope", true},
		{"host=/tmp/agp-s0-full.synthetic/cp/socket dbname=agp_cp", false},
		{"host=/tmp/agp-s0-full.synthetic/cp/socket dbname=agp_identity", false},
		{"host=/tmp/agp-s0-full.synthetic/journal/socket dbname=agp_role_scope", false},
		{"host=/tmp/agp-s0-full.synthetic/../production/cp/socket dbname=agp_role_scope", false},
		{"host=127.0.0.1 dbname=production password='host=/tmp/agp-role-root-pg.fake/socket'", false},
		{"host=/tmp/agp-s0-full.synthetic/cp/socket,127.0.0.1 dbname=agp_role_scope", false},
	} {
		if got := roleScopeDisposableDSN(tc.dsn); got != tc.allow {
			t.Fatalf("disposable cluster/database guard: got %v, want %v for %q", got, tc.allow, tc.dsn)
		}
	}
	t.Setenv("AGP_TEST_S0_DISPOSABLE", "0")
	if roleScopeDisposableDSN("host=/tmp/agp-s0-full.synthetic/cp/socket dbname=agp_role_scope") {
		t.Fatal("shared acceptance cluster requires its explicit disposable marker")
	}
	t.Setenv("AGP_TEST_ROLE_SCOPE_DISPOSABLE", "0")
	if roleScopeDisposableDSN("host=/tmp/agp-role-root-pg.synthetic/socket dbname=scopes") {
		t.Fatal("standalone cluster requires its explicit disposable marker")
	}
}
