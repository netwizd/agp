package identity

import (
	"context"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func TestRoleIdentityWireSQLite(t *testing.T)   { testRoleIdentityWire(t, false) }
func TestRoleIdentityWirePostgres(t *testing.T) { testRoleIdentityWire(t, true) }

// TLS LDAP and HTTPS OIDC peers are real local protocol fixtures. Fixture
// permissions are installed through the final positive-publication helper;
// independent grant approval itself is qualified by the role workflow matrix.
func testRoleIdentityWire(t *testing.T, pg bool) {
	t.Run("AD_scoped_management_and_historical_incarnation", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		publishIdentityRole(t, f.fixture, link.PrincipalID, "role_config_read", "node", "node_scoped", nil)
		a := f.primaryDirectory(t, f.startDirectory(t, "management"))
		f.enroll(t, a)
		done, e := f.s.Complete(f.ctx, a, "192.0.2.91", "actual TLS scoped AD")
		if e != nil {
			t.Fatal(e)
		}
		hash := auth.TokenHash(done.SessionToken)
		session, e := f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin)
		if e != nil || session.User.IsAdmin || len(session.Permissions) != 0 {
			t.Fatalf("AD scoped management projection %+v %v", session, e)
		}
		publishIdentityRole(t, f.fixture, link.PrincipalID, "role_users_privileged_manage", "global", "", nil)
		approval := publishIdentityRole(t, f.fixture, link.PrincipalID, "role_config_approve", "global", "", nil)
		fingerprint := func() string {
			t.Helper()
			var fp string
			fresh, e := f.directory.withDirectoryPeople(f.ctx, []string{link.PrincipalID})
			if e != nil {
				t.Fatal(e)
			}
			e = f.s.Coordinator.Current(fresh, func(tx storage.IdentityTx, h securityjournal.Head) error {
				var e error
				fp, e = directorySubject(fresh, tx, link.PrincipalID, h, true)
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			return fp
		}
		before := fingerprint()
		revokeIdentityRole(t, f.fixture, approval.ID)
		publishIdentityRole(t, f.fixture, link.PrincipalID, "role_config_approve", "global", "", nil)
		if before == fingerprint() {
			t.Fatal("AD historical fingerprint omitted role incarnation")
		}
		f.wire.disabled.Store(true)
		if _, e = f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin); e == nil {
			t.Fatal("new role bypassed current AD account check")
		}
	})
	t.Run("OIDC_scoped_management_keeps_AGP_TOTP_and_global_isolation", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		publishIdentityRole(t, f.fixture, f.directoryIdentity.PrincipalID, "role_config_edit", "site", "site_oidc", nil)
		a := f.primaryOIDC(t, f.startDirectory(t, "management"))
		if _, e := f.s.Complete(f.ctx, a, "192.0.2.92", "OIDC without AGP factor"); e == nil {
			t.Fatal("role bypassed mandatory AGP TOTP")
		}
		f.enroll(t, a)
		done, e := f.s.Complete(f.ctx, a, "192.0.2.92", "actual HTTPS OIDC plus LDAP")
		if e != nil {
			t.Fatal(e)
		}
		hash := auth.TokenHash(done.SessionToken)
		session, e := f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin)
		if e != nil || session.User.ID != f.directoryIdentity.PrincipalID || session.User.IsAdmin || len(session.Permissions) != 0 {
			t.Fatalf("OIDC scoped management leaked authority %+v %v", session, e)
		}
		f.wire.disabled.Store(true)
		if _, e = f.s.Session(context.Background(), hash, "management", f.s.Profile.ManagementOrigin); e == nil {
			t.Fatal("OIDC role bypassed current directory check")
		}
	})
}

func TestRoleStepUpDirectoryFinalSQLite(t *testing.T)   { testRoleStepUpDirectoryFinal(t, false) }
func TestRoleStepUpDirectoryFinalPostgres(t *testing.T) { testRoleStepUpDirectoryFinal(t, true) }
func testRoleStepUpDirectoryFinal(t *testing.T, pg bool) {
	f := newDirectoryAuthFixture(t, pg, false)
	link := f.provision(t)
	publishIdentityRole(t, f.fixture, link.PrincipalID, "role_config_read", "node", "node_step_up", nil)
	a := f.primaryDirectory(t, f.startDirectory(t, "management"))
	seed, _ := f.enroll(t, a)
	initial, e := f.s.Complete(f.ctx, a, "192.0.2.93", "AD scoped initial")
	if e != nil {
		t.Fatal(e)
	}
	f.clock(f.now.Add(30 * time.Second))
	step := f.primaryDirectory(t, f.startDirectoryFlow(t, "step_up", "management", auth.TokenHash(initial.SessionToken)))
	if _, e = f.s.TOTPProof(f.ctx, step, TOTP(seed, f.now.Unix()/30)); e != nil {
		t.Fatal(e)
	}
	fresh, e := f.s.Complete(f.ctx, step, "192.0.2.93", "fresh final AD proof")
	if e != nil || fresh.SessionToken == "" {
		t.Fatalf("fresh AD step-up lost private proof: %+v %v", fresh, e)
	}
	f.clock(f.now.Add(30 * time.Second))
	stale := f.primaryDirectory(t, f.startDirectoryFlow(t, "step_up", "management", auth.TokenHash(fresh.SessionToken)))
	if _, e = f.s.TOTPProof(f.ctx, stale, TOTP(seed, f.now.Unix()/30)); e != nil {
		t.Fatal(e)
	}
	after := f.now.Add(11 * time.Second)
	hook := &roleCompletionClockAuthority{memoryJournal: f.j, session: fresh.Session.ID, after: func() { f.clock(after) }}
	f.s.Coordinator.Authority = hook
	denied, e := f.s.Complete(f.ctx, stale, "192.0.2.93", "expired private AD proof after receipt")
	if !hook.fired || e == nil || denied.SessionToken != "" {
		t.Fatalf("expired AD proof published credential: %+v %v fired=%v", denied, e, hook.fired)
	}
	if e = f.s.Coordinator.Ready(f.ctx); e != nil {
		t.Fatalf("stale AD proof retained barrier: %v", e)
	}
}
