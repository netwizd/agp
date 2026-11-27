package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func publishIdentityRole(t *testing.T, f *fixture, principal, role, scope, id string, expiry *time.Time) securitystate.RoleBinding {
	t.Helper()
	var b securitystate.RoleBinding
	e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if e := securitystate.EnsureBuiltinRolesTx(f.ctx, tx); e != nil {
			return e
		}
		definition, e := securitystate.ReadRoleDefinitionTx(f.ctx, tx, role)
		if e != nil {
			return e
		}
		b = securitystate.RoleBinding{ID: securitystate.ID("rbinding"), PrincipalID: principal, RoleID: definition.ID, RoleVersion: definition.Version, RoleDigest: definition.Digest, ScopeType: scope, ScopeID: id, Revision: 1, AuthorityEpoch: h.Epoch, CreatedAt: h.RecordedAt.UTC().Truncate(time.Microsecond), ExpiresAt: expiry}
		return securitystate.PublishRoleBindingTx(f.ctx, tx, h, b)
	})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func revokeIdentityRole(t *testing.T, f *fixture, id string) {
	t.Helper()
	e := f.s.Coordinator.Execute(f.ctx, securitystate.Intent{Kind: "logout", Data: []byte(`{}`)}, func(storage.IdentityTx, securityjournal.Head) ([]securityjournal.AppendRequest, error) {
		return []securityjournal.AppendRequest{{Kind: "revoke_role_binding", TargetType: "grant", TargetID: id, ActorID: "fixture", Payload: securityjournal.Payload{GrantID: id}}}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func newIdentityRoleFixture(t *testing.T, pg bool) (*fixture, domain.User) {
	t.Helper()
	var user domain.User
	f := newFixtureSetup(t, pg, func(ctx context.Context, s storage.Store, _ string) error {
		admin, e := s.FindUserByUsername(ctx, "admin")
		if e != nil {
			return e
		}
		u, e := s.CreateUser(ctx, domain.UserInput{Username: "scoped-operator", PasswordHash: admin.PasswordHash})
		if e != nil {
			return e
		}
		user = *u
		return nil
	})
	return f, user
}
func primaryRoleUser(t *testing.T, f *fixture, a FlowAuth) FlowAuth {
	t.Helper()
	tr, e := f.s.Primary(f.ctx, a, "scoped-operator", "test-initial-password", "192.0.2.90")
	if e != nil {
		t.Fatal(e)
	}
	a.ID = tr.View.ID
	a.Binding = tr.Binding
	return a
}
func roleFingerprint(t *testing.T, f *fixture, id string) string {
	t.Helper()
	var fp string
	e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		p, e := lifecycleRawUser(f.ctx, tx, h, id)
		if e == nil {
			fp = p.Fingerprint
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return fp
}

func TestRoleIdentityReadersSQLite(t *testing.T)   { testRoleIdentityReaders(t, false) }
func TestRoleIdentityReadersPostgres(t *testing.T) { testRoleIdentityReaders(t, true) }
func testRoleIdentityReaders(t *testing.T, pg bool) {
	t.Run("scoped_management_session_global_alias_and_expiry", func(t *testing.T) {
		f, user := newIdentityRoleFixture(t, pg)
		expiry := f.now.Add(2 * time.Minute)
		publishIdentityRole(t, f, user.ID, "role_config_edit", "site", "site_scoped", &expiry)
		a := primaryRoleUser(t, f, f.start(t, "login", ""))
		f.enroll(t, a)
		done, e := f.s.Complete(f.ctx, a, "192.0.2.90", "typed role reader")
		if e != nil {
			t.Fatal(e)
		}
		hash := auth.TokenHash(done.SessionToken)
		session, e := f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin)
		if e != nil || session.User.IsAdmin || len(session.Permissions) != 0 {
			t.Fatalf("scoped role flattened or login denied: %+v %v", session, e)
		}
		actor := LifecycleActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin}
		access, e := f.s.LifecycleAccess(f.ctx, actor)
		if e != nil || access.UsersRead || access.UsersManage || access.PrivilegedManage || access.Approve {
			t.Fatalf("scoped role leaked identity authority: %+v %v", access, e)
		}
		global := publishIdentityRole(t, f, user.ID, "role_users_privileged_manage", "global", "", &expiry)
		session, e = f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin)
		if e != nil || !authz.HasPermission(session.Permissions, authz.PermUsersSuperAdminManage) || authz.HasPermission(session.Permissions, authz.PermConfigEdit) {
			t.Fatalf("global alias or scoped isolation failed: %+v %v", session, e)
		}
		revokeIdentityRole(t, f, global.ID)
		session, e = f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin)
		if e != nil || len(session.Permissions) != 0 {
			t.Fatalf("revoked global role persisted: %+v %v", session, e)
		}
		f.clock(expiry)
		if _, e = f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("expired-only MG session admitted: %v", e)
		}
		_, e = f.s.Primary(f.ctx, f.start(t, "login", ""), user.Username, "test-initial-password", "192.0.2.90")
		if !errors.Is(e, ErrProof) {
			t.Fatalf("expired-only role admitted primary: %v", e)
		}
	})
	t.Run("historical_incarnation_fingerprint_and_passive_invited", func(t *testing.T) {
		f, user := newIdentityRoleFixture(t, pg)
		before := roleFingerprint(t, f, user.ID)
		b := publishIdentityRole(t, f, user.ID, "role_audit_read", "resource", "resource_one", nil)
		first := roleFingerprint(t, f, user.ID)
		if before == first {
			t.Fatal("role incarnation absent from historical fingerprint")
		}
		revokeIdentityRole(t, f, b.ID)
		publishIdentityRole(t, f, user.ID, "role_audit_read", "resource", "resource_one", nil)
		if first == roleFingerprint(t, f, user.ID) {
			t.Fatal("same-permission replacement reused historical authority")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET lifecycle_state='invited' WHERE id=?`, user.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			raw, e := lifecycleRawUser(f.ctx, tx, h, user.ID)
			if e != nil {
				return e
			}
			if len(raw.Grants) != 1 || len(raw.Permissions) != 0 || raw.Grants[0].RoleDigest == "" {
				t.Fatalf("passive metadata hid pending scoped role: %+v", raw)
			}
			if _, e = securitystate.ReadEffectiveGrants(f.ctx, tx, h, user.ID); !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatalf("invited metadata became authority: %v", e)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("legacy_admin_requires_explicit_global_approval", func(t *testing.T) {
		f := newFixture(t, pg)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `DELETE FROM user_groups WHERE user_id=?`, f.user.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		check := func(want bool) {
			t.Helper()
			e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				_, e := directorySubject(f.ctx, tx, f.user.ID, h, true)
				if want && e != nil {
					return e
				}
				if !want && !errors.Is(e, storage.ErrPermissionDenied) {
					t.Fatalf("admin inferred global approval: %v", e)
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		check(false)
		publishIdentityRole(t, f, f.user.ID, "role_config_approve", "site", "site_one", nil)
		check(false)
		publishIdentityRole(t, f, f.user.ID, "role_config_approve", "global", "", nil)
		check(true)
	})
	t.Run("normal_complete_rechecks_role_expiry", func(t *testing.T) {
		f, user := newIdentityRoleFixture(t, pg)
		expiry := f.now.Add(time.Minute)
		publishIdentityRole(t, f, user.ID, "role_config_read", "site", "site_one", &expiry)
		a := primaryRoleUser(t, f, f.start(t, "login", ""))
		f.enroll(t, a)
		f.clock(expiry)
		completed, e := f.s.Complete(f.ctx, a, "192.0.2.90", "expired role")
		if !errors.Is(e, ErrProof) || completed.SessionToken != "" {
			t.Fatalf("expired role created MG session: %+v %v", completed, e)
		}
		if e = f.s.Coordinator.Ready(f.ctx); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("invitation_rejects_pending_permission_bearing_role", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET lifecycle_state='active' WHERE id=?`, f.pending.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		publishIdentityRole(t, f.fixture, f.pending.ID, "role_config_read", "node", "node_pending", nil)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET lifecycle_state='invited' WHERE id=?`, f.pending.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		_, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "pregranted_invite_denied", f.pending.Revision, InviteRequest{Email: "recipient@corp.example", TTLSeconds: 300})
		if !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatalf("pending scoped positive grant ignored: %v", e)
		}
	})
}

type roleCompletionClockAuthority struct {
	*memoryJournal
	session string
	after   func()
	fired   bool
}

func (a *roleCompletionClockAuthority) Append(ctx context.Context, r securityjournal.AppendRequest) (securityjournal.Event, error) {
	event, e := a.memoryJournal.Append(ctx, r)
	if e == nil && !a.fired && r.Kind == "revoke_session" && r.Payload.SessionID == a.session {
		a.fired = true
		a.after()
	}
	return event, e
}
func TestRoleStepUpFinalSQLite(t *testing.T)       { testRoleStepUpFinal(t, false) }
func TestRoleStepUpFinalPostgres(t *testing.T)     { testRoleStepUpFinal(t, true) }
func testRoleStepUpFinal(t *testing.T, pg bool)    { testRoleStepUpFinalClock(t, pg, false) }
func TestRoleStepUpReadClockSQLite(t *testing.T)   { testRoleStepUpFinalClock(t, false, true) }
func TestRoleStepUpReadClockPostgres(t *testing.T) { testRoleStepUpFinalClock(t, true, true) }
func testRoleStepUpFinalClock(t *testing.T, pg, afterRead bool) {
	f, user := newIdentityRoleFixture(t, pg)
	expiry := f.now.Add(2 * time.Minute)
	publishIdentityRole(t, f, user.ID, "role_config_read", "site", "site_one", &expiry)
	a := primaryRoleUser(t, f, f.start(t, "login", ""))
	seed, _ := f.enroll(t, a)
	done, e := f.s.Complete(f.ctx, a, "192.0.2.90", "initial role session")
	if e != nil {
		t.Fatal(e)
	}
	f.clock(f.now.Add(30 * time.Second))
	step := primaryRoleUser(t, f, f.start(t, "step_up", auth.TokenHash(done.SessionToken)))
	if _, e = f.s.TOTPProof(f.ctx, step, TOTP(seed, f.now.Unix()/30)); e != nil {
		t.Fatal(e)
	}
	advance := func() { f.clock(expiry) }
	var watched *roleAdmissionClockRepository
	if afterRead {
		watched = &roleAdmissionClockRepository{base: f.base, after: advance}
		f.s.Coordinator.Store = watched
		advance = func() { watched.armed = true }
	}
	hook := &roleCompletionClockAuthority{memoryJournal: f.j, session: done.Session.ID, after: advance}
	f.s.Coordinator.Authority = hook
	completed, e := f.s.Complete(f.ctx, step, "192.0.2.90", "role expires after revoke receipt")
	if afterRead && !watched.fired {
		t.Fatal("grant reader clock fault was not reached")
	}
	if !hook.fired || e == nil || completed.SessionToken != "" {
		t.Fatalf("expired final role published session: %+v %v fired=%v", completed, e, hook.fired)
	}
	if e = f.s.Coordinator.Ready(f.ctx); e != nil {
		t.Fatalf("role expiry retained barrier: %v", e)
	}
	e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		var count int
		e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL`, []any{user.ID}, func(r storage.IdentityRows) error { return r.Scan(&count) })
		if e == nil && count != 0 {
			t.Fatal("step-up published a credential after expiry")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}

// Delay the independent clock after the final grant query, while retaining the
// same locked database snapshot. This proves the deadline witness is checked
// against a later independent head rather than the earlier reader timestamp.
type roleAdmissionClockRepository struct {
	base         securitystate.Repository
	after        func()
	armed, fired bool
}

func (r *roleAdmissionClockRepository) WriteIdentity(ctx context.Context, fn func(storage.IdentityTx) error) error {
	return r.base.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return fn(roleAdmissionClockTx{IdentityTx: tx, parent: r}) })
}

type roleAdmissionClockTx struct {
	storage.IdentityTx
	parent *roleAdmissionClockRepository
}

func (t roleAdmissionClockTx) Query(ctx context.Context, q string, args ...any) (storage.IdentityRows, error) {
	rows, e := t.IdentityTx.Query(ctx, q, args...)
	if e == nil && t.parent.armed && !t.parent.fired && strings.Contains(q, "FROM role_bindings b JOIN role_definitions") {
		t.parent.fired = true
		t.parent.after()
	}
	return rows, e
}
