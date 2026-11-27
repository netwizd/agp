package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type legacyRoleFixture struct {
	*emailFixture
	manager, target domain.User
	token           string
}

func newLegacyRoleFixture(t *testing.T, pg bool) *legacyRoleFixture {
	t.Helper()
	var manager, target domain.User
	base := newFixtureSetup(t, pg, func(ctx context.Context, store storage.Store, _ string) error {
		m, e := store.CreateUser(ctx, domain.UserInput{Username: "role-only-manager", PasswordHash: "unused-fixture-hash"})
		if e != nil {
			return e
		}
		manager = *m
		u, e := store.CreateUser(ctx, domain.UserInput{Username: "legacy-role-target", PasswordHash: "unused-fixture-hash"})
		if e == nil {
			target = *u
		}
		return e
	})
	f := attachEmailFixture(t, base)
	a, _ := f.newActor(t, manager.ID, "management")
	return &legacyRoleFixture{emailFixture: f, manager: manager, target: target, token: a.TokenHash}
}

func legacyPublishRole(t *testing.T, f *fixture, principal, permission, scope, id string, expiry *time.Time) {
	t.Helper()
	e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if e := securitystate.EnsureBuiltinRolesTx(f.ctx, tx); e != nil {
			return e
		}
		d, e := securitystate.ReadRoleDefinitionTx(f.ctx, tx, "role_"+strings.ReplaceAll(permission, ".", "_"))
		if e != nil {
			return e
		}
		return securitystate.PublishRoleBindingTx(f.ctx, tx, h, securitystate.RoleBinding{ID: securitystate.ID("rbinding"), PrincipalID: principal, RoleID: d.ID, RoleVersion: d.Version, RoleDigest: d.Digest, ScopeType: scope, ScopeID: id, AuthorityEpoch: h.Epoch, Revision: 1, CreatedAt: h.RecordedAt, ExpiresAt: expiry})
	})
	if e != nil {
		t.Fatal("trusted role fixture", e)
	}
}

func (f *legacyRoleFixture) mutation(kind storage.IdentityMutationKind, id string, update domain.UserUpdate) (*storage.IdentityMutationResult, error) {
	return f.s.Store.ApplyIdentityMutation(f.ctx, f.token, storage.IdentityMutation{Kind: kind, ID: id, ManagementOrigin: f.s.Profile.ManagementOrigin, UserUpdate: update})
}
func (f *legacyRoleFixture) write(t *testing.T, q string, args ...any) {
	t.Helper()
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(f.ctx, q, args...); return e }); e != nil {
		t.Fatal(e)
	}
}

func TestProtectedLegacyRolesSQLite(t *testing.T)   { protectedLegacyRoles(t, false) }
func TestProtectedLegacyRolesPostgres(t *testing.T) { protectedLegacyRoles(t, true) }
func protectedLegacyRoles(t *testing.T, pg bool) {
	t.Run("role_only_global_identity_group_and_resource_management", func(t *testing.T) {
		f := newLegacyRoleFixture(t, pg)
		for _, permission := range []string{"users.manage", "groups.manage", "resources.manage", "portal.settings.manage"} {
			legacyPublishRole(t, f.fixture, f.manager.ID, permission, "global", "", nil)
		}
		name := "Updated by role-only manager"
		if result, e := f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{DisplayName: &name}); e != nil || result.User.DisplayName != name {
			t.Fatal("global role did not authorize ordinary target", result, e)
		}
		group, e := f.s.Store.ApplyIdentityMutation(f.ctx, f.token, storage.IdentityMutation{Kind: storage.IdentityCreateGroup, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: "Empty metadata group"}})
		if e != nil || len(group.Group.PermissionIDs) != 0 {
			t.Fatal("global groups role", group, e)
		}
		ctx := securitystate.WithActor(f.ctx, f.token)
		resource, e := f.s.Store.CreateResource(ctx, domain.ResourceInput{Name: "Disabled controlled resource", InternalURL: "https://backend.example.test", PublicHost: "apps.example.test", PublicPath: "/", Enabled: false})
		if e != nil || resource.Enabled {
			t.Fatal("global resources role", resource, e)
		}
		settings, e := f.base.GetPortalSettings(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		settings.BrandName = "Role-managed branding"
		if updated, e := f.s.Store.UpdatePortalSettings(ctx, *settings); e != nil || updated.BrandName != settings.BrandName {
			t.Fatal("global portal role", updated, e)
		}
		actual, e := f.base.FindUserByUsername(f.ctx, f.manager.Username)
		if e != nil || actual.IsAdmin || len(actual.GroupIDs) != 0 {
			t.Fatal("fresh authority manufactured legacy privileges", actual, e)
		}
		promote := true
		if _, e = f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{IsAdmin: &promote}); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal("role manager bypassed approved promotion workflow", e)
		}
		if _, e = f.s.Store.ApplyIdentityMutation(f.ctx, f.token, storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: group.Group.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: group.Group.Name, PermissionIDs: []string{"users.read"}}}); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal("legacy group extension bypassed approval", e)
		}
	})
	t.Run("scoped_never_global_and_passive_privileged_target_ceiling", func(t *testing.T) {
		f := newLegacyRoleFixture(t, pg)
		legacyPublishRole(t, f.fixture, f.manager.ID, "users.manage", "global", "", nil)
		legacyPublishRole(t, f.fixture, f.manager.ID, "resources.manage", "site", "site_one", nil)
		if _, e := f.s.Store.CreateResource(securitystate.WithActor(f.ctx, f.token), domain.ResourceInput{Name: "Not global", InternalURL: "https://backend.example.test", PublicHost: "not-global.example.test"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("scoped resource role authorized global legacy create", e)
		}
		legacyPublishRole(t, f.fixture, f.target.ID, "config.edit", "site", "site_one", nil)
		name := "Denied target metadata"
		for _, state := range []string{"active", "blocked_below_floor"} {
			if state != "active" {
				f.write(t, `UPDATE users SET blocked_at=? WHERE id=?`, f.now, f.target.ID)
				f.write(t, `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES(?,?,9)`, f.target.ID, "principal_"+f.target.ID)
			}
			if _, e := f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{DisplayName: &name}); !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatal("role-bound privileged target classified as ordinary", state, e)
			}
		}
		legacyPublishRole(t, f.fixture, f.manager.ID, "users.privileged.manage", "global", "", nil)
		if _, e := f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{DisplayName: &name}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("privileged management bypassed full target scope ceiling", e)
		}
		legacyPublishRole(t, f.fixture, f.manager.ID, "config.edit", "site", "site_one", nil)
		if _, e := f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{DisplayName: &name}); e != nil {
			t.Fatal("exact scoped ceiling cannot manage passive blocked target", e)
		}
		var floor uint64
		if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
			var e error
			floor, e = securitystate.Floor(f.ctx, tx, f.target.ID, "principal_"+f.target.ID)
			return e
		}); e != nil || floor != 9 {
			t.Fatal("passive metadata mutation lowered restrictive floor", floor, e)
		}
	})
	t.Run("approved_scope_hierarchy_and_missing_callback_fail_closed", func(t *testing.T) {
		f, _, _ := newRoleScopeFixture(t, pg)
		f.sql(t, `UPDATE users SET is_admin=FALSE WHERE id=?`, f.executorUser.ID)
		for _, permission := range []string{"users.manage", "users.privileged.manage"} {
			legacyPublishRole(t, f.fixture, f.executorUser.ID, permission, "global", "", nil)
		}
		legacyPublishRole(t, f.fixture, f.executorUser.ID, "config.edit", "site", "site_msk", nil)
		legacyPublishRole(t, f.fixture, f.target.ID, "config.edit", "node", "node_msk01", nil)
		name := "Scoped hierarchy accepted"
		mutation := storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: f.target.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, UserUpdate: domain.UserUpdate{DisplayName: &name}}
		if _, e := f.s.Store.ApplyIdentityMutation(f.ctx, f.executor.TokenHash, mutation); e != nil {
			t.Fatal("authoritative parent scope not consumed", e)
		}
		f.s.Coordinator.RegisterIdentityTargetGuard(nil)
		if _, e := f.s.Store.ApplyIdentityMutation(f.ctx, f.executor.TokenHash, mutation); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("missing authority callback allowed hierarchical target", e)
		}
		legacyPublishRole(t, f.fixture, f.executorUser.ID, "config.edit", "node", "node_msk01", nil)
		if _, e := f.s.Store.ApplyIdentityMutation(f.ctx, f.executor.TokenHash, mutation); e != nil {
			t.Fatal("safe exact typed fallback failed", e)
		}
	})
	t.Run("scoped_actor_cannot_delegate_global_legacy_group_permissions", func(t *testing.T) {
		f := newLegacyRoleFixture(t, pg)
		for _, permission := range []string{"users.manage", "users.privileged.manage", "groups.manage"} {
			legacyPublishRole(t, f.fixture, f.manager.ID, permission, "global", "", nil)
		}
		legacyPublishRole(t, f.fixture, f.manager.ID, "config.edit", "site", "site_one", nil)
		group, e := f.base.CreateGroup(f.ctx, domain.GroupInput{Name: "Global configuration readers", PermissionIDs: []string{"config.read"}})
		if e != nil {
			t.Fatal(e)
		}
		f.write(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, f.target.ID, group.ID)
		name := "Must not flatten"
		if _, e = f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{DisplayName: &name}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("scoped permission satisfied global target ceiling", e)
		}
		if _, e = f.s.Store.ApplyIdentityMutation(f.ctx, f.token, storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: group.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: group.Name, Description: "Metadata still requires global delegation", PermissionIDs: group.PermissionIDs}}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("scoped permission satisfied global group delegation", e)
		}
	})
}

type legacyElapsedRepository struct {
	securitystate.Repository
	authority           *roleElapsedAuthority
	boundary            string
	projectionPrincipal string
}

func (r legacyElapsedRepository) WriteIdentity(ctx context.Context, fn func(storage.IdentityTx) error) error {
	return r.Repository.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		boundaryPassed := false
		return fn(legacyElapsedTx{IdentityTx: tx, authority: r.authority, boundary: r.boundary, projectionPrincipal: r.projectionPrincipal, boundaryPassed: &boundaryPassed})
	})
}

type legacyElapsedTx struct {
	storage.IdentityTx
	authority           *roleElapsedAuthority
	boundary            string
	projectionPrincipal string
	boundaryPassed      *bool
}

func (t legacyElapsedTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	n, e := t.IdentityTx.Exec(ctx, q, args...)
	if e == nil && strings.HasPrefix(q, t.boundary) {
		*t.boundaryPassed = true
		if t.projectionPrincipal == "" {
			t.authority.armed.Store(true)
		}
	}
	return n, e
}

func (t legacyElapsedTx) Query(ctx context.Context, q string, args ...any) (storage.IdentityRows, error) {
	rows, e := t.IdentityTx.Query(ctx, q, args...)
	if e == nil && *t.boundaryPassed && t.projectionPrincipal != "" && strings.HasPrefix(q, "SELECT b.binding_id,") && strings.Contains(q, " WHERE b.principal_id=?") && len(args) > 0 && args[0] == t.projectionPrincipal {
		return &legacyElapsedRows{IdentityRows: rows, authority: t.authority}, nil
	}
	return rows, e
}

type legacyElapsedRows struct {
	storage.IdentityRows
	authority *roleElapsedAuthority
}

func (r *legacyElapsedRows) Close() {
	r.IdentityRows.Close()
	r.authority.armed.Store(true)
}

func TestProtectedLegacyRoleExpirySQLite(t *testing.T)   { protectedLegacyRoleExpiry(t, false, false) }
func TestProtectedLegacyRoleExpiryPostgres(t *testing.T) { protectedLegacyRoleExpiry(t, true, false) }
func TestProtectedLegacyRoleFinalProjectionExpirySQLite(t *testing.T) {
	protectedLegacyRoleExpiry(t, false, true)
}
func TestProtectedLegacyRoleFinalProjectionExpiryPostgres(t *testing.T) {
	protectedLegacyRoleExpiry(t, true, true)
}
func protectedLegacyRoleExpiry(t *testing.T, pg, finalProjection bool) {
	for _, mode := range []string{"actor_global", "actor_unrelated_scoped", "target_scoped", "portal_global", "resource_global"} {
		t.Run(mode, func(t *testing.T) {
			f := newLegacyRoleFixture(t, pg)
			expires := f.now.Add(2 * time.Second)
			permission, person, scope, id := "users.manage", f.manager.ID, "global", ""
			boundary := "RELEASE SAVEPOINT authorize_command"
			switch mode {
			case "actor_unrelated_scoped", "target_scoped":
				legacyPublishRole(t, f.fixture, f.manager.ID, "users.manage", "global", "", nil)
				permission, scope, id = "config.read", "site", "site_temporal"
				if mode == "target_scoped" {
					person = f.target.ID
					legacyPublishRole(t, f.fixture, f.manager.ID, "config.read", "global", "", nil)
				}
			case "portal_global":
				permission, boundary = "portal.settings.manage", "INSERT INTO portal_settings"
			case "resource_global":
				permission, boundary = "resources.manage", "RELEASE SAVEPOINT authorize_resource"
			}
			legacyPublishRole(t, f.fixture, person, permission, scope, id, &expires)
			settings, e := f.base.GetPortalSettings(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			authority := &roleElapsedAuthority{Authority: f.s.Coordinator.Authority, advance: func() { f.clock(f.now.Add(6 * time.Second)) }}
			f.s.Coordinator.Authority = authority
			baseStore := f.s.Coordinator.Store
			projectionPrincipal := ""
			if finalProjection {
				projectionPrincipal = person
			}
			f.s.Coordinator.Store = legacyElapsedRepository{Repository: baseStore, authority: authority, boundary: boundary, projectionPrincipal: projectionPrincipal}
			ctx := securitystate.WithActor(f.ctx, f.token)
			var result any
			switch mode {
			case "portal_global":
				changed := *settings
				changed.BrandName = "Expired authority must roll back"
				updated, err := f.s.Store.UpdatePortalSettings(ctx, changed)
				e = err
				if updated != nil {
					result = updated
				}
			case "resource_global":
				created, err := f.s.Store.CreateResource(ctx, domain.ResourceInput{Name: "Expired create", InternalURL: "https://backend.example.test", PublicHost: "expiry.example.test", PublicPath: "/", Enabled: false})
				e = err
				if created != nil {
					result = created
				}
			default:
				name := "Expired authority must roll back"
				updated, err := f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{DisplayName: &name})
				e = err
				if updated != nil {
					result = updated
				}
			}
			if e == nil || result != nil || authority.armed.Load() {
				t.Fatal("late independent time did not reject expired grant", result, e, authority.armed.Load())
			}
			f.s.Coordinator.Store = baseStore
			if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				var operations int
				if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM security_operations`, nil, func(rows storage.IdentityRows) error { return rows.Scan(&operations) }); e != nil {
					return e
				}
				if operations != 0 {
					t.Fatal("expired authorization entered durable barrier", operations)
				}
				var audits int
				if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM audit_events WHERE event_type IN ('identity.admin.mutation','identity.resource.mutation','portal.settings.updated')`, nil, func(rows storage.IdentityRows) error { return rows.Scan(&audits) }); e != nil {
					return e
				}
				if audits != 0 {
					t.Fatal("expired authorization committed mutation audit", audits)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			user, e := f.base.FindUserByUsername(f.ctx, f.target.Username)
			if e != nil || user.DisplayName != f.target.DisplayName {
				t.Fatal("expired preflight committed target metadata", user, e)
			}
			actual, e := f.base.GetPortalSettings(f.ctx)
			if e != nil || actual.BrandName != settings.BrandName {
				t.Fatal("expired authority committed portal branding", actual, e)
			}
			if providerJournalEvents(f.fixture) != 0 {
				t.Fatal("expired fresh authority appended restrictive command")
			}
			if e = f.s.Coordinator.Ready(f.ctx); e != nil {
				t.Fatal("expired fresh command left global barrier", e)
			}
		})
	}
}

func TestProtectedLegacyRoleReplaySQLite(t *testing.T)   { protectedLegacyRoleReplay(t, false) }
func TestProtectedLegacyRoleReplayPostgres(t *testing.T) { protectedLegacyRoleReplay(t, true) }
func protectedLegacyRoleReplay(t *testing.T, pg bool) {
	f := newLegacyRoleFixture(t, pg)
	expires := f.now.Add(2 * time.Second)
	for _, permission := range []string{"groups.manage", "users.privileged.manage"} {
		legacyPublishRole(t, f.fixture, f.manager.ID, permission, "global", "", &expires)
	}
	group, e := f.base.CreateGroup(f.ctx, domain.GroupInput{Name: "Own permissionless membership"})
	if e != nil {
		t.Fatal(e)
	}
	f.write(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, f.manager.ID, group.ID)
	if pg {
		f.write(t, `CREATE FUNCTION test_legacy_audit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='identity.admin.mutation' THEN RAISE EXCEPTION 'injected materialization interruption'; END IF; RETURN NEW; END $$`)
		f.write(t, `CREATE TRIGGER test_legacy_audit_reject BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION test_legacy_audit_reject()`)
	} else {
		f.write(t, `CREATE TRIGGER test_legacy_audit_reject BEFORE INSERT ON audit_events WHEN NEW.event_type='identity.admin.mutation' BEGIN SELECT RAISE(ABORT,'injected materialization interruption'); END`)
	}
	_, e = f.s.Store.ApplyIdentityMutation(f.ctx, f.token, storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: group.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: group.Name, Description: "Exact durable metadata after own revocation"}})
	if e == nil || providerJournalEvents(f.fixture) == 0 {
		t.Fatal("fixture did not interrupt after independent receipt", e)
	}
	if e = f.s.Coordinator.Ready(f.ctx); !errors.Is(e, securitystate.ErrBarrier) && !errors.Is(e, securitystate.ErrUnavailable) {
		t.Fatal("missing restrictive recovery barrier", e)
	}
	if pg {
		f.write(t, `DROP TRIGGER test_legacy_audit_reject ON audit_events`)
	} else {
		f.write(t, `DROP TRIGGER test_legacy_audit_reject`)
	}
	f.write(t, `UPDATE sessions SET revoked_at=? WHERE token_hash=?`, f.now, f.token)
	f.clock(f.now.Add(10 * time.Minute))
	if e = f.s.Coordinator.Recover(f.ctx); e != nil {
		t.Fatal("restrictive replay reauthorized lost session or expired grants", e)
	}
	if e = f.s.Coordinator.Recover(f.ctx); e != nil {
		t.Fatal("exact receipt replay not idempotent", e)
	}
	groups, e := f.base.ListGroups(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	var actual *domain.Group
	for i := range groups {
		if groups[i].ID == group.ID {
			actual = &groups[i]
		}
	}
	if actual == nil || actual.Description != "Exact durable metadata after own revocation" || len(actual.PermissionIDs) != 0 {
		t.Fatal("durable replay lost exact metadata or added grants", actual)
	}
	if _, e = f.mutation(storage.IdentityUpdateUser, f.target.ID, domain.UserUpdate{}); !errors.Is(e, storage.ErrPermissionDenied) {
		t.Fatal("replay authorization leaked into fresh requests", e)
	}
	if e = f.s.Coordinator.Ready(f.ctx); e != nil {
		t.Fatal("recovered command left global barrier", e)
	}
}
