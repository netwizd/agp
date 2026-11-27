package securitystate_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type roleFixture struct {
	ctx         context.Context
	store       storage.Store
	coordinator *securitystate.Coordinator
	authority   *portalAuthority
	user        string
	now         time.Time
}

func newRoleFixture(t *testing.T, pg bool) *roleFixture {
	t.Helper()
	ctx := context.Background()
	s := portalTestStore(t, pg)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g, e := s.CreateGroup(ctx, domain.GroupInput{Name: "Legacy audit", PermissionIDs: []string{"audit.read"}})
	if e != nil {
		t.Fatal(e)
	}
	u, e := s.CreateUser(ctx, domain.UserInput{Username: "role-target", PasswordHash: "unused-test-phc", GroupIDs: []string{g.ID}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,revoked,created_at) VALUES(?,?,?,'site',?,1,FALSE,?)`, "cgrant_role_fixture", u.ID, "config.edit", "site_bootstrap", now)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	a := &portalAuthority{head: securityjournal.Head{AuthorityID: "role_fixture", Epoch: 1, Digest: securitystate.Digest("role_genesis"), RecordedAt: now}}
	c := securitystate.New(s, a)
	if e = c.Activate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = c.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		return securitystate.EnsureBuiltinRolesTx(ctx, tx)
	}); e != nil {
		t.Fatal(e)
	}
	return &roleFixture{ctx: ctx, store: s, coordinator: c, authority: a, user: u.ID, now: now}
}
func (f *roleFixture) write(t *testing.T, fn func(storage.IdentityTx) error) {
	t.Helper()
	if e := f.store.WriteIdentity(f.ctx, fn); e != nil {
		t.Fatal(e)
	}
}
func (f *roleFixture) binding(t *testing.T, permission, scope, id string) securitystate.RoleBinding {
	t.Helper()
	var d securitystate.RoleDefinition
	if e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		var e error
		d, e = securitystate.ReadRoleDefinitionTx(f.ctx, tx, "role_"+rolePermissionID(permission))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	expiry := f.now.Add(time.Hour)
	return securitystate.RoleBinding{ID: securitystate.ID("rbinding"), PrincipalID: f.user, RoleID: d.ID, RoleVersion: d.Version, RoleDigest: d.Digest, ScopeType: scope, ScopeID: id, Revision: 1, AuthorityEpoch: 1, CreatedAt: f.now, ExpiresAt: &expiry}
}
func rolePermissionID(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] == '.' {
			out[i] = '_'
		}
	}
	return string(out)
}
func (f *roleFixture) publish(t *testing.T, b securitystate.RoleBinding) {
	t.Helper()
	if e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		return securitystate.PublishRoleBindingTx(f.ctx, tx, h, b)
	}); e != nil {
		t.Fatal(e)
	}
}
func (f *roleFixture) effective(t *testing.T) securitystate.EffectiveGrants {
	t.Helper()
	var out securitystate.EffectiveGrants
	if e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var e error
		out, e = securitystate.ReadEffectiveGrants(f.ctx, tx, h, f.user)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *roleFixture) revoke(t *testing.T, binding string) {
	t.Helper()
	event := securityjournal.Event{ID: "ev_role_" + binding, Epoch: 1, RecordedAt: f.now.Add(time.Second), Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", TargetType: "grant", TargetID: binding, Payload: securityjournal.Payload{GrantID: binding}}}
	f.write(t, func(tx storage.IdentityTx) error { return securitystate.MaterializeEvent(f.ctx, tx, event) })
}
func roleContains(entries []securitystate.EffectiveGrant, id string) bool {
	for _, g := range entries {
		if g.ID == id {
			return true
		}
	}
	return false
}

func TestRoleGrantProjectionSQLite(t *testing.T)   { testRoleGrantProjection(t, false) }
func TestRoleGrantProjectionPostgres(t *testing.T) { testRoleGrantProjection(t, true) }
func testRoleGrantProjection(t *testing.T, pg bool) {
	t.Run("all_five_scopes_do_not_flatten", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		for _, s := range []struct{ kind, id string }{{"global", ""}, {"site", "site_one"}, {"node_group", "ngroup_one"}, {"node", "node_one"}, {"resource", "resource_one"}} {
			permission := "config.edit"
			if s.kind == "global" {
				permission = "config.read"
			}
			f.publish(t, f.binding(t, permission, s.kind, s.id))
		}
		g := f.effective(t)
		if !reflect.DeepEqual(g.Global, []string{"audit.read", "config.read"}) {
			t.Fatalf("flat projection=%v", g.Global)
		}
		if len(g.Scoped) != 5 || len(g.Entries) != 7 {
			t.Fatalf("scoped=%v entries=%v", g.Scoped, g.Entries)
		}
		for _, entry := range g.Entries {
			if entry.ScopeType == "global" && entry.Permission == "config.edit" {
				t.Fatalf("flattened scoped edit grant %+v", entry)
			}
		}
		f.write(t, func(tx storage.IdentityTx) error {
			rows, e := securitystate.ListRoleDefinitionsTx(f.ctx, tx)
			if e != nil {
				return e
			}
			actual, e := securitystate.Strings(f.ctx, tx, `SELECT id FROM permissions ORDER BY id`)
			if e != nil {
				return e
			}
			for i, p := range actual {
				if p == "users.superadmin.manage" {
					actual[i] = "users.privileged.manage"
				}
			}
			sort.Strings(actual)
			mapped := []string{}
			for _, role := range rows {
				mapped = append(mapped, role.Permissions...)
			}
			sort.Strings(mapped)
			if !reflect.DeepEqual(actual, mapped) {
				t.Fatalf("catalog does not cover actual permission table: actual=%v roles=%v", actual, mapped)
			}
			return securitystate.EnsureBuiltinRolesTx(f.ctx, tx)
		})
	})
	t.Run("registered_presets_scope_validation_and_pending_barrier", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		for _, scope := range []struct{ kind, id string }{{"site", "site_one"}, {"global", "illegal"}, {"site", ""}, {"unknown", "scope_one"}} {
			b := f.binding(t, "users.read", scope.kind, scope.id)
			e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				return securitystate.PublishRoleBindingTx(f.ctx, tx, h, b)
			})
			if !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatalf("invalid scope accepted %+v: %v", scope, e)
			}
		}
		for _, pair := range [][2]string{{"nodes.read", "resource"}, {"nodes.revoke", "resource"}, {"nodes.enroll", "node"}, {"nodes.enroll", "node_group"}, {"nodes.enroll", "resource"}} {
			b := f.binding(t, pair[0], pair[1], "object_forbidden")
			e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				return securitystate.PublishRoleBindingTx(f.ctx, tx, h, b)
			})
			if !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatalf("permission scope policy bypass %v: %v", pair, e)
			}
		}
		b := f.binding(t, "config.read", "global", "")
		b.ExpiresAt = nil
		f.publish(t, b)
		if !roleContains(f.effective(t).Entries, b.ID) {
			t.Fatal("optional expiry dropped positive role")
		}
		tampered := securitystate.BuiltinRoleDefinitions()[0]
		tampered.Name = "unregistered preset"
		e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { return securitystate.RegisterRoleDefinitionTx(f.ctx, tx, tampered) })
		if !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("unregistered preset accepted %v", e)
		}
		f.write(t, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO security_operations(id,requests_json,intent_json,status,actor_id) VALUES('op_pending_role_test','[]','{}','pending','fixture')`)
			return e
		})
		if e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			_, e := securitystate.ReadEffectiveGrants(f.ctx, tx, h, f.user)
			return e
		}); !errors.Is(e, securitystate.ErrBarrier) {
			t.Fatalf("ordinary Current reader bypassed barrier: %v", e)
		}
		f.write(t, func(tx storage.IdentityTx) error {
			// Current closes ordinary readers while the low-level reader remains
			// usable inside an independently authorized restrictive materializer.
			if _, e := securitystate.ReadEffectiveGrants(f.ctx, tx, f.authority.head, f.user); e != nil {
				t.Fatalf("pending materializer cannot read current grants: %v", e)
			}
			b.ID = securitystate.ID("rbinding")
			if e := securitystate.PublishRoleBindingTx(f.ctx, tx, f.authority.head, b); !errors.Is(e, securitystate.ErrBarrier) {
				t.Fatalf("publisher bypassed barrier: %v", e)
			}
			return nil
		})
	})
	t.Run("absent_revoke_is_durable_and_replayed_restored_positive_denied", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		old := f.binding(t, "config.edit", "site", "site_restore")
		f.revoke(t, old.ID)
		e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			return securitystate.PublishRoleBindingTx(f.ctx, tx, h, old)
		})
		if !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("revoked absent incarnation publish=%v", e)
		}
		e = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO role_bindings(binding_id,principal_id,authority_epoch,role_digest,scope_type,scope_id,expires_at,revision,created_at) VALUES(?,?,?,?,?,?,?,1,?)`, old.ID, old.PrincipalID, 1, old.RoleDigest, old.ScopeType, old.ScopeID, old.ExpiresAt, old.CreatedAt)
			return e
		})
		if e == nil {
			t.Fatal("restored row bypassed durable tombstone")
		}
		if roleContains(f.effective(t).Entries, old.ID) {
			t.Fatal("absent revoked incarnation effective")
		}
		fresh := old
		fresh.ID = securitystate.ID("rbinding")
		f.publish(t, fresh)
		if !roleContains(f.effective(t).Entries, fresh.ID) {
			t.Fatal("distinct positive incarnation missing")
		}
		f.revoke(t, fresh.ID)
		f.revoke(t, fresh.ID)
		var saved securitystate.RoleBinding
		f.write(t, func(tx storage.IdentityTx) error {
			var e error
			saved, e = securitystate.ReadRoleBindingTx(f.ctx, tx, fresh.ID)
			return e
		})
		if saved.RevokedAt == nil || saved.Revision != 2 {
			t.Fatalf("nonmonotonic replay %+v", saved)
		}
		if roleContains(f.effective(t).Entries, fresh.ID) {
			t.Fatal("revoked existing incarnation effective")
		}
		// A pre-grant CP snapshot has no positive row. A later restored snapshot may
		// contain that row; independent deny replay must close it before readers run.
		restored := newRoleFixture(t, pg)
		// Restore the same principal identity and the exact old positive binding,
		// including its original ID, epoch, scope, creation and expiry timestamps.
		restored.write(t, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(restored.ctx, `INSERT INTO users(id,username,password_hash,display_name,is_admin,created_at,updated_at,security_version,password_version,lifecycle_state) VALUES(?,'restored-role-target','unused-test-phc','',FALSE,?,?,1,1,'active')`, old.PrincipalID, f.now, f.now)
			return e
		})
		restored.user = old.PrincipalID
		restored.publish(t, old)
		restored.revoke(t, old.ID)
		if roleContains(restored.effective(t).Entries, old.ID) {
			t.Fatal("replayed deny reopened restored positive")
		}
	})
	t.Run("epoch_expiry_and_independent_floors", func(t *testing.T) {
		for _, mode := range []string{"expiry", "epoch", "principal_floor", "password_floor", "blocked", "invited"} {
			t.Run(mode, func(t *testing.T) {
				f := newRoleFixture(t, pg)
				b := f.binding(t, "config.read", "global", "")
				f.publish(t, b)
				switch mode {
				case "expiry":
					f.authority.mu.Lock()
					f.authority.head.RecordedAt = *b.ExpiresAt
					f.authority.mu.Unlock()
				case "epoch":
					f.authority.mu.Lock()
					f.authority.head.Epoch = 2
					f.authority.mu.Unlock()
					f.write(t, func(tx storage.IdentityTx) error {
						_, e := tx.Exec(f.ctx, `UPDATE security_state SET epoch=2 WHERE id=1`)
						return e
					})
				case "principal_floor", "password_floor":
					key := "principal_" + f.user
					if mode == "password_floor" {
						key = "password_" + f.user
					}
					f.write(t, func(tx storage.IdentityTx) error {
						_, e := tx.Exec(f.ctx, `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES(?,?,2)`, f.user, key)
						return e
					})
				case "blocked":
					f.write(t, func(tx storage.IdentityTx) error {
						_, e := tx.Exec(f.ctx, `UPDATE users SET blocked_at=? WHERE id=?`, f.now, f.user)
						return e
					})
				case "invited":
					f.write(t, func(tx storage.IdentityTx) error {
						_, e := tx.Exec(f.ctx, `UPDATE users SET lifecycle_state='invited' WHERE id=?`, f.user)
						return e
					})
				}
				var got securitystate.EffectiveGrants
				e := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					var e error
					got, e = securitystate.ReadEffectiveGrants(f.ctx, tx, h, f.user)
					return e
				})
				if mode == "expiry" || mode == "epoch" {
					if e != nil || roleContains(got.Entries, b.ID) {
						t.Fatalf("%s retained stale binding: %+v %v", mode, got, e)
					}
				} else if !errors.Is(e, storage.ErrPermissionDenied) {
					t.Fatalf("%s not denied %v", mode, e)
				}
				var metadata securitystate.EffectiveGrants
				e = f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					var e error
					metadata, e = securitystate.ReadPrincipalGrantMetadata(f.ctx, tx, h, f.user)
					return e
				})
				if e != nil {
					t.Fatalf("passive metadata failed for %s: %v", mode, e)
				}
				want := mode != "expiry" && mode != "epoch"
				if roleContains(metadata.Entries, b.ID) != want {
					t.Fatalf("passive metadata confused classification with authority for %s: %+v", mode, metadata)
				}
				candidate := b
				candidate.ID = securitystate.ID("rbinding")
				candidate.CreatedAt = f.authority.head.RecordedAt
				e = f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					return securitystate.PublishRoleBindingTx(f.ctx, tx, h, candidate)
				})
				if e == nil {
					t.Fatalf("%s allowed positive publication", mode)
				}
			})
		}
	})
	t.Run("sql_catalog_and_incarnation_immutability", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		b := f.binding(t, "config.read", "site", "site_immutable")
		f.publish(t, b)
		globalOnlyDigest := ""
		for _, preset := range securitystate.BuiltinRoleDefinitions() {
			if preset.ID == "role_users_read" {
				globalOnlyDigest = preset.Digest
			}
		}
		attempts := []struct {
			sql  string
			args []any
		}{
			{`UPDATE role_definitions SET name='tampered' WHERE role_digest=?`, []any{b.RoleDigest}},
			{`UPDATE role_definitions SET sealed=FALSE WHERE role_digest=?`, []any{b.RoleDigest}},
			{`DELETE FROM role_definitions WHERE role_digest=?`, []any{b.RoleDigest}},
			{`INSERT INTO role_definition_permissions(role_digest,permission) VALUES(?,'config.approve')`, []any{b.RoleDigest}},
			{`UPDATE role_definition_permissions SET permission='config.approve' WHERE role_digest=?`, []any{b.RoleDigest}},
			{`DELETE FROM role_definition_permissions WHERE role_digest=?`, []any{b.RoleDigest}},
			{`INSERT INTO role_definition_scopes(role_digest,scope_type) VALUES(?,'site')`, []any{globalOnlyDigest}},
			{`UPDATE role_definition_scopes SET scope_type='global' WHERE role_digest=?`, []any{b.RoleDigest}},
			{`DELETE FROM role_definition_scopes WHERE role_digest=?`, []any{b.RoleDigest}},
			{`UPDATE role_bindings SET scope_id='other_site' WHERE binding_id=?`, []any{b.ID}},
			{`UPDATE role_bindings SET expires_at=? WHERE binding_id=?`, []any{f.now.Add(2 * time.Hour), b.ID}},
			{`UPDATE role_bindings SET revision=2 WHERE binding_id=?`, []any{b.ID}},
			{`DELETE FROM role_bindings WHERE binding_id=?`, []any{b.ID}},
		}
		for _, attempt := range attempts {
			e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(f.ctx, attempt.sql, attempt.args...); return e })
			if e == nil {
				t.Fatalf("immutable SQL accepted %s", attempt.sql)
			}
		}
		f.revoke(t, b.ID)
		for _, q := range []string{`UPDATE role_bindings SET revoked_at=NULL,revision=1 WHERE binding_id=?`, `DELETE FROM role_binding_revocations WHERE binding_id=?`, `UPDATE role_binding_revocations SET authority_epoch=2 WHERE binding_id=?`} {
			if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(f.ctx, q, b.ID); return e }); e == nil {
				t.Fatalf("terminal SQL accepted %s", q)
			}
		}
		if roleContains(f.effective(t).Entries, b.ID) {
			t.Fatal("immutable check changed effective role")
		}
	})
}

func TestRoleDefinitionPublicDigest(t *testing.T) {
	roles := securitystate.BuiltinRoleDefinitions()
	for _, r := range roles {
		digest, e := configmodel.Digest(map[string]any{"id": r.ID, "name": r.Name, "version": r.Version, "permissions": r.Permissions, "allowedScopes": r.AllowedScopes})
		if e != nil || digest != r.Digest {
			t.Fatalf("public JCS role digest %s: %s %v", r.ID, digest, e)
		}
	}
	roles[0].Permissions[0] = "modified caller-owned copy"
	if reflect.DeepEqual(roles, securitystate.BuiltinRoleDefinitions()) {
		t.Fatal("built-in role slices unexpectedly shared")
	}
}
