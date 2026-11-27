package configuration

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// This is trusted fixture publication for reader tests. The approved grant
// workflow, signed journal and real corporate infrastructure are not doubled
// into an implicit qualification by this helper.
func configurationReaderBinding(t *testing.T, f *testFixture, suffix, principal, permission, kind, scope string, expiry *time.Time) securitystate.RoleBinding {
	t.Helper()
	var binding securitystate.RoleBinding
	err := f.service.current.Current(context.Background(), func(tx storage.IdentityTx, h securityjournal.Head) error {
		if err := securitystate.EnsureBuiltinRolesTx(context.Background(), tx); err != nil {
			return err
		}
		role, err := securitystate.ReadRoleDefinitionTx(context.Background(), tx, "role_"+strings.ReplaceAll(permission, ".", "_"))
		if err != nil {
			return err
		}
		binding = securitystate.RoleBinding{ID: "rbinding_" + suffix, PrincipalID: principal, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: kind, ScopeID: scope, Revision: 1, AuthorityEpoch: h.Epoch, CreatedAt: h.RecordedAt, ExpiresAt: expiry}
		return securitystate.PublishRoleBindingTx(context.Background(), tx, h, binding)
	})
	if err != nil {
		t.Fatal("trusted role reader fixture", err)
	}
	return binding
}

func configurationWithdrawFixture(t *testing.T, f *testFixture, id string) {
	t.Helper()
	err := f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		return securitystate.MaterializeEvent(context.Background(), tx, securityjournal.Event{ID: "fixture_revoke_" + id, Epoch: 1, Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", TargetType: "grant", TargetID: id, Payload: securityjournal.Payload{GrantID: id}}, RecordedAt: time.Now().UTC()})
	})
	if err != nil {
		t.Fatal("trusted revocation fixture", err)
	}
}

func configurationRolesFixture(t *testing.T, pg bool) *testFixture {
	t.Helper()
	f := scopedFixture(t, pg)
	configurationWithdrawFixture(t, f, "cgrant_editor")
	configurationWithdrawFixture(t, f, "cgrant_reviewer")
	return f
}

func TestConfigurationRoleReadersSQLite(t *testing.T)   { testConfigurationRoleReaders(t, false) }
func TestConfigurationRoleReadersPostgres(t *testing.T) { testConfigurationRoleReaders(t, true) }

func testConfigurationRoleReaders(t *testing.T, pg bool) {
	ctx := context.Background()
	t.Run("global_and_site_bindings_work_without_scoped_flatten", func(t *testing.T) {
		for _, scope := range []struct{ kind, id string }{{"global", ""}, {"site", "site_msk"}, {"node_group", "group_msk"}, {"node", "node_msk01"}, {"resource", "res_portal"}} {
			t.Run(scope.kind, func(t *testing.T) {
				f := configurationRolesFixture(t, pg)
				configurationReaderBinding(t, f, "reader_"+scope.kind, "editor", "config.edit", scope.kind, scope.id, nil)
				r, err := f.service.CreateRevision(ctx, f.actor, "config_roles_base_001", CreateRevision{Content: example(t)})
				if err != nil {
					t.Fatal(err)
				}
				a := Actor{TokenHash: "editor_token", Origin: f.actor.Origin}
				access, err := f.service.Access(ctx, a)
				if err != nil {
					t.Fatal(err)
				}
				if access.GlobalRead != (scope.kind == "global") || access.GlobalEdit != (scope.kind == "global") {
					t.Fatalf("flattened scope: %#v", access)
				}
				if scope.kind != "site" && len(access.Sites) != 0 {
					t.Fatalf("invented site authority: %#v", access)
				}
				_, err = f.service.GetRevision(ctx, a, r.ID)
				if scope.kind == "global" {
					if err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("full snapshot exposed: %v", err)
				}
				_, err = f.service.GatewayRevision(ctx, a, r.ID, "gw_portal")
				if scope.kind == "global" || scope.kind == "site" {
					if err != nil {
						t.Fatal(err)
					}
				} else if scope.kind == "node_group" || scope.kind == "node" {
					if !errors.Is(err, rolescope.ErrUnavailable) {
						t.Fatalf("missing installation ownership accepted: %v", err)
					}
				} else if !errors.Is(err, storage.ErrNotFound) {
					t.Fatalf("whole gateway exposed by narrow scope: %v", err)
				}
			})
		}
	})
	t.Run("explicit_approval_and_binding_incarnation_invalidate_historical_evidence", func(t *testing.T) {
		f := configurationRolesFixture(t, pg)
		configurationReaderBinding(t, f, "approval_one", "reviewer", "config.approve", "site", "site_msk", nil)
		var before, after string
		err := f.service.transactScoped(ctx, f.actor, false, func(tx storage.IdentityTx, p *Principal) error {
			if err := wafSubjectPermission(ctx, tx, "reviewer", "config.approve", "site_msk", p.head); err != nil {
				return err
			}
			if err := wafSubjectPermission(ctx, tx, "s1_admin", "config.approve", "site_msk", p.head); !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatalf("implicit admin approval: %v", err)
			}
			var err error
			before, err = subjectFingerprint(ctx, tx, "reviewer", p.head)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		configurationWithdrawFixture(t, f, "rbinding_approval_one")
		configurationReaderBinding(t, f, "approval_two", "reviewer", "config.approve", "site", "site_msk", nil)
		err = f.service.transactScoped(ctx, f.actor, false, func(tx storage.IdentityTx, p *Principal) error {
			var err error
			after, err = subjectFingerprint(ctx, tx, "reviewer", p.head)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if before == "" || before == after {
			t.Fatal("replacement incarnation accepted historical approval")
		}
	})
	t.Run("role_expiry_after_revision_insert_rolls_back_revision_audit_and_replay", func(t *testing.T) {
		f := configurationRolesFixture(t, pg)
		expires := time.Now().UTC().Add(time.Minute)
		configurationReaderBinding(t, f, "expires_after_write", "editor", "config.edit", "global", "", &expires)
		clock := &configurationRoleClock{underlying: f.service.current}
		f.service.current = clock
		_, err := f.service.CreateRevision(ctx, Actor{TokenHash: "editor_token", Origin: f.actor.Origin}, "config_role_expiry_001", CreateRevision{Content: example(t)})
		if !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("late expired grant: %v", err)
		}
		if clock.inserts.Load() != 1 {
			t.Fatalf("callback retried or not executed: %d", clock.inserts.Load())
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_revisions`); n != 0 {
			t.Fatalf("positive revision committed: %d", n)
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM audit_events WHERE event_type='config.revision.created'`); n != 0 {
			t.Fatalf("audit committed without revision: %d", n)
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_requests WHERE request_key='config_role_expiry_001'`); n != 0 {
			t.Fatalf("failed response became replayable: %d", n)
		}
	})
}

type configurationRoleClock struct {
	underlying Current
	advance    atomic.Bool
	inserts    atomic.Int64
}

func (c *configurationRoleClock) Head(ctx context.Context) (securityjournal.Head, error) {
	h, err := c.underlying.Head(ctx)
	if err == nil && c.advance.Load() {
		h.RecordedAt = h.RecordedAt.Add(2 * time.Minute)
	}
	return h, err
}

func (c *configurationRoleClock) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		return fn(configurationRoleClockTx{IdentityTx: tx, clock: c}, h)
	})
}

type configurationRoleClockTx struct {
	storage.IdentityTx
	clock *configurationRoleClock
}

func (tx configurationRoleClockTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	n, err := tx.IdentityTx.Exec(ctx, q, args...)
	if err == nil && strings.Contains(q, "INSERT INTO config_revisions") {
		tx.clock.inserts.Add(1)
		tx.clock.advance.Store(true)
	}
	return n, err
}
