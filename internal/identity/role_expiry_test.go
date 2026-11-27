package identity

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// The hook places elapsed independent time after execution's transactional
// replay record but before publication. Without the final time check the
// coordinator's same-state comparison alone would allow this stale grant.
type roleElapsedAuthority struct {
	securityjournal.Authority
	armed   atomic.Bool
	advance func()
}

func (a *roleElapsedAuthority) Head(ctx context.Context) (securityjournal.Head, error) {
	if a.armed.Swap(false) {
		a.advance()
	}
	return a.Authority.Head(ctx)
}

type roleElapsedRepository struct {
	securitystate.Repository
	authority *roleElapsedAuthority
	action    string
}

func (r roleElapsedRepository) WriteIdentity(ctx context.Context, fn func(storage.IdentityTx) error) error {
	return r.Repository.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return fn(roleElapsedTx{IdentityTx: tx, authority: r.authority, action: r.action})
	})
}

type roleElapsedTx struct {
	storage.IdentityTx
	authority *roleElapsedAuthority
	action    string
}

func (t roleElapsedTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	n, e := t.IdentityTx.Exec(ctx, q, args...)
	if e == nil && n > 0 && strings.HasPrefix(q, "INSERT INTO role_grant_requests") && len(args) > 1 && args[1] == t.action {
		t.authority.armed.Store(true)
	}
	return n, e
}
func TestRoleFinalGrantExpirySQLite(t *testing.T)   { roleFinalGrantExpiry(t, false) }
func TestRoleFinalGrantExpiryPostgres(t *testing.T) { roleFinalGrantExpiry(t, true) }
func roleFinalGrantExpiry(t *testing.T, pg bool) {
	for _, scope := range []string{"global", "site"} {
		for _, who := range []string{"creator", "reviewer", "executor", "target"} {
			t.Run(scope+"_"+who, func(t *testing.T) {
				f := newRoleFixture(t, pg)
				person := map[string]string{"creator": f.user.ID, "reviewer": f.other.ID, "executor": f.executorUser.ID, "target": f.target.ID}[who]
				var temporary securitystate.RoleBinding
				publish := func(expires *time.Time) securitystate.RoleBinding {
					t.Helper()
					var binding securitystate.RoleBinding
					e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
						if e := securitystate.EnsureBuiltinRolesTx(f.ctx, tx); e != nil {
							return e
						}
						role, e := securitystate.ReadRoleDefinitionTx(f.ctx, tx, "role_config_read")
						if e != nil {
							return e
						}
						binding = securitystate.RoleBinding{ID: securitystate.ID("rbinding"), PrincipalID: person, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: scope, Revision: 1, AuthorityEpoch: h.Epoch, CreatedAt: h.RecordedAt, ExpiresAt: expires}
						if scope != "global" {
							binding.ScopeID = "site_expiry_fixture"
						}
						return securitystate.PublishRoleBindingTx(f.ctx, tx, h, binding)
					})
					if e != nil {
						t.Fatal("trusted temporal grant fixture", e)
					}
					return binding
				}
				expires := f.now.Add(2 * time.Second)
				temporary = publish(&expires)
				op := f.create(t, "temporal_role_plan_request")
				f.approve(t, op)
				authority := &roleElapsedAuthority{Authority: f.s.Coordinator.Authority, advance: func() { f.clock(f.now.Add(6 * time.Second)) }}
				f.s.Coordinator.Authority = authority
				originalStore := f.s.Coordinator.Store
				f.s.Coordinator.Store = roleElapsedRepository{Repository: originalStore, authority: authority, action: "execute:" + op.ID}
				_, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, op.ID, "temporal_role_execution_request", op.RequestDigest, "grant evidence must remain unexpired")
				if e == nil {
					t.Fatal("elapsed " + who + " " + scope + " grant published a binding")
				}
				if authority.armed.Load() {
					t.Fatal("execution never obtained final independent time")
				}
				f.s.Coordinator.Store = originalStore
				if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					var state string
					var bindings, keys int
					if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_bindings WHERE binding_id=?`, []any{op.RoleGrantRequest.BindingID}, func(row storage.IdentityRows) error { return row.Scan(&bindings) }); e != nil {
						return e
					}
					if e := securitystate.One(f.ctx, tx, `SELECT state FROM role_grant_operations WHERE id=?`, []any{op.ID}, func(row storage.IdentityRows) error { return row.Scan(&state) }); e != nil {
						return e
					}
					if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_grant_requests WHERE action=?`, []any{"execute:" + op.ID}, func(row storage.IdentityRows) error { return row.Scan(&keys) }); e != nil {
						return e
					}
					if bindings != 0 || state != "pending" || keys != 0 {
						t.Fatal("partial expired grant", bindings, state, keys)
					}
					return nil
				}); e != nil {
					t.Fatal(e)
				}
				if e = f.s.Coordinator.Ready(f.ctx); e != nil {
					t.Fatal("positive failure installed global barrier", e)
				}
				newGrant := publish(nil)
				if newGrant.ID == temporary.ID {
					t.Fatal("temporal incarnation reused")
				}
				fresh := f.create(t, "fresh_temporal_role_plan_request")
				f.approve(t, fresh)
				f.execute(t, fresh)
			})
		}
	}
}
