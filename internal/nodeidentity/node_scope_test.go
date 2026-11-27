package nodeidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func scopeFixture(t *testing.T, pg bool) *fixture {
	t.Helper()
	graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "scope_nodes", Sites: []rolescope.Site{{ID: "site_one"}, {ID: "site_other"}}, NodeGroups: []rolescope.NodeGroup{{ID: "group_one", SiteID: "site_one"}}, Nodes: []rolescope.Node{{ID: "node_one", SiteID: "site_one", GroupIDs: []string{"group_one"}}, {ID: "node_two", SiteID: "site_one", GroupIDs: []string{}}, {ID: "node_other", SiteID: "site_other", GroupIDs: []string{}}}, Resources: []rolescope.Resource{}, ResourceRoutes: []rolescope.ResourceRoute{}}
	f := setupWithScopeGraph(t, pg, &graph)
	for _, n := range graph.Nodes {
		_, err := f.service.CreateNode(f.ctx, f.actor, "create_"+n.ID, CreateNodeRequest{ID: n.ID, SiteID: n.SiteID, Name: n.ID, Labels: map[string]string{}, GroupIDs: n.GroupIDs})
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// Fixture publication exercises consumers, not the separately qualified public
// multi-person grant workflow. No immutable SQL trigger is bypassed.
func (f *fixture) scopeActor(t *testing.T, id, permission, kind, scope string, expires *time.Time) Actor {
	t.Helper()
	a := Actor{TokenHash: auth.TokenHash(id), Origin: f.actor.Origin}
	err := f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if _, err := tx.Exec(f.ctx, `INSERT INTO users(id,username,password_hash,is_admin,security_version,password_version) VALUES(?,?,?,FALSE,1,1)`, id, id, "unused"); err != nil {
			return err
		}
		if _, err := tx.Exec(f.ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,primary_at,last_seen_at) VALUES(?,?,?,'csrf','127.0.0.1','scope-test',?,?,'management',?,1,1,?,?,?)`, "session_"+id, id, a.TokenHash, h.RecordedAt.Add(time.Hour), h.RecordedAt, a.Origin, h.RecordedAt, h.RecordedAt, h.RecordedAt); err != nil {
			return err
		}
		return publishScopeRole(f.ctx, tx, h, id, permission, kind, scope, "rbinding_"+id, expires)
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func publishScopeRole(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id, permission, kind, scope, binding string, expires *time.Time) error {
	if err := securitystate.EnsureBuiltinRolesTx(ctx, tx); err != nil {
		return err
	}
	role, err := securitystate.ReadRoleDefinitionTx(ctx, tx, "role_"+strings.ReplaceAll(permission, ".", "_"))
	if err != nil {
		return err
	}
	return securitystate.PublishRoleBindingTx(ctx, tx, h, securitystate.RoleBinding{ID: binding, PrincipalID: id, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: kind, ScopeID: scope, AuthorityEpoch: h.Epoch, Revision: 1, CreatedAt: h.RecordedAt, ExpiresAt: expires})
}
func issueExisting(t *testing.T, f *fixture, id string) {
	t.Helper()
	en := f.enrollment(id)
	in := EnrollmentSubmission{NodeID: id, EnrollmentToken: en.EnrollmentToken, CSRPEM: mustCSR(t)}
	f.approve(in)
	if _, err := f.service.Enroll(f.ctx, in); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRoleScopesSQLite(t *testing.T)   { testNodeRoleScopes(t, false) }
func TestNodeRoleScopesPostgres(t *testing.T) { testNodeRoleScopes(t, true) }
func testNodeRoleScopes(t *testing.T, pg bool) {
	f := scopeFixture(t, pg)
	for _, id := range []string{"node_one", "node_two", "node_other"} {
		issueExisting(t, f, id)
	}
	for _, tc := range []struct {
		name, kind, scope string
		count             int
	}{{"global", "global", "", 3}, {"site", "site", "site_one", 2}, {"group", "node_group", "group_one", 1}, {"node", "node", "node_one", 1}} {
		t.Run(tc.name+"_read_is_filtered_in_all_consumers", func(t *testing.T) {
			a := f.scopeActor(t, "reader_"+tc.name, "nodes.read", tc.kind, tc.scope, nil)
			nodes, err := f.service.ListNodes(f.ctx, a)
			if err != nil || len(nodes) != tc.count {
				t.Fatal("typed nodes", len(nodes), err)
			}
			views, err := f.service.ListNodeViews(f.ctx, a)
			if err != nil || len(views) != tc.count {
				t.Fatal("typed node views", len(views), err)
			}
			agents, err := f.inventory.ListForAdmin(f.ctx, a.TokenHash, a.Origin)
			if err != nil || len(agents) != tc.count {
				t.Fatal("typed inventory", len(agents), err)
			}
			if tc.kind != "global" {
				if _, err = f.service.GetNodeView(f.ctx, a, "node_other"); !errors.Is(err, storage.ErrNotFound) {
					t.Fatal("sibling node leaked", err)
				}
			}
			if _, err = f.service.CreateEnrollment(f.ctx, a, "node_one", "reader_must_not_enroll_"+tc.name, EnrollmentRequest{Role: "agent"}); !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatal("read became enroll", err)
			}
		})
	}
	t.Run("resource_permission_is_not_node_authority", func(t *testing.T) {
		a := f.scopeActor(t, "resource_reader", "audit.read", "resource", "resource_unknown", nil)
		if nodes, err := f.service.ListNodes(f.ctx, a); !errors.Is(err, storage.ErrPermissionDenied) || len(nodes) != 0 {
			t.Fatal("resource scope flattened", nodes, err)
		}
	})
	t.Run("unknown_scope_and_membership_drift_close", func(t *testing.T) {
		a := f.scopeActor(t, "unknown_reader", "nodes.read", "node_group", "group_unknown", nil)
		if _, err := f.service.ListNodes(f.ctx, a); err == nil {
			t.Fatal("unknown group opened inventory")
		}
		a = f.scopeActor(t, "drift_reader", "nodes.read", "node_group", "group_one", nil)
		rollback := errors.New("fixture rollback")
		err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			n, e := loadNode(f.ctx, tx, "node_one")
			if e != nil {
				return e
			}
			n.GroupIDs = []string{}
			raw, _ := inventory.Encode(n)
			if _, e = tx.Exec(f.ctx, `UPDATE managed_nodes SET node_json=? WHERE id='node_one'`, string(raw)); e != nil {
				return e
			}
			access, e := inventory.ReadNodeAccess(f.ctx, tx, f.authority.head, f.coordinator, a.TokenHash, a.Origin, "nodes.read", false)
			if e != nil {
				return e
			}
			if _, e = access.AllowsNode(f.ctx, tx, "node_one"); e == nil {
				t.Fatal("declared membership drift was accepted")
			}
			return rollback
		})
		if !errors.Is(err, rollback) {
			t.Fatal(err)
		}
	})
}

func TestNodeEnrollmentRoleAuthoritySQLite(t *testing.T)   { testNodeEnrollmentRoleAuthority(t, false) }
func TestNodeEnrollmentRoleAuthorityPostgres(t *testing.T) { testNodeEnrollmentRoleAuthority(t, true) }
func testNodeEnrollmentRoleAuthority(t *testing.T, pg bool) {
	for _, mutation := range []string{"none", "touch", "binding_incarnation", "session_rebound", "primary_changed", "mfa_changed", "session_revoked", "source_revoked", "session_expired", "mfa_expired", "role_expired", "membership_drift"} {
		t.Run(mutation, func(t *testing.T) {
			f := scopeFixture(t, pg)
			exp := f.authority.head.RecordedAt.Add(time.Minute)
			a := f.scopeActor(t, "enroller", "nodes.enroll", "site", "site_one", &exp)
			if mutation == "source_revoked" {
				err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					_, e := tx.Exec(f.ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,primary_at,last_seen_at) SELECT 'source_enroller',user_id,'source_hash',csrf_hash,ip,user_agent,expires_at,created_at,'login',audience_origin,authority_epoch,security_version,mfa_at,primary_at,last_seen_at FROM sessions WHERE token_hash=?`, a.TokenHash)
					if e != nil {
						return e
					}
					_, e = tx.Exec(f.ctx, `UPDATE sessions SET source_session_id='source_enroller' WHERE token_hash=?`, a.TokenHash)
					return e
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			en, err := f.service.CreateEnrollment(f.ctx, a, "node_one", "scoped_enroll", EnrollmentRequest{Role: "agent"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.CreateEnrollment(f.ctx, a, "node_other", "wrong_site", EnrollmentRequest{Role: "agent"}); !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatal("sibling enrollment", err)
			}
			if _, err = f.service.CreateNode(f.ctx, a, "unmapped_node", CreateNodeRequest{ID: "node_new", SiteID: "site_one", Name: "untrusted input", Labels: map[string]string{}}); !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatal("request site became ownership", err)
			}
			in := EnrollmentSubmission{NodeID: "node_one", EnrollmentToken: en.EnrollmentToken, CSRPEM: mustCSR(t)}
			pending, err := f.service.RequestEnrollment(f.ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.ApproveEnrollment(f.ctx, a, "node_one", en.ID, "scoped_approve", ApprovalRequest{ExpectedPublicKeyDigest: pending.PublicKeyDigest, RequestDigest: pending.RequestDigest}); err != nil {
				t.Fatal(err)
			}
			if mutation == "role_expired" {
				f.authority.advance(time.Minute)
			}
			if mutation == "touch" {
				f.authority.advance(10 * time.Second)
			}
			if mutation != "none" && mutation != "role_expired" {
				err = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					switch mutation {
					case "touch":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET last_seen_at=? WHERE token_hash=?`, f.authority.head.RecordedAt, a.TokenHash)
					case "session_rebound":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET id='rebound_session' WHERE token_hash=?`, a.TokenHash)
					case "primary_changed":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET primary_at=? WHERE token_hash=?`, f.authority.head.RecordedAt.Add(-time.Second), a.TokenHash)
					case "mfa_changed":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET mfa_at=? WHERE token_hash=?`, f.authority.head.RecordedAt.Add(-time.Second), a.TokenHash)
					case "binding_incarnation":
						if _, e := tx.Exec(f.ctx, `UPDATE role_bindings SET revoked_at=?,revision=revision+1 WHERE binding_id='rbinding_enroller'`, f.authority.head.RecordedAt); e != nil {
							return e
						}
						return publishScopeRole(f.ctx, tx, f.authority.head, "enroller", "nodes.enroll", "site", "site_one", "rbinding_enroller_successor", &exp)
					case "session_revoked":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=? WHERE token_hash=?`, f.authority.head.RecordedAt, a.TokenHash)
					case "source_revoked":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=? WHERE id='source_enroller'`, f.authority.head.RecordedAt)
					case "session_expired":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET expires_at=? WHERE token_hash=?`, f.authority.head.RecordedAt, a.TokenHash)
					case "mfa_expired":
						_, err = tx.Exec(f.ctx, `UPDATE sessions SET mfa_at=? WHERE token_hash=?`, f.authority.head.RecordedAt.Add(-6*time.Minute), a.TokenHash)
					case "membership_drift":
						n, e := loadNode(f.ctx, tx, "node_one")
						if e != nil {
							return e
						}
						n.GroupIDs = []string{}
						raw, _ := inventory.Encode(n)
						_, err = tx.Exec(f.ctx, `UPDATE managed_nodes SET node_json=? WHERE id='node_one'`, string(raw))
					}
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			cert, err := f.service.Enroll(f.ctx, in)
			if mutation == "none" || mutation == "touch" {
				if err != nil || cert.NodeID != "node_one" {
					t.Fatal("scoped issuance", cert, err)
				}
			} else {
				if err == nil || cert.CertificatePEM != "" {
					t.Fatal("stale approval issued", mutation, err)
				}
				var count int
				if err = f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&count); err != nil || count != 0 {
					t.Fatal("external certificate minted", count, err)
				}
			}
		})
	}
}

type advancingNodeCurrent struct {
	*securitystate.Coordinator
	authority *fakeAuthority
	onInsert  bool
	heads     int
}
type advancingNodeTx struct {
	storage.IdentityTx
	owner *advancingNodeCurrent
}

func (t advancingNodeTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	n, err := t.IdentityTx.Exec(ctx, q, args...)
	if err == nil && t.owner.onInsert && strings.Contains(q, "INSERT INTO node_enrollments") {
		t.owner.authority.advance(time.Minute)
		t.owner.onInsert = false
	}
	return n, err
}
func (c *advancingNodeCurrent) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return fn(advancingNodeTx{tx, c}, h) })
}
func (c *advancingNodeCurrent) Head(ctx context.Context) (securityjournal.Head, error) {
	c.heads++
	if !c.onInsert && c.heads == 2 {
		c.authority.advance(time.Minute)
	}
	return c.authority.Head(ctx)
}
func TestNodeGrantFinalExpirySQLite(t *testing.T)   { testNodeGrantFinalExpiry(t, false) }
func TestNodeGrantFinalExpiryPostgres(t *testing.T) { testNodeGrantFinalExpiry(t, true) }
func testNodeGrantFinalExpiry(t *testing.T, pg bool) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "after_projection", true: "after_insert"}[afterWrite], func(t *testing.T) {
			f := scopeFixture(t, pg)
			expires := f.authority.head.RecordedAt.Add(time.Minute)
			a := f.scopeActor(t, "short_enroller", "nodes.enroll", "site", "site_one", &expires)
			service := *f.service
			service.current = &advancingNodeCurrent{Coordinator: f.coordinator, authority: f.authority, onInsert: afterWrite}
			if out, err := service.CreateEnrollment(f.ctx, a, "node_one", "final_expiry", EnrollmentRequest{Role: "agent"}); err == nil || out.TokenAvailable || out.EnrollmentToken != "" {
				t.Fatal("expired role exposed positive enrollment", out, err)
			}
			err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				for _, q := range []string{`SELECT COUNT(*) FROM node_enrollments`, `SELECT COUNT(*) FROM node_identity_requests WHERE actor_id='short_enroller'`, `SELECT COUNT(*) FROM audit_events WHERE event_type='node.enrollment.created' AND subject_user_id='short_enroller'`} {
					var count int
					if e := securitystate.One(f.ctx, tx, q, nil, func(rows storage.IdentityRows) error { return rows.Scan(&count) }); e != nil {
						return e
					}
					if count != 0 {
						t.Fatal("failed final grant check committed", q, count)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeRevokeRoleScopesSQLite(t *testing.T)   { testNodeRevokeRoleScopes(t, false) }
func TestNodeRevokeRoleScopesPostgres(t *testing.T) { testNodeRevokeRoleScopes(t, true) }
func testNodeRevokeRoleScopes(t *testing.T, pg bool) {
	for _, tc := range []struct{ kind, scope string }{{"global", ""}, {"site", "site_one"}, {"node_group", "group_one"}, {"node", "node_one"}} {
		t.Run(tc.kind, func(t *testing.T) {
			f := scopeFixture(t, pg)
			a := f.scopeActor(t, "revoker", "nodes.revoke", tc.kind, tc.scope, nil)
			if tc.kind != "global" {
				if _, err := f.service.RevokeNode(f.ctx, a, "node_other", "wrong_scope_revoke", RevokeNodeRequest{Reason: "test"}); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatal("sibling revoke", err)
				}
			}
			op, err := f.service.RevokeNode(f.ctx, a, "node_one", "scoped_revoke", RevokeNodeRequest{Reason: "test"})
			if err != nil || op.State != "completed" {
				t.Fatal("scoped restriction", op, err)
			}
			got, err := f.service.GetOperation(f.ctx, a, op.ID)
			if err != nil || got != op {
				t.Fatal("own revoke made receipt inaccessible", got, err)
			}
			again, err := f.service.RevokeNode(f.ctx, a, "node_one", "scoped_revoke", RevokeNodeRequest{Reason: "test"})
			if err != nil || again != op {
				t.Fatal("own revoke replay", again, err)
			}
			reader := f.scopeActor(t, "revoked_reader", "nodes.read", tc.kind, tc.scope, nil)
			view, err := f.service.GetNodeView(f.ctx, reader, "node_one")
			if err != nil || view.IdentityState != "revoked" {
				t.Fatal("revoked metadata", view, err)
			}
		})
	}
}
