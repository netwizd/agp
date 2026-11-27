package identity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// These installation-owned facts are bootstrapped before the secure profile,
// then checked against current sealed configuration and actual managed nodes.
// Operator catalogs and route IDs never stand in for scope ownership.
type roleScopeNodeFixture struct {
	ID        string            `json:"id"`
	SiteID    string            `json:"siteId"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	GroupIDs  []string          `json:"groupIds"`
	CreatedAt time.Time         `json:"createdAt"`
}

func newRoleScopeFixture(t *testing.T, pg bool) (*roleFixture, configmodel.Configuration, roleScopeNodeFixture) {
	t.Helper()
	raw, e := os.ReadFile("../../docs/v2/examples/configuration.json")
	if e != nil {
		t.Fatal(e)
	}
	var configuration configmodel.Configuration
	if e = json.Unmarshal(raw, &configuration); e != nil {
		t.Fatal(e)
	}
	node := roleScopeNodeFixture{ID: "node_msk01", SiteID: "site_msk", Name: "Scope fixture node", Labels: map[string]string{"environment": "pilot"}, GroupIDs: []string{"ng_msk"}, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	manifest := rolescope.Manifest{
		APIVersion: "agp.role-scopes/v1alpha1", ID: "scope_workflow_fixture",
		Sites: []rolescope.Site{{ID: "site_msk"}}, NodeGroups: []rolescope.NodeGroup{{ID: "ng_msk", SiteID: "site_msk"}},
		Nodes:          []rolescope.Node{{ID: node.ID, SiteID: node.SiteID, GroupIDs: node.GroupIDs}},
		Resources:      []rolescope.Resource{{ID: "resource_portal"}},
		ResourceRoutes: []rolescope.ResourceRoute{{ResourceID: "resource_portal", GatewayID: "gw_portal", RouteID: "route_portal"}},
	}
	f := newRoleFixtureSetup(t, pg, func(ctx context.Context, store storage.Store, author string) error {
		return store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES('gw_portal','site_msk')`); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO resources(id,name,internal_url,public_host) VALUES('resource_portal','Workflow resource','https://backend.example.net:8443','app.example.net')`); e != nil {
				return e
			}
			if e := rolescope.BootstrapTx(ctx, tx, 1, manifest); e != nil {
				return e
			}
			raw, e := json.Marshal(node)
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, node.ID, node.SiteID, string(raw), node.CreatedAt); e != nil {
				return e
			}
			return insertRoleScopeConfiguration(ctx, tx, configuration, "revision_role_scope_initial", 1, author, node.CreatedAt)
		})
	})
	return f, configuration, node
}

func insertRoleScopeConfiguration(ctx context.Context, tx storage.IdentityTx, c configmodel.Configuration, id string, revision int, author string, now time.Time) error {
	doc, e := configmodel.Canonicalize(c)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO config_revisions(id,revision_number,parent_id,schema_version,capacity_profile,canonical_size_bytes,content_digest,canonical_json,state,created_by,created_at) VALUES(?,?,(SELECT revision_id FROM config_head WHERE id=1),?,'pilot-500',?,?,?,'draft',?,?)`, id, revision, c.APIVersion, len(doc.Canonical), doc.Digest, string(doc.Canonical), author, now); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO config_revision_seals(revision_id,created_at) VALUES(?,?)`, id, now); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE config_head SET revision_id=?,row_version=? WHERE id=1`, id, revision)
	return e
}

func TestRoleScopedWorkflowSQLite(t *testing.T)   { roleScopedWorkflow(t, false) }
func TestRoleScopedWorkflowPostgres(t *testing.T) { roleScopedWorkflow(t, true) }
func roleScopedWorkflow(t *testing.T, pg bool) {
	for _, scope := range []RoleScopeRef{{ScopeType: "site", ScopeID: "site_msk"}, {ScopeType: "node_group", ScopeID: "ng_msk"}, {ScopeType: "node", ScopeID: "node_msk01"}, {ScopeType: "resource", ScopeID: "resource_portal"}} {
		t.Run(scope.ScopeType, func(t *testing.T) {
			f, configuration, node := newRoleScopeFixture(t, pg)
			create := func(key string) *RoleSecurityOperation {
				t.Helper()
				op, e := f.roles.Create(f.ctx, f.creator, key, RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: scope.ScopeType, ScopeID: scope.ScopeID})
				if e != nil {
					t.Fatal("scoped plan", e)
				}
				if op.RoleGrantRequest.ScopeClosureDigest == "" || len(op.RoleGrantRequest.ScopeSourceVersions) == 0 || len(op.RoleGrantRequest.ScopeClosure) < 2 {
					t.Fatal("scope lacks current authoritative evidence")
				}
				return op
			}
			assertUnpublished := func(op *RoleSecurityOperation, action string) {
				t.Helper()
				if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					var bindings, keys int
					var state string
					if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_bindings WHERE binding_id=?`, []any{op.RoleGrantRequest.BindingID}, func(rows storage.IdentityRows) error { return rows.Scan(&bindings) }); e != nil {
						return e
					}
					if e := securitystate.One(f.ctx, tx, `SELECT state FROM role_grant_operations WHERE id=?`, []any{op.ID}, func(rows storage.IdentityRows) error { return rows.Scan(&state) }); e != nil {
						return e
					}
					if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_grant_requests WHERE action=?`, []any{action + ":" + op.ID}, func(rows storage.IdentityRows) error { return rows.Scan(&keys) }); e != nil {
						return e
					}
					if bindings != 0 || state != "pending" || keys != 0 {
						t.Fatal("stale scope left positive state", bindings, state, keys)
					}
					return nil
				}); e != nil {
					t.Fatal(e)
				}
				if e := f.s.Coordinator.Ready(f.ctx); e != nil {
					t.Fatal("scope failure installed a global barrier", e)
				}
			}

			op := create("scoped_initial_role_request")
			if len(f.effective(t).Entries) != 0 {
				t.Fatal("pending scoped grant became effective")
			}
			f.approve(t, op)
			f.execute(t, op)
			effective := f.effective(t)
			if len(effective.Global) != 0 || len(effective.Scoped) != 1 || len(effective.Entries) != 1 || effective.Scoped[0].Permission != "config.read" || effective.Scoped[0].ScopeType != scope.ScopeType || effective.Scoped[0].ScopeID != scope.ScopeID {
				t.Fatal("scoped grant was lost or flattened into global authority", effective)
			}

			stale := create("scoped_source_drift_request")
			if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				return insertRoleScopeConfiguration(f.ctx, tx, configuration, "revision_role_scope_successor", 2, f.user.ID, f.now)
			}); e != nil {
				t.Fatal(e)
			}
			if _, e := f.roles.ApproveOperationRequest(f.ctx, f.reviewer, stale.ID, "scoped_source_drift_approval", stale.RequestDigest, "scope source must remain current"); !errors.Is(e, ErrLifecycleStale) {
				t.Fatal("new sealed config source reused old approval intent", e)
			}
			assertUnpublished(stale, "approve")

			current := create("scoped_current_source_request")
			if current.RoleGrantRequest.ScopeClosureDigest == stale.RoleGrantRequest.ScopeClosureDigest {
				t.Fatal("fresh plan did not pin successor source")
			}
			f.approve(t, current)
			node.GroupIDs = []string{}
			raw, e := json.Marshal(node)
			if e != nil {
				t.Fatal(e)
			}
			f.sql(t, `UPDATE managed_nodes SET node_json=? WHERE id=?`, string(raw), node.ID)
			if _, e = f.roles.ExecuteOperationRequest(f.ctx, f.executor, current.ID, "scoped_membership_execution", current.RequestDigest, "membership must remain authoritative"); !errors.Is(e, rolescope.ErrUnavailable) {
				t.Fatal("changed actual node membership reused approved scope", e)
			}
			assertUnpublished(current, "execute")
			if _, e = f.roles.Create(f.ctx, f.creator, "scoped_invalid_current_request", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: scope.ScopeType, ScopeID: scope.ScopeID}); !errors.Is(e, rolescope.ErrUnavailable) {
				t.Fatal("fresh plan accepted stale installation ownership", e)
			}
			if len(f.effective(t).Global) != 0 || len(f.effective(t).Scoped) != 1 {
				t.Fatal("failed scope checks changed effective grants")
			}
		})
	}
}
