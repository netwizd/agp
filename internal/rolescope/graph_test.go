package rolescope

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type graphFixture struct {
	ctx           context.Context
	store         storage.Store
	head          securityjournal.Head
	manifest      Manifest
	configuration configmodel.Configuration
}

func newGraphFixture(t *testing.T, pg bool, extraNodes ...Node) *graphFixture {
	t.Helper()
	ctx := context.Background()
	var store storage.Store
	var e error
	if pg {
		dsn := os.Getenv("AGP_TEST_ROLE_SCOPE_DSN")
		if dsn == "" {
			t.Skip("AGP_TEST_ROLE_SCOPE_DSN required for native PostgreSQL")
		}
		if !roleScopeDisposableDSN(dsn) {
			t.Fatal("scope test requires its explicitly disposable private Unix PostgreSQL lab")
		}
		connection, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, e = connection.Exec(ctx, `DROP SCHEMA public CASCADE`)
		if e == nil {
			_, e = connection.Exec(ctx, `CREATE SCHEMA public`)
		}
		if closeErr := connection.Close(ctx); e == nil {
			e = closeErr
		}
		if e == nil {
			store, e = postgres.Open(ctx, dsn)
		}
	} else {
		store, e = sqlite.Open(filepath.Join(t.TempDir(), "scope.db"))
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../docs/v2/examples/configuration.json")
	if e != nil {
		t.Fatal(e)
	}
	var configuration configmodel.Configuration
	if e = json.Unmarshal(raw, &configuration); e != nil {
		t.Fatal(e)
	}
	first := &configuration.Gateways[0]
	shared := first.Spec.Routes[0]
	shared.ID = "route_shared_a"
	shared.Path = "/shared"
	first.Spec.Routes = append(first.Spec.Routes, shared)
	copyRaw, _ := json.Marshal(*first)
	var other configmodel.Gateway
	if e = json.Unmarshal(copyRaw, &other); e != nil {
		t.Fatal(e)
	}
	other.Metadata.ID = "gw_second"
	other.Spec.NodeSelector.NodeIDs = []string{"node_msk02"}
	other.Spec.Routes = other.Spec.Routes[:1]
	other.Spec.Routes[0].ID = "route_shared_b"
	other.Spec.Routes[0].Hostname = "second.example.net"
	configuration.Gateways = append(configuration.Gateways, other)
	m := Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "scope_installation", Sites: []Site{{"site_msk"}, {"site_other"}}, NodeGroups: []NodeGroup{{"ng_msk", "site_msk"}, {"ng_other", "site_other"}}, Nodes: []Node{{"node_msk01", "site_msk", []string{"ng_msk"}}, {"node_msk02", "site_msk", []string{"ng_msk"}}}, Resources: []Resource{{"resource_portal"}, {"resource_shared"}}, ResourceRoutes: []ResourceRoute{{"resource_portal", "gw_portal", "route_portal"}, {"resource_shared", "gw_portal", "route_shared_a"}, {"resource_shared", "gw_second", "route_shared_b"}}}
	m.Nodes = append(m.Nodes, extraNodes...)
	f := &graphFixture{ctx: ctx, store: store, manifest: m, configuration: configuration, head: securityjournal.Head{AuthorityID: "scope_test", Epoch: 1, RecordedAt: time.Now().UTC()}}
	e = store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		for _, gateway := range configuration.Gateways {
			if _, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,?)`, gateway.Metadata.ID, gateway.Metadata.SiteID); e != nil {
				return e
			}
		}
		for i, resource := range m.Resources {
			if _, e := tx.Exec(ctx, `INSERT INTO resources(id,name,internal_url,public_host) VALUES(?,?,?,?)`, resource.ID, resource.ID, "https://backend.example.net", "resource"+strconv.Itoa(i)+".example.net"); e != nil {
				return e
			}
		}
		if e := BootstrapTx(ctx, tx, 1, m); e != nil {
			return e
		}
		for _, node := range m.Nodes {
			fact := nodeFact{ID: node.ID, SiteID: node.SiteID, Name: node.ID, Labels: map[string]string{"environment": "pilot"}, GroupIDs: node.GroupIDs, CreatedAt: f.head.RecordedAt}
			raw, _ := json.Marshal(fact)
			if _, e := tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, node.ID, node.SiteID, string(raw), f.head.RecordedAt); e != nil {
				return e
			}
		}
		if e := f.insertConfiguration(tx, configuration, "revision_scope_initial", 1); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,'scope_test',1,0,'',TRUE)`)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return f
}

// These tests reset public, so the shared S1 acceptance must supply a separate
// database on its own private cluster, never the CP or identity database.
func roleScopeDisposableDSN(dsn string) bool {
	if os.Getenv("AGP_TEST_ROLE_SCOPE_DISPOSABLE") != "1" {
		return false
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || filepath.Clean(cfg.Host) != cfg.Host {
		return false
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.Host != cfg.Host {
			return false
		}
	}
	if strings.HasPrefix(cfg.Host, "/tmp/agp-role-root-pg.") && strings.HasSuffix(cfg.Host, "/socket") {
		return true
	}
	return os.Getenv("AGP_TEST_S0_DISPOSABLE") == "1" && strings.HasPrefix(cfg.Host, "/tmp/agp-s0-full.") && strings.HasSuffix(cfg.Host, "/cp/socket") && cfg.Database == "agp_role_scope"
}
func (f *graphFixture) insertConfiguration(tx storage.IdentityTx, c configmodel.Configuration, id string, number int) error {
	doc, e := configmodel.Canonicalize(c)
	if e != nil {
		return e
	}
	_, e = tx.Exec(f.ctx, `INSERT INTO config_revisions(id,revision_number,parent_id,schema_version,capacity_profile,canonical_size_bytes,content_digest,canonical_json,state,created_by,created_at) VALUES(?,?,(SELECT revision_id FROM config_head WHERE id=1),?,'pilot-500',?,?,?,'draft','scope_fixture',?)`, id, number, c.APIVersion, len(doc.Canonical), doc.Digest, string(doc.Canonical), f.head.RecordedAt)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(f.ctx, `INSERT INTO config_revision_seals(revision_id,created_at) VALUES(?,?)`, id, f.head.RecordedAt); e != nil {
		return e
	}
	_, e = tx.Exec(f.ctx, `UPDATE config_head SET revision_id=?,row_version=? WHERE id=1`, id, number)
	return e
}
func (f *graphFixture) snapshot(t *testing.T, kind, id string) Snapshot {
	t.Helper()
	var out Snapshot
	e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		var e error
		out, e = Resolve(f.ctx, tx, f.head, kind, id)
		return e
	})
	if e != nil {
		t.Fatal(kind, id, e)
	}
	return out
}
func has(s Snapshot, kind, id string) bool {
	for _, r := range s.Closure {
		if r.ScopeType == kind && r.ScopeID == id {
			return true
		}
	}
	return false
}

func TestScopeGraphSQLite(t *testing.T)   { testScopeGraph(t, false) }
func TestScopeGraphPostgres(t *testing.T) { testScopeGraph(t, true) }

func TestScopeGraphSelectorClosureSQLite(t *testing.T) { testScopeGraphSelectorClosure(t, false) }
func TestScopeGraphSelectorClosurePostgres(t *testing.T) {
	testScopeGraphSelectorClosure(t, true)
}

func testScopeGraphSelectorClosure(t *testing.T, pg bool) {
	f := newGraphFixture(t, pg)
	labels := configmodel.Labels{"environment": "pilot"}
	f.configuration.Gateways[0].Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
	if err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return f.insertConfiguration(tx, f.configuration, "revision_complete_selector", 2)
	}); err != nil {
		t.Fatal(err)
	}
	t.Run("nodes_without_certificates_remain_in_complete_selector", func(t *testing.T) {
		// These are declared managed nodes without enrollment/certificate rows.
		// Positive scope resolution must not prune pending identities.
		resource := f.snapshot(t, "resource", "resource_portal")
		if !has(resource, "node", "node_msk01") || !has(resource, "node", "node_msk02") {
			t.Fatal("selector discarded a declared node without an active certificate")
		}
		if has(f.snapshot(t, "node", "node_msk01"), "resource", "resource_portal") {
			t.Fatal("one node acquired authority over a resource received by two nodes")
		}
	})
	t.Run("revoked_label_match_cannot_shrink_receiving_closure", func(t *testing.T) {
		rollback := errors.New("selector fixture rollback")
		err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			before, err := ResolveNodeManagement(f.ctx, tx, f.head, "node", "node_msk02")
			if err != nil {
				return err
			}
			if _, err := tx.Exec(f.ctx, `INSERT INTO security_node_revocations(node_id,event_id) VALUES('node_msk02','event_selector_revoke')`); err != nil {
				return err
			}
			for _, scope := range []Ref{{"node", "node_msk01"}, {"resource", "resource_portal"}, {"node", "node_msk02"}, {"resource", "resource_shared"}} {
				if _, err := Resolve(f.ctx, tx, f.head, scope.ScopeType, scope.ScopeID); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("revoked selector/explicit target was pruned for %v: %v", scope, err)
				}
			}
			for _, scope := range []Ref{{"node", "node_msk02"}, {"node_group", "ng_msk"}, {"site", "site_msk"}} {
				metadata, err := ResolveNodeManagement(f.ctx, tx, f.head, scope.ScopeType, scope.ScopeID)
				if err != nil || !has(metadata, "node", "node_msk02") || has(metadata, "resource", "resource_portal") || has(metadata, "resource", "resource_shared") {
					t.Fatalf("restrictive node ownership became positive/hidden: %v %v", metadata, err)
				}
				if scope.ScopeType == "node" && metadata.Digest != before.Digest {
					t.Fatal("node revocation changed its immutable management ownership")
				}
			}
			if _, err := ResolveNodeManagement(f.ctx, tx, f.head, "resource", "resource_portal"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("node metadata API accepted resource authority: %v", err)
			}
			changed := nodeFact{ID: "node_msk02", SiteID: "site_other", Name: "Moved", Labels: map[string]string{}, GroupIDs: []string{}, CreatedAt: f.head.RecordedAt}
			raw, _ := json.Marshal(changed)
			if _, err := tx.Exec(f.ctx, `UPDATE managed_nodes SET site_id=?,node_json=? WHERE id=?`, changed.SiteID, string(raw), changed.ID); err != nil {
				return err
			}
			if _, err := ResolveNodeManagement(f.ctx, tx, f.head, "node", "node_msk02"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("metadata resolver accepted ownership drift: %v", err)
			}
			return rollback
		})
		if !errors.Is(err, rollback) {
			t.Fatal(err)
		}
	})
}

func testScopeGraph(t *testing.T, pg bool) {
	f := newGraphFixture(t, pg)
	t.Run("exact_typed_five_scopes_and_shared_resource_boundary", func(t *testing.T) {
		global := f.snapshot(t, "global", "")
		if len(global.Closure) != 1 || len(global.Sources) != 0 {
			t.Fatal("global was inferred from a bounded graph")
		}
		site := f.snapshot(t, "site", "site_msk")
		group := f.snapshot(t, "node_group", "ng_msk")
		node := f.snapshot(t, "node", "node_msk01")
		resource := f.snapshot(t, "resource", "resource_portal")
		if !has(site, "resource", "resource_shared") || !has(group, "resource", "resource_shared") || has(node, "resource", "resource_shared") || !has(node, "resource", "resource_portal") {
			t.Fatal("shared resource scope was incompletely covered")
		}
		if has(site, "site", "site_other") || has(site, "node_group", "ng_other") {
			t.Fatal("unrelated scope leaked into closure")
		}
		if !has(resource, "node", "node_msk01") || CanContain("resource", "node") || CanContain("node", "node_group") {
			t.Fatal("impact became parent authority")
		}
	})
	rollback := errors.New("scope fixture rollback")
	t.Run("canonical_resource_id_never_inferred_from_route", func(t *testing.T) {
		e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := Resolve(f.ctx, tx, f.head, "resource", "route_portal")
			if !errors.Is(e, storage.ErrNotFound) {
				t.Fatal("route ID used as resource authority", e)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("current_config_source_changes_snapshot", func(t *testing.T) {
		before := f.snapshot(t, "resource", "resource_portal")
		e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if e := f.insertConfiguration(tx, f.configuration, "revision_scope_successor", 2); e != nil {
				return e
			}
			after, e := Resolve(f.ctx, tx, f.head, "resource", "resource_portal")
			if e != nil {
				return e
			}
			if before.Digest == after.Digest {
				t.Fatal("head/revision drift retained approved scope digest")
			}
			return rollback
		})
		if !errors.Is(e, rollback) {
			t.Fatal(e)
		}
	})
	t.Run("label_selected_node_missing_sealed_graph_closes", func(t *testing.T) {
		e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			fact := nodeFact{ID: "node_unmapped", SiteID: "site_msk", Name: "Unmapped", Labels: map[string]string{"environment": "pilot"}, GroupIDs: []string{}, CreatedAt: f.head.RecordedAt}
			raw, _ := json.Marshal(fact)
			if _, e := tx.Exec(f.ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, fact.ID, fact.SiteID, string(raw), fact.CreatedAt); e != nil {
				return e
			}
			copyRaw, _ := json.Marshal(f.configuration)
			var changed configmodel.Configuration
			_ = json.Unmarshal(copyRaw, &changed)
			labels := configmodel.Labels{"environment": "pilot"}
			changed.Gateways[0].Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
			if e := f.insertConfiguration(tx, changed, "revision_scope_labels", 2); e != nil {
				return e
			}
			if _, e := Resolve(f.ctx, tx, f.head, "resource", "resource_portal"); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unmapped label match supplied ownership", e)
			}
			return rollback
		})
		if !errors.Is(e, rollback) {
			t.Fatal(e)
		}
	})
	t.Run("actual_node_membership_and_epoch_rechecked", func(t *testing.T) {
		e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			fact := nodeFact{ID: "node_msk01", SiteID: "site_msk", Name: "Changed", Labels: map[string]string{}, GroupIDs: []string{}, CreatedAt: f.head.RecordedAt}
			raw, _ := json.Marshal(fact)
			if _, e := tx.Exec(f.ctx, `UPDATE managed_nodes SET node_json=? WHERE id=?`, string(raw), fact.ID); e != nil {
				return e
			}
			if _, e := Resolve(f.ctx, tx, f.head, "node_group", "ng_msk"); !errors.Is(e, ErrUnavailable) {
				t.Fatal("membership drift accepted", e)
			}
			return rollback
		})
		if !errors.Is(e, rollback) {
			t.Fatal(e)
		}
		e = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			h := f.head
			h.Epoch = 2
			_, e := Resolve(f.ctx, tx, h, "node", "node_msk01")
			if !errors.Is(e, ErrUnavailable) {
				t.Fatal("old graph reused across epoch", e)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("bootstrap_and_sql_graph_mutations_closed_after_activation", func(t *testing.T) {
		if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { return BootstrapTx(f.ctx, tx, 1, f.manifest) }); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("post activation bootstrap accepted", e)
		}
		for _, q := range []string{`UPDATE role_scope_graph SET revision=revision`, `DELETE FROM role_scope_graph`} {
			if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(f.ctx, q); return e }); e == nil {
				t.Fatal("immutable graph mutation accepted")
			}
		}
	})
}

func TestScopeGraphEnvelopeCapacityAndClosedShape(t *testing.T) {
	m := Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "scope_capacity", Sites: []Site{}, NodeGroups: []NodeGroup{}, Nodes: []Node{}, Resources: []Resource{}, ResourceRoutes: []ResourceRoute{}}
	for i := 0; i < 20001; i++ {
		m.Resources = append(m.Resources, Resource{"resource_" + strconv.Itoa(i)})
	}
	_, raw, e := CanonicalManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	var decoded Manifest
	if e = configmodel.DecodeEnvelopeJSON(raw, &decoded); e == nil {
		t.Fatal("ordinary envelope array budget was globally weakened")
	}
	if e = configmodel.DecodeEnvelopeJSONWithArrayLimits(raw, &decoded, map[string]int{"/resources": 100000}); e != nil {
		t.Fatal("explicit graph capacity rejected", e)
	}
	for _, raw := range []string{`{"resources":[],"resources":[]}`, `{"Resources":[]}`, `{"unknown":1}`, `{"resources":["wrong"]}`} {
		if e = configmodel.DecodeEnvelopeJSONWithArrayLimits([]byte(raw), &decoded, map[string]int{"/resources": 100000}); e == nil {
			t.Fatal("invalid graph envelope accepted", raw)
		}
	}
	m.Nodes = nil
	if _, _, e = CanonicalManifest(m); !errors.Is(e, ErrInvalid) {
		t.Fatal("null required graph collection accepted", e)
	}
}
