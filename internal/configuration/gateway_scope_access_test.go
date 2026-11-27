package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func gatewayScopedFixture(t *testing.T, pg bool) *testFixture {
	t.Helper()
	return fixtureConfigured(t, pg, func(tx storage.IdentityTx) error {
		ctx := context.Background()
		now := time.Now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES('editor','editor','hash',FALSE)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES('editor','editor','editor_token','csrf','','',?,?,'management','https://management.test',1,1,?,?)`, now.Add(time.Hour), now, now, now); err != nil {
			return err
		}
		for _, owner := range []struct{ id, site string }{{"gw_portal", "site_msk"}, {"gw_second", "site_msk"}, {"gw_shared", "site_msk"}, {"gw_other", "site_other"}} {
			if _, err := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,?)`, owner.id, owner.site); err != nil {
				return err
			}
		}
		graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "gateway_scopes", Sites: []rolescope.Site{{ID: "site_msk"}, {ID: "site_other"}}, NodeGroups: []rolescope.NodeGroup{{ID: "ng_front", SiteID: "site_msk"}, {ID: "ng_back", SiteID: "site_msk"}}, Nodes: []rolescope.Node{{ID: "node_msk01", SiteID: "site_msk", GroupIDs: []string{"ng_front"}}, {ID: "node_msk02", SiteID: "site_msk", GroupIDs: []string{"ng_back"}}, {ID: "node_other01", SiteID: "site_other", GroupIDs: []string{}}}, Resources: []rolescope.Resource{}, ResourceRoutes: []rolescope.ResourceRoute{}}
		if err := rolescope.BootstrapTx(ctx, tx, 1, graph); err != nil {
			return err
		}
		for _, node := range graph.Nodes {
			raw, _ := json.Marshal(map[string]any{"id": node.ID, "siteId": node.SiteID, "name": node.ID, "groupIds": node.GroupIDs, "labels": map[string]string{"environment": "pilot"}, "createdAt": now})
			if _, err := tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, node.ID, node.SiteID, string(raw), now); err != nil {
				return err
			}
		}
		return nil
	})
}

func gatewayConfiguration(t *testing.T) configmodel.Configuration {
	t.Helper()
	var cfg configmodel.Configuration
	if err := json.Unmarshal(example(t), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []struct{ id, site, node string }{{"gw_second", "site_msk", "node_msk02"}, {"gw_shared", "site_msk", "node_msk01"}, {"gw_other", "site_other", "node_other01"}} {
		var g configmodel.Gateway
		if err := json.Unmarshal(mustJSON(t, cfg.Gateways[0]), &g); err != nil {
			t.Fatal(err)
		}
		g.Metadata.ID, g.Metadata.SiteID, g.Metadata.Name = extra.id, extra.site, extra.id
		g.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{extra.node}}
		if extra.id == "gw_shared" {
			g.Spec.NodeSelector.NodeIDs = []string{"node_msk01", "node_msk02"}
		}
		g.Spec.Routes[0].ID, g.Spec.Routes[0].Hostname = "route_"+extra.id, extra.id[3:]+".example.net"
		cfg.Gateways = append(cfg.Gateways, g)
	}
	return cfg
}

func gatewayBase(t *testing.T, f *testFixture, cfg configmodel.Configuration) *Revision {
	t.Helper()
	r, err := f.service.CreateRevision(context.Background(), f.actor, "gateway_fixture_base_001", CreateRevision{Content: mustJSON(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGatewayScopedConfigurationSQLite(t *testing.T)   { testGatewayScopedConfiguration(t, false) }
func TestGatewayScopedConfigurationPostgres(t *testing.T) { testGatewayScopedConfiguration(t, true) }

func testGatewayScopedConfiguration(t *testing.T, pg bool) {
	ctx := context.Background()
	actor := Actor{TokenHash: "editor_token", Origin: "https://management.test"}
	t.Run("node_edit_has_object_workflow_without_site_or_global_authority", func(t *testing.T) {
		f := gatewayScopedFixture(t, pg)
		configurationReaderBinding(t, f, "gateway_node", "editor", "config.edit", "node", "node_msk01", nil)
		base := gatewayBase(t, f, gatewayConfiguration(t))
		access, err := f.service.Access(ctx, actor)
		if err != nil || !access.GatewayRead || !access.GatewayEdit || access.GlobalRead || access.GlobalEdit || len(access.Sites) != 0 {
			t.Fatalf("scoped workflow flattened: %#v %v", access, err)
		}
		if err := f.service.AuthorizeGateway(ctx, actor, true); err != nil {
			t.Fatal(err)
		}
		if err := f.service.AuthorizePermission(ctx, actor, "config.edit", true); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("full workflow admitted: %v", err)
		}
		view, err := f.service.GatewayRevision(ctx, actor, base.ID, "gw_portal")
		if err != nil || view.GatewayAccess == nil || !view.GatewayAccess.Edit || view.GatewayView == nil || len(view.Content) != 0 {
			t.Fatalf("scoped view: %#v %v", view, err)
		}
		for _, hidden := range []string{"gw_shared", "gw_second", "gw_other"} {
			if _, err := f.service.GatewayRevision(ctx, actor, base.ID, hidden); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("uncovered recipient exposed %s: %v", hidden, err)
			}
		}
		if _, err := f.service.GetRevision(ctx, actor, base.ID); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("full snapshot exposed: %v", err)
		}
		page, err := f.service.ListGateways(ctx, actor, "", 1, "")
		if err != nil || page.RevisionID != base.ID || len(page.Items) != 1 || page.Items[0].ID != "gw_portal" || page.NextCursor != "" || !page.Items[0].Access.Edit || page.Items[0].DeploymentState != "unknown" {
			t.Fatalf("hidden metadata/page count escaped: %#v %v", page, err)
		}
		if _, err := f.service.ListGateways(ctx, actor, base.ID, 1, "gw_other"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("hidden cursor accepted: %v", err)
		}
	})
	t.Run("mixed_node_group_union_covers_every_recipient_and_survives_own_CAS", func(t *testing.T) {
		f := gatewayScopedFixture(t, pg)
		configurationReaderBinding(t, f, "gateway_front", "editor", "config.edit", "node", "node_msk01", nil)
		configurationReaderBinding(t, f, "gateway_back", "editor", "config.edit", "node_group", "ng_back", nil)
		cfg := gatewayConfiguration(t)
		base := gatewayBase(t, f, cfg)
		page, err := f.service.ListGateways(ctx, actor, "", 1, "")
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != "gw_portal" || page.NextCursor != "gw_portal" {
			t.Fatalf("first authorized page: %#v %v", page, err)
		}
		nextPage, err := f.service.ListGateways(ctx, actor, page.RevisionID, 1, page.NextCursor)
		if err != nil || len(nextPage.Items) != 1 || nextPage.Items[0].ID != "gw_second" || nextPage.NextCursor != "gw_second" {
			t.Fatalf("second authorized page: %#v %v", nextPage, err)
		}
		next := cfg.Gateways[2]
		next.Metadata.Name = "Reviewed receiving closure"
		command := CreateRevision{BaseRevisionID: base.ID, GatewayChange: &GatewayChange{GatewayID: next.Metadata.ID, Content: mustJSON(t, next)}}
		changed, err := f.service.ChangeGateway(ctx, actor, "gateway_union_write_001", command)
		if err != nil || changed.GatewayAccess == nil || !changed.GatewayAccess.Edit || len(changed.Content) != 0 {
			t.Fatalf("own CAS invalidated authority: %#v %v", changed, err)
		}
		full, err := f.service.GetRevision(ctx, f.actor, changed.ID)
		if err != nil {
			t.Fatal(err)
		}
		neighbor, err := gatewayFrom(full, "gw_other")
		if err != nil || neighbor.Metadata.Name != "gw_other" {
			t.Fatal("hidden neighbor overwritten", err)
		}
		if replay, err := f.service.ChangeGateway(ctx, actor, "gateway_union_write_001", command); err != nil || replay.ID != changed.ID {
			t.Fatal("exact retry lost", err)
		}
		if _, err := f.service.ChangeGateway(ctx, actor, "gateway_union_stale_001", command); !errors.Is(err, ErrRevisionMismatch) {
			t.Fatalf("stale base won: %v", err)
		}
		configurationWithdrawFixture(t, f, "rbinding_gateway_back")
		if _, err := f.service.ChangeGateway(ctx, actor, "gateway_union_write_001", command); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("replay outlived current authority: %v", err)
		}
	})
	t.Run("read_only_and_resource_grants_do_not_authorize_gateway_mutation", func(t *testing.T) {
		f := gatewayScopedFixture(t, pg)
		configurationReaderBinding(t, f, "gateway_read", "editor", "config.read", "node_group", "ng_front", nil)
		configurationReaderBinding(t, f, "gateway_resource", "editor", "config.edit", "resource", "resource_fixture", nil)
		cfg := gatewayConfiguration(t)
		base := gatewayBase(t, f, cfg)
		view, err := f.service.GatewayRevision(ctx, actor, base.ID, "gw_portal")
		if err != nil || view.GatewayAccess == nil || !view.GatewayAccess.Read || view.GatewayAccess.Edit {
			t.Fatalf("resource grant broadened whole gateway: %#v %v", view, err)
		}
		if err := f.service.AuthorizeGateway(ctx, actor, true); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("resource authority admitted gateway mutation: %v", err)
		}
		command := CreateRevision{BaseRevisionID: base.ID, GatewayChange: &GatewayChange{GatewayID: "gw_portal", Content: mustJSON(t, cfg.Gateways[0])}}
		if _, err := f.service.ChangeGateway(ctx, actor, "gateway_read_write_001", command); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("read-only wrote gateway: %v", err)
		}
	})
	t.Run("scoped_editor_cannot_move_selector_or_shared_infrastructure", func(t *testing.T) {
		f := gatewayScopedFixture(t, pg)
		configurationReaderBinding(t, f, "gateway_lock", "editor", "config.edit", "node", "node_msk01", nil)
		configurationReaderBinding(t, f, "gateway_lock_back", "editor", "config.edit", "node_group", "ng_back", nil)
		cfg := gatewayConfiguration(t)
		base := gatewayBase(t, f, cfg)
		for _, field := range []string{"selector", "tls", "component", "ownership"} {
			var next configmodel.Gateway
			_ = json.Unmarshal(mustJSON(t, cfg.Gateways[0]), &next)
			switch field {
			case "selector":
				labels := configmodel.Labels{"environment": "pilot"}
				next.Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
			case "tls":
				next.Spec.TLS.CertificateVersionID = "certificate_other"
			case "component":
				next.Spec.ComponentProfileRef.ID = "component_other"
			case "ownership":
				if next.Spec.Ownership == "adopted" {
					next.Spec.Ownership = "managed"
				} else {
					next.Spec.Ownership = "adopted"
				}
			}
			if _, err := f.service.ChangeGateway(ctx, actor, "gateway_locked_"+field, CreateRevision{BaseRevisionID: base.ID, GatewayChange: &GatewayChange{GatewayID: next.Metadata.ID, Content: mustJSON(t, next)}}); !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatal("structural lock did not deny a fully covered change", field, err)
			}
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_revisions`); n != 1 {
			t.Fatal("denied infrastructure created revision", n)
		}
	})
	for _, mode := range []string{"source_error", "label_drift", "last_head_expiry"} {
		t.Run("final_"+mode+"_rolls_back_all_positive_effects", func(t *testing.T) {
			f := gatewayScopedFixture(t, pg)
			expires := time.Now().UTC().Add(time.Minute)
			configurationReaderBinding(t, f, "gateway_final", "editor", "config.edit", "node", "node_msk01", &expires)
			cfg := gatewayConfiguration(t)
			labels := configmodel.Labels{"environment": "pilot"}
			cfg.Gateways[0].Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
			if err := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return gatewayChangeNodeLabel(ctx, tx, "node_msk02", "unselected") }); err != nil {
				t.Fatal(err)
			}
			base := gatewayBase(t, f, cfg)
			fault := &gatewayFinalFault{underlying: f.service.current, mode: mode}
			f.service.current = fault
			next := cfg.Gateways[0]
			next.Metadata.Name = "Must not commit"
			_, err := f.service.ChangeGateway(ctx, actor, "gateway_final_"+mode, CreateRevision{BaseRevisionID: base.ID, GatewayChange: &GatewayChange{GatewayID: next.Metadata.ID, Content: mustJSON(t, next)}})
			if mode == "source_error" {
				if !errors.Is(err, errGatewayAuthoritySource) {
					t.Fatalf("outage swallowed as scope denial: %v", err)
				}
			} else if !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatalf("late authority accepted: %v", err)
			}
			if fault.writes.Load() != 1 || !fault.finalRead.Load() {
				t.Fatalf("fault missed boundary or callback retried: %d %v", fault.writes.Load(), fault.finalRead.Load())
			}
			if n := scalar(t, f, `SELECT COUNT(*) FROM config_revisions`); n != 1 {
				t.Fatal("positive revision committed", n)
			}
			if n := scalar(t, f, `SELECT COUNT(*) FROM audit_events WHERE event_type='config.revision.created'`); n != 1 {
				t.Fatal("positive audit committed", n)
			}
			if n := scalar(t, f, `SELECT COUNT(*) FROM config_requests WHERE request_key=?`, "gateway_final_"+mode); n != 0 {
				t.Fatal("failed mutation became replayable", n)
			}
		})
	}
}

var errGatewayAuthoritySource = errors.New("synthetic gateway authority SQL outage")

type gatewayFinalFault struct {
	underlying Current
	mode       string
	writes     atomic.Int64
	finalRead  atomic.Bool
}

func (c *gatewayFinalFault) Head(ctx context.Context) (securityjournal.Head, error) {
	h, err := c.underlying.Head(ctx)
	if c.mode == "last_head_expiry" && c.finalRead.Load() {
		h.RecordedAt = h.RecordedAt.Add(2 * time.Minute)
	}
	return h, err
}

func (c *gatewayFinalFault) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		return fn(gatewayFinalFaultTx{IdentityTx: tx, fault: c}, h)
	})
}

type gatewayFinalFaultTx struct {
	storage.IdentityTx
	fault *gatewayFinalFault
}

func (tx gatewayFinalFaultTx) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	n, err := tx.IdentityTx.Exec(ctx, query, args...)
	if err == nil && strings.Contains(query, "INSERT INTO config_revisions") {
		tx.fault.writes.Add(1)
	}
	return n, err
}

func (tx gatewayFinalFaultTx) Query(ctx context.Context, query string, args ...any) (storage.IdentityRows, error) {
	if tx.fault.writes.Load() > 0 && strings.Contains(query, "FROM managed_nodes n WHERE n.authority_epoch") && tx.fault.finalRead.CompareAndSwap(false, true) {
		switch tx.fault.mode {
		case "source_error":
			return nil, errGatewayAuthoritySource
		case "label_drift":
			if err := gatewayChangeNodeLabel(ctx, tx.IdentityTx, "node_msk02", "pilot"); err != nil {
				return nil, err
			}
		}
	}
	return tx.IdentityTx.Query(ctx, query, args...)
}

func gatewayChangeNodeLabel(ctx context.Context, tx storage.IdentityTx, id, value string) error {
	rows, err := tx.Query(ctx, `SELECT node_json FROM managed_nodes WHERE id=?`, id)
	if err != nil {
		return err
	}
	var raw string
	if !rows.Next() {
		rows.Close()
		return storage.ErrNotFound
	}
	err = rows.Scan(&raw)
	rows.Close()
	if err != nil {
		return err
	}
	var node map[string]any
	if err = json.Unmarshal([]byte(raw), &node); err != nil {
		return err
	}
	node["labels"] = map[string]string{"environment": value}
	encoded, err := json.Marshal(node)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE managed_nodes SET node_json=? WHERE id=?`, string(encoded), id)
	return err
}
