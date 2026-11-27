package configuration

import (
	"bytes"
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

// Resource identity, route placements and node ownership are installation facts.
// Publish them before activation, rather than deriving authority from the draft.
func resourceScopedFixture(t *testing.T, pg bool) *testFixture {
	t.Helper()
	return fixtureConfigured(t, pg, func(tx storage.IdentityTx) error {
		ctx, now := context.Background(), time.Now().UTC()
		for _, id := range []string{"editor", "waf_author", "waf_approver"} {
			if _, err := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "hash"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management','https://management.test',1,1,?,?)`, id, id, id+"_token", "csrf", "", "", now.Add(time.Hour), now, now, now); err != nil {
				return err
			}
		}
		for _, grant := range []struct{ id, principal, permission string }{{"resource_waf_author", "waf_author", "config.edit"}, {"resource_waf_read", "waf_approver", "config.read"}, {"resource_waf_approve", "waf_approver", "config.approve"}} {
			if _, err := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES(?,?,?,'site','site_msk',1,?)`, "cgrant_"+grant.id, grant.principal, grant.permission, now); err != nil {
				return err
			}
		}
		for _, id := range []string{"gw_portal", "gw_second", "gw_hidden"} {
			if _, err := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,'site_msk')`, id); err != nil {
				return err
			}
		}
		graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "resource_scopes", Sites: []rolescope.Site{{ID: "site_msk"}}, NodeGroups: []rolescope.NodeGroup{{ID: "ng_front", SiteID: "site_msk"}, {ID: "ng_back", SiteID: "site_msk"}}, Nodes: []rolescope.Node{{ID: "node_msk01", SiteID: "site_msk", GroupIDs: []string{"ng_front"}}, {ID: "node_msk02", SiteID: "site_msk", GroupIDs: []string{"ng_back"}}}, Resources: []rolescope.Resource{{ID: "resource_owned"}, {ID: "resource_neighbor"}, {ID: "resource_hidden"}}, ResourceRoutes: []rolescope.ResourceRoute{{ResourceID: "resource_owned", GatewayID: "gw_portal", RouteID: "route_portal"}, {ResourceID: "resource_owned", GatewayID: "gw_second", RouteID: "route_placement"}, {ResourceID: "resource_neighbor", GatewayID: "gw_portal", RouteID: "route_neighbor"}, {ResourceID: "resource_hidden", GatewayID: "gw_hidden", RouteID: "route_hidden"}}}
		for _, resource := range graph.Resources {
			if _, err := tx.Exec(ctx, `INSERT INTO resources(id,name,internal_url,public_host,updated_at) VALUES(?,?,?,?,?)`, resource.ID, resource.ID, "https://backend.example.net", resource.ID+".example.net", now); err != nil {
				return err
			}
		}
		if err := rolescope.BootstrapTx(ctx, tx, 1, graph); err != nil {
			return err
		}
		for _, node := range graph.Nodes {
			raw, err := json.Marshal(map[string]any{"id": node.ID, "siteId": node.SiteID, "name": node.ID, "groupIds": node.GroupIDs, "labels": map[string]string{"environment": "pilot"}, "createdAt": now})
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, node.ID, node.SiteID, string(raw), now); err != nil {
				return err
			}
		}
		return nil
	})
}

func resourceConfiguration(t *testing.T) configmodel.Configuration {
	t.Helper()
	var c configmodel.Configuration
	if err := json.Unmarshal(example(t), &c); err != nil {
		t.Fatal(err)
	}
	base := c.Gateways[0]
	base.Spec.Routes[0].Path = "/owned"
	neighbor := base.Spec.Routes[0]
	neighbor.ID, neighbor.Name, neighbor.Path = "route_neighbor", "Private neighbor", "/neighbor"
	base.Spec.Routes = append(base.Spec.Routes, neighbor)
	c.Gateways[0] = base
	for _, extra := range []struct{ gateway, route, host string }{{"gw_second", "route_placement", "second.example.net"}, {"gw_hidden", "route_hidden", "hidden.example.net"}} {
		var gateway configmodel.Gateway
		if err := json.Unmarshal(mustJSON(t, base), &gateway); err != nil {
			t.Fatal(err)
		}
		gateway.Metadata.ID, gateway.Metadata.Name = extra.gateway, extra.gateway
		gateway.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{"node_msk02"}}
		gateway.Spec.Routes = gateway.Spec.Routes[:1]
		gateway.Spec.Routes[0].ID, gateway.Spec.Routes[0].Hostname, gateway.Spec.Routes[0].Path = extra.route, extra.host, "/placement"
		c.Gateways = append(c.Gateways, gateway)
	}
	return c
}

func resourceCommand(t *testing.T, base *Revision, route configmodel.Route) CreateRevision {
	t.Helper()
	return CreateRevision{BaseRevisionID: base.ID, ResourceChange: &ResourceChange{ResourceID: "resource_owned", GatewayID: "gw_portal", RouteID: "route_portal", Content: mustJSON(t, route)}}
}

func assertResourceView(t *testing.T, r *Revision, resource, gateway, route string, edit bool) {
	t.Helper()
	if r == nil || r.ViewScope != "resource" || len(r.Content) != 0 || r.GatewayView != nil || r.GatewayAccess != nil || r.ResourceView == nil || r.ResourceAccess == nil || !r.ResourceAccess.Read || r.ResourceAccess.Edit != edit || r.ResourceView.ResourceID != resource || r.ResourceView.GatewayID != gateway || r.ResourceView.Route.ID != route {
		t.Fatalf("resource view crossed its object boundary: %#v", r)
	}
}

func TestResourceScopedConfigurationSQLite(t *testing.T)   { testResourceScopedConfiguration(t, false) }
func TestResourceScopedConfigurationPostgres(t *testing.T) { testResourceScopedConfiguration(t, true) }

func testResourceScopedConfiguration(t *testing.T, pg bool) {
	ctx := context.Background()
	actor := Actor{TokenHash: "editor_token", Origin: "https://management.test"}
	t.Run("exact_resource_authority_preserves_all_placements_and_neighbors_under_CAS", func(t *testing.T) {
		f := resourceScopedFixture(t, pg)
		configurationReaderBinding(t, f, "resource_owner", "editor", "config.edit", "resource", "resource_owned", nil)
		cfg := resourceConfiguration(t)
		base := gatewayBase(t, f, cfg)
		access, err := f.service.Access(ctx, actor)
		if err != nil || !access.ResourceRead || !access.ResourceEdit || access.GatewayRead || access.GatewayEdit || access.GlobalRead || access.GlobalEdit || len(access.Sites) != 0 {
			t.Fatalf("resource grant flattened to broader authority: %#v %v", access, err)
		}
		if err := f.service.AuthorizeResource(ctx, actor, true); err != nil {
			t.Fatal(err)
		}
		if err := f.service.AuthorizeGateway(ctx, actor, true); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("resource grant admitted whole-Gateway workflow: %v", err)
		}
		if _, err := f.service.GetRevision(ctx, actor, base.ID); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("full desired snapshot exposed: %v", err)
		}
		if _, err := f.service.GatewayRevision(ctx, actor, base.ID, "gw_portal"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("resource grant exposed whole Gateway: %v", err)
		}
		for _, placement := range []struct{ gateway, route string }{{"gw_portal", "route_portal"}, {"gw_second", "route_placement"}} {
			view, err := f.service.ResourceRevision(ctx, actor, base.ID, "resource_owned", placement.gateway, placement.route)
			if err != nil {
				t.Fatal(err)
			}
			assertResourceView(t, view, "resource_owned", placement.gateway, placement.route, true)
		}
		for _, hidden := range []struct{ resource, gateway, route string }{{"resource_neighbor", "gw_portal", "route_neighbor"}, {"resource_hidden", "gw_hidden", "route_hidden"}, {"resource_owned", "gw_portal", "route_neighbor"}, {"resource_owned", "gw_second", "route_portal"}} {
			if out, err := f.service.ResourceRevision(ctx, actor, base.ID, hidden.resource, hidden.gateway, hidden.route); !errors.Is(err, storage.ErrNotFound) || out != nil {
				t.Fatalf("hidden or incorrectly mapped route exposed: %+v %#v %v", hidden, out, err)
			}
		}
		page, err := f.service.ListResources(ctx, actor, "", 1, "")
		if err != nil || page.RevisionID != base.ID || len(page.Items) != 1 || page.Items[0].ResourceID != "resource_owned" || page.Items[0].GatewayID != "gw_portal" || !page.Items[0].Access.Edit || page.NextCursor == "" {
			t.Fatalf("first authorized page: %#v %v", page, err)
		}
		nextPage, err := f.service.ListResources(ctx, actor, base.ID, 1, page.NextCursor)
		if err != nil || len(nextPage.Items) != 1 || nextPage.Items[0].GatewayID != "gw_second" || nextPage.Items[0].RouteID != "route_placement" || nextPage.NextCursor != "" {
			t.Fatalf("second authorized page or hidden count: %#v %v", nextPage, err)
		}
		hiddenCursor := (resourceListKey{"resource_neighbor", "gw_portal", "route_neighbor"}).cursor()
		if out, err := f.service.ListResources(ctx, actor, base.ID, 1, hiddenCursor); !errors.Is(err, storage.ErrNotFound) || len(out.Items) != 0 || out.RevisionID != "" || out.NextCursor != "" {
			t.Fatalf("foreign cursor became an existence oracle: %#v %v", out, err)
		}
		next := cfg.Gateways[0].Spec.Routes[0]
		next.Upstream.URL = "https://changed.example.net"
		command := resourceCommand(t, base, next)
		changed, err := f.service.ChangeResource(ctx, actor, "resource_exact_change_01", command)
		if err != nil {
			t.Fatal(err)
		}
		assertResourceView(t, changed, "resource_owned", "gw_portal", "route_portal", true)
		full, err := f.service.GetRevision(ctx, f.actor, changed.ID)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Gateways[0].Spec.Routes[0] = next
		expected, err := configmodel.Canonicalize(cfg)
		if err != nil || !bytes.Equal(full.Content, expected.Canonical) {
			t.Fatalf("selected edit overwrote a second placement, neighbor or infrastructure: %v", err)
		}
		if replay, err := f.service.ChangeResource(ctx, actor, "resource_exact_change_01", command); err != nil || replay.ID != changed.ID {
			t.Fatalf("authorized exact retry failed: %#v %v", replay, err)
		}
		if _, err := f.service.ChangeResource(ctx, actor, "resource_stale_change_01", command); !errors.Is(err, ErrRevisionMismatch) {
			t.Fatalf("stale base bypassed CAS: %v", err)
		}
		next.Name = "Different request under the same key"
		if _, err := f.service.ChangeResource(ctx, actor, "resource_exact_change_01", resourceCommand(t, base, next)); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("idempotency key accepted a different object command: %v", err)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 2 || scalar(t, f, `SELECT COUNT(*) FROM audit_events WHERE event_type='config.revision.created'`) != 2 {
			t.Fatal("retry or stale request published an extra revision/audit")
		}
	})
	t.Run("read_only_resource_grant_cannot_write_or_read_neighbor", func(t *testing.T) {
		f := resourceScopedFixture(t, pg)
		configurationReaderBinding(t, f, "resource_reader", "editor", "config.read", "resource", "resource_owned", nil)
		cfg := resourceConfiguration(t)
		base := gatewayBase(t, f, cfg)
		view, err := f.service.ResourceRevision(ctx, actor, base.ID, "resource_owned", "gw_portal", "route_portal")
		if err != nil {
			t.Fatal(err)
		}
		assertResourceView(t, view, "resource_owned", "gw_portal", "route_portal", false)
		if err := f.service.AuthorizeResource(ctx, actor, true); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("read authority admitted mutation workflow: %v", err)
		}
		if out, err := f.service.ChangeResource(ctx, actor, "resource_read_only_01", resourceCommand(t, base, cfg.Gateways[0].Spec.Routes[0])); !errors.Is(err, storage.ErrNotFound) || out != nil {
			t.Fatalf("read-only route changed: %#v %v", out, err)
		}
	})
	for _, tc := range []struct {
		name          string
		fallback      bool
		changeHost    bool
		neighborGrant bool
		allowed       bool
	}{{"empty_space_move", false, false, false, true}, {"path_winner_without_neighbor", true, false, false, false}, {"path_winner_with_neighbor", true, false, true, true}, {"host_winner_without_neighbor", true, true, false, false}, {"host_winner_with_neighbor", true, true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := resourceScopedFixture(t, pg)
			configurationReaderBinding(t, f, "resource_effect", "editor", "config.edit", "resource", "resource_owned", nil)
			if tc.neighborGrant {
				configurationReaderBinding(t, f, "resource_effect_neighbor", "editor", "config.edit", "resource", "resource_neighbor", nil)
			}
			cfg := resourceConfiguration(t)
			if tc.fallback {
				cfg.Gateways[0].Spec.Routes[1].Path = "/"
			}
			base := gatewayBase(t, f, cfg)
			next := cfg.Gateways[0].Spec.Routes[0]
			if tc.changeHost {
				next.Hostname = "new-resource.example.net"
			} else {
				next.Path = "/new-owned"
			}
			out, err := f.service.ChangeResource(ctx, actor, "resource_routing_effect_01", resourceCommand(t, base, next))
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
				assertResourceView(t, out, "resource_owned", "gw_portal", "route_portal", true)
			} else if !errors.Is(err, storage.ErrNotFound) || out != nil {
				t.Fatalf("indirect winner change lacked neighbor edit authority: %#v %v", out, err)
			}
			want := int64(1)
			if tc.allowed {
				want++
			}
			if n := scalar(t, f, `SELECT COUNT(*) FROM config_revisions`); n != want {
				t.Fatalf("unexpected publication count: %d", n)
			}
		})
	}
	for _, mode := range []string{"disjoint", "shared", "unknown"} {
		t.Run("cross_gateway_host_"+mode, func(t *testing.T) {
			f := resourceScopedFixture(t, pg)
			configurationReaderBinding(t, f, "resource_cross_host", "editor", "config.edit", "resource", "resource_owned", nil)
			cfg := resourceConfiguration(t)
			if mode == "shared" {
				cfg.Gateways[1].Spec.NodeSelector.NodeIDs = []string{"node_msk01"}
			} else if mode == "unknown" {
				cfg.Gateways[1].Spec.NodeSelector.NodeIDs = []string{"node_missing"}
			}
			base := gatewayBase(t, f, cfg)
			next := cfg.Gateways[0].Spec.Routes[0]
			next.Hostname = cfg.Gateways[1].Spec.Routes[0].Hostname
			out, err := f.service.ChangeResource(ctx, actor, "resource_cross_host_001", resourceCommand(t, base, next))
			switch mode {
			case "disjoint":
				if err != nil {
					t.Fatal(err)
				}
				assertResourceView(t, out, "resource_owned", "gw_portal", "route_portal", true)
			case "shared":
				if !errors.Is(err, storage.ErrConflict) || out != nil {
					t.Fatalf("overlapping host receivers accepted: %#v %v", out, err)
				}
			case "unknown":
				if !errors.Is(err, rolescope.ErrUnavailable) || out != nil {
					t.Fatalf("unknown receivers silently treated as disjoint: %#v %v", out, err)
				}
			}
		})
	}
	for _, mode := range []string{"revocation", "expiry"} {
		t.Run("saved_response_rechecks_"+mode, func(t *testing.T) {
			f := resourceScopedFixture(t, pg)
			expires := time.Now().UTC().Add(time.Minute)
			configurationReaderBinding(t, f, "resource_replay", "editor", "config.edit", "resource", "resource_owned", &expires)
			cfg := resourceConfiguration(t)
			base := gatewayBase(t, f, cfg)
			next := cfg.Gateways[0].Spec.Routes[0]
			next.Name = "Saved resource response"
			command := resourceCommand(t, base, next)
			if _, err := f.service.ChangeResource(ctx, actor, "resource_replay_current_1", command); err != nil {
				t.Fatal(err)
			}
			if mode == "revocation" {
				configurationWithdrawFixture(t, f, "rbinding_resource_replay")
			} else {
				clock := &configurationRoleClock{underlying: f.service.current}
				clock.advance.Store(true)
				f.service.current = clock
			}
			out, err := f.service.ChangeResource(ctx, actor, "resource_replay_current_1", command)
			if out != nil || !(errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrPermissionDenied)) {
				t.Fatalf("saved response survived lost authority: %#v %v", out, err)
			}
			if scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 2 {
				t.Fatal("replay changed immutable history")
			}
		})
	}
	for _, mode := range []string{"metadata_drift", "label_drift", "source_error", "last_head_expiry"} {
		t.Run("final_"+mode+"_atomically_rolls_back_without_callback_retry", func(t *testing.T) {
			f := resourceScopedFixture(t, pg)
			expires := time.Now().UTC().Add(time.Minute)
			configurationReaderBinding(t, f, "resource_final", "editor", "config.edit", "resource", "resource_owned", &expires)
			cfg := resourceConfiguration(t)
			labels := configmodel.Labels{"environment": "pilot"}
			cfg.Gateways[0].Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
			if err := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return gatewayChangeNodeLabel(ctx, tx, "node_msk02", "unselected") }); err != nil {
				t.Fatal(err)
			}
			base := gatewayBase(t, f, cfg)
			fault := &resourceFinalFault{underlying: f.service.current, mode: mode}
			f.service.current = fault
			next := cfg.Gateways[0].Spec.Routes[0]
			next.Name = "Must roll back with the final source check"
			out, err := f.service.ChangeResource(ctx, actor, "resource_final_"+mode, resourceCommand(t, base, next))
			if mode == "source_error" {
				if !errors.Is(err, errResourceAuthoritySource) {
					t.Fatalf("source outage hidden as denial: %v", err)
				}
			} else if !errors.Is(err, storage.ErrPermissionDenied) {
				t.Fatalf("late source drift or expiry authorized mutation: %v", err)
			}
			if out != nil || fault.writes.Load() != 1 || fault.callbacks.Load() != 1 || !fault.finalRead.Load() {
				t.Fatalf("positive result, missed fault, or callback retry: %#v writes=%d callbacks=%d final=%t", out, fault.writes.Load(), fault.callbacks.Load(), fault.finalRead.Load())
			}
			for _, check := range []struct {
				query string
				want  int64
			}{{`SELECT COUNT(*) FROM config_revisions`, 1}, {`SELECT COUNT(*) FROM config_revision_seals`, 1}, {`SELECT COUNT(*) FROM config_gateways`, 3}, {`SELECT COUNT(*) FROM config_routes`, 4}, {`SELECT COUNT(*) FROM audit_events WHERE event_type='config.revision.created'`, 1}} {
				if n := scalar(t, f, check.query); n != check.want {
					t.Fatalf("partial commit: %s => %d", check.query, n)
				}
			}
			if scalar(t, f, `SELECT COUNT(*) FROM config_requests WHERE request_key=?`, "resource_final_"+mode) != 0 || scalar(t, f, `SELECT COUNT(*) FROM config_head WHERE revision_id=?`, base.ID) != 1 || scalar(t, f, `SELECT COUNT(*) FROM resources WHERE id='resource_owned' AND name='resource_owned'`) != 1 {
				t.Fatal("head, request handle or metadata drift escaped rollback")
			}
		})
	}
	t.Run("assigned_WAF_allows_display_name_but_requires_trusted_resolution_for_security", func(t *testing.T) {
		f := resourceScopedFixture(t, pg)
		configurationReaderBinding(t, f, "resource_zone", "editor", "config.edit", "resource", "resource_owned", nil)
		f.service.WithWAFQualifier(&testWafQualifier{}).WithTrustedInventory(&testTrustedInventory{source: "8"})
		policy := createWaf(t, f)
		validateWaf(t, f, policy)
		approveWaf(t, f, policy)
		if _, err := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), policy.ID, "resource_policy_publish1", WafPolicyPublicationRequest{policy.ContentDigest}); err != nil {
			t.Fatal(err)
		}
		cfg := resourceConfiguration(t)
		// A trusted resolution checks original bindings of every Gateway in
		// the Site, including neighbors outside the selected zone membership.
		for i := range cfg.Gateways {
			cfg.Gateways[i].Spec.WAF.PolicyRevisionID = policy.ID
			cfg.Gateways[i].Spec.ComponentProfileRef = configmodel.Reference{ID: "native_profile", Digest: "sha256:" + strings.Repeat("2", 64)}
		}
		base := gatewayBase(t, f, cfg)
		zone := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_resource", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		resolution := resolveTrustedZone(t, f, zone, base)
		assigned, err := f.service.MaterializeZone(ctx, wafActor(f, "waf_author"), "resource_zone_materialize", trustedChange(base, zone, resolution))
		if err != nil {
			t.Fatal(err)
		}
		next := cfg.Gateways[0].Spec.Routes[0]
		next.Name = "Updated display name under the same trusted WAF binding"
		renamed, err := f.service.ChangeResource(ctx, actor, "resource_zone_rename_001", resourceCommand(t, assigned, next))
		if err != nil {
			t.Fatal(err)
		}
		assertResourceView(t, renamed, "resource_owned", "gw_portal", "route_portal", true)
		if scalar(t, f, `SELECT COUNT(*) FROM config_revision_zone_assignments WHERE revision_id=?`, renamed.ID) != 1 {
			t.Fatal("display-only edit lost trusted assignment")
		}
		next.Upstream.URL = "https://security-change.example.net"
		out, err := f.service.ChangeResource(ctx, actor, "resource_zone_security1", resourceCommand(t, renamed, next))
		var invalid *configmodel.ValidationError
		if out != nil || !errors.As(err, &invalid) {
			t.Fatalf("security edit bypassed the trusted zone workflow: %#v %v", out, err)
		}
		found := false
		for _, issue := range invalid.Issues {
			found = found || issue.Code == "zone_resolution_required"
		}
		if !found || scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 3 || scalar(t, f, `SELECT COUNT(*) FROM config_requests WHERE request_key='resource_zone_security1'`) != 0 {
			t.Fatalf("security edit lost its explicit controlled-workflow error or partially committed: %v", err)
		}
	})
}

var errResourceAuthoritySource = errors.New("synthetic resource authority SQL outage")

type resourceFinalFault struct {
	underlying Current
	mode       string
	writes     atomic.Int64
	callbacks  atomic.Int64
	finalRead  atomic.Bool
}

func (c *resourceFinalFault) Head(ctx context.Context) (securityjournal.Head, error) {
	h, err := c.underlying.Head(ctx)
	if err == nil && c.mode == "last_head_expiry" && c.finalRead.Load() {
		h.RecordedAt = h.RecordedAt.Add(2 * time.Minute)
	}
	return h, err
}

func (c *resourceFinalFault) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		c.callbacks.Add(1)
		return fn(resourceFinalFaultTx{IdentityTx: tx, fault: c}, h)
	})
}

type resourceFinalFaultTx struct {
	storage.IdentityTx
	fault *resourceFinalFault
}

func (tx resourceFinalFaultTx) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	n, err := tx.IdentityTx.Exec(ctx, query, args...)
	if err == nil && strings.Contains(query, "INSERT INTO config_revisions") {
		tx.fault.writes.Add(1)
	}
	return n, err
}

func (tx resourceFinalFaultTx) Query(ctx context.Context, query string, args ...any) (storage.IdentityRows, error) {
	trigger := strings.Contains(query, "FROM resources")
	if tx.fault.mode == "label_drift" || tx.fault.mode == "last_head_expiry" {
		trigger = strings.Contains(query, "FROM managed_nodes n WHERE n.authority_epoch")
	}
	if trigger && tx.fault.writes.Load() > 0 && tx.fault.finalRead.CompareAndSwap(false, true) {
		switch tx.fault.mode {
		case "metadata_drift":
			if _, err := tx.IdentityTx.Exec(ctx, `UPDATE resources SET name='Changed underneath',updated_at=? WHERE id='resource_owned'`, time.Now().UTC().Add(time.Second)); err != nil {
				return nil, err
			}
		case "label_drift":
			if err := gatewayChangeNodeLabel(ctx, tx.IdentityTx, "node_msk02", "pilot"); err != nil {
				return nil, err
			}
		case "source_error":
			return nil, errResourceAuthoritySource
		}
	}
	return tx.IdentityTx.Query(ctx, query, args...)
}
