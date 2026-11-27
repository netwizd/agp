package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func zoneBody(id string, membership configmodel.ZoneMembership) configmodel.WafZone {
	return configmodel.WafZone{APIVersion: "agp.waf-zone/v1alpha1", Kind: "WafZone", Metadata: configmodel.ZoneMetadata{ID: id, Name: "Authored WAF zone", SiteID: "site_msk", OwnerID: "s1_admin"}, Spec: configmodel.ZoneSpec{PolicyRevisionID: "waf_balanced_v1", Mode: "detection", Membership: membership, Reason: "Explicit authoring fixture reason"}}
}

func createZone(t *testing.T, f *testFixture, key, base string, body configmodel.WafZone) *ZoneRevision {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.service.CreateZoneRevision(context.Background(), f.actor, key, ZoneCreate{BaseRevisionID: base, Content: raw})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func zonePreviewFixture(t *testing.T, pg bool) (*testFixture, *Revision, *CatalogSnapshot, configmodel.Catalog) {
	t.Helper()
	f := fixture(t, pg)
	ctx := context.Background()
	if err := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `INSERT INTO groups(id,name) VALUES('grp_AbCdEf123','Zone fixture group')`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	catalog := configmodel.Catalog{APIVersion: "agp.catalog/v1alpha1", ID: "catalog_zone_test", SourceKind: "operator_declared", SourceRef: "WAF zone test declared inventory", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Sites: []configmodel.CatalogSite{{ID: "site_msk"}}, Nodes: []configmodel.CatalogNode{{ID: "node_msk01", SiteID: "site_msk", Labels: configmodel.Labels{}, NodeGroupIDs: []string{}}}, Groups: []string{"grp_AbCdEf123"}, Inputs: []configmodel.CatalogInput{
		{Kind: "component_profile", ID: "profile_nginx_waf_001", Digest: "sha256:" + strings.Repeat("a", 64), SiteID: "site_msk", State: "published"},
		{Kind: "certificate", ID: "cert_portal_v1", Digest: "sha256:" + strings.Repeat("b", 64), SiteID: "site_msk", State: "published"},
		{Kind: "waf_policy", ID: "waf_balanced_v1", Digest: "sha256:" + strings.Repeat("c", 64), SiteID: "site_msk", State: "published"},
	}}
	raw, _ := json.Marshal(catalog)
	snapshot, err := f.service.ImportCatalog(ctx, f.actor, "zone_catalog_create01", raw, configmodel.JSON)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := f.service.CreateRevision(ctx, f.actor, "zone_config_create01", CreateRevision{Content: example(t)})
	if err != nil {
		t.Fatal(err)
	}
	return f, revision, snapshot, catalog
}

func previewRequest(r *Revision, c *CatalogSnapshot) ZonePreviewRequest {
	return ZonePreviewRequest{BaseRevisionID: r.ID, CatalogSnapshotID: c.ID, CapacityProfile: "pilot-500", Action: "reconcile"}
}

func TestZoneAuthoringSQLite(t *testing.T)   { testZoneAuthoring(t, false) }
func TestZoneAuthoringPostgres(t *testing.T) { testZoneAuthoring(t, true) }
func testZoneAuthoring(t *testing.T, pg bool) {
	t.Run("immutable_exact_replay_per_stable_zone_CAS", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		body := zoneBody("zone_cas", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		first := createZone(t, f, "zone_create_first01", "", body)
		body.Metadata.Name = "A subsequent immutable body"
		raw, _ := json.Marshal(body)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, key := range []string{"zone_concurrent_0001", "zone_concurrent_0002"} {
			wg.Add(1)
			go func(key string) {
				defer wg.Done()
				_, e := f.service.CreateZoneRevision(ctx, f.actor, key, ZoneCreate{BaseRevisionID: first.ID, Content: raw})
				errs <- e
			}(key)
		}
		wg.Wait()
		close(errs)
		success, stale := 0, 0
		for err := range errs {
			if err == nil {
				success++
			} else if errors.Is(err, ErrRevisionMismatch) {
				stale++
			} else {
				t.Fatal(err)
			}
		}
		if success != 1 || stale != 1 {
			t.Fatalf("zone CAS failed: success=%d stale=%d", success, stale)
		}
		body.Metadata.Name = "Authored WAF zone"
		raw, _ = json.Marshal(body)
		again, err := f.service.CreateZoneRevision(ctx, f.actor, "zone_create_first01", ZoneCreate{Content: raw})
		if err != nil || again.ID != first.ID || string(again.Content) != string(first.Content) || again.Revision != "0" || again.State != "draft" {
			t.Fatalf("immutable retry returned current head: %#v %v", again, err)
		}
		body.Spec.Reason = "A different request fingerprint"
		raw, _ = json.Marshal(body)
		if _, err = f.service.CreateZoneRevision(ctx, f.actor, "zone_create_first01", ZoneCreate{Content: raw}); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("different request replay accepted: %v", err)
		}
		page, err := f.service.ListZones(ctx, f.actor, 1, "", "site_msk")
		if err != nil || len(page.Items) != 1 || page.Items[0].ID == first.ID || len(page.Items[0].Content) > 0 {
			t.Fatalf("list did not return current authoring metadata: %#v %v", page, err)
		}
		for _, q := range []string{
			`UPDATE config_zone_revisions SET canonical_json='{}' WHERE id=?`,
			`DELETE FROM config_zone_revisions WHERE id=?`,
			`UPDATE config_zone_heads SET revision_id=? WHERE zone_id='zone_cas'`,
		} {
			if err = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q, first.ID); return e }); err == nil {
				t.Fatalf("immutable/CAS database guard accepted %s", q)
			}
		}
	})
	t.Run("owner_identity_and_typed_bodies", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		body := zoneBody("zone_owner", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		first := createZone(t, f, "zone_owner_create01", "", body)
		body.Metadata.SiteID = "site_elsewhere"
		raw, _ := json.Marshal(body)
		if _, err := f.service.CreateZoneRevision(ctx, f.actor, "zone_owner_site_001", ZoneCreate{BaseRevisionID: first.ID, Content: raw}); err == nil {
			t.Fatal("stable zone changed Site")
		}
		body.Metadata.SiteID = "site_msk"
		body.Metadata.OwnerID = "missing_owner"
		raw, _ = json.Marshal(body)
		if _, err := f.service.CreateZoneRevision(ctx, f.actor, "zone_owner_bad_0001", ZoneCreate{BaseRevisionID: first.ID, Content: raw}); err == nil {
			t.Fatal("nonexistent owner accepted")
		}
		if _, err := f.service.CreateZoneRevision(ctx, f.actor, "zone_typed_bad_0001", ZoneCreate{Content: json.RawMessage(`{"apiVersion":"agp.waf-zone/v1alpha1","kind":"WafZone","metadata":{},"spec":{},"published":true}`)}); err == nil {
			t.Fatal("unknown field or required body fields accepted")
		}
	})
	t.Run("durable_frozen_membership_exact_pins_not_runtime_resolution", func(t *testing.T) {
		f, revision, snapshot, catalog := zonePreviewFixture(t, pg)
		ctx := context.Background()
		body := zoneBody("zone_preview", configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "pilot"}})
		zone := createZone(t, f, "zone_preview_create01", "", body)
		request := previewRequest(revision, snapshot)
		report, err := f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_preview_first01", request)
		if err != nil {
			t.Fatal(err)
		}
		if report.Purpose != "authoring_preview" || report.AssignmentSource != "hypothetical_authoring_membership" || report.Deployable || !report.AuthoringValid || report.AuthorID != "s1_admin" || report.CatalogDigest != snapshot.ContentDigest || report.ConfigDigest != revision.ContentDigest || report.HeadsDigest == "" || report.ExpiresAt.Sub(report.CreatedAt) != 30*time.Minute {
			t.Fatalf("preview lost boundary, identity or exact pins: %#v", report)
		}
		if report.CreatedAt.Nanosecond()%1000 != 0 || report.ExpiresAt.Nanosecond()%1000 != 0 {
			t.Fatal("preview timestamps exceed persistent PostgreSQL precision")
		}
		var storedCreated, storedExpires time.Time
		if err = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			return securitystate.One(ctx, tx, `SELECT created_at,expires_at FROM config_zone_previews WHERE id=?`, []any{report.ID}, func(r storage.IdentityRows) error {
				return r.Scan(&storedCreated, &storedExpires)
			})
		}); err != nil {
			t.Fatal(err)
		}
		if !storedCreated.Equal(report.CreatedAt) || !storedExpires.Equal(report.ExpiresAt) {
			t.Fatalf("SQL timestamp precision changed frozen preview: created=%s/%s expires=%s/%s", storedCreated, report.CreatedAt, storedExpires, report.ExpiresAt)
		}
		if len(report.Members) != 1 || report.Members[0].GatewayID != "gw_portal" || len(report.Members[0].RouteIDs) != 1 || len(report.Members[0].NodeIDs) != 1 || report.Members[0].Disposition != "inherited" || len(report.Conflicts) != 0 || len(report.Pins) != 1 {
			t.Fatalf("incomplete frozen membership: %#v", report)
		}
		raw, _ := json.Marshal(report)
		if strings.Contains(string(raw), `"resolutionDigest"`) || strings.Contains(string(raw), `"published":true`) {
			t.Fatal("hypothetical report escaped as a trusted resolution or published zone")
		}
		if _, err = configmodel.ParseZoneResolution(strings.NewReader(string(raw)), configmodel.JSON); err == nil {
			t.Fatal("authoring preview accepted as a runtime resolution")
		}
		// New authoring heads and catalogs never alter a recorded retry.
		body.Metadata.Name = "Changed after frozen preview"
		createZone(t, f, "zone_preview_next001", zone.ID, body)
		catalog.ID = "catalog_zone_newer"
		catalog.SourceRef = "A later operator declaration"
		raw, _ = json.Marshal(catalog)
		if _, err = f.service.ImportCatalog(ctx, f.actor, "zone_catalog_newer01", raw, configmodel.JSON); err != nil {
			t.Fatal(err)
		}
		again, err := f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_preview_first01", request)
		if err != nil || again.ID != report.ID || again.PreviewDigest != report.PreviewDigest || !again.ExpiresAt.Equal(report.ExpiresAt) || again.HeadsDigest != report.HeadsDigest {
			t.Fatalf("retry re-resolved or refreshed frozen preview: %#v %v", again, err)
		}
		saved, err := f.service.GetZonePreview(ctx, f.actor, report.ID)
		if err != nil || saved.PreviewDigest != report.PreviewDigest {
			t.Fatalf("preview was not durable: %#v %v", saved, err)
		}
		for _, q := range []string{`UPDATE config_zone_previews SET report_json='{}' WHERE id=?`, `DELETE FROM config_zone_previews WHERE id=?`} {
			if err = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q, report.ID); return e }); err == nil {
				t.Fatalf("immutable preview database guard accepted %s", q)
			}
		}
	})
	t.Run("ordinary_overlap_default_and_policy_conflicts_are_complete", func(t *testing.T) {
		f, revision, snapshot, _ := zonePreviewFixture(t, pg)
		ctx := context.Background()
		body := zoneBody("zone_ordinary", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		zone := createZone(t, f, "zone_overlap_first01", "", body)
		other := zoneBody("zone_overlap", configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "pilot"}})
		otherZone := createZone(t, f, "zone_overlap_other01", "", other)
		report, err := f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_overlap_report1", previewRequest(revision, snapshot))
		if err != nil {
			t.Fatal(err)
		}
		if report.AuthoringValid || len(report.Members) != 1 || len(report.Conflicts) != 1 || report.Conflicts[0].Code != "waf_zone_ambiguous" || len(report.Conflicts[0].CandidateZoneRevisionIDs) != 2 || report.Members[0].TargetBindingDigest != "" {
			t.Fatalf("ordinary selector overlap was silently resolved: %#v", report)
		}
		// Shift the ordinary zones away; then two defaults remain ambiguous.
		body.Spec.Membership = configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "elsewhere"}}
		createZone(t, f, "zone_overlap_shift01", zone.ID, body)
		other.Spec.Membership = body.Spec.Membership
		createZone(t, f, "zone_overlap_shift02", otherZone.ID, other)
		truth := true
		defaultZone := createZone(t, f, "zone_default_create1", "", zoneBody("zone_default_a", configmodel.ZoneMembership{SiteDefault: &truth}))
		createZone(t, f, "zone_default_create2", "", zoneBody("zone_default_b", configmodel.ZoneMembership{SiteDefault: &truth}))
		report, err = f.service.PreviewZone(ctx, f.actor, defaultZone.ID, "zone_default_report1", previewRequest(revision, snapshot))
		if err != nil || report.AuthoringValid || len(report.Conflicts) != 1 || report.Conflicts[0].Code != "waf_zone_ambiguous" {
			t.Fatalf("multiple defaults were silently resolved: %#v %v", report, err)
		}
	})
	t.Run("missing_catalog_policy_nodes_and_explicit_capacity_fail_closed", func(t *testing.T) {
		f, revision, snapshot, catalog := zonePreviewFixture(t, pg)
		ctx := context.Background()
		zone := createZone(t, f, "zone_missing_create1", "", zoneBody("zone_missing", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		request := previewRequest(revision, snapshot)
		request.CatalogSnapshotID = "catalog_missing"
		if _, err := f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_missing_report1", request); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("unknown catalog accepted: %v", err)
		}
		request = previewRequest(revision, snapshot)
		request.CapacityProfile = "fleet-10k"
		if _, err := f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_capacity_report", request); err == nil {
			t.Fatal("implicit capacity upgrade accepted")
		}
		for i, kind := range []string{"policy", "nodes"} {
			changed := catalog
			changed.ID = "catalog_zone_missing_" + kind
			changed.SourceRef = "A missing authoring dependency " + kind
			if kind == "policy" {
				changed.Inputs = []configmodel.CatalogInput{}
			} else {
				changed.Nodes = []configmodel.CatalogNode{}
			}
			raw, _ := json.Marshal(changed)
			snapshot, err := f.service.ImportCatalog(ctx, f.actor, fmt.Sprintf("zone_catalog_bad_%02d", i), raw, configmodel.JSON)
			if err != nil {
				t.Fatal(err)
			}
			report, err := f.service.PreviewZone(ctx, f.actor, zone.ID, fmt.Sprintf("zone_report_bad_%02d", i), previewRequest(revision, snapshot))
			if err != nil || report.AuthoringValid || report.Deployable || len(report.Conflicts) != 1 {
				t.Fatalf("missing %s did not close proposal: %#v %v", kind, report, err)
			}
		}
	})
	t.Run("hypothetical_retire_requires_exact_replacement", func(t *testing.T) {
		f, revision, snapshot, _ := zonePreviewFixture(t, pg)
		ctx := context.Background()
		zone := createZone(t, f, "zone_retire_create1", "", zoneBody("zone_retiring", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		truth := true
		replacement := createZone(t, f, "zone_retire_create2", "", zoneBody("zone_replacement", configmodel.ZoneMembership{SiteDefault: &truth}))
		request := previewRequest(revision, snapshot)
		request.Action = "retire"
		report, err := f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_retire_report1", request)
		if err != nil || report.AuthoringValid || len(report.Conflicts) != 1 || report.Conflicts[0].Code != "waf_zone_replacement_required" {
			t.Fatalf("retire silently detached members: %#v %v", report, err)
		}
		request.ReplacementAssignments = []configmodel.ReplacementAssignment{{GatewayID: "gw_portal", ZoneRevisionID: replacement.ID}}
		report, err = f.service.PreviewZone(ctx, f.actor, zone.ID, "zone_retire_report2", request)
		if err != nil || !report.AuthoringValid || report.Deployable || len(report.Members) != 1 || report.Members[0].TargetZoneRevisionID != replacement.ID {
			t.Fatalf("exact hypothetical replacement failed: %#v %v", report, err)
		}
	})
	t.Run("receiving_zone_parent_closure_and_explicit_leaving_replacement", func(t *testing.T) {
		for _, targetHasParent := range []bool{false, true} {
			t.Run(fmt.Sprintf("target_has_parent_%t", targetHasParent), func(t *testing.T) {
				f, revision, snapshot, _ := zonePreviewFixture(t, pg)
				ctx := context.Background()
				var config configmodel.Configuration
				if err := json.Unmarshal(example(t), &config); err != nil {
					t.Fatal(err)
				}
				template := config.Gateways[0]
				config.Gateways = []configmodel.Gateway{}
				for _, id := range []string{"gw_move", "gw_stay", "gw_old_b"} {
					g := template
					g.Metadata.ID = id
					g.Spec.Routes = append([]configmodel.Route{}, template.Spec.Routes...)
					g.Spec.Routes[0].ID = "route_" + id
					g.Spec.Routes[0].Hostname = strings.ReplaceAll(id, "_", "-") + ".example.net"
					config.Gateways = append(config.Gateways, g)
				}
				raw, _ := json.Marshal(config)
				base, err := f.service.CreateRevision(ctx, f.actor, "zone_receiving_base01", CreateRevision{BaseRevisionID: revision.ID, Content: raw})
				if err != nil {
					t.Fatal(err)
				}
				var aOld *ZoneRevision
				if targetHasParent {
					aOld = createZone(t, f, "zone_receiving_a_old01", "", zoneBody("zone_a", configmodel.ZoneMembership{GatewayIDs: []string{"gw_move", "gw_stay"}}))
				}
				aParent := ""
				if aOld != nil {
					aParent = aOld.ID
				}
				aNew := createZone(t, f, "zone_receiving_a_new01", aParent, zoneBody("zone_a", configmodel.ZoneMembership{GatewayIDs: []string{"gw_stay"}}))
				bOld := createZone(t, f, "zone_receiving_b_old01", "", zoneBody("zone_b", configmodel.ZoneMembership{GatewayIDs: []string{"gw_old_b"}}))
				bNew := createZone(t, f, "zone_receiving_b_new01", bOld.ID, zoneBody("zone_b", configmodel.ZoneMembership{GatewayIDs: []string{"gw_move"}}))
				request := previewRequest(base, snapshot)
				request.ReplacementAssignments = []configmodel.ReplacementAssignment{{GatewayID: "gw_move", ZoneRevisionID: bNew.ID}}
				report, err := f.service.PreviewZone(ctx, f.actor, aNew.ID, "zone_receiving_report1", request)
				if err != nil {
					t.Fatal(err)
				}
				if report.AuthoringValid || len(report.Members) != 3 || len(report.Conflicts) != 1 || report.Conflicts[0].GatewayID != "gw_old_b" || report.Conflicts[0].Code != "waf_zone_unassigned" {
					t.Fatalf("receiving zone silently dropped old membership or invented old ambiguity: %#v", report)
				}
				members := map[string]configmodel.ZoneMember{}
				for _, member := range report.Members {
					members[member.GatewayID] = member
				}
				if old := members["gw_old_b"]; old.SourceZoneRevisionID != bOld.ID || old.Disposition != "conflict" || old.TargetBindingDigest != "" {
					t.Fatalf("receiving parent provenance/closed target missing: %#v", old)
				}
				if moved := members["gw_move"]; moved.TargetZoneRevisionID != bNew.ID || moved.Disposition != "inherited" {
					t.Fatalf("unambiguous move became a false lineage conflict: %#v", moved)
				}
				pinnedParent := false
				for _, pin := range report.Pins {
					if pin.ZoneRevisionID == bOld.ID {
						pinnedParent = true
					}
				}
				if !pinnedParent {
					t.Fatal("exact receiving parent was absent from frozen pins")
				}
				// A fallback cannot silently consume the member leaving B_old.
				truth := true
				c := createZone(t, f, "zone_receiving_c_new01", "", zoneBody("zone_c", configmodel.ZoneMembership{SiteDefault: &truth}))
				report, err = f.service.PreviewZone(ctx, f.actor, aNew.ID, "zone_receiving_report2", request)
				if err != nil || report.AuthoringValid || len(report.Members) != 3 || len(report.Conflicts) != 1 || report.Conflicts[0].Code != "waf_zone_replacement_required" {
					t.Fatalf("receiving member changed zone without explicit replacement: %#v %v", report, err)
				}
				request.ReplacementAssignments = append(request.ReplacementAssignments, configmodel.ReplacementAssignment{GatewayID: "gw_old_b", ZoneRevisionID: c.ID})
				report, err = f.service.PreviewZone(ctx, f.actor, aNew.ID, "zone_receiving_report3", request)
				if err != nil || !report.AuthoringValid || report.Deployable || len(report.Members) != 3 || len(report.Conflicts) != 0 {
					t.Fatalf("complete explicit receiving replacement was rejected: %#v %v", report, err)
				}
			})
		}
	})

	t.Run("scoped_objects_list_replays_and_complete_bridge_coverage", func(t *testing.T) {
		f := scopedFixture(t, pg)
		ctx := context.Background()
		editor := Actor{"editor_token", f.actor.Origin}
		for _, id := range []string{"a_foreign", "b_allowed", "c_foreign", "d_allowed"} {
			body := zoneBody(id, configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
			if strings.HasSuffix(id, "foreign") {
				body.Metadata.SiteID = "site_other"
			}
			createZone(t, f, "zone_scope_"+id+"01", "", body)
		}
		foreign, err := f.service.ListZones(ctx, f.actor, 1, "", "site_other")
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{foreign.Items[0].ID, "unknown_zone_revision"} {
			if _, err = f.service.GetZoneRevision(ctx, editor, id); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("zone ID existence oracle: %v", err)
			}
		}
		page, err := f.service.ListZones(ctx, editor, 1, "", "")
		if err != nil || len(page.Items) != 1 || page.Items[0].ZoneID != "b_allowed" || page.NextCursor != "b_allowed" {
			t.Fatalf("foreign metadata/cursor leaked %#v %v", page, err)
		}
		page, err = f.service.ListZones(ctx, editor, 1, page.NextCursor, "")
		if err != nil || len(page.Items) != 1 || page.Items[0].ZoneID != "d_allowed" || page.NextCursor != "" {
			t.Fatalf("scoped page skipped/leaked %#v %v", page, err)
		}
		revision, err := f.service.CreateRevision(ctx, f.actor, "zone_scope_config01", CreateRevision{Content: example(t)})
		if err != nil {
			t.Fatal(err)
		}
		request := ZonePreviewRequest{BaseRevisionID: revision.ID, CatalogSnapshotID: "irrelevant_catalog", CapacityProfile: "pilot-500", Action: "reconcile"}
		if _, err = f.service.PreviewZone(ctx, editor, foreign.Items[0].ID, "zone_scope_foreign1", request); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("preview ID existence oracle: %v", err)
		}
		// A second Gateway in the same Site has no immutable ownership bridge;
		// preview must reject the entire Site rather than filter that Gateway.
		var config configmodel.Configuration
		json.Unmarshal(example(t), &config)
		neighbor := config.Gateways[0]
		neighbor.Metadata.ID = "gw_missing_bridge"
		neighbor.Spec.Routes = append([]configmodel.Route{}, neighbor.Spec.Routes...)
		neighbor.Spec.Routes[0].ID = "route_missing_bridge"
		neighbor.Spec.Routes[0].Hostname = "missing-bridge.example.net"
		config.Gateways = append(config.Gateways, neighbor)
		raw, _ := json.Marshal(config)
		next, err := f.service.CreateRevision(ctx, f.actor, "zone_scope_config02", CreateRevision{BaseRevisionID: revision.ID, Content: raw})
		if err != nil {
			t.Fatal(err)
		}
		request.BaseRevisionID = next.ID
		if _, err = f.service.PreviewZone(ctx, editor, page.Items[0].ID, "zone_scope_bridge01", request); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("partial Gateway authorization was accepted: %v", err)
		}
		if err = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			return securitystate.MaterializeEvent(ctx, tx, securityjournal.Event{Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", Payload: securityjournal.Payload{GrantID: "cgrant_editor"}}, RecordedAt: time.Now()})
		}); err != nil {
			t.Fatal(err)
		}
		if _, err = f.service.GetZoneRevision(ctx, editor, page.Items[0].ID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("revoked zone read allowed: %v", err)
		}
	})

}

func TestZoneAuthoringWorkAdmission(t *testing.T) {
	// The slices share tiny fixtures; no adversarial nested computation runs.
	c := configmodel.Configuration{Gateways: make([]configmodel.Gateway, 10000)}
	selector := configmodel.Labels{}
	for i := 0; i < 32; i++ {
		selector[fmt.Sprintf("key_%02d", i)] = "value"
	}
	zones := make([]configmodel.ZoneRevision, 1000)
	for i := range zones {
		zones[i].Content.Spec.Membership.MatchLabels = &selector
	}
	if err := boundZonePreviewWork(c, configmodel.Catalog{}, zones); err == nil {
		t.Fatal("unbounded Gateway x Zone x Labels work accepted")
	}
	if err := boundZonePreviewWork(configmodel.Configuration{Gateways: make([]configmodel.Gateway, 10000)}, configmodel.Catalog{Nodes: make([]configmodel.CatalogNode, 500)}, []configmodel.ZoneRevision{{}}); err != nil {
		t.Fatalf("ordinary fleet-size indexed work rejected: %v", err)
	}
}
