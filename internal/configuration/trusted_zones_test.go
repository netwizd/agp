package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// This is a service-boundary double, not native component qualification.
type testTrustedInventory struct {
	mu          sync.Mutex
	source      string
	unavailable bool
	calls       int
}

func (v *testTrustedInventory) Current(ctx context.Context, _ storage.IdentityTx, epoch securityjournal.UInt63, site string, proofs []WAFQualification) (*TrustedInventorySnapshot, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.unavailable || epoch != 1 || site != "site_msk" || len(proofs) == 0 {
		return nil, storage.ErrConflict
	}
	return &TrustedInventorySnapshot{SourceDigest: "sha256:" + strings.Repeat(v.source, 64), Nodes: []configmodel.CatalogNode{{ID: "node_msk01", SiteID: "site_msk", Labels: configmodel.Labels{}, NodeGroupIDs: []string{}, CapabilityDigest: "sha256:" + strings.Repeat("9", 64)}}}, nil
}
func trustedZoneFixture(t *testing.T, pg bool) (*testFixture, *testWafQualifier, *testTrustedInventory, *WafPolicyRevision, *Revision) {
	t.Helper()
	ctx := context.Background()
	f := fixtureConfigured(t, pg, func(tx storage.IdentityTx) error {
		now := time.Now().UTC()
		for _, id := range []string{"waf_author", "waf_approver", "waf_foreign", "waf_reader"} {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "hash"); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management','https://management.test',1,1,?,?)`, id, id, id+"_token", "csrf", "", "", now.Add(time.Hour), now, now, now); e != nil {
				return e
			}
		}
		for _, g := range []struct{ id, user, permission, site string }{{"author_edit", "waf_author", "config.edit", "site_msk"}, {"author_approve", "waf_author", "config.approve", "site_msk"}, {"approver_read", "waf_approver", "config.read", "site_msk"}, {"approver_approve", "waf_approver", "config.approve", "site_msk"}, {"foreign_edit", "waf_foreign", "config.edit", "site_other"}, {"reader_read", "waf_reader", "config.read", "site_msk"}} {
			if _, e := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES(?,?,?,'site',?,1,?)`, "cgrant_"+g.id, g.user, g.permission, g.site, now); e != nil {
				return e
			}
		}
		for _, g := range []string{"gw_portal", "gw_second"} {
			if _, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,'site_msk')`, g); e != nil {
				return e
			}
		}
		return nil
	})
	q := &testWafQualifier{}
	source := &testTrustedInventory{source: "8"}
	f.service.WithWAFQualifier(q).WithTrustedInventory(source)
	policy := createWaf(t, f)
	validateWaf(t, f, policy)
	approveWaf(t, f, policy)
	if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), policy.ID, "trusted_policy_publish01", WafPolicyPublicationRequest{policy.ContentDigest}); e != nil {
		t.Fatal(e)
	}
	var c configmodel.Configuration
	if e := json.Unmarshal(example(t), &c); e != nil {
		t.Fatal(e)
	}
	c.Gateways[0].Spec.WAF.PolicyRevisionID = policy.ID
	c.Gateways[0].Spec.ComponentProfileRef = configmodel.Reference{ID: "native_profile", Digest: "sha256:" + strings.Repeat("2", 64)}
	base, e := f.service.CreateRevision(ctx, f.actor, "trusted_base_revision01", CreateRevision{Content: mustJSON(t, c)})
	if e != nil {
		t.Fatal(e)
	}
	return f, q, source, policy, base
}
func createTrustedZone(t *testing.T, f *testFixture, policy, id string, membership configmodel.ZoneMembership) *ZoneRevision {
	t.Helper()
	z := zoneBody(id, membership)
	z.Metadata.OwnerID = "waf_author"
	z.Spec.PolicyRevisionID = policy
	r, e := f.service.CreateZoneRevision(context.Background(), wafActor(f, "waf_author"), "trusted_create_"+id, ZoneCreate{Content: mustJSON(t, z)})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func publishTrustedZone(t *testing.T, f *testFixture, z *ZoneRevision) *ZoneRevision {
	t.Helper()
	ctx := context.Background()
	if _, e := f.service.ValidateZoneRevision(ctx, wafActor(f, "waf_author"), z.ID, "trusted_validate_"+z.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.service.ApproveZoneRevision(ctx, wafActor(f, "waf_approver"), z.ID, "trusted_approve_"+z.ID, WafPolicyApprovalRequest{z.ContentDigest, "Проверены точные опубликованные зависимости"}); e != nil {
		t.Fatal(e)
	}
	out, e := f.service.PublishZoneRevision(ctx, wafActor(f, "waf_approver"), z.ID, "trusted_publish_"+z.ID, WafPolicyPublicationRequest{z.ContentDigest})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func resolveTrustedZone(t *testing.T, f *testFixture, z *ZoneRevision, base *Revision) *configmodel.WafZoneResolution {
	t.Helper()
	r, e := f.service.ResolveZone(context.Background(), wafActor(f, "waf_author"), z.ID, "trusted_resolve_"+z.ID, ZoneResolutionRequest{BaseRevisionID: base.ID, CapacityProfile: "pilot-500", Action: "reconcile"})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func trustedChange(base *Revision, z *ZoneRevision, r *configmodel.WafZoneResolution) configmodel.WafZoneChange {
	return configmodel.WafZoneChange{APIVersion: "agp.waf-zone-change/v1alpha1", Kind: "WafZoneChange", BaseRevisionID: base.ID, ZoneRevisionID: z.ID, ResolutionID: r.ID, ResolutionDigest: r.ResolutionDigest, Reason: "Проверено полное замыкание желаемой конфигурации"}
}
func TestTrustedZonesSQLite(t *testing.T)   { testTrustedZones(t, false) }
func TestTrustedZonesPostgres(t *testing.T) { testTrustedZones(t, true) }
func testTrustedZones(t *testing.T, pg bool) {
	ctx := context.Background()
	t.Run("independent_lifecycle_and_historical_published_pin", func(t *testing.T) {
		f, q, _, policy, _ := trustedZoneFixture(t, pg)
		z := createTrustedZone(t, f, policy.ID, "zone_lifecycle", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		if _, e := f.service.ApproveZoneRevision(ctx, wafActor(f, "waf_approver"), z.ID, "trusted_no_validation01", WafPolicyApprovalRequest{z.ContentDigest, "Exact digest requires validation"}); e == nil {
			t.Fatal("approval without validation")
		}
		accepted, e := f.service.ValidateZoneRevision(ctx, wafActor(f, "waf_author"), z.ID, "trusted_validation_0001")
		if e != nil {
			t.Fatal(e)
		}
		report, e := f.service.GetZoneValidation(ctx, wafActor(f, "waf_approver"), accepted.ResourceID)
		if e != nil || !report.Valid || !report.Current || report.Deployable {
			t.Fatalf("report %#v %v", report, e)
		}
		if _, e = f.service.ApproveZoneRevision(ctx, wafActor(f, "waf_author"), z.ID, "trusted_self_approval01", WafPolicyApprovalRequest{z.ContentDigest, "Self approval must be rejected"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("self approval: %v", e)
		}
		if _, e = f.service.ApproveZoneRevision(ctx, f.actor, z.ID, "trusted_admin_approval1", WafPolicyApprovalRequest{z.ContentDigest, "Admin has no implicit approve grant"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("implicit approve: %v", e)
		}
		z = publishTrustedZone(t, f, z)
		got, e := f.service.GetZoneRevision(ctx, wafActor(f, "waf_approver"), z.ID)
		if e != nil || got.State != "published" {
			t.Fatalf("published view %#v %v", got, e)
		}
		page, e := f.service.ListZones(ctx, wafActor(f, "waf_approver"), 10, "", "site_msk")
		if e != nil || len(page.Items) != 1 || page.Items[0].State != "published" {
			t.Fatalf("published page %#v %v", page, e)
		}
		// A successor policy draft is unrelated to the immutable pin already published.
		var body configmodel.WafPolicy
		if e = json.Unmarshal(policy.Content, &body); e != nil {
			t.Fatal(e)
		}
		body.Metadata.Name = "A later unpublished policy draft"
		if _, e = f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), "trusted_successor_policy1", WafPolicyCreate{BaseRevisionID: policy.ID, Content: mustJSON(t, body)}); e != nil {
			t.Fatal(e)
		}
		if e = f.service.transactScoped(ctx, wafActor(f, "waf_author"), false, func(tx storage.IdentityTx, p *Principal) error {
			_, _, _, e := f.service.publishedZone(ctx, tx, p, z.ID, "site_msk")
			return e
		}); e != nil {
			t.Fatalf("unpublished successor invalidated exact pin: %v", e)
		}
		q.revoked.Store(true)
		if e = f.service.transactScoped(ctx, wafActor(f, "waf_author"), false, func(tx storage.IdentityTx, p *Principal) error {
			_, _, _, e := f.service.publishedZone(ctx, tx, p, z.ID, "site_msk")
			return e
		}); e == nil {
			t.Fatal("publication bypassed revoked native proof")
		}
	})
	t.Run("real_operation_frozen_resolution_atomic_full_revision_and_sealed_provenance", func(t *testing.T) {
		f, _, source, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_atomic", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		request := ZoneResolutionRequest{BaseRevisionID: base.ID, CapacityProfile: "pilot-500", Action: "reconcile"}
		accepted, e := f.service.ResolveZoneAccepted(ctx, wafActor(f, "waf_author"), z.ID, "trusted_resolution_op1", request)
		if e != nil {
			t.Fatal(e)
		}
		op, e := f.service.GetZoneOperation(ctx, wafActor(f, "waf_author"), accepted.OperationID)
		if e != nil || op.State != "succeeded" || op.ResourceID != accepted.ResourceID {
			t.Fatalf("operation %#v %v", op, e)
		}
		r, e := f.service.GetZoneResolution(ctx, wafActor(f, "waf_author"), accepted.ResourceID)
		if e != nil || len(r.Conflicts) != 0 || len(r.Members) != 1 || r.Members[0].NodeIDs[0] != "node_msk01" {
			t.Fatalf("resolution %#v %v", r, e)
		}
		again, e := f.service.ResolveZone(ctx, wafActor(f, "waf_author"), z.ID, "trusted_resolution_op1", request)
		if e != nil || again.ResolutionDigest != r.ResolutionDigest || again.CreatedAt != r.CreatedAt {
			t.Fatalf("unchanged heartbeat changed frozen input %#v %v", again, e)
		}
		change := trustedChange(base, z, r)
		result, e := f.service.MaterializeZone(ctx, wafActor(f, "waf_author"), "trusted_materialize_01", change)
		if e != nil {
			t.Fatal(e)
		}
		if result.ID == base.ID || result.BaseRevisionID != base.ID || result.ViewScope != "metadata" || len(result.Content) != 0 {
			t.Fatalf("scoped full revision result %#v", result)
		}
		full, e := f.service.GetRevision(ctx, f.actor, result.ID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = configmodel.ParseConfiguration(bytes.NewReader(full.Content), configmodel.JSON); e != nil {
			t.Fatal(e)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_revision_zone_assignments WHERE revision_id=?`, result.ID) != 1 || scalar(t, f, `SELECT COUNT(*) FROM config_revision_seals WHERE revision_id=?`, result.ID) != 1 {
			t.Fatal("desired provenance and seal were not committed")
		}
		if source.calls < 3 {
			t.Fatal("fresh inventory was not rechecked")
		}
		retry, e := f.service.MaterializeZone(ctx, wafActor(f, "waf_author"), "trusted_materialize_01", change)
		if e != nil || retry.ID != result.ID {
			t.Fatalf("exact materialization retry %#v %v", retry, e)
		}
		for _, query := range []string{`UPDATE config_revision_zone_assignments SET binding_digest='bad' WHERE revision_id=?`, `DELETE FROM config_revision_zone_assignments WHERE revision_id=?`, `INSERT INTO config_revision_zone_assignments(revision_id,gateway_id,zone_revision_id,resolution_id,binding_digest) SELECT ?,gateway_id,zone_revision_id,resolution_id,binding_digest FROM config_revision_zone_assignments LIMIT 1`} {
			if e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, query, result.ID); return e }); e == nil {
				t.Fatalf("sealed provenance allowed %s", query)
			}
		}
		var configuration configmodel.Configuration
		if e = json.Unmarshal(full.Content, &configuration); e != nil {
			t.Fatal(e)
		}
		configuration.Metadata.Name = "Preserve trusted provenance during unrelated authoring"
		copied, e := f.service.CreateRevision(ctx, f.actor, "trusted_preserve_prov01", CreateRevision{BaseRevisionID: result.ID, Content: mustJSON(t, configuration)})
		if e != nil {
			t.Fatal(e)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_revision_zone_assignments WHERE revision_id=?`, copied.ID) != 1 {
			t.Fatal("unrelated edit dropped provenance")
		}
		configuration.Gateways[0].Spec.WAF.Mode = "blocking"
		if _, e = f.service.CreateRevision(ctx, f.actor, "trusted_manual_bypass1", CreateRevision{BaseRevisionID: copied.ID, Content: mustJSON(t, configuration)}); e == nil {
			t.Fatal("manual WAF binding bypassed zone provenance")
		}
	})
	t.Run("changed_or_stale_inventory_rejects_without_advancing_any_head", func(t *testing.T) {
		for _, stale := range []bool{false, true} {
			t.Run(strconv.FormatBool(stale), func(t *testing.T) {
				f, _, source, policy, base := trustedZoneFixture(t, pg)
				z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_current", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
				r := resolveTrustedZone(t, f, z, base)
				source.mu.Lock()
				if stale {
					source.unavailable = true
				} else {
					source.source = "7"
				}
				source.mu.Unlock()
				if _, e := f.service.MaterializeZone(ctx, wafActor(f, "waf_author"), "trusted_reject_current1", trustedChange(base, z, r)); e == nil {
					t.Fatal("changed/stale source consumed frozen resolution")
				}
				if scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 1 || scalar(t, f, `SELECT COUNT(*) FROM config_zone_changes`) != 0 || scalar(t, f, `SELECT COUNT(*) FROM config_revision_zone_assignments`) != 0 {
					t.Fatal("failed resolution changed desired state")
				}
			})
		}
	})
	t.Run("whole_transition_closure_requires_every_departing_replacement", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_departing", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		r := resolveTrustedZone(t, f, z, base)
		assigned, e := f.service.MaterializeZone(ctx, f.actor, "trusted_assign_first01", trustedChange(base, z, r))
		if e != nil {
			t.Fatal(e)
		}
		var body configmodel.WafZone
		if e = json.Unmarshal(z.Content, &body); e != nil {
			t.Fatal(e)
		}
		body.Spec.Membership = configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "other"}}
		next, e := f.service.CreateZoneRevision(ctx, wafActor(f, "waf_author"), "trusted_departing_new1", ZoneCreate{BaseRevisionID: z.ID, Content: mustJSON(t, body)})
		if e != nil {
			t.Fatal(e)
		}
		next = publishTrustedZone(t, f, next)
		unresolved := resolveTrustedZone(t, f, next, assigned)
		if len(unresolved.Members) != 1 || len(unresolved.Conflicts) != 1 {
			t.Fatalf("departing member disappeared %#v", unresolved)
		}
		if _, e = f.service.MaterializeZone(ctx, f.actor, "trusted_no_replacement", trustedChange(assigned, next, unresolved)); e == nil {
			t.Fatal("departing closure without replacement materialized")
		}
		destination := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_receiving", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		resolved, e := f.service.ResolveZone(ctx, wafActor(f, "waf_author"), next.ID, "trusted_full_transfer01", ZoneResolutionRequest{BaseRevisionID: assigned.ID, CapacityProfile: "pilot-500", Action: "reconcile", ReplacementAssignments: []configmodel.ReplacementAssignment{{GatewayID: "gw_portal", ZoneRevisionID: destination.ID}}})
		if e != nil {
			t.Fatal(e)
		}
		if len(resolved.Conflicts) > 0 || resolved.Members[0].TargetZoneRevisionID != destination.ID {
			t.Fatalf("receiving closure %#v", resolved)
		}
		if _, e = f.service.MaterializeZone(ctx, f.actor, "trusted_full_transfer02", trustedChange(assigned, next, resolved)); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("receiving_revision_includes_its_existing_complete_membership", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		var c configmodel.Configuration
		if e := json.Unmarshal(base.Content, &c); e != nil {
			t.Fatal(e)
		}
		second := c.Gateways[0]
		second.Metadata.ID, second.Metadata.Name = "gw_second", "Existing destination member"
		second.Spec.Routes = append([]configmodel.Route{}, second.Spec.Routes...)
		second.Spec.Routes[0].ID, second.Spec.Routes[0].Hostname = "route_second", "second.example.net"
		c.Gateways = append(c.Gateways, second)
		base, e := f.service.CreateRevision(ctx, f.actor, "trusted_two_gateway_base", CreateRevision{BaseRevisionID: base.ID, Content: mustJSON(t, c)})
		if e != nil {
			t.Fatal(e)
		}
		a := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_source_full", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		b := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_target_full", configmodel.ZoneMembership{GatewayIDs: []string{"gw_second"}}))
		r := resolveTrustedZone(t, f, a, base)
		base, e = f.service.MaterializeZone(ctx, f.actor, "trusted_assign_source01", trustedChange(base, a, r))
		if e != nil {
			t.Fatal(e)
		}
		r = resolveTrustedZone(t, f, b, base)
		base, e = f.service.MaterializeZone(ctx, f.actor, "trusted_assign_target01", trustedChange(base, b, r))
		if e != nil {
			t.Fatal(e)
		}
		var az, bz configmodel.WafZone
		if e = json.Unmarshal(a.Content, &az); e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b.Content, &bz); e != nil {
			t.Fatal(e)
		}
		az.Spec.Membership = configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "departed"}}
		bz.Spec.Membership = configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal", "gw_second"}}
		nextA, e := f.service.CreateZoneRevision(ctx, wafActor(f, "waf_author"), "trusted_source_next01", ZoneCreate{BaseRevisionID: a.ID, Content: mustJSON(t, az)})
		if e != nil {
			t.Fatal(e)
		}
		nextB, e := f.service.CreateZoneRevision(ctx, wafActor(f, "waf_author"), "trusted_target_next01", ZoneCreate{BaseRevisionID: b.ID, Content: mustJSON(t, bz)})
		if e != nil {
			t.Fatal(e)
		}
		nextA, nextB = publishTrustedZone(t, f, nextA), publishTrustedZone(t, f, nextB)
		transfer, e := f.service.ResolveZone(ctx, wafActor(f, "waf_author"), nextA.ID, "trusted_whole_transfer1", ZoneResolutionRequest{BaseRevisionID: base.ID, CapacityProfile: "pilot-500", Action: "reconcile", ReplacementAssignments: []configmodel.ReplacementAssignment{{GatewayID: "gw_portal", ZoneRevisionID: nextB.ID}}})
		if e != nil || len(transfer.Conflicts) != 0 || len(transfer.Members) != 2 {
			t.Fatalf("incomplete destination closure %#v %v", transfer, e)
		}
		for _, member := range transfer.Members {
			if member.TargetZoneRevisionID != nextB.ID {
				t.Fatalf("mixed destination version %#v", member)
			}
		}
		result, e := f.service.MaterializeZone(ctx, f.actor, "trusted_whole_transfer2", trustedChange(base, nextA, transfer))
		if e != nil {
			t.Fatal(e)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_revision_zone_assignments WHERE revision_id=? AND zone_revision_id=?`, result.ID, nextB.ID) != 2 {
			t.Fatal("destination only partially advanced")
		}
	})
	t.Run("independent_approval_revocation_and_fresh_mfa", func(t *testing.T) {
		f, _, _, policy, _ := trustedZoneFixture(t, pg)
		z := createTrustedZone(t, f, policy.ID, "zone_revoke", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		if _, e := f.service.ValidateZoneRevision(ctx, wafActor(f, "waf_author"), z.ID, "trusted_revoke_validate"); e != nil {
			t.Fatal(e)
		}
		in := WafPolicyApprovalRequest{z.ContentDigest, "Exact independent approval before revocation"}
		if _, e := f.service.ApproveZoneRevision(ctx, wafActor(f, "waf_approver"), z.ID, "trusted_revoke_approve1", in); e != nil {
			t.Fatal(e)
		}
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id='cgrant_approver_read'`)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.PublishZoneRevision(ctx, wafActor(f, "waf_author"), z.ID, "trusted_revoke_publish1", WafPolicyPublicationRequest{z.ContentDigest}); e == nil {
			t.Fatal("revoked historical approver authorized publication")
		}
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE sessions SET mfa_at=? WHERE token_hash='waf_author_token'`, time.Now().Add(-6*time.Minute))
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.ValidateZoneRevision(ctx, wafActor(f, "waf_author"), z.ID, "trusted_stale_mfa_check"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("stale MFA: %v", e)
		}
	})
	t.Run("scope_minimum_and_explicit_unsupported_profiles", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_scope", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		if _, e := f.service.ResolveZone(ctx, wafActor(f, "waf_foreign"), z.ID, "trusted_foreign_resolve", ZoneResolutionRequest{BaseRevisionID: base.ID, CapacityProfile: "pilot-500", Action: "reconcile"}); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("foreign scope: %v", e)
		}
		f.service.compiler.MinimumWAFMode = "blocking"
		if _, e := f.service.ResolveZone(ctx, wafActor(f, "waf_author"), z.ID, "trusted_minimum_reject1", ZoneResolutionRequest{BaseRevisionID: base.ID, CapacityProfile: "pilot-500", Action: "reconcile"}); e == nil {
			t.Fatal("minimum weakening accepted")
		}
		f.service.compiler.MinimumWAFMode = "detection"
		var c configmodel.Configuration
		if e := json.Unmarshal(base.Content, &c); e != nil {
			t.Fatal(e)
		}
		c.ProfileAssignments = []configmodel.ProfileAssignment{{ID: "assignment_unqualified", ProfileRevisionID: "profile_unqualified", ScopeType: "site", ScopeID: "site_msk"}}
		next, e := f.service.CreateRevision(ctx, f.actor, "trusted_profiles_base1", CreateRevision{BaseRevisionID: base.ID, Content: mustJSON(t, c)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.ResolveZone(ctx, wafActor(f, "waf_author"), z.ID, "trusted_profiles_deny1", ZoneResolutionRequest{BaseRevisionID: next.ID, CapacityProfile: "pilot-500", Action: "reconcile"}); e == nil {
			t.Fatal("unqualified policy inheritance silently ignored")
		}
	})
	t.Run("audit_failure_rolls_back_full_revision_projections_provenance_and_change", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_rollback", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		r := resolveTrustedZone(t, f, z, base)
		f.service.current = wafAuditFailCurrent{f.service.current, "config.waf.zone.materialized"}
		if _, e := f.service.MaterializeZone(ctx, f.actor, "trusted_audit_rollback", trustedChange(base, z, r)); e == nil {
			t.Fatal("audit failure accepted")
		}
		for _, table := range []string{"config_revisions", "config_gateways", "config_routes", "config_revision_seals"} {
			if scalar(t, f, `SELECT COUNT(*) FROM `+table) != 1 {
				t.Fatalf("partial state in %s", table)
			}
		}
		for _, table := range []string{"config_revision_zone_assignments", "config_zone_changes"} {
			if scalar(t, f, `SELECT COUNT(*) FROM `+table) != 0 {
				t.Fatalf("partial state in %s", table)
			}
		}
	})
	t.Run("inherited_provenance_rejects_changed_security_closure_and_allows_display_names", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_security_inputs", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		r := resolveTrustedZone(t, f, z, base)
		assigned, e := f.service.MaterializeZone(ctx, f.actor, "trusted_security_assign", trustedChange(base, z, r))
		if e != nil {
			t.Fatal(e)
		}
		var c configmodel.Configuration
		if e = json.Unmarshal(assigned.Content, &c); e != nil {
			t.Fatal(e)
		}
		c.Gateways[0].Metadata.Name = "A harmless display name"
		c.Gateways[0].Spec.Routes[0].Name = "A harmless route display name"
		cosmetic, e := f.service.ChangeGateway(ctx, wafActor(f, "waf_author"), "trusted_cosmetic_scoped", CreateRevision{BaseRevisionID: assigned.ID, GatewayChange: &GatewayChange{GatewayID: "gw_portal", Content: mustJSON(t, c.Gateways[0])}})
		if e != nil {
			t.Fatal(e)
		}
		full, e := f.service.GetRevision(ctx, f.actor, cosmetic.ID)
		if e != nil {
			t.Fatal(e)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_revision_zone_assignments WHERE revision_id=?`, cosmetic.ID) != 1 {
			t.Fatal("cosmetic edit lost provenance")
		}
		mutations := []struct {
			name   string
			change func(*configmodel.Configuration)
		}{
			{"labels", func(c *configmodel.Configuration) { c.Gateways[0].Metadata.Labels["environment"] = "expanded" }},
			{"nodes", func(c *configmodel.Configuration) { c.Gateways[0].Spec.NodeSelector.NodeIDs = []string{"node_changed"} }},
			{"profile", func(c *configmodel.Configuration) {
				c.Gateways[0].Spec.ComponentProfileRef.Digest = "sha256:" + strings.Repeat("a", 64)
			}},
			{"certificate", func(c *configmodel.Configuration) {
				c.Gateways[0].Spec.TLS.CertificateVersionID = "certificate_changed"
			}},
			{"access", func(c *configmodel.Configuration) {
				c.Gateways[0].Spec.Routes[0].Access.GroupIDs = []string{"group_changed"}
			}},
			{"route", func(c *configmodel.Configuration) { c.Gateways[0].Spec.Routes[0].Hostname = "changed.example.net" }},
			{"upstream", func(c *configmodel.Configuration) {
				c.Gateways[0].Spec.Routes[0].Upstream.URL = "https://changed.example.net:8443"
			}},
			{"monitoring", func(c *configmodel.Configuration) { c.Gateways[0].Spec.Monitoring.Logs = false }},
			{"profiles", func(c *configmodel.Configuration) {
				c.ProfileAssignments = []configmodel.ProfileAssignment{{ID: "profile_assignment", ProfileRevisionID: "profile_unqualified", ScopeType: "site", ScopeID: "site_msk"}}
			}},
		}
		for _, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				var changed configmodel.Configuration
				if e := json.Unmarshal(full.Content, &changed); e != nil {
					t.Fatal(e)
				}
				mutation.change(&changed)
				if _, e := f.service.CreateRevision(ctx, f.actor, "trusted_security_"+mutation.name, CreateRevision{BaseRevisionID: full.ID, Content: mustJSON(t, changed)}); e == nil {
					t.Fatal("full authoring reused stale security closure")
				}
			})
		}
		var changed configmodel.Configuration
		if e = json.Unmarshal(full.Content, &changed); e != nil {
			t.Fatal(e)
		}
		changed.Gateways[0].Metadata.Labels["environment"] = "expanded"
		if _, e = f.service.ChangeGateway(ctx, wafActor(f, "waf_author"), "trusted_scoped_labels1", CreateRevision{BaseRevisionID: full.ID, GatewayChange: &GatewayChange{GatewayID: "gw_portal", Content: mustJSON(t, changed.Gateways[0])}}); e == nil {
			t.Fatal("scoped authoring reused stale security labels")
		}
		draft, e := f.service.CreateDraft(ctx, f.actor, "trusted_security_draft1", CreateDraft{BaseRevisionID: full.ID, Content: mustJSON(t, changed)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.SealDraft(ctx, f.actor, draft.ID, draft.Revision, "trusted_security_seal01"); e == nil {
			t.Fatal("draft sealing reused stale security closure")
		}
		profile, e := f.service.Profile(ctx, f.actor)
		if e != nil || profile.HeadRevisionID != full.ID {
			t.Fatalf("rejected security edit advanced head %#v %v", profile, e)
		}
	})
	t.Run("same_site_readers_can_read_frozen_resolution_without_mutation_rights", func(t *testing.T) {
		f, _, source, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_read_scope", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		resolved := resolveTrustedZone(t, f, z, base)
		request := ZoneResolutionRequest{BaseRevisionID: base.ID, CapacityProfile: "pilot-500", Action: "reconcile"}
		change := trustedChange(base, z, resolved)
		for _, id := range []string{"waf_reader", "waf_approver"} {
			actor := wafActor(f, id)
			got, e := f.service.GetZoneResolution(ctx, actor, resolved.ID)
			if e != nil || got.ID != resolved.ID || got.ResolutionDigest != resolved.ResolutionDigest || len(got.Members) != len(resolved.Members) {
				t.Fatalf("same-Site %s could not read the exact frozen snapshot: %#v %v", id, got, e)
			}
			if _, e = f.service.ResolveZone(ctx, actor, z.ID, "trusted_readonly_resolve_"+id, request); !errors.Is(e, storage.ErrNotFound) {
				t.Fatalf("%s without config.edit requested a new resolution: %v", id, e)
			}
			if _, e = f.service.MaterializeZone(ctx, actor, "trusted_readonly_materialize_"+id, change); !errors.Is(e, storage.ErrNotFound) {
				t.Fatalf("%s without config.edit materialized a change: %v", id, e)
			}
		}
		foreign := wafActor(f, "waf_foreign")
		if _, e := f.service.GetZoneResolution(ctx, foreign, resolved.ID); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("foreign Site could read frozen resolution: %v", e)
		}
		// A historical read exposes the original immutable result, not a newly
		// valid permit. Loss of freshness must not prevent auditing that result.
		source.mu.Lock()
		source.unavailable = true
		source.mu.Unlock()
		got, e := f.service.GetZoneResolution(ctx, wafActor(f, "waf_reader"), resolved.ID)
		if e != nil || got.ResolutionDigest != resolved.ResolutionDigest {
			t.Fatalf("historical read incorrectly required a fresh permit: %#v %v", got, e)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 1 || scalar(t, f, `SELECT COUNT(*) FROM config_zone_changes`) != 0 {
			t.Fatal("read-only operations changed desired configuration")
		}
	})
	t.Run("mixed_revision_intent_is_rejected_for_direct_callers", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		z := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "zone_intent", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		r := resolveTrustedZone(t, f, z, base)
		change := trustedChange(base, z, r)
		for _, in := range []CreateRevision{{Content: base.Content, WafZoneChange: &change}, {BaseRevisionID: base.ID, WafZoneChange: &change}, {GatewayChange: &GatewayChange{}, WafZoneChange: &change}} {
			if _, e := f.service.CreateRevision(ctx, f.actor, "trusted_mixed_intent01", in); !errors.Is(e, ErrInvalidRequest) {
				t.Fatalf("mixed intent: %v", e)
			}
		}
		if _, e := f.service.ChangeGateway(ctx, wafActor(f, "waf_author"), "trusted_mixed_scoped01", CreateRevision{BaseRevisionID: base.ID, GatewayChange: &GatewayChange{}, WafZoneChange: &change}); !errors.Is(e, ErrInvalidRequest) {
			t.Fatalf("mixed scoped intent: %v", e)
		}
		result, e := f.service.CreateRevision(ctx, f.actor, "trusted_direct_intent1", CreateRevision{WafZoneChange: &change})
		if e != nil || result.BaseRevisionID != base.ID {
			t.Fatalf("direct intent %#v %v", result, e)
		}
	})
}
