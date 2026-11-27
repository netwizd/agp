package configmodel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTrustedResolverSeparatesAuthorityAndPreservesCanonicalRoutes(t *testing.T) {
	c := configuration(t)
	second := c.Gateways[0].Spec.Routes[0]
	second.ID = "route_aaaa"
	second.Hostname = "second.example.net"
	c.Gateways[0].Spec.Routes = append(c.Gateways[0].Spec.Routes, second)
	catalog := catalogFor(c)
	nodes := append([]CatalogNode{}, catalog.Nodes...)
	for i := range nodes {
		nodes[i].CapabilityDigest = "sha256:" + strings.Repeat("7", 64)
	}
	policies := []CatalogInput{}
	for _, p := range catalog.Inputs {
		if p.Kind == "waf_policy" {
			policies = append(policies, p)
		}
	}
	inputs := TrustedZoneInputs{SourceDigest: "sha256:" + strings.Repeat("1", 64), MinimumWAFMode: "detection", Nodes: nodes, Policies: policies}
	zone := WafZone{APIVersion: "agp.waf-zone/v1alpha1", Kind: "WafZone", Metadata: ZoneMetadata{ID: "zone_trusted", Name: "Trusted zone", SiteID: "site_msk", OwnerID: "owner_1"}, Spec: ZoneSpec{PolicyRevisionID: c.Gateways[0].Spec.WAF.PolicyRevisionID, Mode: "detection", Membership: ZoneMembership{GatewayIDs: []string{c.Gateways[0].Metadata.ID}}, Reason: "Exact authenticated inventory only"}}
	zoneDigest, e := Digest(zone)
	if e != nil {
		t.Fatal(e)
	}
	request := ResolveRequest{ID: "resolution_trusted", SiteID: "site_msk", ZoneRevisionID: "zone_revision", BaseConfigRevisionID: "configuration_base", Action: "reconcile", CapacityProfile: "pilot-500", CreatedAt: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), CurrentAssignments: map[string]string{}, ReplacementAssignments: []ReplacementAssignment{}, ZoneRevisions: []ZoneRevision{{ID: "zone_revision", Digest: zoneDigest, Content: zone, Published: true}}, AllowLegacyMigration: true}
	r, e := ResolveTrustedZones(context.Background(), c, inputs, request)
	if e != nil || len(r.Conflicts) != 0 {
		t.Fatalf("resolution %#v %v", r, e)
	}
	materialized, e := MaterializeWithTrustedInputs(context.Background(), c, inputs, request, *r, request.CreatedAt.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := Canonicalize(c)
	if e != nil {
		t.Fatal(e)
	}
	if materialized.Configuration.Gateways[0].Spec.Routes[0].ID != canonical.Configuration.Gateways[0].Spec.Routes[0].ID || materialized.Configuration.Gateways[0].Spec.Routes[1].ID != canonical.Configuration.Gateways[0].Spec.Routes[1].ID {
		t.Fatal("materialization changed canonical routes")
	}
	changed := inputs
	changed.SourceDigest = "sha256:" + strings.Repeat("2", 64)
	if _, e = MaterializeWithTrustedInputs(context.Background(), c, changed, request, *r, request.CreatedAt.Add(time.Minute)); e == nil {
		t.Fatal("changed source consumed frozen resolution")
	}
	if _, e = MaterializeWithTrustedInputs(context.Background(), c, inputs, request, *r, request.CreatedAt.Add(30*time.Minute)); e == nil {
		t.Fatal("expired resolution accepted")
	}
	if _, e = MaterializeWithTrustedInputs(context.Background(), c, inputs, request, *r, request.CreatedAt.Add(-time.Second)); e == nil {
		t.Fatal("clock before resolution accepted")
	}
	min := inputs
	min.MinimumWAFMode = "blocking"
	blocked, e := ResolveTrustedZones(context.Background(), c, min, request)
	if e != nil || len(blocked.Conflicts) != 1 || blocked.Conflicts[0].Code != "waf_zone_security_minimum" {
		t.Fatalf("minimum %#v %v", blocked, e)
	}
	for _, invalid := range []TrustedZoneInputs{
		{SourceDigest: inputs.SourceDigest, MinimumWAFMode: "detection", Nodes: catalog.Nodes, Policies: policies},
		{SourceDigest: inputs.SourceDigest, MinimumWAFMode: "detection", Nodes: append(append([]CatalogNode{}, nodes...), nodes[0]), Policies: policies},
		{SourceDigest: inputs.SourceDigest, MinimumWAFMode: "detection", Nodes: nodes, Policies: []CatalogInput{{Kind: "certificate", ID: "certificate", Digest: inputs.SourceDigest, State: "published", SiteID: "site_msk"}}},
	} {
		if _, e = ResolveTrustedZones(context.Background(), c, invalid, request); e == nil {
			t.Fatal("invalid trusted facts accepted")
		}
	}
	// The original authoring API remains explicitly operator-declared.
	catalog.SourceKind = "agent_authenticated"
	if _, e = ResolveZones(context.Background(), c, catalog, request); e == nil {
		t.Fatal("operator catalog masqueraded as trusted inventory")
	}
}

func TestTrustedResolverRejectsOversizedFleetClosureBeforeWholeMarshal(t *testing.T) {
	c := configuration(t)
	c.APIVersion, c.CapacityProfile = "agp.config/v1alpha2", "fleet-10k"
	template := c.Gateways[0]
	c.Gateways = []Gateway{}
	for i := 0; i < 1100; i++ {
		g := template
		g.Metadata.ID = fmt.Sprintf("gw_%04d", i)
		g.Spec.Routes = append([]Route{}, template.Spec.Routes...)
		g.Spec.Routes[0].ID = fmt.Sprintf("route_%04d", i)
		g.Spec.Routes[0].Hostname = fmt.Sprintf("g%04d.example.net", i)
		g.Spec.NodeSelector = NodeSelector{MatchLabels: &Labels{"environment": "pilot"}}
		c.Gateways = append(c.Gateways, g)
	}
	nodes := []CatalogNode{}
	for i := 0; i < 500; i++ {
		nodes = append(nodes, CatalogNode{ID: fmt.Sprintf("node_%03d_", i) + strings.Repeat("n", 119), SiteID: "site_msk", Labels: Labels{"environment": "pilot"}, NodeGroupIDs: []string{}, CapabilityDigest: "sha256:" + strings.Repeat("9", 64)})
	}
	inputs := TrustedZoneInputs{SourceDigest: "sha256:" + strings.Repeat("1", 64), MinimumWAFMode: "detection", Nodes: nodes, Policies: []CatalogInput{{Kind: "waf_policy", ID: template.Spec.WAF.PolicyRevisionID, Digest: "sha256:" + strings.Repeat("2", 64), SiteID: "site_msk", State: "published"}}}
	yes := true
	zone := WafZone{APIVersion: "agp.waf-zone/v1alpha1", Kind: "WafZone", Metadata: ZoneMetadata{ID: "zone_large", Name: "Large fleet zone", SiteID: "site_msk", OwnerID: "owner_1"}, Spec: ZoneSpec{PolicyRevisionID: template.Spec.WAF.PolicyRevisionID, Mode: "detection", Membership: ZoneMembership{SiteDefault: &yes}, Reason: "Authenticated complete fleet target closure"}}
	zoneDigest, e := Digest(zone)
	if e != nil {
		t.Fatal(e)
	}
	request := ResolveRequest{ID: "resolution_large", SiteID: "site_msk", ZoneRevisionID: "zone_large_revision", BaseConfigRevisionID: "base_large", Action: "reconcile", CapacityProfile: "fleet-10k", CreatedAt: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), CurrentAssignments: map[string]string{}, ReplacementAssignments: []ReplacementAssignment{}, ZoneRevisions: []ZoneRevision{{ID: "zone_large_revision", Digest: zoneDigest, Content: zone, Published: true}}, AllowLegacyMigration: true}
	if _, e = ResolveTrustedZones(context.Background(), c, inputs, request); e == nil || !strings.Contains(e.Error(), "resolution_byte_limit") {
		t.Fatalf("oversized fleet closure was not explicitly rejected: %v", e)
	}
}
