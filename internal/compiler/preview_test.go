package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
)

func fixture(t *testing.T) (configmodel.Configuration, configmodel.Catalog, Options) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/v2/examples/configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := configmodel.ParseConfiguration(bytes.NewReader(raw), configmodel.JSON)
	if err != nil {
		t.Fatal(err)
	}
	c := doc.Configuration
	g := c.Gateways[0]
	digest := "sha256:" + strings.Repeat("a", 64)
	catalog := configmodel.Catalog{APIVersion: "agp.catalog/v1alpha1", ID: "catalog_test", SourceKind: "operator_declared", SourceRef: "fixture", RecordedAt: "2026-11-18T00:00:00Z", Sites: []configmodel.CatalogSite{{ID: g.Metadata.SiteID}}, Nodes: []configmodel.CatalogNode{{ID: g.Spec.NodeSelector.NodeIDs[0], SiteID: g.Metadata.SiteID, Labels: configmodel.Labels{}, NodeGroupIDs: []string{}}}, Groups: []string{g.Spec.Routes[0].Access.GroupIDs[0]}, Inputs: []configmodel.CatalogInput{{Kind: "component_profile", ID: g.Spec.ComponentProfileRef.ID, Digest: g.Spec.ComponentProfileRef.Digest, State: "published", SiteID: g.Metadata.SiteID}, {Kind: "certificate", ID: g.Spec.TLS.CertificateVersionID, Digest: digest, State: "published", SiteID: g.Metadata.SiteID}, {Kind: "waf_policy", ID: g.Spec.WAF.PolicyRevisionID, Digest: digest, State: "published", SiteID: g.Metadata.SiteID}}}
	return c, catalog, Options{Version: "s1-preview-1", BuildDigest: digest}
}
func TestDeterministicPreviewPinsAndNoQualification(t *testing.T) {
	c, cat, opts := fixture(t)
	first, err := Preview(context.Background(), c, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Preview(context.Background(), c, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) || first.PreviewDigest == "" || first.CompilerDigest == "" || first.CatalogDigest == "" || first.ConfigDigest == "" {
		t.Fatal("preview not deterministic or missing pins")
	}
	if first.Deployable || len(first.Bundles) != 1 || first.Bundles[0].Deployable || len(first.Bundles[0].Artifacts) != 2 {
		t.Fatal("operator inventory qualified as deployable")
	}
	for _, artifact := range first.Bundles[0].Artifacts {
		if artifact.Digest != configmodel.DigestBytes([]byte(artifact.Content)) {
			t.Fatal("artifact digest mismatch")
		}
	}
	if !hasCode(first, "native_qualification_required") || !hasCode(first, "capability_unqualified") || !hasCode(first, "baseline_unavailable") {
		t.Fatal("qualification gaps hidden")
	}
	original := first.PreviewDigest
	cat.RecordedAt = "2026-11-18T00:00:01Z"
	changed, err := Preview(context.Background(), c, cat, opts)
	if err != nil || changed.PreviewDigest == original {
		t.Fatal("inventory snapshot not pinned")
	}
}
func hasCode(r *Result, code string) bool {
	for _, i := range r.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestSharedHostnameAcrossGatewaysOnNode(t *testing.T) {
	for _, sharedNode := range []bool{true, false} {
		t.Run(fmt.Sprintf("shared_node_%t", sharedNode), func(t *testing.T) {
			c, cat, opts := fixture(t)
			first := c.Gateways[0]
			first.Spec.Routes = append([]configmodel.Route(nil), first.Spec.Routes...)
			first.Spec.Routes[0].Path = "/first"
			second := first
			second.Metadata.ID = "gateway_second"
			second.Spec.Routes = append([]configmodel.Route(nil), first.Spec.Routes...)
			second.Spec.Routes[0].ID = "route_second"
			second.Spec.Routes[0].Path = "/second"
			second.Spec.Routes[0].Hostname = strings.ToUpper(first.Spec.Routes[0].Hostname)
			node := cat.Nodes[0]
			node.ID = "node_second"
			cat.Nodes = append(cat.Nodes, node)
			third := first
			third.Metadata.ID = "gateway_third"
			third.Spec.NodeSelector.NodeIDs = []string{node.ID}
			third.Spec.Routes = append([]configmodel.Route(nil), first.Spec.Routes...)
			third.Spec.Routes[0].ID = "route_third"
			third.Spec.Routes[0].Hostname = "unrelated.example.net"
			if !sharedNode {
				second.Spec.NodeSelector.NodeIDs = []string{node.ID}
			}
			c.Gateways = []configmodel.Gateway{first, second, third}
			r, err := Preview(context.Background(), c, cat, opts)
			if err != nil {
				t.Fatal(err)
			}
			if hasCode(r, "shared_host_conflict") != sharedNode || len(r.Bundles) != 2 {
				t.Fatalf("wrong host ownership result: %+v", r.Issues)
			}
			totalRoutes := 0
			for _, bundle := range r.Bundles {
				totalRoutes += len(bundle.Routes)
				conflicting := sharedNode && bundle.NodeID == first.Spec.NodeSelector.NodeIDs[0]
				hasNginx, hasEffective := false, false
				for _, artifact := range bundle.Artifacts {
					hasNginx = hasNginx || artifact.Name == "nginx/proposal.conf"
					hasEffective = hasEffective || artifact.Name == "effective-routes.json"
				}
				if !hasEffective || hasNginx == conflicting {
					t.Fatalf("node %s: effective=%t nginx=%t conflicting=%t", bundle.NodeID, hasEffective, hasNginx, conflicting)
				}
			}
			if totalRoutes != 3 {
				t.Fatalf("effective routes omitted: %d", totalRoutes)
			}
		})
	}
}

func TestUnknownScopeAndReferences(t *testing.T) {
	for _, scope := range []string{"route", "node_group", "node"} {
		t.Run(scope, func(t *testing.T) {
			c, cat, opts := fixture(t)
			c.ProfileAssignments = []configmodel.ProfileAssignment{{ID: "assignment_1", ProfileRevisionID: "missing", ScopeType: scope, ScopeID: "unknown"}}
			r, err := Preview(context.Background(), c, cat, opts)
			if err != nil {
				t.Fatal(err)
			}
			if !hasCode(r, "unresolved_reference") {
				t.Fatal("dangling assignment accepted")
			}
		})
	}
	c, cat, opts := fixture(t)
	c.Gateways[0].Spec.ComponentProfileRef.Digest = "sha256:" + strings.Repeat("b", 64)
	r, err := Preview(context.Background(), c, cat, opts)
	if err != nil || !hasCode(r, "unresolved_reference") {
		t.Fatal("mismatched exact component digest accepted")
	}
}

func TestWAFPolicyCannotCrossExistingSites(t *testing.T) {
	c, cat, opts := fixture(t)
	cat.Sites = append(cat.Sites, configmodel.CatalogSite{ID: "site_other"})
	for i := range cat.Inputs {
		if cat.Inputs[i].Kind == "waf_policy" {
			cat.Inputs[i].SiteID = "site_other"
		}
	}
	r, err := Preview(context.Background(), c, cat, opts)
	if err != nil || !hasCode(r, "unresolved_reference") {
		t.Fatalf("cross-Site policy accepted: result=%+v err=%v", r, err)
	}
}

func TestReservedOriginsPinnedAndNativeArtifactsSuppressed(t *testing.T) {
	c, cat, opts := fixture(t)
	first := c.Gateways[0]
	first.Spec.Routes = append([]configmodel.Route(nil), first.Spec.Routes...)
	first.Spec.Routes[0].Hostname = "management.example.net"
	second := first
	second.Metadata.ID = "gateway_login"
	second.Spec.Routes = append([]configmodel.Route(nil), first.Spec.Routes...)
	second.Spec.Routes[0].ID = "route_login"
	second.Spec.Routes[0].Hostname = "LOGIN.example.net"
	third := first
	third.Metadata.ID = "gateway_other"
	third.Spec.NodeSelector.NodeIDs = []string{"node_other"}
	third.Spec.Routes = append([]configmodel.Route(nil), first.Spec.Routes...)
	third.Spec.Routes[0].ID = "route_other"
	third.Spec.Routes[0].Hostname = "app.example.net"
	node := cat.Nodes[0]
	node.ID = "node_other"
	cat.Nodes = append(cat.Nodes, node)
	c.Gateways = []configmodel.Gateway{first, second, third}
	opts.ReservedHosts = []string{"LOGIN.example.net", "MANAGEMENT.example.net"}
	r, err := Preview(context.Background(), c, cat, opts)
	if err != nil || !hasCode(r, "reserved_origin") {
		t.Fatalf("reserved origins accepted: result=%+v err=%v", r, err)
	}
	issues := 0
	for _, issue := range r.Issues {
		if issue.Code == "reserved_origin" {
			issues++
		}
	}
	if issues != 2 || len(r.Bundles) != 2 {
		t.Fatalf("expected both reserved hosts to block: %+v", r.Issues)
	}
	totalRoutes := 0
	for _, bundle := range r.Bundles {
		totalRoutes += len(bundle.Routes)
		hasNative, hasEffective := false, false
		for _, artifact := range bundle.Artifacts {
			hasNative = hasNative || artifact.Name == "nginx/proposal.conf"
			hasEffective = hasEffective || artifact.Name == "effective-routes.json"
		}
		if !hasEffective || hasNative != (bundle.NodeID == "node_other") {
			t.Fatalf("wrong artifact suppression: %+v", bundle)
		}
	}
	if totalRoutes != 3 {
		t.Fatalf("effective routes omitted: %d", totalRoutes)
	}
	opts.ReservedHosts = []string{"management.example.net", "login.example.net", "LOGIN.EXAMPLE.NET"}
	normalized, err := Preview(context.Background(), c, cat, opts)
	if err != nil || normalized.PreviewDigest != r.PreviewDigest {
		t.Fatalf("reserved host set not canonical: %v", err)
	}
	opts.ReservedHosts = []string{"login.example.net"}
	changed, err := Preview(context.Background(), c, cat, opts)
	if err != nil || changed.CompilerDigest == r.CompilerDigest {
		t.Fatalf("reserved hosts not pinned: %v", err)
	}
	opts.ReservedHosts = []string{"https://management.example.net"}
	if _, err := Preview(context.Background(), c, cat, opts); err == nil {
		t.Fatal("reserved hostname accepted as URL")
	}
}

func profileInput(id, level, site string, overrides configmodel.Overrides, locks []string) configmodel.CatalogInput {
	profile := &configmodel.PolicyProfile{APIVersion: "agp.profile/v1alpha1", Kind: "PolicyProfile", Metadata: configmodel.ProfileMetadata{ID: "profile_" + id, Name: "Profile", SiteID: site}, Spec: configmodel.ProfileSpec{Level: level, Overrides: overrides, LockedFields: locks}}
	digest, _ := configmodel.Digest(profile)
	return configmodel.CatalogInput{Kind: "policy_profile", ID: id, Digest: digest, SiteID: site, State: "published", Profile: profile}
}

func TestProfilesScopedAndInheritedLocks(t *testing.T) {
	c, cat, opts := fixture(t)
	value := 10
	mode := "blocking"
	global := profileInput("profile_version_global", "global", "", configmodel.Overrides{ConnectTimeoutSeconds: &value}, []string{"wafMode"})
	node := profileInput("profile_version_node", "node", "site_msk", configmodel.Overrides{WAFMode: &mode}, []string{})
	cat.Inputs = append(cat.Inputs, global, node)
	c.ProfileAssignments = []configmodel.ProfileAssignment{{ID: "a_global", ProfileRevisionID: global.ID, ScopeType: "global"}, {ID: "a_node", ProfileRevisionID: node.ID, ScopeType: "node", ScopeID: cat.Nodes[0].ID}}
	r, err := Preview(context.Background(), c, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if hasCode(r, "unresolved_reference") || !hasCode(r, "profile_locked") {
		t.Fatalf("scoped refs or inherited lock wrong %+v", r.Issues)
	}
	if r.Bundles[0].Routes[0].WAF.Mode != "detection" {
		t.Fatal("descendant escaped inherited lock")
	}
}
func TestIssueOverflowRemainsBlocking(t *testing.T) {
	c, cat, opts := fixture(t)
	labels := configmodel.Labels{}
	c.Gateways[0].Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
	cat.Nodes = []configmodel.CatalogNode{}
	for i := 0; i < 60; i++ {
		cat.Nodes = append(cat.Nodes, configmodel.CatalogNode{ID: fmt.Sprintf("node_%03d", i), SiteID: "site_msk", Labels: configmodel.Labels{}, NodeGroupIDs: []string{}})
	}
	off := false
	p := profileInput("late_profile", "node", "site_msk", configmodel.Overrides{RequireMFA: &off}, []string{})
	cat.Inputs = append(cat.Inputs, p)
	c.ProfileAssignments = []configmodel.ProfileAssignment{{ID: "late_assignment", ProfileRevisionID: p.ID, ScopeType: "node", ScopeID: "node_059"}}
	r, err := Preview(context.Background(), c, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Issues) != 100 || !hasCode(r, "issues_truncated") {
		t.Fatalf("late security error disappeared: %d %+v", len(r.Issues), r.Issues)
	}
}
func TestReplicatedPreviewBound(t *testing.T) {
	c, cat, opts := fixture(t)
	c.APIVersion = "agp.config/v1alpha2"
	c.CapacityProfile = "fleet-10k"
	g := &c.Gateways[0]
	route := g.Spec.Routes[0]
	g.Spec.Routes = []configmodel.Route{}
	for i := 0; i < 1000; i++ {
		r := route
		r.ID = fmt.Sprintf("route_%04d", i)
		r.Path = fmt.Sprintf("/route/%04d", i)
		g.Spec.Routes = append(g.Spec.Routes, r)
	}
	labels := configmodel.Labels{}
	g.Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
	cat.Nodes = []configmodel.CatalogNode{}
	for i := 0; i < 500; i++ {
		cat.Nodes = append(cat.Nodes, configmodel.CatalogNode{ID: fmt.Sprintf("node_%03d", i), SiteID: "site_msk", Labels: configmodel.Labels{}, NodeGroupIDs: []string{}})
	}
	_, err := Preview(context.Background(), c, cat, opts)
	if err == nil || !strings.Contains(err.Error(), "preview_capacity_exceeded") {
		t.Fatalf("replication not bounded: %v", err)
	}
}
func TestRealFleetDatasets(t *testing.T) {
	if testing.Short() {
		t.Skip("real fleet datasets omitted in short mode")
	}
	for _, count := range []int{1000, 5000, 10000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c, cat, opts := fixture(t)
			c.APIVersion = "agp.config/v1alpha2"
			c.CapacityProfile = "fleet-10k"
			base := c.Gateways[0]
			c.Gateways = make([]configmodel.Gateway, 0, count)
			for i := 0; i < count; i++ {
				g := base
				g.Metadata.ID = fmt.Sprintf("gateway_%05d", i)
				g.Metadata.Name = "Application"
				g.Metadata.Labels = configmodel.Labels{"environment": "production"}
				r := base.Spec.Routes[0]
				r.ID = fmt.Sprintf("route_%05d", i)
				r.Name = "Application"
				r.Hostname = fmt.Sprintf("app-%05d.example.net", i)
				g.Spec.Routes = []configmodel.Route{r}
				c.Gateways = append(c.Gateways, g)
			}
			start := time.Now()
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := configmodel.ParseConfiguration(bytes.NewReader(raw), configmodel.JSON)
			if err != nil {
				t.Fatal(err)
			}
			parseDuration := time.Since(start)
			if len(parsed.Configuration.Gateways) != count {
				t.Fatal("dataset was sampled")
			}
			zone := configmodel.WafZone{APIVersion: "agp.waf-zone/v1alpha1", Kind: "WafZone", Metadata: configmodel.ZoneMetadata{ID: "zone_all", Name: "All applications", SiteID: "site_msk", OwnerID: "owner_1"}, Spec: configmodel.ZoneSpec{PolicyRevisionID: base.Spec.WAF.PolicyRevisionID, Mode: "detection", Membership: configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "production"}}, Reason: "Scale qualification fixture"}}
			zoneDigest, _ := configmodel.Digest(zone)
			request := configmodel.ResolveRequest{ID: "resolution_scale", SiteID: "site_msk", ZoneRevisionID: "zone_version", BaseConfigRevisionID: "config_version", Action: "reconcile", CapacityProfile: "fleet-10k", CreatedAt: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), CurrentAssignments: map[string]string{}, ZoneRevisions: []configmodel.ZoneRevision{{ID: "zone_version", Digest: zoneDigest, Content: zone, Published: true}}, ReplacementAssignments: []configmodel.ReplacementAssignment{}, AllowLegacyMigration: true}
			resolved, err := configmodel.ResolveZones(context.Background(), parsed.Configuration, cat, request)
			if err != nil || len(resolved.Members) != count || len(resolved.Conflicts) != 0 {
				t.Fatalf("full frozen resolution: members=%d err=%v", len(resolved.Members), err)
			}
			compileStart := time.Now()
			preview, err := Preview(context.Background(), parsed.Configuration, cat, opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(preview.Bundles) != 1 || len(preview.Bundles[0].Routes) != count {
				t.Fatal("preview sampled routes")
			}
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			encoded, _ := json.Marshal(preview)
			t.Logf("actual Gateways=%d source=%d canonical=%d preview=%d parse=%s compile=%s heap=%d", count, len(raw), len(parsed.Canonical), len(encoded), parseDuration, time.Since(compileStart), memory.HeapAlloc)
		})
	}
}
