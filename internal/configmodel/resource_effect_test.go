package configmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type routingTestRoute struct{ id, host, path string }

func routingTestGateway(t *testing.T, routes ...routingTestRoute) Gateway {
	t.Helper()
	g, err := ParseGateway(bytes.NewReader(example(t, "examples/gateway.json")), JSON)
	if err != nil {
		t.Fatal(err)
	}
	template := g.Spec.Routes[0]
	g.Spec.Routes = nil
	for _, input := range routes {
		route := template
		route.ID, route.Hostname, route.Path = input.id, input.host, input.path
		route.Access.GroupIDs = slices.Clone(template.Access.GroupIDs)
		route.Access.AllowCIDRs = slices.Clone(template.Access.AllowCIDRs)
		route.WAFExceptionIDs = []string{}
		g.Spec.Routes = append(g.Spec.Routes, route)
	}
	return *g
}

func cloneRoutingGateway(t *testing.T, g Gateway) Gateway {
	t.Helper()
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var result Gateway
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRoutingChangeImpacts(t *testing.T) {
	const host = "app.example.net"
	for _, tc := range []struct {
		name       string
		routes     []routingTestRoute
		newHost    string
		newPath    string
		changeBody bool
		want       []string
	}{
		{"content_only", []routingTestRoute{{"own", host, "/a"}, {"neighbor", host, "/"}}, host, "/a", true, []string{}},
		{"canonical_host_only", []routingTestRoute{{"own", host, "/a"}, {"neighbor", host, "/"}}, "APP.EXAMPLE.NET", "/a", false, []string{}},
		{"narrow_exposes_fallback", []routingTestRoute{{"own", host, "/a"}, {"fallback", host, "/"}, {"nested", host, "/a/b/locked"}}, host, "/a/b", false, []string{"fallback", "own"}},
		{"widen_takes_fallback", []routingTestRoute{{"own", host, "/a/b"}, {"fallback", host, "/"}, {"nested", host, "/a/b/locked"}}, host, "/a", false, []string{"fallback", "own"}},
		{"nested_shadow_unchanged", []routingTestRoute{{"own", host, "/a"}, {"nested", host, "/a/locked"}}, host, "/a/open", false, []string{"own"}},
		{"root_narrow_does_not_touch_neighbor", []routingTestRoute{{"own", host, "/"}, {"neighbor", host, "/public"}}, host, "/private", false, []string{"own"}},
		{"move_to_deny", []routingTestRoute{{"own", host, "/a"}}, "other.example.net", "/a", false, []string{"own"}},
		{"both_host_fallbacks", []routingTestRoute{{"own", host, "/a"}, {"old_fallback", host, "/"}, {"new_fallback", "other.example.net", "/"}}, "other.example.net", "/a", false, []string{"new_fallback", "old_fallback", "own"}},
		{"segment_boundary_no_neighbor", []routingTestRoute{{"own", host, "/a"}, {"neighbor", host, "/ab"}}, host, "/a/next", false, []string{"own"}},
		{"prefix_move_to_neighbor_host", []routingTestRoute{{"own", host, "/a"}, {"neighbor", "other.example.net", "/ab"}}, "other.example.net", "/a", false, []string{"own"}},
		{"same_host_move_between_fallbacks", []routingTestRoute{{"own", host, "/a/own"}, {"z_old", host, "/a"}, {"a_new", host, "/b"}}, host, "/b/own", false, []string{"a_new", "own", "z_old"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := routingTestGateway(t, tc.routes...)
			candidate := cloneRoutingGateway(t, old)
			candidate.Spec.Routes[0].Hostname = tc.newHost
			candidate.Spec.Routes[0].Path = tc.newPath
			if tc.changeBody {
				candidate.Spec.Routes[0].Name = "Changed display name"
				candidate.Spec.Routes[0].Upstream.URL = "https://changed.example.net"
				candidate.Spec.Routes[0].Access.GroupIDs = []string{"new_group"}
				candidate.Spec.Routes[0].WAFExceptionIDs = []string{"exception_new"}
			}
			beforeOld, _ := json.Marshal(old)
			beforeCandidate, _ := json.Marshal(candidate)
			got, err := RoutingChangeImpacts(old, candidate, "own")
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("impacts=%v want=%v err=%v", got, tc.want, err)
			}
			afterOld, _ := json.Marshal(old)
			afterCandidate, _ := json.Marshal(candidate)
			if !bytes.Equal(beforeOld, afterOld) || !bytes.Equal(beforeCandidate, afterCandidate) {
				t.Fatal("caller-owned gateway changed during normalization")
			}
		})
	}
}

func TestRoutingChangeImpactsRejectsBoundaryChanges(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Gateway)
	}{
		{"gateway_id", func(g *Gateway) { g.Metadata.ID = "different_gateway" }},
		{"site", func(g *Gateway) { g.Metadata.SiteID = "different_site" }},
		{"name", func(g *Gateway) { g.Metadata.Name = "Renamed gateway" }},
		{"labels", func(g *Gateway) { g.Metadata.Labels["environment"] = "production" }},
		{"ownership", func(g *Gateway) { g.Spec.Ownership = "managed" }},
		{"selector", func(g *Gateway) { g.Spec.NodeSelector.NodeIDs = []string{"node_other"} }},
		{"component", func(g *Gateway) { g.Spec.ComponentProfileRef.ID = "component_other" }},
		{"certificate", func(g *Gateway) { g.Spec.TLS.CertificateVersionID = "certificate_other" }},
		{"waf", func(g *Gateway) { g.Spec.WAF.Mode = "blocking" }},
		{"monitoring", func(g *Gateway) { g.Spec.Monitoring.Logs = false }},
		{"neighbor_content", func(g *Gateway) { g.Spec.Routes[1].Upstream.URL = "https://changed.example.net" }},
		{"neighbor_path", func(g *Gateway) { g.Spec.Routes[1].Path = "/other" }},
		{"route_id", func(g *Gateway) { g.Spec.Routes[0].ID = "replacement" }},
		{"remove_neighbor", func(g *Gateway) { g.Spec.Routes = g.Spec.Routes[:1] }},
		{"add_neighbor", func(g *Gateway) {
			r := g.Spec.Routes[1]
			r.ID, r.Path = "added", "/added"
			g.Spec.Routes = append(g.Spec.Routes, r)
		}},
		{"duplicate_id", func(g *Gateway) { g.Spec.Routes[1].ID = "own" }},
		{"canonical_collision", func(g *Gateway) { g.Spec.Routes[1].Hostname, g.Spec.Routes[1].Path = "APP.EXAMPLE.NET", "/a" }},
		{"invalid_route", func(g *Gateway) { g.Spec.Routes[0].Path = "/a/" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := routingTestGateway(t, routingTestRoute{"own", "app.example.net", "/a"}, routingTestRoute{"neighbor", "app.example.net", "/"})
			candidate := cloneRoutingGateway(t, old)
			tc.edit(&candidate)
			if got, err := RoutingChangeImpacts(old, candidate, "own"); err == nil || got != nil {
				t.Fatalf("boundary change accepted: impacts=%v err=%v", got, err)
			}
		})
	}
	old := routingTestGateway(t, routingTestRoute{"own", "app.example.net", "/a"})
	if _, err := RoutingChangeImpacts(old, old, "missing"); err == nil {
		t.Fatal("missing edited route accepted")
	}
	duplicate := routingTestGateway(t, routingTestRoute{"own", "app.example.net", "/a"}, routingTestRoute{"own", "other.example.net", "/a"})
	if _, err := RoutingChangeImpacts(duplicate, duplicate, "own"); err == nil {
		t.Fatal("ambiguous old route ID accepted")
	}
	if _, err := RoutingChangeImpacts(Gateway{}, Gateway{}, "own"); err == nil {
		t.Fatal("invalid gateway accepted")
	}
}

func TestRoutingChangeImpactsUsesSegmentBoundary(t *testing.T) {
	routes := []Route{{ID: "a", Hostname: "app.example.net", Path: "/a"}, {ID: "root", Hostname: "app.example.net", Path: "/"}}
	for path, want := range map[string]string{"/a": "a", "/a/b": "a", "/ab": "root", "/ab/c": "root", "/": "root"} {
		if got := routingWinner(routes, "app.example.net", path); got != want {
			t.Errorf("request %s selected %s, want %s", path, got, want)
		}
	}
}

func TestParseRouteClosedAndNormalized(t *testing.T) {
	g := routingTestGateway(t, routingTestRoute{"own", "BÜCHER.example", "/a"})
	route := g.Spec.Routes[0]
	route.Name = "Cafe\u0301"
	route.Upstream.URL = "HTTP://UPSTREAM.EXAMPLE:80/base/"
	route.Access.AllowCIDRs = []string{"10.20.1.1/16", "192.0.2.5/24"}
	route.Access.GroupIDs = []string{"z_group", "a_group"}
	route.WAFExceptionIDs = []string{"z_exception", "a_exception"}
	rawJSON, _ := json.Marshal(route)
	rawYAML, err := YAMLDocument(route)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		format Format
		raw    []byte
	}{{JSON, rawJSON}, {YAML, rawYAML}} {
		parsed, err := ParseRoute(bytes.NewReader(input.raw), input.format)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Name != "Café" || parsed.Hostname != "xn--bcher-kva.example" || parsed.Upstream.URL != "http://upstream.example/base/" ||
			!slices.Equal(parsed.Access.AllowCIDRs, []string{"10.20.0.0/16", "192.0.2.0/24"}) || !slices.Equal(parsed.Access.GroupIDs, []string{"a_group", "z_group"}) ||
			!slices.Equal(parsed.WAFExceptionIDs, []string{"a_exception", "z_exception"}) {
			t.Fatalf("route not normalized: %+v", parsed)
		}
		g.Spec.Routes = []Route{route}
		if err := NormalizeGateway(&g); err != nil || !reflect.DeepEqual(g.Spec.Routes[0], *parsed) {
			t.Fatalf("standalone/gateway normalization differs: %v", err)
		}
	}
	for _, bad := range []string{
		strings.Replace(string(rawJSON), `"id":"own"`, `"id":"own","ID":"own"`, 1),
		strings.Replace(string(rawJSON), `"id":"own"`, `"id":"own","id":"own"`, 1),
		strings.Replace(string(rawJSON), `"wafExceptionIds":["z_exception","a_exception"]`, `"wafExceptionIds":null`, 1),
		strings.Replace(string(rawJSON), `"hostname":"BÜCHER.example",`, "", 1),
	} {
		if _, err := ParseRoute(strings.NewReader(bad), JSON); err == nil {
			t.Fatal("open or incomplete route DTO accepted")
		}
	}
}

func TestParseRouteMatchesSupportedEdgeAuthPrefixes(t *testing.T) {
	for _, path := range []string{"/", "/a", "/a/b", "/_ag"} {
		g := routingTestGateway(t, routingTestRoute{"own", "app.example.net", path})
		raw, _ := json.Marshal(g.Spec.Routes[0])
		if _, err := ParseRoute(bytes.NewReader(raw), JSON); err != nil {
			t.Fatalf("supported prefix %q rejected: %v", path, err)
		}
	}
	for _, path := range []string{"/a/", "/a/b/", "/_agp", "/_agp/start", "/_agp-other"} {
		g := routingTestGateway(t, routingTestRoute{"own", "app.example.net", path})
		raw, _ := json.Marshal(g.Spec.Routes[0])
		_, routeErr := ParseRoute(bytes.NewReader(raw), JSON)
		gatewayRaw, _ := json.Marshal(g)
		_, gatewayErr := ParseGateway(bytes.NewReader(gatewayRaw), JSON)
		if routeErr == nil || gatewayErr != nil || !strings.HasPrefix(routeErr.Error(), "/path: invalid_path:") {
			t.Errorf("unsupported prefix %q: route=%v gateway=%v", path, routeErr, gatewayErr)
		}
		c := configuration(t)
		c.Gateways[0].Spec.Routes[0].Path = path
		if _, err := Canonicalize(c); err != nil {
			t.Errorf("historically accepted prefix %q rejected by canonicalization: %v", path, err)
		}
		configurationRaw, _ := json.Marshal(c)
		if _, err := ParseConfiguration(bytes.NewReader(configurationRaw), JSON); err != nil {
			t.Errorf("historically accepted prefix %q rejected by configuration parser: %v", path, err)
		}
	}
}

func TestRoutingChangeImpactsRejectsUnsupportedHistoricalPrefixes(t *testing.T) {
	for _, path := range []string{"/a/", "/_agp", "/_agp/start", "/_agp-other"} {
		t.Run(path, func(t *testing.T) {
			old := routingTestGateway(t, routingTestRoute{"own", "app.example.net", "/a"})
			candidate := cloneRoutingGateway(t, old)
			candidate.Spec.Routes[0].Path = path
			if got, err := RoutingChangeImpacts(old, candidate, "own"); err == nil || got != nil {
				t.Fatalf("unsupported candidate accepted: impacts=%v err=%v", got, err)
			}
			if got, err := RoutingChangeImpacts(candidate, old, "own"); err == nil || got != nil {
				t.Fatalf("unsupported old route accepted: impacts=%v err=%v", got, err)
			}
			withNeighbor := routingTestGateway(t, routingTestRoute{"own", "app.example.net", "/a"}, routingTestRoute{"neighbor", "app.example.net", path})
			changed := cloneRoutingGateway(t, withNeighbor)
			changed.Spec.Routes[0].Upstream.URL = "https://updated.example.net"
			if got, err := RoutingChangeImpacts(withNeighbor, changed, "own"); err == nil || got != nil {
				t.Fatalf("unsupported unchanged neighbor accepted: impacts=%v err=%v", got, err)
			}
		})
	}
}

func TestFleetGatewayRoutingBeyondPilotByteBudget(t *testing.T) {
	g := routingTestGateway(t, routingTestRoute{"route_000", "app.example.net", "/0"})
	template := g.Spec.Routes[0]
	groups := make([]string, 100)
	for i := range groups {
		groups[i] = fmt.Sprintf("group_%03d_%s", i, strings.Repeat("x", 116))
	}
	g.Spec.Routes = make([]Route, 200)
	for i := range g.Spec.Routes {
		route := template
		route.ID = fmt.Sprintf("route_%03d", i)
		route.Path = fmt.Sprintf("/%d", i)
		route.Access.GroupIDs = slices.Clone(groups)
		g.Spec.Routes[i] = route
	}
	raw, err := json.Marshal(g)
	if err != nil || len(raw) <= Pilot.MaxBytes || len(raw) > Fleet.MaxBytes {
		t.Fatalf("bad large valid fixture: bytes=%d err=%v", len(raw), err)
	}
	if _, err := ParseGateway(bytes.NewReader(raw), JSON); err == nil {
		t.Fatal("legacy pilot byte budget changed")
	}
	if _, err := ParseGatewayForProfile(bytes.NewReader(raw), JSON, Pilot.Profile); err == nil {
		t.Fatal("explicit pilot byte budget changed")
	}
	fleet, err := ParseGatewayForProfile(bytes.NewReader(raw), JSON, Fleet.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGatewayForProfile(bytes.NewReader(raw), JSON, "unknown"); err == nil {
		t.Fatal("unknown capacity profile accepted")
	}
	for _, kind := range []string{"Configuration", "Unknown", ""} {
		changedKind := bytes.Replace(raw, []byte(`"kind":"Gateway"`), []byte(`"kind":"`+kind+`"`), 1)
		if err := jsonPreflight(changedKind); err == nil || !strings.Contains(err.Error(), "capacity_limit") {
			t.Fatalf("kind %q bypassed pilot preflight: %v", kind, err)
		}
	}
	missingKind := bytes.Replace(raw, []byte(`"kind":"Gateway",`), nil, 1)
	if err := jsonPreflight(missingKind); err == nil || !strings.Contains(err.Error(), "capacity_limit") {
		t.Fatalf("missing kind bypassed pilot preflight: %v", err)
	}
	yamlRaw, err := YAMLDocument(g)
	if err != nil || len(yamlRaw) <= Pilot.MaxBytes {
		t.Fatalf("bad large YAML fixture: bytes=%d err=%v", len(yamlRaw), err)
	}
	if _, err := ParseGateway(bytes.NewReader(yamlRaw), YAML); err == nil {
		t.Fatal("legacy YAML gateway byte budget changed")
	}
	if _, err := ParseGatewayForProfile(bytes.NewReader(yamlRaw), YAML, Fleet.Profile); err != nil {
		t.Fatalf("large fleet YAML gateway rejected: %v", err)
	}
	for _, kind := range []string{"Configuration", "Unknown", ""} {
		changedKind := bytes.Replace(yamlRaw, []byte("kind: \"Gateway\"\n"), []byte("kind: \""+kind+"\"\n"), 1)
		if bytes.Equal(changedKind, yamlRaw) {
			t.Fatal("YAML kind fixture was not changed")
		}
		if err := yamlPreflight(changedKind); err == nil || !strings.Contains(err.Error(), "capacity_limit") {
			t.Fatalf("YAML kind %q bypassed pilot preflight: %v", kind, err)
		}
	}
	missingYAMLKind := bytes.Replace(yamlRaw, []byte("kind: \"Gateway\"\n"), nil, 1)
	if err := yamlPreflight(missingYAMLKind); err == nil || !strings.Contains(err.Error(), "capacity_limit") {
		t.Fatalf("missing YAML kind bypassed pilot preflight: %v", err)
	}
	candidate := cloneRoutingGateway(t, *fleet)
	candidate.Spec.Routes[0].Upstream.URL = "https://updated.example.net"
	if impacts, err := RoutingChangeImpacts(*fleet, candidate, "route_000"); err != nil || len(impacts) != 0 {
		t.Fatalf("valid fleet gateway resource change denied: impacts=%v err=%v", impacts, err)
	}
}
