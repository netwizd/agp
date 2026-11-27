package configmodel

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCatalogInputCapacityBeyondGenericArrayBudget(t *testing.T) {
	c := catalogFor(configuration(t))
	c.Inputs = make([]CatalogInput, 20001)
	for i := range c.Inputs {
		c.Inputs[i] = CatalogInput{Kind: "certificate", ID: "cert_" + strconv.Itoa(i), Digest: "sha256:" + strings.Repeat("a", 64), State: "published"}
	}
	canonical, err := CanonicalizeCatalog(c)
	if err != nil {
		t.Fatal(err)
	}
	yamlBytes, err := YAMLDocument(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		format Format
		data   []byte
	}{{JSON, canonical.Canonical}, {YAML, yamlBytes}} {
		parsed, err := ParseCatalog(bytes.NewReader(tc.data), tc.format)
		if err != nil || parsed.Digest != canonical.Digest {
			t.Fatalf("%s catalog round-trip: %v", tc.format, err)
		}
	}
	if err := jsonPreflight([]byte(`{"inputs":[` + strings.Repeat(`0,`, 50000) + `0]}`)); err == nil {
		t.Fatal("oversized catalog inputs escaped preflight")
	}
	if err := yamlPreflight([]byte("inputs: [\n" + strings.Repeat("0,\n", 50000) + "0]\n")); err == nil {
		t.Fatal("oversized flow catalog inputs escaped preflight")
	}
}

func example(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../docs/v2", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func configuration(t *testing.T) Configuration {
	t.Helper()
	d, err := ParseConfiguration(bytes.NewReader(example(t, "examples/configuration.json")), JSON)
	if err != nil {
		t.Fatal(err)
	}
	return d.Configuration
}
func catalogFor(c Configuration) Catalog {
	return Catalog{APIVersion: "agp.catalog/v1alpha1", ID: "catalog_1", SourceKind: "operator_declared", SourceRef: "test inventory", RecordedAt: "2026-11-18T00:00:00Z", Sites: []CatalogSite{{ID: "site_msk"}}, Nodes: []CatalogNode{{ID: "node_msk01", SiteID: "site_msk", Labels: Labels{}, NodeGroupIDs: []string{}}}, Groups: []string{"grp_AbCdEf123"}, Inputs: []CatalogInput{{Kind: "component_profile", ID: c.Gateways[0].Spec.ComponentProfileRef.ID, Digest: c.Gateways[0].Spec.ComponentProfileRef.Digest, State: "published", SiteID: "site_msk"}, {Kind: "certificate", ID: c.Gateways[0].Spec.TLS.CertificateVersionID, Digest: "sha256:" + strings.Repeat("b", 64), State: "published", SiteID: "site_msk"}, {Kind: "waf_policy", ID: c.Gateways[0].Spec.WAF.PolicyRevisionID, Digest: "sha256:" + strings.Repeat("c", 64), State: "published", SiteID: "site_msk"}}}
}

func TestWAFPolicyCatalogRequiresSite(t *testing.T) {
	c := catalogFor(configuration(t))
	for i := range c.Inputs {
		if c.Inputs[i].Kind != "waf_policy" {
			// Components and certificates may retain their global scope.
			c.Inputs[i].SiteID = ""
		}
	}
	if _, err := CanonicalizeCatalog(c); err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"", "site_unknown"} {
		for i := range c.Inputs {
			if c.Inputs[i].Kind == "waf_policy" {
				c.Inputs[i].SiteID = site
			}
		}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseCatalog(bytes.NewReader(raw), JSON); err == nil {
			t.Fatalf("WAF policy scope %q accepted", site)
		}
	}
}

func TestApprovedFixtures(t *testing.T) {
	var cases []struct {
		File, Schema string
		Valid        bool
	}
	if err := json.Unmarshal(example(t, "fixtures/cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, tc := range cases {
		if tc.Schema != "configuration" && tc.Schema != "configuration-v1alpha2" && tc.Schema != "gateway" && tc.Schema != "waf-zone" && tc.Schema != "waf-zone-resolution" && tc.Schema != "waf-zone-change" && tc.Schema != "profile" {
			continue
		}
		t.Run(tc.File, func(t *testing.T) {
			format := JSON
			if strings.HasSuffix(tc.File, ".yaml") {
				format = YAML
			}
			b := bytes.NewReader(example(t, tc.File))
			var err error
			switch tc.Schema {
			case "configuration":
				_, err = ParseConfigurationForProfile(b, format, "pilot-500")
			case "configuration-v1alpha2":
				_, err = ParseConfigurationForProfile(b, format, "fleet-10k")
			case "gateway":
				_, err = ParseGateway(b, format)
			case "waf-zone":
				_, err = ParseWafZone(b, format)
			case "waf-zone-resolution":
				_, err = ParseZoneResolution(b, format)
			case "waf-zone-change":
				_, err = ParseZoneChange(b, format)
			case "profile":
				_, err = ParsePolicyProfile(b, format)
			}
			if (err == nil) != tc.Valid {
				t.Fatalf("valid=%t err=%v", tc.Valid, err)
			}
		})
		checked++
	}
	if checked < 15 {
		t.Fatal("fixture coverage unexpectedly empty")
	}
}
func TestStrictParserAdversarial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		f      Format
		source string
	}{
		{"duplicate", JSON, `{"apiVersion":"a","apiVersion":"b"}`}, {"escaped_duplicate", JSON, `{"a":1,"\u0061":2}`}, {"surrogate", JSON, `{"name":"\ud800"}`}, {"low_surrogate", JSON, `{"name":"\udc00"}`}, {"multi_json", JSON, `{} {}`}, {"deep_json", JSON, `{"x":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`}, {"anchor", YAML, "a: &a [1]\nb: *a\n"}, {"merge", YAML, "x:\n  <<: {a: b}\n"}, {"tag", YAML, "a: !!str hello\n"}, {"nan", YAML, "a: .nan\n"}, {"coercion", YAML, "a: 01\n"}, {"multi_yaml", YAML, "a: b\n---\na: c\n"}, {"duplicate_yaml", YAML, "a: b\na: c\n"}, {"key_limit_json", JSON, `{"` + strings.Repeat("x", 1000) + `":1}`}, {"key_limit_yaml", YAML, strings.Repeat("x", 1000) + ": x\n"}, {"plain_apostrophe", YAML, "name: a'b\na: " + strings.Repeat("[", 50) + "0" + strings.Repeat("]", 50)}, {"plain_quote", YAML, "name: a\"b\na: " + strings.Repeat("[", 50) + "0" + strings.Repeat("]", 50)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfiguration(strings.NewReader(tc.source), tc.f); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	if err := yamlPreflight([]byte("unknown: [" + strings.Repeat("1,", 25000) + "1]")); err == nil {
		t.Fatal("flow cardinality escaped preflight")
	}
	if err := yamlPreflight([]byte("unknown:\n" + strings.Repeat("- x\n", 25000))); err == nil {
		t.Fatal("block cardinality escaped preflight")
	}
}
func TestRoundTripCanonicalAndNFC(t *testing.T) {
	c := configuration(t)
	doc, err := Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	yamlBytes, err := YAMLDocument(c)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConfiguration(bytes.NewReader(yamlBytes), YAML)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Digest != parsed.Digest || !bytes.Equal(doc.Canonical, parsed.Canonical) {
		t.Fatal("YAML changed meaning")
	}
	yamlGateway, err := ParseGateway(bytes.NewReader(example(t, "examples/gateway.yaml")), YAML)
	if err != nil {
		t.Fatal(err)
	}
	jsonGateway, err := ParseGateway(bytes.NewReader(example(t, "examples/gateway.json")), JSON)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Digest(yamlGateway)
	b, _ := Digest(jsonGateway)
	if a != b {
		t.Fatal("approved YAML and JSON gateway differ")
	}
	c.Metadata.Name = "Cafe\u0301"
	aDoc, err := Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Metadata.Name = "Café"
	bDoc, err := Canonicalize(c)
	if err != nil || aDoc.Digest != bDoc.Digest {
		t.Fatal("NFC not canonical")
	}
	c.Gateways[0].Metadata.ID = "GW_Case"
	c.Gateways[0].Spec.Routes[0].Hostname = "Пример.РФ"
	idn, err := Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	if idn.Configuration.Gateways[0].Metadata.ID != "GW_Case" || idn.Configuration.Gateways[0].Spec.Routes[0].Hostname != "xn--e1afmkfd.xn--p1ai" {
		t.Fatal("IDNA or opaque ID corrupted")
	}
	canonical, err := CanonicalJSON(map[string]any{"\ue000": 1, "😀": 2, "line": "x\u2028y"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(canonical), `{"line":`) || strings.Index(string(canonical), "😀") > strings.Index(string(canonical), "\ue000") || bytes.Contains(canonical, []byte(`\u2028`)) {
		t.Fatalf("not JCS: %s", canonical)
	}
}
func TestRequiredFalseAndUnknownFields(t *testing.T) {
	c := configuration(t)
	c.Gateways[0].Spec.Monitoring.Logs = false
	raw, _ := json.Marshal(c)
	if _, err := ParseConfiguration(bytes.NewReader(raw), JSON); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	json.Unmarshal(raw, &v)
	g := v["gateways"].([]any)[0].(map[string]any)
	delete(g["spec"].(map[string]any)["monitoring"].(map[string]any), "logs")
	missing, _ := json.Marshal(v)
	if _, err := ParseConfiguration(bytes.NewReader(missing), JSON); err == nil {
		t.Fatal("required false boolean defaulted silently")
	}
	g["spec"].(map[string]any)["monitoring"].(map[string]any)["Logs"] = false
	wrongCase, _ := json.Marshal(v)
	if _, err := ParseConfiguration(bytes.NewReader(wrongCase), JSON); err == nil {
		t.Fatal("case-insensitive property accepted")
	}
}
func TestSemanticDiffSecurityFields(t *testing.T) {
	base := configuration(t)
	for _, kind := range []string{"waf", "group", "labels", "name"} {
		t.Run(kind, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var next Configuration
			json.Unmarshal(raw, &next)
			switch kind {
			case "waf":
				next.Gateways[0].Spec.WAF.Mode = "off"
			case "group":
				next.Gateways[0].Spec.Routes[0].Access.GroupIDs = []string{"other"}
			case "labels":
				next.Gateways[0].Metadata.Labels["environment"] = "changed"
			case "name":
				next.Gateways[0].Metadata.Name = "new name"
			}
			diff, err := SemanticDiff(base, next)
			if err != nil || len(diff) != 1 {
				t.Fatalf("diff=%+v err=%v", diff, err)
			}
			if diff[0].Dangerous != (kind != "name") || diff[0].Path == "/gateways" {
				t.Fatalf("incomplete security diff %+v", diff)
			}
		})
	}
}
func TestUnsafeRouteAndUpstream(t *testing.T) {
	for _, value := range []string{"/a/../b", "/a%2fb", "//a", "/a\\b", "/a?x", "/a;return", "/a$var"} {
		c := configuration(t)
		c.Gateways[0].Spec.Routes[0].Path = value
		if _, err := Canonicalize(c); err == nil {
			t.Fatalf("unsafe path accepted %s", value)
		}
	}
	for _, value := range []string{"http://u:p@a.example/", "http://a.example/?x=y", "http://a.example/#x", "file:///tmp/a", "http://a.example:0", "http://a.example/a;return", "http://a.example/a%2fb", "http://a.example/a$var"} {
		c := configuration(t)
		c.Gateways[0].Spec.Routes[0].Upstream.URL = value
		if _, err := Canonicalize(c); err == nil {
			t.Fatalf("unsafe upstream accepted %s", value)
		}
	}
}
func TestEnvelopeLargeDocument(t *testing.T) {
	var dst struct {
		Format   string `json:"format"`
		Document string `json:"document"`
	}
	source := `{"document":"` + strings.Repeat("a", 20000) + `"}`
	if err := DecodeEnvelopeJSON([]byte(source), &dst); err != nil || len(dst.Document) != 20000 {
		t.Fatal(err)
	}
	if err := DecodeEnvelopeJSON([]byte(`{"Document":"x"}`), &dst); err == nil {
		t.Fatal("case-insensitive envelope accepted")
	}
}
func TestZoneDefaultNodesAndFrozenInventory(t *testing.T) {
	c := configuration(t)
	catalog := catalogFor(c)
	zone, err := ParseWafZone(bytes.NewReader(example(t, "examples/waf-zone-default.json")), JSON)
	if err != nil {
		t.Fatal(err)
	}
	zone.Metadata.SiteID = "site_msk"
	zone.Spec.PolicyRevisionID = c.Gateways[0].Spec.WAF.PolicyRevisionID
	digest, _ := Digest(zone)
	revision := ZoneRevision{ID: "zone_v1", Digest: digest, Content: *zone, Published: true}
	request := ResolveRequest{ID: "resolution_1", SiteID: "site_msk", ZoneRevisionID: "zone_v1", BaseConfigRevisionID: "config_v1", Action: "reconcile", CapacityProfile: "pilot-500", CreatedAt: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), CurrentAssignments: map[string]string{}, ZoneRevisions: []ZoneRevision{revision}, ReplacementAssignments: []ReplacementAssignment{}, AllowLegacyMigration: true}
	resolved, err := ResolveZones(context.Background(), c, catalog, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Members) != 1 || len(resolved.Conflicts) != 0 {
		t.Fatalf("default omitted legacy closure %+v", resolved)
	}
	if _, err = MaterializeWithInventory(c, catalog, request, *resolved, request.CreatedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	changed := c
	changed.Gateways[0].Metadata.Labels["new"] = "changed"
	if _, err = MaterializeWithInventory(changed, catalog, request, *resolved, request.CreatedAt.Add(time.Minute)); err == nil {
		t.Fatal("changed labels passed frozen inventory")
	}
	c = configuration(t)
	c.Gateways[0].Spec.NodeSelector.NodeIDs = append(c.Gateways[0].Spec.NodeSelector.NodeIDs, "missing_node")
	broken, err := ResolveZones(context.Background(), c, catalog, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(broken.Conflicts) != 1 || broken.Conflicts[0].Code != "waf_zone_node_unresolved" {
		t.Fatalf("incomplete explicit nodes accepted %+v", broken)
	}
}

func TestPreflightCapacityBeforeDTO(t *testing.T) {
	doc := example(t, "examples/configuration.json")
	if _, err := ParseConfiguration(bytes.NewReader(append(doc, bytes.Repeat([]byte{' '}, 2<<20)...)), JSON); err == nil {
		t.Fatal("pilot accepted oversized source whitespace")
	}
	var input strings.Builder
	input.WriteString(`{"apiVersion":"agp.config/v1alpha2","capacityProfile":"fleet-10k","gateways":[`)
	for gateway := 0; gateway < 101; gateway++ {
		if gateway > 0 {
			input.WriteByte(',')
		}
		input.WriteString(`{"spec":{"routes":[`)
		for route := 0; route < 1000; route++ {
			if route > 0 {
				input.WriteByte(',')
			}
			input.WriteString(`{}`)
		}
		input.WriteString(`]}}`)
	}
	input.WriteString(`]}`)
	err := jsonPreflight([]byte(input.String()))
	if err == nil || !strings.Contains(err.Error(), "route_limit") {
		t.Fatalf("total routes not checked in preflight: %v", err)
	}
	if _, err := CanonicalJSON(map[string]any{"bad": string([]byte{0xff})}); err == nil {
		t.Fatal("invalid Go UTF-8 silently replaced before digest")
	}
}

func TestZoneAmbiguityNoExplicitPriority(t *testing.T) {
	c := configuration(t)
	cat := catalogFor(c)
	base := WafZone{APIVersion: "agp.waf-zone/v1alpha1", Kind: "WafZone", Metadata: ZoneMetadata{ID: "zone_selector", Name: "Selector", SiteID: "site_msk", OwnerID: "owner_1"}, Spec: ZoneSpec{PolicyRevisionID: c.Gateways[0].Spec.WAF.PolicyRevisionID, Mode: "detection", Membership: ZoneMembership{MatchLabels: &Labels{"environment": "pilot"}}, Reason: "Explicit fixture reason"}}
	d1, _ := Digest(base)
	explicit := base
	explicit.Metadata.ID = "zone_explicit"
	explicit.Spec.Membership = ZoneMembership{GatewayIDs: []string{c.Gateways[0].Metadata.ID}}
	d2, _ := Digest(explicit)
	request := ResolveRequest{ID: "res_1", SiteID: "site_msk", ZoneRevisionID: "rev_selector", BaseConfigRevisionID: "cfg_1", Action: "reconcile", CapacityProfile: "pilot-500", CreatedAt: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), CurrentAssignments: map[string]string{c.Gateways[0].Metadata.ID: "rev_explicit"}, ZoneRevisions: []ZoneRevision{{ID: "rev_selector", Digest: d1, Content: base, Published: true}, {ID: "rev_explicit", Digest: d2, Content: explicit, Published: true}}, ReplacementAssignments: []ReplacementAssignment{}, AllowLegacyMigration: true}
	r, err := ResolveZones(context.Background(), c, cat, request)
	if err != nil || len(r.Conflicts) != 1 || r.Conflicts[0].Code != "waf_zone_ambiguous" {
		t.Fatalf("explicit zone silently won: %+v %v", r, err)
	}
	if _, err = MaterializeWithInventory(c, cat, request, *r, request.CreatedAt); err == nil {
		t.Fatal("conflicted zone materialized")
	}
}

func TestQuotedYAMLAllLegitimateStrings(t *testing.T) {
	c := configuration(t)
	c.Metadata.Name = "a'b \"quoted\": {braces}[list] ? # & * ! Café"
	c.Gateways[0].Metadata.Name = c.Metadata.Name
	c.Gateways[0].Metadata.Labels["punctuation"] = "a'b \"quoted\" {x}: ? # & * !"
	c.Gateways[0].Spec.Routes[0].Name = c.Metadata.Name
	c.Gateways[0].Spec.Routes[0].Upstream.URL = "https://backend.example.net:8443/api/v1@user&scope"
	original, err := Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	yamlBytes, err := YAMLDocument(original.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, err := ParseConfiguration(bytes.NewReader(yamlBytes), YAML)
	if err != nil {
		t.Fatalf("emitted YAML not readable: %v\n%s", err, yamlBytes)
	}
	if !bytes.Equal(original.Canonical, roundtrip.Canonical) {
		t.Fatal("quoted names or URL punctuation changed meaning")
	}
	zone := WafZone{APIVersion: "agp.waf-zone/v1alpha1", Kind: "WafZone", Metadata: ZoneMetadata{ID: "zone_unicode", Name: "Zone", SiteID: "site_msk", OwnerID: "owner"}, Spec: ZoneSpec{PolicyRevisionID: "policy_revision", Mode: "detection", Membership: ZoneMembership{MatchLabels: &Labels{"unicode": "Cafe\u0301"}}, Reason: strings.Repeat("\x00", 1024)}}
	if err = ValidateWafZone(&zone); err != nil {
		t.Fatal(err)
	}
	zoneYAML, err := YAMLDocument(zone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseWafZone(bytes.NewReader(zoneYAML), YAML); err != nil {
		t.Fatalf("schema-bounded escaped scalar exceeded supported YAML subset: %v", err)
	}
}
