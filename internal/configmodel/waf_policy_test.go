package configmodel

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWafPolicyContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/v2/examples/waf-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseWafPolicy(bytes.NewReader(raw), JSON)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWafPolicy(bytes.NewReader(canonical), JSON)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Digest(p)
	b, _ := Digest(parsed)
	if a != b {
		t.Fatal("canonical round trip changed policy digest")
	}
	for _, change := range []struct {
		name  string
		apply func(map[string]any)
	}{
		{"unknown", func(p map[string]any) { p["rawDirectives"] = "SecRuleEngine Off" }},
		{"assignment_mode", func(p map[string]any) { p["spec"].(map[string]any)["mode"] = "blocking" }},
		{"missing_required", func(p map[string]any) { delete(p["spec"].(map[string]any), "exceptions") }},
		{"null_exceptions", func(p map[string]any) { p["spec"].(map[string]any)["exceptions"] = nil }},
		{"unsupported_engine", func(p map[string]any) { p["spec"].(map[string]any)["engine"] = "coraza" }},
		{"invalid_paranoia", func(p map[string]any) { p["spec"].(map[string]any)["paranoiaLevel"] = 5 }},
		{"invalid_threshold", func(p map[string]any) { p["spec"].(map[string]any)["inboundAnomalyThreshold"] = 0 }},
		{"fraction", func(p map[string]any) { p["spec"].(map[string]any)["outboundAnomalyThreshold"] = 2.5 }},
		{"rule_injection", func(p map[string]any) {
			p["spec"].(map[string]any)["exceptions"].([]any)[0].(map[string]any)["ruleIds"] = []string{"942100\nSecRuleEngine Off"}
		}},
		{"duplicate_rule", func(p map[string]any) {
			p["spec"].(map[string]any)["exceptions"].([]any)[0].(map[string]any)["ruleIds"] = []string{"942100", "942100"}
		}},
		{"bad_match", func(p map[string]any) {
			p["spec"].(map[string]any)["exceptions"].([]any)[0].(map[string]any)["match"].(map[string]any)["name"] = "foo bar"
		}},
		{"bad_lifetime", func(p map[string]any) {
			e := p["spec"].(map[string]any)["exceptions"].([]any)[0].(map[string]any)
			e["reviewAt"] = e["expiresAt"]
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			change.apply(doc)
			body, _ := json.Marshal(doc)
			if _, err := ParseWafPolicy(bytes.NewReader(body), JSON); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	if _, err := ParseWafPolicy(strings.NewReader(strings.Replace(string(raw), `"kind": "WafPolicy"`, `"kind": "WafPolicy", "kind": "WafPolicy"`, 1)), JSON); err == nil {
		t.Fatal("duplicate key accepted")
	}
}
