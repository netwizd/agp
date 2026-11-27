package deploymentplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
)

func testPlan() Plan {
	d := "sha256:" + strings.Repeat("a", 64)
	return Plan{
		APIVersion: Version1, ID: "plan_1", Kind: "apply_config", SiteID: "site_1", RevisionID: "rev_2", CreatedBy: "usr_editor",
		CreatedAt: "2026-11-24T09:00:00Z", ExpiresAt: "2026-11-24T09:30:00Z", CompilerVersion: "agp-compiler/0.1.0", Reason: "Apply reviewed configuration", AuthorityEpoch: 3, MinimumDenySequence: 19,
		Targets: []Target{
			{NodeID: "node_B", BaseRevisionID: "rev_1", ExpectedNodeDeploymentSequence: 22, CapabilityDigest: d, BundleDigest: d, BaseBundleDigest: d, SecretVersionIDs: []string{"secret_z", "secret_a"}},
			{NodeID: "node_A", BaseRevisionID: "rev_1", ExpectedNodeDeploymentSequence: 17, CapabilityDigest: d, BundleDigest: d, BaseBundleDigest: d, SecretVersionIDs: []string{}},
		},
		RolloutPolicy:  RolloutPolicy{CanaryNodeIDs: []string{"node_B", "node_A"}, MaxParallel: 2, MaxUnavailable: 0, ObservationSeconds: 60, FailureAction: "pause"},
		ResolvedInputs: []ResolvedInput{{Kind: "waf_policy", ID: "waf_1", Digest: d}, {Kind: "component_profile", ID: "profile_1", Digest: d}},
	}
}

func normalized(t *testing.T, p Plan) Plan {
	t.Helper()
	n, err := Normalize(p)
	if err != nil {
		t.Fatal(err)
	}
	return *n
}

func wire(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mutateWire(t *testing.T, p Plan, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(wire(t, p), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	return wire(t, m)
}

func TestCanonicalDigestAndDetachedNormalization(t *testing.T) {
	p := testPlan()
	before := wire(t, p)
	n := normalized(t, p)
	// Independently computed from the ASCII schema fixture with sorted JSON
	// object keys and canonical set order, including an empty planDigest field.
	const goldenDigest = "sha256:f6f851d3e239f708744f2cc510bcddddd2353318237788db814aadfa809eb71c"
	if n.PlanDigest != goldenDigest {
		t.Fatalf("canonical wire contract changed: %s", n.PlanDigest)
	}
	if !bytes.Equal(before, wire(t, p)) {
		t.Fatal("Normalize mutated caller-owned data")
	}
	if n.Targets[0].NodeID != "node_A" || n.Targets[1].SecretVersionIDs[0] != "secret_a" || n.RolloutPolicy.CanaryNodeIDs[0] != "node_A" || n.ResolvedInputs[0].Kind != "component_profile" {
		t.Fatal("sets not canonically ordered")
	}
	blank := n
	blank.PlanDigest = ""
	raw, err := configmodel.CanonicalJSON(blank)
	if err != nil || configmodel.DigestBytes(raw) != n.PlanDigest {
		t.Fatal("self field must be present as empty string in digest input")
	}
	reordered := n
	reordered.Targets = slices.Clone(n.Targets)
	slices.Reverse(reordered.Targets)
	reordered.ResolvedInputs = slices.Clone(n.ResolvedInputs)
	slices.Reverse(reordered.ResolvedInputs)
	reordered.RolloutPolicy.CanaryNodeIDs = slices.Clone(n.RolloutPolicy.CanaryNodeIDs)
	slices.Reverse(reordered.RolloutPolicy.CanaryNodeIDs)
	d, err := Digest(reordered)
	if err != nil || d != n.PlanDigest || VerifyDigest(reordered) != nil {
		t.Fatal("semantic set order changed digest")
	}
	decoded, err := Parse(bytes.NewReader(wire(t, reordered)))
	if err != nil || !reflect.DeepEqual(decoded, &n) {
		t.Fatal("parse did not produce canonical equivalent")
	}
	reordered.Reason = "Another reviewed configuration"
	if VerifyDigest(reordered) == nil {
		t.Fatal("semantic change retained digest")
	}
	p.Targets[0].SecretVersionIDs[0] = "changed"
	if n.Targets[1].SecretVersionIDs[1] != "secret_z" {
		t.Fatal("normalized data aliases input")
	}
}

func TestConcurrentDigestDoesNotMutateSharedPlan(t *testing.T) {
	p := testPlan()
	expected, err := Digest(p)
	if err != nil {
		t.Fatal(err)
	}
	before := wire(t, p)
	var workers sync.WaitGroup
	errorsCh := make(chan error, 12)
	for range 12 {
		workers.Go(func() {
			for range 3 {
				d, err := Digest(p)
				if err != nil || d != expected {
					errorsCh <- ErrInvalid
					return
				}
			}
		})
	}
	workers.Wait()
	close(errorsCh)
	if len(errorsCh) != 0 || !bytes.Equal(before, wire(t, p)) {
		t.Fatal("concurrent digest mutated a shared plan")
	}
}

func TestSchemaAndSemanticRejections(t *testing.T) {
	cases := map[string]func(*Plan){
		"version":        func(p *Plan) { p.APIVersion = "agp.plan/v9" },
		"pilot_profile":  func(p *Plan) { p.CapacityProfile = FleetProfile },
		"fleet_profile":  func(p *Plan) { p.APIVersion = Version2 },
		"kind":           func(p *Plan) { p.Kind = "shell" },
		"node_duplicate": func(p *Plan) { p.Targets = append(p.Targets, p.Targets[0]) },
		"no_targets":     func(p *Plan) { p.Targets = nil },
		"node_path":      func(p *Plan) { p.Targets[0].NodeID = "../node" },
		"base_revision":  func(p *Plan) { p.Targets[0].BaseRevisionID = "" },
		"digest_case":    func(p *Plan) { p.Targets[0].BundleDigest = "sha256:" + strings.Repeat("A", 64) },
		"secret_duplicate": func(p *Plan) {
			p.Targets[0].SecretVersionIDs = []string{"secret_1", "secret_1"}
		},
		"secret_null":     func(p *Plan) { p.Targets[0].SecretVersionIDs = nil },
		"secret_id":       func(p *Plan) { p.Targets[0].SecretVersionIDs = []string{"../secret"} },
		"no_inputs":       func(p *Plan) { p.ResolvedInputs = nil },
		"input_duplicate": func(p *Plan) { p.ResolvedInputs = append(p.ResolvedInputs, p.ResolvedInputs[0]) },
		"input_kind":      func(p *Plan) { p.ResolvedInputs[0].Kind = "raw_path" },
		"input_id":        func(p *Plan) { p.ResolvedInputs[0].ID = "" },
		"foreign_canary":  func(p *Plan) { p.RolloutPolicy.CanaryNodeIDs = []string{"foreign"} },
		"canary_duplicate": func(p *Plan) {
			p.RolloutPolicy.CanaryNodeIDs = []string{"node_A", "node_A"}
		},
		"no_canary":       func(p *Plan) { p.RolloutPolicy.CanaryNodeIDs = nil },
		"parallel_zero":   func(p *Plan) { p.RolloutPolicy.MaxParallel = 0 },
		"parallel_large":  func(p *Plan) { p.RolloutPolicy.MaxParallel = 26 },
		"unavailable_neg": func(p *Plan) { p.RolloutPolicy.MaxUnavailable = -1 },
		"unavailable_big": func(p *Plan) { p.RolloutPolicy.MaxUnavailable = 26 },
		"observation_low": func(p *Plan) { p.RolloutPolicy.ObservationSeconds = 29 },
		"observation_big": func(p *Plan) { p.RolloutPolicy.ObservationSeconds = 86401 },
		"failure_action":  func(p *Plan) { p.RolloutPolicy.FailureAction = "continue" },
		"compiler_empty":  func(p *Plan) { p.CompilerVersion = "" },
		"compiler_long":   func(p *Plan) { p.CompilerVersion = strings.Repeat("a", 65) },
		"reason_short":    func(p *Plan) { p.Reason = "short" },
		"reason_long":     func(p *Plan) { p.Reason = strings.Repeat("a", 1025) },
		"reason_utf8":     func(p *Plan) { p.Reason = string([]byte{0xff}) + "long reason" },
		"epoch_zero":      func(p *Plan) { p.AuthorityEpoch = 0 },
		"epoch_overflow":  func(p *Plan) { p.AuthorityEpoch = securityjournal.MaxUInt63 + 1 },
		"sequence_overflow": func(p *Plan) {
			p.Targets[0].ExpectedNodeDeploymentSequence = securityjournal.MaxUInt63 + 1
		},
		"deny_overflow":  func(p *Plan) { p.MinimumDenySequence = securityjournal.MaxUInt63 + 1 },
		"time_offset":    func(p *Plan) { p.CreatedAt = "2026-11-24T09:00:00+00:00" },
		"expiry_equal":   func(p *Plan) { p.ExpiresAt = p.CreatedAt },
		"time_invalid":   func(p *Plan) { p.CreatedAt = "2026-11-99T09:00:00Z" },
		"time_hour":      func(p *Plan) { p.CreatedAt = "2026-11-24T9:00:00Z" },
		"time_comma":     func(p *Plan) { p.CreatedAt = "2026-11-24T09:00:00,1Z" },
		"time_precision": func(p *Plan) { p.CreatedAt = "2026-11-24T09:00:00.1234567891Z" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := testPlan()
			change(&p)
			if _, err := Normalize(p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted invalid semantic content: %v", err)
			}
		})
	}
}

func TestClosedParserRejectsMalformedAndLeakingInput(t *testing.T) {
	p := normalized(t, testPlan())
	raw := wire(t, p)
	mutations := map[string][]byte{
		"duplicate":          bytes.Replace(raw, []byte(`"id":"plan_1"`), []byte(`"id":"plan_1","id":"plan_1"`), 1),
		"wrong_case":         bytes.Replace(raw, []byte(`"siteId"`), []byte(`"SiteId"`), 1),
		"trailing":           append(slices.Clone(raw), []byte(` {}`)...),
		"null_root":          []byte(`null`),
		"array_root":         []byte(`[]`),
		"bad_utf8":           append([]byte{0xff}, raw...),
		"field_leak":         mutateWire(t, p, func(m map[string]any) { m["sensitive_unknown_secret"] = "secret-value" }),
		"missing":            mutateWire(t, p, func(m map[string]any) { delete(m, "authorityEpoch") }),
		"missing_deny_floor": mutateWire(t, p, func(m map[string]any) { delete(m, "minimumDenySequence") }),
		"missing_node_counter": mutateWire(t, p, func(m map[string]any) {
			delete(m["targets"].([]any)[0].(map[string]any), "expectedNodeDeploymentSequence")
		}),
		"missing_zero_rollout_counter": mutateWire(t, p, func(m map[string]any) {
			delete(m["rolloutPolicy"].(map[string]any), "maxUnavailable")
		}),
		"null": mutateWire(t, p, func(m map[string]any) { m["targets"] = nil }),
		"num_counter": mutateWire(t, p, func(m map[string]any) {
			m["minimumDenySequence"] = 19
		}),
		"counter_leading_zero": mutateWire(t, p, func(m map[string]any) { m["minimumDenySequence"] = "019" }),
		"counter_overflow":     mutateWire(t, p, func(m map[string]any) { m["minimumDenySequence"] = "9223372036854775808" }),
		"capacity_empty":       mutateWire(t, p, func(m map[string]any) { m["capacityProfile"] = "" }),
		"capacity_null":        mutateWire(t, p, func(m map[string]any) { m["capacityProfile"] = nil }),
		"digest_changed":       mutateWire(t, p, func(m map[string]any) { m["planDigest"] = "sha256:" + strings.Repeat("b", 64) }),
		"digest_missing":       mutateWire(t, p, func(m map[string]any) { delete(m, "planDigest") }),
	}
	for name, b := range mutations {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader(b))
			if err != ErrInvalid || strings.Contains(err.Error(), "secret") {
				t.Fatalf("closed parser returned unsafe/nonstatic error: %v", err)
			}
		})
	}
	if _, err := Parse(nil); err != ErrInvalid {
		t.Fatal("nil reader accepted")
	}
	if _, err := Parse(failedReader{}); err != ErrInvalid {
		t.Fatal("reader error exposed")
	}
	if _, err := Parse(io.LimitReader(repeatedReader{}, MaxFleetBytes+1)); err != ErrInvalid {
		t.Fatal("oversized stream accepted")
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("sensitive-reader-path") }

type repeatedReader struct{}

func (repeatedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestWireIntegerExactMaximumAndNFC(t *testing.T) {
	p := testPlan()
	p.AuthorityEpoch, p.MinimumDenySequence = securityjournal.MaxUInt63, securityjournal.MaxUInt63
	p.Targets[0].ExpectedNodeDeploymentSequence = securityjournal.MaxUInt63
	p.Reason = "Apply cafe\u0301 reviewed policy"
	p.CreatedAt = "2026-11-24T09:00:00.000Z"
	n := normalized(t, p)
	if n.Reason != "Apply café reviewed policy" || n.CreatedAt != "2026-11-24T09:00:00Z" {
		t.Fatal("text/time normalization missing")
	}
	parsed, err := Parse(bytes.NewReader(wire(t, n)))
	if err != nil || parsed.AuthorityEpoch != securityjournal.MaxUInt63 || parsed.Targets[1].ExpectedNodeDeploymentSequence != securityjournal.MaxUInt63 {
		t.Fatalf("exact max integer failed: %v", err)
	}
	// The contract has no universal TTL: expiry policy belongs to authorization.
	p.ExpiresAt = "2026-12-24T09:00:00Z"
	if _, err := Normalize(p); err != nil {
		t.Fatal("introduced unapproved universal TTL")
	}
}

func TestPlanPilotByteBudgetAndRolloutExport(t *testing.T) {
	p := testPlan()
	targetIDs := []string{p.Targets[0].NodeID, p.Targets[1].NodeID}
	if ValidateRollout(p.RolloutPolicy, targetIDs) != nil || ValidateRollout(p.RolloutPolicy, []string{"node_A"}) != ErrInvalid || ValidateRollout(p.RolloutPolicy, []string{"node_A", "node_A"}) != ErrInvalid {
		t.Fatal("exported rollout validator diverged")
	}
	n := normalized(t, p)
	raw := append(wire(t, n), bytes.Repeat([]byte(" "), MaxPilotBytes)...)
	if _, err := Parse(bytes.NewReader(raw)); err != ErrInvalid {
		t.Fatal("pilot whitespace stream bypassed byte limit")
	}
	p.Targets = make([]Target, 200)
	for i := range p.Targets {
		p.Targets[i] = testPlan().Targets[0]
		p.Targets[i].NodeID = fmt.Sprintf("node_%04d", i)
		p.Targets[i].SecretVersionIDs = make([]string, 100)
		for j := range p.Targets[i].SecretVersionIDs {
			p.Targets[i].SecretVersionIDs[j] = fmt.Sprintf("secret_%03d_", j) + strings.Repeat("x", 117)
		}
	}
	p.RolloutPolicy.CanaryNodeIDs = []string{p.Targets[0].NodeID}
	if _, err := Normalize(p); err != ErrInvalid {
		t.Fatal("pilot canonical byte budget bypassed")
	}
	p.APIVersion, p.CapacityProfile = Version2, FleetProfile
	if _, err := Normalize(p); err != nil {
		t.Fatal("fleet did not accept otherwise-valid plan above pilot budget")
	}
}

func TestPlanVersionCapacityLimits(t *testing.T) {
	for _, count := range []int{500, 501} {
		p := testPlan()
		p.Targets = make([]Target, count)
		for i := range p.Targets {
			p.Targets[i] = testPlan().Targets[0]
			p.Targets[i].NodeID = fmt.Sprintf("node_%05d", i)
		}
		p.RolloutPolicy.CanaryNodeIDs = []string{p.Targets[0].NodeID}
		_, err := Normalize(p)
		if (err == nil) != (count == 500) {
			t.Fatalf("targets count=%d: %v", count, err)
		}
	}
	for _, tc := range []struct {
		version string
		count   int
		valid   bool
	}{{Version1, 1000, true}, {Version1, 1001, false}, {Version2, 50000, true}, {Version2, 50001, false}} {
		t.Run(fmt.Sprintf("%s_%d", tc.version, tc.count), func(t *testing.T) {
			p := testPlan()
			p.APIVersion = tc.version
			if tc.version == Version2 {
				p.CapacityProfile = FleetProfile
			}
			p.ResolvedInputs = make([]ResolvedInput, tc.count)
			for i := range p.ResolvedInputs {
				p.ResolvedInputs[i] = ResolvedInput{Kind: "waf_policy", ID: fmt.Sprintf("input_%05d", i), Digest: p.Targets[0].BundleDigest}
			}
			n, err := Normalize(p)
			if (err == nil) != tc.valid {
				t.Fatalf("capacity validation=%v", err)
			}
			if tc.valid {
				parsed, err := Parse(bytes.NewReader(wire(t, n)))
				if err != nil || len(parsed.ResolvedInputs) != tc.count {
					t.Fatalf("valid capacity parser failed: %v", err)
				}
			}
		})
	}
	for _, tc := range []struct{ count, allowed int }{{100, 100}, {101, 100}} {
		p := testPlan()
		p.Targets[0].SecretVersionIDs = make([]string, tc.count)
		for i := range p.Targets[0].SecretVersionIDs {
			p.Targets[0].SecretVersionIDs[i] = fmt.Sprintf("secret_%03d", i)
		}
		_, err := Normalize(p)
		if (err == nil) != (tc.count <= tc.allowed) {
			t.Fatalf("secret count=%d: %v", tc.count, err)
		}
	}
}
