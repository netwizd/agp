package deploymentplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func TestSignVerifyFullPurposeSeparatedPlan(t *testing.T) {
	pub, key := testKeys(t)
	s, err := Sign(testPlan(), "plan_key_1", key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 9, 15, 0, 0, time.UTC)
	if err := Verify(*s, "plan_key_1", pub, now); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(bytes.NewReader(wire(t, s)))
	if err != nil || Verify(*parsed, "plan_key_1", pub, now) != nil {
		t.Fatalf("signed closed decode: %v", err)
	}
	reordered := *s
	reordered.Plan.Targets = slices.Clone(s.Plan.Targets)
	slices.Reverse(reordered.Plan.Targets)
	if err := Verify(reordered, "plan_key_1", pub, now); err != nil {
		t.Fatal("semantic set ordering affected signature")
	}
	if _, err := Sign(testPlan(), "key", ed25519.PrivateKey{}); err != ErrInvalid {
		t.Fatal("invalid signing key accepted")
	}
	if _, err := Sign(testPlan(), "../key", key); err != ErrInvalid {
		t.Fatal("invalid signing key ID accepted")
	}
	otherPub, _ := testKeys(t)
	if Verify(*s, "plan_key_1", otherPub, now) != ErrUnauthorized || Verify(*s, "other_key", pub, now) != ErrUnauthorized || Verify(*s, "plan_key_1", nil, now) != ErrUnauthorized {
		t.Fatal("unpinned signer accepted")
	}
	for _, when := range []time.Time{now.Add(-16 * time.Minute), now.Add(15 * time.Minute), now.Add(time.Hour), {}} {
		if Verify(*s, "plan_key_1", pub, when) != ErrNotCurrent {
			t.Fatal("noncurrent plan accepted")
		}
	}
	if Verify(*s, "plan_key_1", pub, now.Add(-15*time.Minute)) != nil {
		t.Fatal("creation time must be inclusive")
	}
	changed := *s
	changed.Purpose = "preview"
	if Verify(changed, "plan_key_1", pub, now) != ErrInvalid {
		t.Fatal("wrong purpose accepted")
	}
	changed = *s
	changed.Plan.Reason = "Edited after server signature"
	changed.Plan = normalized(t, changed.Plan)
	if Verify(changed, "plan_key_1", pub, now) != ErrUnauthorized {
		t.Fatal("recomputed digest bypassed full-plan signature")
	}
	changed = *s
	// The same digest signed under another domain cannot authorize execution.
	message, _ := signingBytes(changed)
	message = bytes.Replace(message, []byte(signatureDomain), []byte("AGP-HELPER-PERMIT-v1"), 1)
	changed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	if Verify(changed, "plan_key_1", pub, now) != ErrUnauthorized {
		t.Fatal("cross-purpose signature accepted")
	}
}

func TestEveryPlanPinIsCoveredByDigestAndSignature(t *testing.T) {
	pub, key := testKeys(t)
	s, _ := Sign(testPlan(), "plan_key_1", key)
	now := time.Date(2026, 11, 24, 9, 15, 0, 0, time.UTC)
	d := "sha256:" + strings.Repeat("b", 64)
	changes := map[string]func(*Plan){
		"id":            func(p *Plan) { p.ID = "another_plan" },
		"site":          func(p *Plan) { p.SiteID = "other_site" },
		"revision":      func(p *Plan) { p.RevisionID = "rev_3" },
		"actor":         func(p *Plan) { p.CreatedBy = "another_actor" },
		"epoch":         func(p *Plan) { p.AuthorityEpoch++ },
		"deny":          func(p *Plan) { p.MinimumDenySequence++ },
		"compiler":      func(p *Plan) { p.CompilerVersion = "agp-compiler/0.2.0" },
		"created":       func(p *Plan) { p.CreatedAt = "2026-11-24T09:01:00Z" },
		"expires":       func(p *Plan) { p.ExpiresAt = "2026-11-24T09:31:00Z" },
		"reason":        func(p *Plan) { p.Reason = "Different reviewed reason" },
		"kind":          func(p *Plan) { p.Kind = "rollback_config" },
		"base_revision": func(p *Plan) { p.Targets[0].BaseRevisionID = "rev_0" },
		"sequence":      func(p *Plan) { p.Targets[0].ExpectedNodeDeploymentSequence++ },
		"capability":    func(p *Plan) { p.Targets[0].CapabilityDigest = d },
		"bundle":        func(p *Plan) { p.Targets[0].BundleDigest = d },
		"base_bundle":   func(p *Plan) { p.Targets[0].BaseBundleDigest = d },
		"secret":        func(p *Plan) { p.Targets[0].SecretVersionIDs = []string{"secret_new"} },
		"canary":        func(p *Plan) { p.RolloutPolicy.CanaryNodeIDs = []string{"node_A"} },
		"parallel":      func(p *Plan) { p.RolloutPolicy.MaxParallel++ },
		"unavailable":   func(p *Plan) { p.RolloutPolicy.MaxUnavailable++ },
		"observation":   func(p *Plan) { p.RolloutPolicy.ObservationSeconds++ },
		"action":        func(p *Plan) { p.RolloutPolicy.FailureAction = "rollback_wave" },
		"input_digest":  func(p *Plan) { p.ResolvedInputs[0].Digest = d },
		"input_id":      func(p *Plan) { p.ResolvedInputs[0].ID = "other_profile" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := *s
			changed.Plan = normalized(t, s.Plan)
			change(&changed.Plan)
			if VerifyDigest(changed.Plan) == nil {
				t.Fatal("changed pin retained digest")
			}
			changed.Plan = normalized(t, changed.Plan)
			if Verify(changed, "plan_key_1", pub, now) != ErrUnauthorized {
				t.Fatal("recomputed digest retained valid signature")
			}
		})
	}
}

func TestSignedParserClosedEnvelope(t *testing.T) {
	_, key := testKeys(t)
	s, _ := Sign(testPlan(), "plan_key_1", key)
	raw := wire(t, s)
	for name, malformed := range map[string][]byte{
		"unknown":           bytes.Replace(raw, []byte(`"purpose":"execution"`), []byte(`"purpose":"execution","hidden_secret":"value"`), 1),
		"case":              bytes.Replace(raw, []byte(`"keyId"`), []byte(`"KeyId"`), 1),
		"missing":           bytes.Replace(raw, []byte(`"purpose":"execution",`), nil, 1),
		"duplicate":         bytes.Replace(raw, []byte(`"purpose":"execution"`), []byte(`"purpose":"execution","purpose":"execution"`), 1),
		"v1_capacity_empty": bytes.Replace(raw, []byte(`"plan":{"apiVersion"`), []byte(`"plan":{"capacityProfile":"","apiVersion"`), 1),
		"signature_null":    bytes.Replace(raw, []byte(`"signature":"`+s.Signature+`"`), []byte(`"signature":null`), 1),
		"signature_padding": bytes.Replace(raw, []byte(s.Signature), []byte(s.Signature+"="), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSigned(bytes.NewReader(malformed)); err != ErrInvalid {
				t.Fatalf("malformed envelope accepted or error leaked: %v", err)
			}
		})
	}
}

func TestFleetSignedParserAtFullInputCapacity(t *testing.T) {
	pub, key := testKeys(t)
	p := testPlan()
	p.APIVersion, p.CapacityProfile = Version2, FleetProfile
	p.ResolvedInputs = make([]ResolvedInput, 50000)
	for i := range p.ResolvedInputs {
		p.ResolvedInputs[i] = ResolvedInput{Kind: "waf_policy", ID: fmt.Sprintf("waf_%05d", i), Digest: p.Targets[0].BundleDigest}
	}
	s, err := Sign(p, "plan_key_1", key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(bytes.NewReader(wire(t, s)))
	if err != nil || len(parsed.Plan.ResolvedInputs) != 50000 {
		t.Fatalf("nested full fleet-capacity signed plan rejected: %v", err)
	}
	now := time.Date(2026, 11, 24, 9, 15, 0, 0, time.UTC)
	if err := Verify(*parsed, "plan_key_1", pub, now); err != nil {
		t.Fatal(err)
	}
}
