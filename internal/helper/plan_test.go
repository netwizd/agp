package helper

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/securityjournal"
)

func TestAdmissionSignedPlanTargetBinding(t *testing.T) {
	cases := []struct {
		name string
		edit func(*deploymentplan.Plan)
	}{
		{"plan_id", func(p *deploymentplan.Plan) { p.ID = "other-plan" }},
		{"site", func(p *deploymentplan.Plan) { p.SiteID = "other-site" }},
		{"target_revision", func(p *deploymentplan.Plan) { p.RevisionID = "other-revision" }},
		{"author", func(p *deploymentplan.Plan) { p.CreatedBy = "other-author" }},
		{"authority_epoch", func(p *deploymentplan.Plan) { p.AuthorityEpoch++ }},
		{"operation", func(p *deploymentplan.Plan) { p.Kind = "rollback_config" }},
		{"node", func(p *deploymentplan.Plan) {
			p.Targets[0].NodeID = "foreign-node"
			p.RolloutPolicy.CanaryNodeIDs = []string{"foreign-node"}
		}},
		{"base_revision", func(p *deploymentplan.Plan) { p.Targets[0].BaseRevisionID = "foreign-base" }},
		{"base_bundle", func(p *deploymentplan.Plan) { p.Targets[0].BaseBundleDigest = testDigest("foreign-base") }},
		{"target_bundle", func(p *deploymentplan.Plan) { p.Targets[0].BundleDigest = testDigest("foreign-target") }},
		{"capability", func(p *deploymentplan.Plan) { p.Targets[0].CapabilityDigest = testDigest("foreign-capability") }},
		{"expected_sequence", func(p *deploymentplan.Plan) { p.Targets[0].ExpectedNodeDeploymentSequence++ }},
		{"secrets", func(p *deploymentplan.Plan) { p.Targets[0].SecretVersionIDs = []string{"foreign-secret-version"} }},
		{"component_profile", func(p *deploymentplan.Plan) { p.ResolvedInputs[0].Digest = testDigest("foreign-profile") }},
		{"stronger_plan_floor", func(p *deploymentplan.Plan) { p.MinimumDenySequence++ }},
		{"task_outlives_plan", func(p *deploymentplan.Plan) { p.ExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano) }},
		{"unsupported_fleet_node_budget", func(p *deploymentplan.Plan) {
			p.APIVersion = deploymentplan.Version2
			p.CapacityProfile = deploymentplan.FleetProfile
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmissionFixture(t)
			p := f.r.SignedPlan.Plan
			tc.edit(&p)
			signed, err := deploymentplan.Sign(p, f.trust.PermitKeyID, f.permit)
			if err != nil {
				t.Fatal(err)
			}
			f.r.SignedPlan, f.r.Task.PlanDigest = signed, signed.Plan.PlanDigest
			f.sign(t)
			s, g := f.open(t, admissionTempDir(t), true)
			if receipt, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); receipt != nil || err == nil {
				t.Fatalf("foreign signed plan admitted: %#v %v", receipt, err)
			}
			if status, err := s.Status(context.Background()); err != nil || status.HighWater != 7 || status.Admission != nil || f.sources.starts != 0 {
				t.Fatalf("plan rejection consumed state/authorization: %#v %v", status, err)
			}
		})
	}
}

func TestAdmissionPlanPurposeAndSignatureCannotBeReused(t *testing.T) {
	for _, attack := range []string{"review_purpose", "permit_signature", "review_envelope", "v1_empty_capacity"} {
		t.Run(attack, func(t *testing.T) {
			f := newAdmissionFixture(t)
			_, g := f.open(t, admissionTempDir(t), true)
			switch attack {
			case "review_purpose":
				f.r.SignedPlan.Purpose = "planning_review"
			case "permit_signature":
				f.r.SignedPlan.Signature = f.r.Permit.Signature
			case "review_envelope":
				raw := testBytes(t, map[string]any{"task": f.r.Task, "permit": f.r.Permit, "signedPlan": map[string]any{"apiVersion": "agp.signed-plan-review/v1alpha1", "purpose": "planning_review", "deployable": false, "noExecution": true, "signatureBase64": "synthetic"}})
				if _, err := g.Admit(context.Background(), bytes.NewReader(raw)); err != ErrInvalid {
					t.Fatal("review envelope accepted", err)
				}
				return
			case "v1_empty_capacity":
				raw := bytes.Replace(testBytes(t, f.r), []byte(`"plan":{"apiVersion":`), []byte(`"plan":{"capacityProfile":"","apiVersion":`), 1)
				if _, err := g.Admit(context.Background(), bytes.NewReader(raw)); err != ErrInvalid {
					t.Fatal("v1 extra empty field accepted", err)
				}
				return
			}
			if receipt, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); err == nil || receipt != nil {
				t.Fatal("cross-purpose signature admitted")
			}
		})
	}
}

func TestAdmissionMissingPlanRejectsNewButPreservesHistoricalReplay(t *testing.T) {
	f := newAdmissionFixture(t)
	f.r.SignedPlan = nil
	f.sign(t)
	raw := testBytes(t, f.r)
	dir := admissionTempDir(t)
	s, g := f.open(t, dir, true)
	if result, err := g.Admit(context.Background(), bytes.NewReader(raw)); err != ErrPlanRequired || result != nil || f.sources.heads != 0 {
		t.Fatalf("new unsigned-plan request = %#v %v", result, err)
	}
	// Import the exact previously supported noExecution image. This builds a
	// historical receipt; it cannot start an operation through the new gate.
	headRaw, err := f.sources.Head(context.Background(), "historical-journal-challenge")
	if err != nil {
		t.Fatal(err)
	}
	var h securityjournal.Head
	if decodeClosed(headRaw, &h, 16<<10) != nil {
		t.Fatal("historical head")
	}
	digest, _ := configmodel.Digest(f.r)
	query := StartQuery{APIVersion: StartVersion, Challenge: "historical-control-challenge", RequestDigest: digest, InstallationDigest: s.digest, Head: pin(h)}
	proofRaw, err := f.sources.Authorize(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	var proof StartProof
	if decodeClosed(proofRaw, &proof, 16<<10) != nil {
		t.Fatal("historical proof")
	}
	receipt := Receipt{APIVersion: AdmissionVersion, TaskID: f.r.Task.ID, NodeID: f.i.NodeID, RequestDigest: digest, NodeDeploymentSequence: 8, AuthorityEpoch: 1, WriterEpoch: 3, State: "accepted", NoExecution: true, RecordedAt: h.RecordedAt.Format(time.RFC3339Nano)}
	if err := s.transaction(context.Background(), func(state *diskState) (bool, error) {
		state.HighWater, state.MinimumDenySequence = 8, h.Sequence
		state.Intent = &Intent{Request: f.r, RequestDigest: digest, Head: h, Proof: proof, Receipt: receipt}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	f.sources.offline = true
	f.sources.now = f.sources.now.Add(24 * time.Hour)
	_, g = f.open(t, dir, false)
	got, err := g.Admit(context.Background(), bytes.NewReader(raw))
	if err != nil || got == nil || *got != receipt || f.sources.heads != 1 || f.sources.starts != 1 {
		t.Fatalf("legacy replay lost or reran authorization: %#v %v", got, err)
	}
}
