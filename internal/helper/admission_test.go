package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/securityjournal"
)

func testDigest(s string) string { d, _ := configmodel.Digest(s); return d }

func testSign(t *testing.T, value any, purpose string, key ed25519.PrivateKey) string {
	t.Helper()
	d, err := configmodel.Digest(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(purpose+"\n"+d)))
}

func testBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func admissionTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agp-helper-admission-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

type testSources struct {
	t            *testing.T
	now          time.Time
	journal      ed25519.PrivateKey
	control      ed25519.PrivateKey
	epoch        UInt63
	sequence     UInt63
	writer       UInt63
	heads        int
	starts       int
	offline      bool
	headHook     func(*securityjournal.Head, int)
	proofHook    func(*StartProof)
	afterProof   func()
	proofPurpose string
}

func (s *testSources) Head(_ context.Context, challenge string) ([]byte, error) {
	s.heads++
	if s.offline {
		return nil, errors.New("sensitive /installation/private/secret.key")
	}
	h := securityjournal.Head{AuthorityID: "journal", Epoch: s.epoch, Sequence: s.sequence, Digest: testDigest(fmt.Sprint(s.sequence)), Challenge: challenge, RecordedAt: s.now, KeyID: "journal-key"}
	if s.sequence == 0 {
		h.Digest = ""
	}
	if s.epoch > 1 {
		h.RestoreCutoff = s.now.Add(-2 * time.Minute)
		h.ReleaseAfter = s.now.Add(-30 * time.Second)
	}
	if s.headHook != nil {
		s.headHook(&h, s.heads)
	}
	h.Signature = testSign(s.t, h, "AGP-JOURNAL-HEAD-v1", s.journal)
	return testBytes(s.t, h), nil
}

func (s *testSources) Authorize(_ context.Context, q StartQuery) ([]byte, error) {
	s.starts++
	if s.offline {
		return nil, errors.New("control private URL or token")
	}
	p := StartProof{Query: q, KeyID: "control-key", WriterEpoch: s.writer, CheckedAt: s.now.Format(time.RFC3339Nano), ExpiresAt: s.now.Add(10 * time.Second).Format(time.RFC3339Nano)}
	if s.proofHook != nil {
		s.proofHook(&p)
	}
	purpose := s.proofPurpose
	if purpose == "" {
		purpose = "AGP-HELPER-START-v1"
	}
	p.Signature = testSign(s.t, p, purpose, s.control)
	if s.afterProof != nil {
		s.afterProof()
	}
	return testBytes(s.t, p), nil
}

type admissionFixture struct {
	i       Installation
	trust   Trust
	permit  ed25519.PrivateKey
	sources *testSources
	r       Request
}

func newAdmissionFixture(t *testing.T) *admissionFixture {
	t.Helper()
	permit := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	control := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	journal := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	trust := Trust{PermitKeyID: "permit-key", PermitKey: permit.Public().(ed25519.PublicKey), ControlKeyID: "control-key", ControlKey: control.Public().(ed25519.PublicKey), JournalKeyID: "journal-key", JournalKey: journal.Public().(ed25519.PublicKey)}
	td, err := TrustDigest(trust)
	if err != nil {
		t.Fatal(err)
	}
	i := Installation{APIVersion: InstallationVersion, NodeID: "node", SiteID: "site", IdentityDigest: testDigest("identity"), OwnershipDigest: testDigest("ownership"), CapabilityDigest: testDigest("capability"), ComponentProfileDigest: testDigest("profile"), ReleaseManifestDigest: testDigest("release"), TupleDigest: testDigest("tuple"), CompilerDigest: testDigest("compiler"), TrustDigest: td, AuthorityID: "journal", AuthorityEpoch: 1, WriterEpoch: 3, MinimumDenySequence: 2, Baseline: Baseline{RevisionID: "baseline", BundleDigest: testDigest("baseline"), NodeDeploymentSequence: 7}}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sources := &testSources{t: t, now: now, journal: journal, control: control, epoch: 1, sequence: 5, writer: 3}
	id, _ := installationDigest(i)
	r := Request{Task: Task{APIVersion: "agp.task/v1alpha1", ID: "task", NodeID: "node", Kind: "apply_config", IdempotencyKey: "abcdefghijklmnop", AuthorityEpoch: 1, WriterEpoch: 3, NodeDeploymentSequence: 8, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), PlanID: "plan", PlanDigest: testDigest("plan"), Preconditions: Preconditions{BaseRevisionID: "baseline", ExpectedNodeDeploymentSequence: 7, CapabilityDigest: i.CapabilityDigest}, Payload: Payload{TargetRevisionID: "target", DeploymentGeneration: "generation", BundleDigest: testDigest("target"), SecretVersionIDs: []string{"secret-v1"}, MinimumDenySequence: 2, RecoveryBaseBundleDigest: i.Baseline.BundleDigest}}, Permit: Permit{APIVersion: PermitVersion, KeyID: "permit-key", InstallationDigest: id, IdentityDigest: i.IdentityDigest, OwnershipDigest: i.OwnershipDigest, ComponentProfileDigest: i.ComponentProfileDigest, ReleaseManifestDigest: i.ReleaseManifestDigest, TupleDigest: i.TupleDigest, CompilerDigest: i.CompilerDigest, Approval: Approval{SiteID: "site", CreatedBy: "author", ApprovedBy: "reviewer", ApprovalDigest: testDigest("approval")}, Recovery: Recovery{BaseRevisionID: i.Baseline.RevisionID, BaseBundleDigest: i.Baseline.BundleDigest, OwnershipDigest: i.OwnershipDigest, MinimumDenySequence: 2}}}
	f := &admissionFixture{i: i, trust: trust, permit: permit, sources: sources, r: r}
	f.bindPlan(t)
	f.sign(t)
	return f
}

func (f *admissionFixture) bindPlan(t *testing.T) {
	t.Helper()
	r := f.r.Task
	issued, err := utc(r.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := utc(r.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := deploymentplan.Sign(deploymentplan.Plan{
		APIVersion: deploymentplan.Version1, ID: r.PlanID, Kind: r.Kind,
		SiteID: f.i.SiteID, RevisionID: r.Payload.TargetRevisionID, CreatedBy: f.r.Permit.Approval.CreatedBy,
		CreatedAt: issued.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: expires.Add(time.Minute).Format(time.RFC3339Nano),
		Targets:         []deploymentplan.Target{{NodeID: r.NodeID, BaseRevisionID: r.Preconditions.BaseRevisionID, ExpectedNodeDeploymentSequence: r.Preconditions.ExpectedNodeDeploymentSequence, CapabilityDigest: r.Preconditions.CapabilityDigest, BundleDigest: r.Payload.BundleDigest, SecretVersionIDs: r.Payload.SecretVersionIDs, BaseBundleDigest: r.Payload.RecoveryBaseBundleDigest}},
		RolloutPolicy:   deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{r.NodeID}, MaxParallel: 1, MaxUnavailable: 0, ObservationSeconds: 60, FailureAction: "pause"},
		CompilerVersion: "helper-test/1", MinimumDenySequence: r.Payload.MinimumDenySequence, Reason: "Synthetic installer fixture for admission only",
		ResolvedInputs: []deploymentplan.ResolvedInput{{Kind: "component_profile", ID: "profile", Digest: f.i.ComponentProfileDigest}}, AuthorityEpoch: r.AuthorityEpoch,
	}, f.trust.PermitKeyID, f.permit)
	if err != nil {
		t.Fatal(err)
	}
	f.r.SignedPlan = plan
	f.r.Task.PlanDigest = plan.Plan.PlanDigest
}

func (f *admissionFixture) sign(t *testing.T) {
	t.Helper()
	f.r.Permit.TaskDigest, _ = TaskDigest(f.r.Task)
	f.r.Permit.Signature = ""
	f.r.Permit.Signature = testSign(t, f.r.Permit, "AGP-HELPER-PERMIT-v1", f.permit)
	f.r.Task.PermitDigest, _ = PermitDigest(f.r.Permit)
}

func (f *admissionFixture) open(t *testing.T, dir string, create bool) (*Store, *Gate) {
	t.Helper()
	var s *Store
	var err error
	if create {
		s, err = CreateStore(dir, f.i)
	} else {
		s, err = OpenStore(dir, f.i)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	g, err := NewGate(s, f.trust, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() time.Time { return f.sources.now }
	return s, g
}

func TestAdmissionDurableReplayAndRecoveryBlocker(t *testing.T) {
	f := newAdmissionFixture(t)
	dir := admissionTempDir(t)
	s, g := f.open(t, dir, true)
	raw := testBytes(t, f.r)
	first, err := g.Admit(context.Background(), bytes.NewReader(raw))
	if err != nil || first == nil || !first.NoExecution || first.State != "accepted" || first.APIVersion == "agp.receipt/v1alpha1" {
		t.Fatalf("admission = %#v, %v", first, err)
	}
	if f.sources.heads != 2 || f.sources.starts != 1 {
		t.Fatal("missing independently bracketed current authorization")
	}
	if err = s.RequireRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	f.sources.now = f.sources.now.Add(time.Hour)
	f.sources.offline = true
	s, g = f.open(t, dir, false)
	retry, err := g.Admit(context.Background(), bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(first, retry) || f.sources.heads != 2 || f.sources.starts != 1 {
		t.Fatalf("historical replay reran authorization: %#v %v", retry, err)
	}
	status, err := s.Status(context.Background())
	if err != nil || status.State != "recovery_required" || status.HighWater != 8 || !status.NoExecution || !reflect.DeepEqual(status.Admission, first) {
		t.Fatalf("recovery status = %#v, %v", status, err)
	}
	f.r.Task.ID, f.r.Task.IdempotencyKey, f.r.Task.NodeDeploymentSequence = "new-task", "new-idempotency-key", 9
	f.sign(t)
	if _, err = g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); err != ErrPending {
		t.Fatalf("recovery cleared blocker: %v", err)
	}
}

func TestAdmissionRejectsChangedTaskAndIdempotencyReuse(t *testing.T) {
	for _, change := range []string{"same_id", "same_key", "same_both"} {
		t.Run(change, func(t *testing.T) {
			f := newAdmissionFixture(t)
			_, g := f.open(t, admissionTempDir(t), true)
			if _, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); err != nil {
				t.Fatal(err)
			}
			f.r.Task.Payload.BundleDigest = testDigest("changed")
			if change == "same_id" {
				f.r.Task.IdempotencyKey = "different-idempotency"
			}
			if change == "same_key" {
				f.r.Task.ID = "different-id"
			}
			f.sign(t)
			if _, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); err != ErrConflict || f.sources.starts != 1 {
				t.Fatalf("changed request = %v", err)
			}
		})
	}
}

func TestAdmissionCurrentChecksAndPins(t *testing.T) {
	cases := []struct {
		name string
		edit func(*admissionFixture)
	}{
		{"partition", func(f *admissionFixture) { f.sources.offline = true }},
		{"expired", func(f *admissionFixture) { f.r.Task.ExpiresAt = f.sources.now.Format(time.RFC3339Nano) }},
		{"future", func(f *admissionFixture) { f.r.Task.IssuedAt = f.sources.now.Add(time.Second).Format(time.RFC3339Nano) }},
		{"foreign_node", func(f *admissionFixture) { f.r.Task.NodeID = "other" }},
		{"foreign_site", func(f *admissionFixture) { f.r.Permit.Approval.SiteID = "other" }},
		{"identity", func(f *admissionFixture) { f.r.Permit.IdentityDigest = testDigest("other") }},
		{"ownership", func(f *admissionFixture) { f.r.Permit.OwnershipDigest = testDigest("other") }},
		{"profile", func(f *admissionFixture) { f.r.Permit.ComponentProfileDigest = testDigest("other") }},
		{"manifest", func(f *admissionFixture) { f.r.Permit.ReleaseManifestDigest = testDigest("other") }},
		{"tuple", func(f *admissionFixture) { f.r.Permit.TupleDigest = testDigest("other") }},
		{"compiler", func(f *admissionFixture) { f.r.Permit.CompilerDigest = testDigest("other") }},
		{"capability", func(f *admissionFixture) { f.r.Task.Preconditions.CapabilityDigest = testDigest("other") }},
		{"unknown_base", func(f *admissionFixture) { f.r.Task.Preconditions.BaseRevisionID = "other" }},
		{"recovery_bundle", func(f *admissionFixture) { f.r.Permit.Recovery.BaseBundleDigest = testDigest("other") }},
		{"expected_sequence", func(f *admissionFixture) { f.r.Task.Preconditions.ExpectedNodeDeploymentSequence = 6 }},
		{"old_writer", func(f *admissionFixture) { f.r.Task.WriterEpoch = 2 }},
		{"future_authority", func(f *admissionFixture) { f.r.Task.AuthorityEpoch = 2 }},
		{"unmet_floor", func(f *admissionFixture) { f.r.Permit.Recovery.MinimumDenySequence = 6 }},
		{"forged_challenge", func(f *admissionFixture) {
			f.sources.proofHook = func(p *StartProof) { p.Query.Challenge = "different-challenge" }
		}},
		{"forged_request", func(f *admissionFixture) {
			f.sources.proofHook = func(p *StartProof) { p.Query.RequestDigest = testDigest("other") }
		}},
		{"forged_installation", func(f *admissionFixture) {
			f.sources.proofHook = func(p *StartProof) { p.Query.InstallationDigest = testDigest("other") }
		}},
		{"forged_head", func(f *admissionFixture) { f.sources.proofHook = func(p *StartProof) { p.Query.Head.Sequence++ } }},
		{"wrong_writer_proof", func(f *admissionFixture) { f.sources.proofHook = func(p *StartProof) { p.WriterEpoch++ } }},
		{"stale_proof", func(f *admissionFixture) {
			f.sources.proofHook = func(p *StartProof) { p.CheckedAt = f.sources.now.Add(-time.Minute).Format(time.RFC3339Nano) }
		}},
		{"expired_proof", func(f *admissionFixture) {
			f.sources.proofHook = func(p *StartProof) { p.ExpiresAt = f.sources.now.Format(time.RFC3339Nano) }
		}},
		{"proof_wrong_purpose", func(f *admissionFixture) { f.sources.proofPurpose = "AGP-HELPER-PERMIT-v1" }},
		{"revocation_during_proof", func(f *admissionFixture) { f.sources.afterProof = func() { f.sources.sequence++ } }},
		{"epoch_during_proof", func(f *admissionFixture) { f.sources.afterProof = func() { f.sources.epoch++ } }},
		{"journal_wrong_challenge", func(f *admissionFixture) {
			f.sources.headHook = func(h *securityjournal.Head, _ int) { h.Challenge = "wrong" }
		}},
		{"journal_quarantine", func(f *admissionFixture) {
			f.sources.headHook = func(h *securityjournal.Head, _ int) {
				h.Epoch = 2
				h.RestoreCutoff = f.sources.now.Add(-time.Minute)
				h.ReleaseAfter = f.sources.now.Add(30 * time.Second)
			}
		}},
		{"authorization_expires_before_second_head", func(f *admissionFixture) {
			f.sources.afterProof = func() { f.sources.now = f.sources.now.Add(11 * time.Second) }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmissionFixture(t)
			s, g := f.open(t, admissionTempDir(t), true)
			tc.edit(f)
			f.sign(t)
			_, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r)))
			if err == nil {
				t.Fatal("accepted invalid authorization")
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "/") || strings.Contains(err.Error(), "token") {
				t.Fatalf("leaked internal error: %v", err)
			}
			status, statusErr := s.Status(context.Background())
			if statusErr != nil || status.HighWater != 7 || status.Admission != nil {
				t.Fatalf("rejection consumed state: %#v %v", status, statusErr)
			}
		})
	}
}

func TestAdmissionEpochAndRollbackSequence(t *testing.T) {
	f := newAdmissionFixture(t)
	f.r.Task.Kind = "rollback_config"
	f.r.Task.AuthorityEpoch, f.sources.epoch = 2, 2
	f.r.Task.WriterEpoch, f.sources.writer = 4, 4
	f.r.Task.NodeDeploymentSequence = 100 // gaps are valid; reset is not
	f.bindPlan(t)
	f.sign(t)
	_, g := f.open(t, admissionTempDir(t), true)
	r, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if err != nil || r.AuthorityEpoch != 2 || r.WriterEpoch != 4 || r.NodeDeploymentSequence != 100 || !r.NoExecution {
		t.Fatalf("independent epochs and new rollback sequence: %#v %v", r, err)
	}
}

func TestAdmissionBaselineAndSequenceBoundaries(t *testing.T) {
	for _, missing := range []string{"revision", "bundle", "epoch", "writer", "sequence_overflow"} {
		t.Run(missing, func(t *testing.T) {
			f := newAdmissionFixture(t)
			switch missing {
			case "revision":
				f.i.Baseline.RevisionID = ""
			case "bundle":
				f.i.Baseline.BundleDigest = ""
			case "epoch":
				f.i.AuthorityEpoch = 0
			case "writer":
				f.i.WriterEpoch = 0
			case "sequence_overflow":
				f.i.Baseline.NodeDeploymentSequence = securityjournal.MaxUInt63 + 1
			}
			if s, err := CreateStore(admissionTempDir(t), f.i); err != ErrInvalid || s != nil {
				t.Fatalf("invalid installation opened: %v", err)
			}
		})
	}
	t.Run("new_writer_does_not_reset_sequence", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.r.Task.WriterEpoch, f.sources.writer = 4, 4
		f.r.Task.NodeDeploymentSequence = f.i.Baseline.NodeDeploymentSequence
		f.sign(t)
		s, g := f.open(t, admissionTempDir(t), true)
		if _, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); err != ErrInvalid {
			t.Fatalf("reset sequence with new writer: %v", err)
		}
		if status, err := s.Status(context.Background()); err != nil || status.HighWater != 7 || status.Admission != nil {
			t.Fatalf("rejected sequence changed state: %#v %v", status, err)
		}
	})
	t.Run("max_sequence_is_exact", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.r.Task.NodeDeploymentSequence = securityjournal.MaxUInt63
		f.sign(t)
		dir := admissionTempDir(t)
		s, g := f.open(t, dir, true)
		r, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r)))
		if err != nil || r.NodeDeploymentSequence != securityjournal.MaxUInt63 {
			t.Fatalf("maximum sequence: %#v %v", r, err)
		}
		_ = s.Close()
		s, _ = f.open(t, dir, false)
		if status, err := s.Status(context.Background()); err != nil || status.HighWater != securityjournal.MaxUInt63 {
			t.Fatalf("counter lost decimal precision: %#v %v", status, err)
		}
	})
}

func TestAdmissionConcurrentDistinctTasksAndHandles(t *testing.T) {
	f := newAdmissionFixture(t)
	dir := admissionTempDir(t)
	s, g := f.open(t, dir, true)
	if _, err := OpenStore(dir, f.i); err != ErrBusy {
		t.Fatalf("second handle = %v", err)
	}
	raw1 := testBytes(t, f.r)
	f.r.Task.ID, f.r.Task.IdempotencyKey = "second", "second-idempotency"
	f.sign(t)
	raw2 := testBytes(t, f.r)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, raw := range [][]byte{raw1, raw2} {
		wg.Add(1)
		go func(raw []byte) {
			defer wg.Done()
			_, err := g.Admit(context.Background(), bytes.NewReader(raw))
			results <- err
		}(raw)
	}
	wg.Wait()
	close(results)
	accepted, pending := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if err == ErrPending {
			pending++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || pending != 1 || f.sources.starts != 1 {
		t.Fatalf("concurrent starts: accepted=%d pending=%d live=%d", accepted, pending, f.sources.starts)
	}
	if status, err := s.Status(context.Background()); err != nil || status.HighWater != 8 {
		t.Fatalf("lost highwater: %#v %v", status, err)
	}
}

func TestAdmissionClosedContract(t *testing.T) {
	f := newAdmissionFixture(t)
	raw := string(testBytes(t, f.r))
	cases := map[string]string{
		"unknown":      strings.Replace(raw, `"task":{`, `"task":{"argv":["/private/secret"],`, 1),
		"duplicate":    strings.Replace(raw, `"nodeId":"node"`, `"nodeId":"node","nodeId":"other"`, 1),
		"case":         strings.Replace(raw, `"nodeId"`, `"NodeID"`, 1),
		"null":         strings.Replace(raw, `"secretVersionIds":["secret-v1"]`, `"secretVersionIds":null`, 1),
		"numeric":      strings.Replace(raw, `"nodeDeploymentSequence":"8"`, `"nodeDeploymentSequence":8`, 1),
		"overflow":     strings.Replace(raw, `"nodeDeploymentSequence":"8"`, `"nodeDeploymentSequence":"9223372036854775808"`, 1),
		"leading_zero": strings.Replace(raw, `"nodeDeploymentSequence":"8"`, `"nodeDeploymentSequence":"08"`, 1),
		"trailing":     raw + `{}`,
		"oversize":     raw + strings.Repeat(" ", MaxRequestBytes),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(in)); err != ErrInvalid {
				t.Fatalf("closed decode = %v", err)
			}
		})
	}
	for _, kind := range []string{"upgrade_components", "collect_diagnostics", "shell"} {
		f.r.Task.Kind = kind
		f.sign(t)
		if _, err := Decode(bytes.NewReader(testBytes(t, f.r))); err != ErrInvalid {
			t.Fatalf("unsupported kind %s: %v", kind, err)
		}
	}
}

func TestAdmissionTrustPurposeAndTampering(t *testing.T) {
	for _, attack := range []string{"wrong_permit_key", "wrong_permit_purpose", "wrong_control_key", "wrong_journal_key", "task_tamper", "trust_anchor_change"} {
		t.Run(attack, func(t *testing.T) {
			f := newAdmissionFixture(t)
			_, g := f.open(t, admissionTempDir(t), true)
			wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
			switch attack {
			case "wrong_permit_key":
				f.permit = wrong
				f.sign(t)
			case "wrong_permit_purpose":
				f.r.Permit.Signature = ""
				f.r.Permit.Signature = testSign(t, f.r.Permit, "AGP-HELPER-START-v1", f.permit)
				f.r.Task.PermitDigest, _ = PermitDigest(f.r.Permit)
			case "wrong_control_key":
				f.sources.control = wrong
			case "wrong_journal_key":
				f.sources.journal = wrong
			case "task_tamper":
				f.r.Task.Payload.TargetRevisionID = "tampered"
			case "trust_anchor_change":
				f.trust.ControlKey = wrong.Public().(ed25519.PublicKey)
				if _, err := NewGate(g.store, f.trust, f.sources); err != ErrInvalid {
					t.Fatal("anchor replacement accepted")
				}
				return
			}
			if _, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); err == nil {
				t.Fatal("signature attack accepted")
			}
		})
	}
	f := newAdmissionFixture(t)
	f.trust.ControlKey = f.trust.PermitKey
	if _, err := TrustDigest(f.trust); err != ErrInvalid {
		t.Fatal("reused purpose key accepted")
	}
}

func TestAdmissionDurabilityFailures(t *testing.T) {
	for _, checkpoint := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(checkpoint, func(t *testing.T) {
			f := newAdmissionFixture(t)
			dir := admissionTempDir(t)
			s, g := f.open(t, dir, true)
			s.fault = func(stage string) error {
				if stage == checkpoint {
					return errors.New("disk /private/device failure")
				}
				return nil
			}
			raw := testBytes(t, f.r)
			if result, err := g.Admit(context.Background(), bytes.NewReader(raw)); err != ErrState || result != nil {
				t.Fatalf("durability failure returned evidence: %#v %v", result, err)
			}
			if _, err := s.Status(context.Background()); err != ErrState {
				t.Fatal("failed store not poisoned")
			}
			_ = s.Close()
			s, g = f.open(t, dir, false)
			status, err := s.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if checkpoint == "directory_sync" {
				if status.HighWater != 8 || status.State != "reconciliation_required" {
					t.Fatalf("visible accepted state lost: %#v", status)
				}
				f.sources.offline = true
				if retry, err := g.Admit(context.Background(), bytes.NewReader(raw)); err != nil || retry == nil {
					t.Fatalf("lost-response replay: %#v %v", retry, err)
				}
			} else if status.HighWater != 7 || status.Admission != nil {
				t.Fatalf("partial state published: %#v", status)
			}
		})
	}
}

// A killed process cannot retain in-memory counters or locks. These are real
// process-crash tests on the local filesystem, not power-loss qualification.
func TestAdmissionProcessCrash(t *testing.T) {
	if stage := os.Getenv("AGP_HELPER_ADMISSION_CRASH"); stage != "" {
		f := newAdmissionFixture(t)
		dir := os.Getenv("AGP_HELPER_ADMISSION_DIR")
		_, g := f.open(t, dir, false)
		g.store.fault = func(point string) error {
			if point == stage {
				os.Exit(81)
			}
			return nil
		}
		_, _ = g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r)))
		os.Exit(82)
	}
	for _, stage := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newAdmissionFixture(t)
			dir := admissionTempDir(t)
			s, _ := f.open(t, dir, true)
			_ = s.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestAdmissionProcessCrash$", "-test.count=1")
			cmd.Env = append(os.Environ(), "AGP_HELPER_ADMISSION_CRASH="+stage, "AGP_HELPER_ADMISSION_DIR="+dir)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 81 {
				t.Fatalf("crash checkpoint missing: %s %v", output, err)
			}
			s, _ = f.open(t, dir, false)
			status, err := s.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if stage == "directory_sync" {
				if status.HighWater != 8 || status.Admission == nil || !status.NoExecution {
					t.Fatalf("crash lost accepted intent: %#v", status)
				}
			} else if status.HighWater != 7 || status.Admission != nil {
				t.Fatalf("partial intent: %#v", status)
			}
			// The state and lock are the only named durable records; orphan
			// staging bytes cannot independently grant execution or reset state.
			if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
