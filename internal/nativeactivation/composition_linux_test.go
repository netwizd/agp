//go:build linux

package nativeactivation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securityjournal"
)

type compositionSources struct {
	t                *testing.T
	journal, control ed25519.PrivateKey
}

func compositionSign(t *testing.T, v any, purpose string, key ed25519.PrivateKey) string {
	t.Helper()
	digest, e := configmodel.Digest(v)
	if e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(purpose+"\n"+digest)))
}
func (s *compositionSources) Head(_ context.Context, challenge string) ([]byte, error) {
	h := securityjournal.Head{AuthorityID: "journal", Epoch: 1, Sequence: 5, Digest: configmodel.DigestBytes([]byte("head5")), Challenge: challenge, RecordedAt: time.Now().UTC(), KeyID: "journal-key"}
	h.Signature = compositionSign(s.t, h, "AGP-JOURNAL-HEAD-v1", s.journal)
	return json.Marshal(h)
}
func (s *compositionSources) Authorize(_ context.Context, q helper.StartQuery) ([]byte, error) {
	now := time.Now().UTC()
	proof := helper.StartProof{Query: q, KeyID: "control-key", WriterEpoch: 3, CheckedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Second).Format(time.RFC3339Nano)}
	proof.Signature = compositionSign(s.t, proof, "AGP-HELPER-START-v1", s.control)
	return json.Marshal(proof)
}

type compositionFixture struct {
	f            *fixture
	installation helper.Installation
	permit       ed25519.PrivateKey
	store        *helper.ExecutionStore
	executor     *helper.Executor
}

func newComposition(t *testing.T) *compositionFixture {
	t.Helper()
	f := makeFixture(t)
	keys := make([]ed25519.PrivateKey, 4)
	for i := range keys {
		keys[i] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(31 + i)}, ed25519.SeedSize))
	}
	trust := helper.Trust{PermitKeyID: "permit-key", PermitKey: keys[0].Public().(ed25519.PublicKey), ControlKeyID: "control-key", ControlKey: keys[1].Public().(ed25519.PublicKey), JournalKeyID: "journal-key", JournalKey: keys[2].Public().(ed25519.PublicKey)}
	trustDigest, e := helper.TrustDigest(trust)
	if e != nil {
		t.Fatal(e)
	}
	i := helper.Installation{APIVersion: helper.InstallationVersion, NodeID: f.cfg.NodeID, SiteID: f.cfg.SiteID, IdentityDigest: configmodel.DigestBytes([]byte("identity")), OwnershipDigest: f.cfg.LayoutDigest, CapabilityDigest: configmodel.DigestBytes([]byte("capability")), ComponentProfileDigest: f.cfg.QualificationDigest, ReleaseManifestDigest: f.cfg.ReleaseManifestDigest, TupleDigest: configmodel.DigestBytes([]byte("tuple")), CompilerDigest: configmodel.DigestBytes([]byte("compiler")), TrustDigest: trustDigest, AuthorityID: "journal", AuthorityEpoch: 1, WriterEpoch: 3, MinimumDenySequence: 2, Baseline: f.base.Baseline}
	anchor := helper.ExecutionAnchor{APIVersion: helper.ExecutionAnchorVersion, Installation: i, LayoutDigest: i.OwnershipDigest, ReceiptKeyID: "helper-receipt", ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(keys[3].Public().(ed25519.PublicKey))}
	dir, e := os.MkdirTemp("/tmp", "agp-native-composition-ledger-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, e := helper.CreateExecutionStore(context.Background(), dir, anchor, f.driver)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	executor, e := helper.NewExecutor(store, trust, &compositionSources{t: t, journal: keys[2], control: keys[1]}, f.driver, keys[3])
	if e != nil {
		t.Fatal(e)
	}
	return &compositionFixture{f: f, installation: i, permit: keys[0], store: store, executor: executor}
}
func (c *compositionFixture) request(t *testing.T, kind string, base helper.ExecutionGeneration, high helper.UInt63, b Bundle) helper.Request {
	t.Helper()
	now := time.Now().UTC()
	installationDigest, _ := configmodel.Digest(c.installation)
	r := helper.Request{Task: helper.Task{APIVersion: "agp.task/v1alpha1", ID: fmt.Sprintf("task-%d", high+1), NodeID: c.installation.NodeID, Kind: kind, IdempotencyKey: fmt.Sprintf("native-task-key-%016d", high+1), AuthorityEpoch: 1, WriterEpoch: 3, NodeDeploymentSequence: high + 1, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), PlanID: fmt.Sprintf("plan-%d", high+1), Preconditions: helper.Preconditions{BaseRevisionID: base.Baseline.RevisionID, ExpectedNodeDeploymentSequence: high, CapabilityDigest: c.installation.CapabilityDigest}, Payload: helper.Payload{TargetRevisionID: b.RevisionID, DeploymentGeneration: b.GenerationID, BundleDigest: b.BundleDigest, SecretVersionIDs: []string{}, MinimumDenySequence: 2, RecoveryBaseBundleDigest: base.Baseline.BundleDigest}}, Permit: helper.Permit{APIVersion: helper.PermitVersion, KeyID: "permit-key", InstallationDigest: installationDigest, IdentityDigest: c.installation.IdentityDigest, OwnershipDigest: c.installation.OwnershipDigest, ComponentProfileDigest: c.installation.ComponentProfileDigest, ReleaseManifestDigest: c.installation.ReleaseManifestDigest, TupleDigest: c.installation.TupleDigest, CompilerDigest: c.installation.CompilerDigest, Approval: helper.Approval{SiteID: c.installation.SiteID, CreatedBy: "author", ApprovedBy: "reviewer", ApprovalDigest: configmodel.DigestBytes([]byte("approval"))}, Recovery: helper.Recovery{BaseRevisionID: base.Baseline.RevisionID, BaseBundleDigest: base.Baseline.BundleDigest, OwnershipDigest: c.installation.OwnershipDigest, MinimumDenySequence: 2}}}
	plan, e := deploymentplan.Sign(deploymentplan.Plan{APIVersion: deploymentplan.Version1, ID: r.Task.PlanID, Kind: kind, SiteID: c.installation.SiteID, RevisionID: b.RevisionID, CreatedBy: r.Permit.Approval.CreatedBy, CreatedAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(6 * time.Minute).Format(time.RFC3339Nano), Targets: []deploymentplan.Target{{NodeID: r.Task.NodeID, BaseRevisionID: base.Baseline.RevisionID, ExpectedNodeDeploymentSequence: high, CapabilityDigest: r.Task.Preconditions.CapabilityDigest, BundleDigest: b.BundleDigest, SecretVersionIDs: []string{}, BaseBundleDigest: base.Baseline.BundleDigest}}, RolloutPolicy: deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{r.Task.NodeID}, MaxParallel: 1, MaxUnavailable: 0, ObservationSeconds: 60, FailureAction: "pause"}, CompilerVersion: "native-composition-test/1", MinimumDenySequence: 2, Reason: "Controlled local filesystem composition", ResolvedInputs: []deploymentplan.ResolvedInput{{Kind: "component_profile", ID: "profile", Digest: c.installation.ComponentProfileDigest}}, AuthorityEpoch: 1}, "permit-key", c.permit)
	if e != nil {
		t.Fatal(e)
	}
	r.SignedPlan = plan
	r.Task.PlanDigest = plan.Plan.PlanDigest
	r.Permit.TaskDigest, _ = helper.TaskDigest(r.Task)
	r.Permit.Signature = compositionSign(t, r.Permit, "AGP-HELPER-PERMIT-v1", c.permit)
	r.Task.PermitDigest, _ = helper.PermitDigest(r.Permit)
	return r
}
func (c *compositionFixture) execute(t *testing.T, r helper.Request) *helper.ExecutionReceipt {
	t.Helper()
	raw, _ := json.Marshal(r)
	receipt, e := c.executor.Execute(context.Background(), bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if receipt == nil {
		t.Fatal("missing execution receipt")
	}
	return receipt
}

func TestExecutorRealFilesystemApplyThenExplicitRollbackReusesQualifiedContent(t *testing.T) {
	c := newComposition(t)
	first := c.execute(t, c.request(t, "apply_config", c.f.base, 1, c.f.next))
	if first.State != "succeeded" || first.Active.Baseline.NodeDeploymentSequence != 2 {
		t.Fatalf("apply: %+v", first)
	}
	original := testBundle("generation-a", "revision-a")
	rollback := c.execute(t, c.request(t, "rollback_config", first.Active, 2, original))
	if rollback.State != "succeeded" || rollback.Active.GenerationID != c.f.base.GenerationID || rollback.Active.Baseline.NodeDeploymentSequence != 3 || rollback.Active.Baseline.BundleDigest != c.f.base.Baseline.BundleDigest {
		t.Fatalf("explicit rollback: %+v", rollback)
	}
	if storageSlot(rollback.Active) == storageSlot(c.f.base) {
		t.Fatal("execution sequence reused original storage slot")
	}
	if rollback.Active.TreeDigest != c.f.base.TreeDigest {
		t.Fatal("same qualified content changed digest during explicit rollback")
	}
	if e := c.f.driver.Verify(context.Background(), rollback.Active); e != nil {
		t.Fatal(e)
	}
}
func TestExecutorRealFilesystemRecoveredApplyThenSameContentNewTask(t *testing.T) {
	c := newComposition(t)
	c.f.runtime.failVerifyMarker = c.f.next.GenerationID
	first := c.execute(t, c.request(t, "apply_config", c.f.base, 1, c.f.next))
	if first.State != "recovered" || first.Active != c.f.base {
		t.Fatalf("recovered apply: %+v", first)
	}
	state, e := c.store.Status(context.Background())
	if e != nil || state.HighWater != 2 || state.Active != c.f.base {
		t.Fatal(state, e)
	}
	c.f.runtime.failVerifyMarker = ""
	original := testBundle("generation-a", "revision-a")
	rollback := c.execute(t, c.request(t, "rollback_config", c.f.base, 2, original))
	if rollback.State != "succeeded" || rollback.Active.Baseline.NodeDeploymentSequence != 3 || rollback.Active.GenerationID != c.f.base.GenerationID {
		t.Fatalf("same-content new task failed: %+v", rollback)
	}
}
func TestAuthorizationContextExpiresInsideLastPointerCheckpoint(t *testing.T) {
	f := makeFixture(t)
	target := f.prepare(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.driver.fault = func(point string) error {
		if point == "pointer_exchange" {
			cancel()
		}
		return nil
	}
	if e := f.driver.Activate(ctx, f.base, target); !errors.Is(e, context.Canceled) {
		t.Fatalf("expired authorization mutated pointer: %v", e)
	}
	active, e := f.driver.Snapshot(context.Background())
	if e != nil || active != f.base || f.runtime.reloads != 0 {
		t.Fatalf("authorization expired after checks but pointer changed: %+v %v", active, e)
	}
}
