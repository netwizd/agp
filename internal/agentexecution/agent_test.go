package agentexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/helper"
)

type controlFunc func(context.Context) ([]helper.Request, error)

func (f controlFunc) ExecutionPending(ctx context.Context) ([]helper.Request, error) { return f(ctx) }

type helperFunc func(context.Context, helper.Request) (*helper.ExecutionReceipt, error)

func (f helperFunc) Execute(ctx context.Context, r helper.Request) (*helper.ExecutionReceipt, error) {
	return f(ctx, r)
}

func testRequest(t *testing.T, highwater ...helper.UInt63) helper.Request {
	t.Helper()
	expected := helper.UInt63(7)
	if len(highwater) == 1 {
		expected = highwater[0]
	}
	d := "sha256:" + strings.Repeat("1", 64)
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	r := helper.Request{Task: helper.Task{APIVersion: "agp.task/v1alpha1", ID: "task_one", NodeID: "node_one", Kind: "apply_config", IdempotencyKey: "abcdefghijklmnop", AuthorityEpoch: 1, WriterEpoch: 1, NodeDeploymentSequence: expected + 1, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), PlanID: "plan_one", Preconditions: helper.Preconditions{BaseRevisionID: "base", ExpectedNodeDeploymentSequence: expected, CapabilityDigest: d}, Payload: helper.Payload{TargetRevisionID: "target", DeploymentGeneration: "generation", BundleDigest: d, SecretVersionIDs: []string{}, MinimumDenySequence: 0, RecoveryBaseBundleDigest: d}}, Permit: helper.Permit{APIVersion: helper.PermitVersion, KeyID: "permit_key", InstallationDigest: d, IdentityDigest: d, OwnershipDigest: d, ComponentProfileDigest: d, ReleaseManifestDigest: d, TupleDigest: d, CompilerDigest: d, Approval: helper.Approval{SiteID: "site_one", CreatedBy: "author", ApprovedBy: "reviewer", ApprovalDigest: d}, Recovery: helper.Recovery{BaseRevisionID: "base", BaseBundleDigest: d, OwnershipDigest: d}}}
	plan, err := deploymentplan.Sign(deploymentplan.Plan{APIVersion: deploymentplan.Version1, ID: r.Task.PlanID, Kind: r.Task.Kind, SiteID: "site_one", RevisionID: "target", CreatedBy: "author", CreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), Targets: []deploymentplan.Target{{NodeID: r.Task.NodeID, BaseRevisionID: "base", ExpectedNodeDeploymentSequence: expected, CapabilityDigest: d, BundleDigest: d, SecretVersionIDs: []string{}, BaseBundleDigest: d}}, RolloutPolicy: deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{r.Task.NodeID}, MaxParallel: 1, ObservationSeconds: 60, FailureAction: "pause"}, CompilerVersion: "agent-test/1", Reason: "Controlled transport fixture", ResolvedInputs: []deploymentplan.ResolvedInput{{Kind: "component_profile", ID: "profile", Digest: d}}, AuthorityEpoch: 1}, "permit_key", key)
	if err != nil {
		t.Fatal(err)
	}
	r.SignedPlan, r.Task.PlanDigest = plan, plan.Plan.PlanDigest
	r.Permit.TaskDigest, _ = helper.TaskDigest(r.Task)
	digest, _ := configmodel.Digest(r.Permit)
	r.Permit.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte("AGP-HELPER-PERMIT-v1\n"+digest)))
	r.Task.PermitDigest, _ = helper.PermitDigest(r.Permit)
	return r
}

func testReceipt(t *testing.T, r helper.Request) *helper.ExecutionReceipt {
	t.Helper()
	digest, err := configmodel.Digest(r)
	if err != nil {
		t.Fatal(err)
	}
	return &helper.ExecutionReceipt{APIVersion: helper.ExecutionReceiptVersion, Purpose: "local_execution_outcome", ReceiptID: "receipt_one", ReceiptSequence: 1, NodeID: r.Task.NodeID, TaskID: r.Task.ID, RequestDigest: digest, NodeDeploymentSequence: r.Task.NodeDeploymentSequence, Active: helper.ExecutionGeneration{Baseline: helper.Baseline{RevisionID: r.Task.Payload.TargetRevisionID, BundleDigest: r.Task.Payload.BundleDigest, NodeDeploymentSequence: r.Task.NodeDeploymentSequence}, GenerationID: r.Task.Payload.DeploymentGeneration, TreeDigest: r.Task.Payload.BundleDigest}, State: "succeeded", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyID: "root_receipt_key", Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
}

func TestAgentExactRetryAfterLostLocalResponse(t *testing.T) {
	r := testRequest(t)
	receipt := testReceipt(t, r)
	var attempts []helper.Request
	a, err := New(controlFunc(func(context.Context) ([]helper.Request, error) { return []helper.Request{r}, nil }), helperFunc(func(_ context.Context, got helper.Request) (*helper.ExecutionReceipt, error) {
		attempts = append(attempts, got)
		if len(attempts) == 1 {
			return nil, errors.New("private /root/key or endpoint must not escape")
		}
		return receipt, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.RunOnce(context.Background()); got != nil || err != ErrUnavailable {
		t.Fatalf("lost reply = %#v, %v", got, err)
	}
	got, err := a.RunOnce(context.Background())
	if err != nil || !reflect.DeepEqual(got, receipt) || len(attempts) != 2 || !reflect.DeepEqual(attempts[0], attempts[1]) || !reflect.DeepEqual(attempts[0], r) {
		t.Fatalf("retry changed task or lost outcome: %#v, %v", got, err)
	}
}

func TestAgentRejectsUnboundOrMissingReceipt(t *testing.T) {
	r := testRequest(t)
	for _, tc := range []struct {
		name string
		edit func(*helper.ExecutionReceipt)
	}{
		{"task", func(r *helper.ExecutionReceipt) { r.TaskID = "other_task" }},
		{"node", func(r *helper.ExecutionReceipt) { r.NodeID = "other_node" }},
		{"digest", func(r *helper.ExecutionReceipt) { r.RequestDigest = "sha256:" + strings.Repeat("2", 64) }},
		{"sequence", func(r *helper.ExecutionReceipt) { r.NodeDeploymentSequence++ }},
		{"active_generation", func(r *helper.ExecutionReceipt) { r.Active.GenerationID = "other_generation" }},
		{"unhealthy_success", func(r *helper.ExecutionReceipt) { r.RecoveryRequired = true }},
		{"admission", func(r *helper.ExecutionReceipt) { r.APIVersion = helper.AdmissionVersion }},
		{"unknown_state", func(r *helper.ExecutionReceipt) { r.State = "accepted" }},
		{"no_signature", func(r *helper.ExecutionReceipt) { r.Signature = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := testReceipt(t, r)
			tc.edit(receipt)
			a, _ := New(controlFunc(func(context.Context) ([]helper.Request, error) { return []helper.Request{r}, nil }), helperFunc(func(context.Context, helper.Request) (*helper.ExecutionReceipt, error) { return receipt, nil }))
			if got, err := a.RunOnce(context.Background()); got != nil || err != ErrInvalid {
				t.Fatalf("unbound receipt accepted: %#v %v", got, err)
			}
		})
	}
	a, _ := New(controlFunc(func(context.Context) ([]helper.Request, error) { return []helper.Request{r}, nil }), helperFunc(func(context.Context, helper.Request) (*helper.ExecutionReceipt, error) { return nil, nil }))
	if got, err := a.RunOnce(context.Background()); got != nil || err != ErrInvalid {
		t.Fatalf("missing outcome became success: %#v %v", got, err)
	}
}

func TestAgentCancellationSerializesAndDoesNotGenerateTasks(t *testing.T) {
	r := testRequest(t)
	entered := make(chan struct{}, 1)
	var active, maximum, fetches atomic.Int32
	var once sync.Once
	a, _ := New(controlFunc(func(context.Context) ([]helper.Request, error) {
		fetches.Add(1)
		return []helper.Request{r}, nil
	}), helperFunc(func(ctx context.Context, _ helper.Request) (*helper.ExecutionReceipt, error) {
		n := active.Add(1)
		defer active.Add(-1)
		maximum.Store(n)
		once.Do(func() { entered <- struct{}{} })
		<-ctx.Done()
		return nil, errors.New("private local error")
	}))
	first, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() { _, err := a.RunOnce(first); firstResult <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first execution did not start")
	}
	waiting, cancelWaiting := context.WithCancel(context.Background())
	waitResult := make(chan error, 1)
	go func() { _, err := a.RunOnce(waiting); waitResult <- err }()
	cancelWaiting()
	if err := <-waitResult; !errors.Is(err, context.Canceled) || fetches.Load() != 1 {
		t.Fatalf("canceled waiter fetched a new task: %v", err)
	}
	cancelFirst()
	if err := <-firstResult; !errors.Is(err, context.Canceled) || maximum.Load() != 1 {
		t.Fatalf("cancellation lost or concurrent execution: %v", err)
	}
	if got, err := a.RunOnce(waiting); got != nil || !errors.Is(err, context.Canceled) || fetches.Load() != 1 {
		t.Fatal("already canceled operation entered transport")
	}
}

func TestAgentPendingAdmissionAndTerminalFailure(t *testing.T) {
	r := testRequest(t)
	var executed bool
	local := helperFunc(func(context.Context, helper.Request) (*helper.ExecutionReceipt, error) {
		executed = true
		return nil, nil
	})
	for _, items := range [][]helper.Request{nil, {r, r}} {
		a, _ := New(controlFunc(func(context.Context) ([]helper.Request, error) { return items, nil }), local)
		got, err := a.RunOnce(context.Background())
		if executed || got != nil || (len(items) > 1 && err != ErrInvalid) || (len(items) == 0 && err != nil) {
			t.Fatal("empty or ambiguous pending set executed")
		}
	}
	receipt := testReceipt(t, r)
	receipt.State = "recovered"
	receipt.Active.Baseline = helper.Baseline{RevisionID: "base", BundleDigest: r.Task.Payload.RecoveryBaseBundleDigest, NodeDeploymentSequence: 7}
	a, _ := New(controlFunc(func(context.Context) ([]helper.Request, error) { return []helper.Request{r}, nil }), helperFunc(func(context.Context, helper.Request) (*helper.ExecutionReceipt, error) { return receipt, nil }))
	got, err := a.RunOnce(context.Background())
	if err != nil || got.State != "recovered" {
		t.Fatalf("terminal failure was relabeled or lost: %#v %v", got, err)
	}
}

func TestAgentRecoveryPreservesOlderBaselineAfterConsumedFailureSequence(t *testing.T) {
	// A prior failed attempt consumed sequence 8 but kept healthy generation 7.
	r := testRequest(t, 8)
	receipt := testReceipt(t, r)
	receipt.State = "recovered"
	receipt.Active.Baseline = helper.Baseline{RevisionID: "base", BundleDigest: r.Task.Payload.RecoveryBaseBundleDigest, NodeDeploymentSequence: 7}
	a, _ := New(controlFunc(func(context.Context) ([]helper.Request, error) { return []helper.Request{r}, nil }), helperFunc(func(context.Context, helper.Request) (*helper.ExecutionReceipt, error) { return receipt, nil }))
	if got, err := a.RunOnce(context.Background()); err != nil || got == nil || got.Active.Baseline.NodeDeploymentSequence != 7 || got.NodeDeploymentSequence != 9 {
		t.Fatalf("accepted highwater conflated with healthy generation: %#v %v", got, err)
	}
}
