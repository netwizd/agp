//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
)

// This controlled adapter proves orchestration and persistence behavior. It is
// deliberately NOT evidence of a native Nginx/service/root qualification.
type executionTestDriver struct {
	pointer, runtime, base, target ExecutionGeneration
	healthy                        map[string]bool
	calls                          map[string]int
	hook                           func(string) error
	savedBase                      bool
	onActivate                     func(context.Context) error
}

func (d *executionTestDriver) call(ctx context.Context, name string) error {
	d.calls[name]++
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.hook != nil {
		return d.hook(name)
	}
	return nil
}
func (d *executionTestDriver) Snapshot(ctx context.Context) (ExecutionGeneration, error) {
	if err := d.call(ctx, "snapshot"); err != nil {
		return ExecutionGeneration{}, err
	}
	if d.pointer != d.runtime {
		return ExecutionGeneration{}, ErrOwnedTree
	}
	return d.runtime, nil
}
func (d *executionTestDriver) Prepare(ctx context.Context, r Request, base ExecutionGeneration) (ExecutionGeneration, error) {
	if err := d.call(ctx, "prepare"); err != nil {
		return ExecutionGeneration{}, err
	}
	if d.pointer != base || d.runtime != base {
		return ExecutionGeneration{}, ErrOwnedTree
	}
	d.base = base
	d.savedBase = true
	t := r.Task
	d.target = ExecutionGeneration{Baseline: Baseline{RevisionID: t.Payload.TargetRevisionID, BundleDigest: t.Payload.BundleDigest, NodeDeploymentSequence: t.NodeDeploymentSequence}, GenerationID: t.Payload.DeploymentGeneration, TreeDigest: testDigest("tree-" + t.Payload.DeploymentGeneration)}
	d.healthy[d.target.GenerationID] = true
	return d.target, nil
}
func (d *executionTestDriver) Validate(ctx context.Context, target ExecutionGeneration) error {
	if err := d.call(ctx, "validate"); err != nil {
		return err
	}
	if target != d.target {
		return ErrStale
	}
	return nil
}
func (d *executionTestDriver) Activate(ctx context.Context, base, target ExecutionGeneration) error {
	if err := d.call(ctx, "activate"); err != nil {
		return err
	}
	if d.onActivate != nil {
		if err := d.onActivate(ctx); err != nil {
			return err
		}
	}
	if !d.savedBase || d.pointer != base || d.runtime != base || target != d.target {
		return ErrStale
	}
	d.pointer = target
	if d.hook != nil {
		return d.hook("activated")
	}
	return nil
}
func (d *executionTestDriver) Reload(ctx context.Context, target ExecutionGeneration) error {
	if err := d.call(ctx, "reload"); err != nil {
		return err
	}
	if d.pointer != target {
		return ErrStale
	}
	d.runtime = target
	if d.hook != nil {
		return d.hook("reloaded")
	}
	return nil
}
func (d *executionTestDriver) Verify(ctx context.Context, target ExecutionGeneration) error {
	if err := d.call(ctx, "verify"); err != nil {
		return err
	}
	if d.pointer != target || d.runtime != target || !d.healthy[target.GenerationID] {
		return ErrOwnedTree
	}
	return nil
}
func (d *executionTestDriver) Contain(ctx context.Context) error { return d.call(ctx, "contain") }

func (d *executionTestDriver) Recover(ctx context.Context, target, base ExecutionGeneration) error {
	if err := d.call(ctx, "recover"); err != nil {
		return err
	}
	if !d.savedBase || base != d.base || target != d.target || d.pointer != target && d.pointer != base {
		return ErrStale
	}
	d.pointer, d.runtime = base, base
	return nil
}

func executionFixture(t *testing.T) (*admissionFixture, *ExecutionStore, *Executor, *executionTestDriver, string) {
	t.Helper()
	f := newAdmissionFixture(t)
	base := ExecutionGeneration{Baseline: f.i.Baseline, GenerationID: "initial-generation", TreeDigest: testDigest("initial-tree")}
	d := &executionTestDriver{pointer: base, runtime: base, healthy: map[string]bool{base.GenerationID: true}, calls: map[string]int{}}
	a := ExecutionAnchor{APIVersion: ExecutionAnchorVersion, Installation: f.i, LayoutDigest: f.i.OwnershipDigest, ReceiptKeyID: "helper-receipt", ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(executionTestKey().Public().(ed25519.PublicKey))}
	dir := admissionTempDir(t)
	s, err := CreateExecutionStore(context.Background(), dir, a, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e, err := NewExecutor(s, f.trust, f.sources, d, executionTestKey())
	if err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return f.sources.now }
	return f, s, e, d, dir
}

func executeFixture(t *testing.T, e *Executor, f *admissionFixture) *ExecutionReceipt {
	t.Helper()
	r, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("missing receipt")
	}
	return r
}

func executionNext(t *testing.T, f *admissionFixture, active ExecutionGeneration, high UInt63, kind string) {
	t.Helper()
	f.r.Task.ID += "-next"
	f.r.Task.IdempotencyKey += "x"
	f.r.Task.PlanID += "-next"
	f.r.Task.Kind = kind
	f.r.Task.NodeDeploymentSequence = high + 1
	f.r.Task.Preconditions.ExpectedNodeDeploymentSequence = high
	f.r.Task.Preconditions.BaseRevisionID = active.Baseline.RevisionID
	f.r.Task.Payload.RecoveryBaseBundleDigest = active.Baseline.BundleDigest
	f.r.Permit.Recovery.BaseRevisionID = active.Baseline.RevisionID
	f.r.Permit.Recovery.BaseBundleDigest = active.Baseline.BundleDigest
	f.r.Task.Payload.TargetRevisionID += "-next"
	f.r.Task.Payload.DeploymentGeneration += "-next"
	f.r.Task.Payload.BundleDigest = testDigest(f.r.Task.Payload.TargetRevisionID)
	f.bindPlan(t)
	f.sign(t)
}

func TestExecutionSuccessDurableReplayOutboxAndCurrentLedgerBase(t *testing.T) {
	f, s, e, d, dir := executionFixture(t)
	receipt := executeFixture(t, e, f)
	if receipt.State != "succeeded" || receipt.APIVersion != ExecutionReceiptVersion || receipt.Active != d.target || receipt.RecoveryRequired || f.sources.heads != 6 || f.sources.starts != 3 {
		t.Fatalf("incomplete execution %#v, heads/starts=%d/%d", receipt, f.sources.heads, f.sources.starts)
	}
	state, err := s.Status(context.Background())
	if err != nil || state.Attempt != nil || state.HighWater != 8 || state.Active != d.target || state.LastHealthy != d.target || state.MinimumDenySequence != 5 {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	out, err := s.Outbox(context.Background())
	if err != nil || len(out) != 1 || out[0] != *receipt {
		t.Fatal("missing immutable outbox", out, err)
	}
	before := map[string]int{}
	for k, v := range d.calls {
		before[k] = v
	}
	f.sources.offline = true
	f.sources.now = f.sources.now.Add(time.Hour)
	replay := executeFixture(t, e, f)
	if *replay != *receipt || !reflect.DeepEqual(before, d.calls) || f.sources.heads != 6 {
		t.Fatal("exact replay repeated side effects")
	}
	if err = s.Acknowledge(context.Background(), "unknown-receipt"); !errors.Is(err, ErrInvalid) {
		t.Fatal("ack invented receipt", err)
	}
	if err = s.Acknowledge(context.Background(), receipt.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if err = s.Acknowledge(context.Background(), receipt.ReceiptID); err != nil {
		t.Fatal(err)
	}
	out, err = s.Outbox(context.Background())
	if err != nil || len(out) != 0 {
		t.Fatal(out, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExecutionStore(dir, s.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	e, err = NewExecutor(reopened, f.trust, f.sources, d, executionTestKey())
	if err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return f.sources.now }
	if replay = executeFixture(t, e, f); *replay != *receipt {
		t.Fatal("restart lost receipt")
	}
	// Refresh only the new task's time. Its base is the serving ledger target,
	// while the immutable Installation still pins the original installation base.
	f.sources.offline = false
	f.sources.now = f.sources.now.Add(-time.Hour)
	executionNext(t, f, state.Active, state.HighWater, "apply_config")
	next := executeFixture(t, e, f)
	if next.State != "succeeded" || next.NodeDeploymentSequence != 9 || next.ReceiptSequence != 2 || next.Active == receipt.Active {
		t.Fatal("second apply used static installation baseline", next)
	}
}

func TestExecutionFailedSequenceRetainedAndExplicitRollbackIsNewTask(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	d.hook = func(name string) error {
		if name == "validate" {
			return errors.New("syntax")
		}
		return nil
	}
	first := executeFixture(t, e, f)
	if first.State != "failed" || d.calls["activate"] != 0 {
		t.Fatalf("syntax changed runtime %#v", first)
	}
	state, err := s.Status(context.Background())
	if err != nil || state.HighWater != 8 || state.Active.Baseline.NodeDeploymentSequence != 7 {
		t.Fatal(state, err)
	}
	d.hook = nil
	executionNext(t, f, state.Active, state.HighWater, "rollback_config")
	second := executeFixture(t, e, f)
	if second.State != "succeeded" || second.NodeDeploymentSequence != 9 || d.calls["activate"] != 1 {
		t.Fatal("rollback was not new signed plan/task/sequence", second)
	}
}

func TestExecutionEffectBoundaryRevokeExpiryAndTreeDrift(t *testing.T) {
	for _, mode := range []string{"head-change", "offline", "expired-after-fsync", "tree-drift"} {
		t.Run(mode, func(t *testing.T) {
			f, s, e, d, _ := executionFixture(t)
			d.hook = func(name string) error {
				if name != "validate" {
					return nil
				}
				switch mode {
				case "head-change":
					f.sources.headHook = func(h *securityjournal.Head, n int) {
						if n == 4 {
							h.Sequence++
							h.Digest = testDigest("late-revoke")
						}
					}
				case "offline":
					f.sources.offline = true
				case "expired-after-fsync":
					syncs := 0
					s.fault = func(point string) error {
						if point == "directory_sync" {
							syncs++
							if syncs == 2 {
								f.sources.now = f.sources.now.Add(11 * time.Second)
							}
						}
						return nil
					}
				case "tree-drift":
					d.pointer.TreeDigest = testDigest("drift")
					d.runtime = d.pointer
				}
				return nil
			}
			result, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
			if mode == "tree-drift" {
				if result != nil || !errors.Is(err, ErrPending) {
					t.Fatal(result, err)
				}
			} else if err != nil || result == nil || result.State != "failed" {
				t.Fatal(result, err)
			}
			if d.calls["activate"] != 0 {
				t.Fatal("stale effect boundary activated runtime")
			}
			state, stateErr := s.Status(context.Background())
			if stateErr != nil || state.HighWater != 8 {
				t.Fatal(state, stateErr)
			}
		})
	}
}

func TestExecutionCancellationRecoversWithIndependentBoundedContext(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	d.hook = func(name string) error {
		if name == "activated" {
			cancel()
		}
		return nil
	}
	result, err := e.Execute(ctx, bytes.NewReader(testBytes(t, f.r)))
	if err != nil || result == nil || result.State != "recovered" || d.calls["recover"] != 1 || d.runtime != d.base {
		t.Fatal(result, err, d.calls)
	}
	state, err := s.Status(context.Background())
	if err != nil || state.HighWater != 8 || state.Active != d.base || state.RecoveryRequired {
		t.Fatal(state, err)
	}
}

func TestExecutionHealthyTargetSurvivesLostReloadResponseAndPartition(t *testing.T) {
	f, _, e, d, _ := executionFixture(t)
	d.hook = func(name string) error {
		if name == "reloaded" {
			f.sources.offline = true
			return errors.New("response lost")
		}
		return nil
	}
	result := executeFixture(t, e, f)
	if result.State != "succeeded" || result.Active != d.target || d.calls["recover"] != 0 {
		t.Fatal("healthy target rolled back", result, d.calls)
	}
}

func TestExecutionCrashRecoveryFromDurableCheckpoint(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-reload", true: "after-healthy-reload"}[healthy], func(t *testing.T) {
			f, s, e, d, dir := executionFixture(t)
			d.hook = func(name string) error {
				if name == "activated" && !healthy || name == "reloaded" && healthy {
					s.fault = func(point string) error {
						if point == "write" {
							return errors.New("crash")
						}
						return nil
					}
				}
				return nil
			}
			result, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
			if result != nil || !errors.Is(err, ErrState) {
				t.Fatal(result, err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenExecutionStore(dir, s.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			e, err = NewExecutor(s, f.trust, f.sources, d, executionTestKey())
			if err != nil {
				t.Fatal(err)
			}
			e.now = func() time.Time { return f.sources.now }
			d.hook = nil
			f.sources.offline = true
			result, err = e.RecoverPending(context.Background())
			if err != nil || result == nil {
				t.Fatal(result, err)
			}
			if healthy {
				if result.State != "succeeded" || d.calls["recover"] != 0 {
					t.Fatal("lost terminal receipt rolled back healthy target", result)
				}
			} else if result.State != "recovered" || d.calls["recover"] != 1 {
				t.Fatal(result, d.calls)
			}
			state, err := s.Status(context.Background())
			if err != nil || state.HighWater != 8 || state.Attempt != nil {
				t.Fatal(state, err)
			}
		})
	}
}

func TestExecutionUnknownThirdStateBlocksNewWorkUntilExactBaseRecovery(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	d.hook = func(name string) error {
		if name == "activated" {
			d.pointer.GenerationID = "unknown-third"
			d.runtime = d.pointer
			return errors.New("ambiguous switch")
		}
		return nil
	}
	result, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if result != nil || !errors.Is(err, ErrPending) {
		t.Fatal(result, err)
	}
	state, err := s.Status(context.Background())
	if err != nil || !state.RecoveryRequired || state.Attempt == nil || state.Attempt.Stage != "recovery_required" || state.HighWater != 8 {
		t.Fatal(state, err)
	}
	before := d.calls["activate"]
	result, err = e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if result != nil || !errors.Is(err, ErrPending) || d.calls["activate"] != before {
		t.Fatal("retry resumed unresolved effect", result, err)
	}
	// The operator/adapter may make the known preserved base observable again;
	// reconciliation does not consume a new task or decrease the high-water.
	d.hook = nil
	d.pointer, d.runtime = d.base, d.base
	result, err = e.RecoverPending(context.Background())
	if err != nil || result == nil || result.State != "recovered" {
		t.Fatal(result, err)
	}
}

func TestExecutionLedgerRejectsResetForeignStateAndMutation(t *testing.T) {
	f, s, _, d, dir := executionFixture(t)
	if other, err := CreateExecutionStore(context.Background(), dir, s.anchor, d); other != nil || !errors.Is(err, ErrState) {
		t.Fatal("execution ledger reset", err)
	}
	if other, err := OpenExecutionStore(dir, s.anchor); other != nil || !errors.Is(err, ErrBusy) {
		t.Fatal("execution lock missing", err)
	}
	statePath := filepath.Join(dir, storeStateName)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(statePath, bytes.Replace(raw, []byte(`"highWater":"7"`), []byte(`"highWater":"8"`), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Status(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("in-place state mutation accepted", err)
	}
	otherDir := admissionTempDir(t)
	old, err := CreateStore(otherDir, f.i)
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	if other, err := OpenExecutionStore(otherDir, s.anchor); other != nil || !errors.Is(err, ErrState) {
		t.Fatal("admission receipt became execution ledger", err)
	}
}

func TestExecutionInitializationRequiresServingGenerationAndFullVerification(t *testing.T) {
	for _, mode := range []string{"runtime-mismatch", "unhealthy", "wrong-base", "changing-tree"} {
		t.Run(mode, func(t *testing.T) {
			f := newAdmissionFixture(t)
			base := ExecutionGeneration{Baseline: f.i.Baseline, GenerationID: "initial", TreeDigest: testDigest("tree")}
			d := &executionTestDriver{pointer: base, runtime: base, healthy: map[string]bool{"initial": true}, calls: map[string]int{}}
			switch mode {
			case "runtime-mismatch":
				d.runtime.GenerationID = "candidate"
			case "unhealthy":
				d.healthy["initial"] = false
			case "wrong-base":
				d.pointer.Baseline.RevisionID = "candidate"
				d.runtime = d.pointer
			case "changing-tree":
				d.hook = func(name string) error {
					if name == "verify" {
						d.pointer.TreeDigest = testDigest("changed")
						d.runtime = d.pointer
					}
					return nil
				}
			}
			a := ExecutionAnchor{APIVersion: ExecutionAnchorVersion, Installation: f.i, LayoutDigest: f.i.OwnershipDigest, ReceiptKeyID: "helper-receipt", ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(executionTestKey().Public().(ed25519.PublicKey))}
			dir := admissionTempDir(t)
			s, err := CreateExecutionStore(context.Background(), dir, a, d)
			if s != nil || !errors.Is(err, ErrOwnedTree) {
				t.Fatal("unverified baseline initialized", s, err)
			}
			names, err := os.ReadDir(dir)
			if err != nil || len(names) != 0 {
				t.Fatal("failed baseline left initialized marker", names, err)
			}
		})
	}
}

func executionTestKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
}

func TestExecutionReceiptRequiresPinnedHelperIdentityAndExactSignedOutcome(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	if other, err := NewExecutor(s, f.trust, f.sources, d, nil); other != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("missing signer accepted", err)
	}
	if other, err := NewExecutor(s, f.trust, f.sources, d, f.permit); other != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong signing purpose accepted", err)
	}
	result := executeFixture(t, e, f)
	public := executionTestKey().Public().(ed25519.PublicKey)
	if VerifyExecutionReceipt(*result, s.anchor.ReceiptKeyID, public) != nil {
		t.Fatal("receipt signature missing")
	}
	mutations := []func(*ExecutionReceipt){
		func(r *ExecutionReceipt) { r.Active.TreeDigest = testDigest("forged") },
		func(r *ExecutionReceipt) { r.Active.GenerationID = "other-generation" },
		func(r *ExecutionReceipt) { r.NodeDeploymentSequence++ },
		func(r *ExecutionReceipt) { r.RequestDigest = testDigest("other-request") },
		func(r *ExecutionReceipt) { r.ReceiptSequence++ },
		func(r *ExecutionReceipt) { r.Purpose = "admission" },
		func(r *ExecutionReceipt) { r.Signature = "" },
	}
	for i, mutate := range mutations {
		copy := *result
		mutate(&copy)
		if VerifyExecutionReceipt(copy, s.anchor.ReceiptKeyID, public) == nil {
			t.Errorf("forged outcome %d accepted", i)
		}
	}
	// Agent-controlled envelopes cannot reuse a valid admission signature under
	// the separately pinned receipt purpose and identity.
	forged := *result
	forged.Signature = f.r.Permit.Signature
	if VerifyExecutionReceipt(forged, s.anchor.ReceiptKeyID, f.trust.PermitKey) == nil {
		t.Fatal("admission signature became execution outcome")
	}
	before := d.calls["activate"]
	f.r.Task.Payload.TargetRevisionID = "other-target"
	f.bindPlan(t)
	f.sign(t)
	if _, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r))); !errors.Is(err, ErrConflict) || d.calls["activate"] != before {
		t.Fatal("same key changed signed request", err)
	}
}

func TestExecutionDurabilityFaultBeforeActivationNeverRunsEffects(t *testing.T) {
	for _, point := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(point, func(t *testing.T) {
			f, s, e, d, dir := executionFixture(t)
			s.fault = func(name string) error {
				if name == point {
					return errors.New("fault")
				}
				return nil
			}
			receipt, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
			if receipt != nil || !errors.Is(err, ErrState) || d.calls["prepare"] != 0 || d.calls["activate"] != 0 {
				t.Fatal("effect escaped durability fault", receipt, err, d.calls)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenExecutionStore(dir, s.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			state, err := reopened.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if point == "directory_sync" {
				if state.HighWater != 8 || state.Attempt == nil {
					t.Fatal("persisted intent lost consumed sequence", state)
				}
				e, err = NewExecutor(reopened, f.trust, f.sources, d, executionTestKey())
				if err != nil {
					t.Fatal(err)
				}
				e.now = func() time.Time { return f.sources.now }
				receipt, err = e.RecoverPending(context.Background())
				if err != nil || receipt == nil || receipt.State != "failed" {
					t.Fatal(receipt, err)
				}
			} else if state.HighWater != 7 || state.Attempt != nil {
				t.Fatal("uncommitted intent became active", state)
			}
		})
	}
}

func TestExecutionLedgerDescriptorCollisionsRejected(t *testing.T) {
	for _, mode := range []string{"state-hardlink", "extra-entry", "directory-replaced"} {
		t.Run(mode, func(t *testing.T) {
			_, s, _, _, dir := executionFixture(t)
			switch mode {
			case "state-hardlink":
				if err := os.Link(filepath.Join(dir, storeStateName), filepath.Join(dir, "outside-state")); err != nil {
					t.Fatal(err)
				}
			case "extra-entry":
				if err := os.WriteFile(filepath.Join(dir, "unmanaged"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-replaced":
				if err := os.Rename(dir, dir+"-moved"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir + "-moved") })
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Status(context.Background()); !errors.Is(err, ErrState) {
				t.Fatal("descriptor collision accepted", err)
			}
		})
	}
}

func TestExecutionWaitingObserverHonorsCancellation(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	d.hook = func(name string) error {
		if name == "validate" {
			close(entered)
			<-release
		}
		return nil
	}
	result := make(chan error, 1)
	go func() { _, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r))); result <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := s.Status(ctx)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("waiting observer ignored context", err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}

func TestExecutionUnresolvedRecoveryContainsServiceAndRecordsSanitizedFailure(t *testing.T) {
	for _, failContain := range []bool{false, true} {
		t.Run(map[bool]string{false: "contained", true: "contain-failed"}[failContain], func(t *testing.T) {
			f, s, e, d, _ := executionFixture(t)
			d.hook = func(name string) error {
				if name == "activated" {
					d.pointer.GenerationID = "unrecognized"
					d.runtime = d.pointer
					return errors.New("ambiguous switch")
				}
				if name == "contain" && failContain {
					return errors.New("private service path and secret detail")
				}
				return nil
			}
			result, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
			if result != nil || !errors.Is(err, ErrPending) || d.calls["contain"] != 1 {
				t.Fatal("unresolved runtime was not contained", result, err, d.calls)
			}
			state, err := s.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if state.Attempt == nil || state.Attempt.Containment == nil || !state.RecoveryRequired || state.Attempt.Stage != "recovery_required" {
				t.Fatal(state)
			}
			c := state.Attempt.Containment
			if c.Reason != "unverified_after_activation" {
				t.Fatal("lost recovery reason", c)
			}
			if failContain {
				if c.State != "failed" || c.ErrorCode != "containment_failed" {
					t.Fatal(c)
				}
			} else if c.State != "succeeded" || c.ErrorCode != "" {
				t.Fatal(c)
			}
			out, err := s.Outbox(context.Background())
			if err != nil || len(out) != 0 {
				t.Fatal("containment became healthy terminal receipt", out, err)
			}
		})
	}
}

func TestExecutionPoisonedLedgerStillContainsUnresolvedActivatedRuntime(t *testing.T) {
	f, s, e, d, dir := executionFixture(t)
	d.hook = func(name string) error {
		if name == "activated" {
			d.pointer.GenerationID = "unknown-after-activation"
			d.runtime = d.pointer
			s.fault = func(point string) error {
				if point == "write" {
					return errors.New("disk unavailable")
				}
				return nil
			}
		}
		return nil
	}
	result, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if result != nil || !errors.Is(err, ErrState) || d.calls["contain"] != 1 {
		t.Fatal("poisoned ledger skipped containment", result, err, d.calls)
	}
	if _, err = s.Status(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("poisoned handle reused", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExecutionStore(dir, s.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, err := reopened.Status(context.Background())
	if err != nil || state.Attempt == nil || state.Attempt.Stage != "activating" || state.HighWater != 8 || len(state.Records) != 0 {
		t.Fatal("unsafe terminal outcome fabricated", state, err)
	}
}

type executionRejectingStartSources struct {
	base   *testSources
	reject bool
}

func (s *executionRejectingStartSources) Head(ctx context.Context, challenge string) ([]byte, error) {
	return s.base.Head(ctx, challenge)
}
func (s *executionRejectingStartSources) Authorize(ctx context.Context, q StartQuery) ([]byte, error) {
	if s.reject {
		s.base.starts++
		return nil, ErrUnauthorized
	}
	return s.base.Authorize(ctx, q)
}

func TestExecutionAfterActivatingFsyncRequiresFreshLiveFence(t *testing.T) {
	for _, mode := range []string{"cp-cancel-same-head", "new-deny-head", "changed-head-digest", "authority-epoch", "context-cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, s, e, d, _ := executionFixture(t)
			source := &executionRejectingStartSources{base: f.sources}
			e.gate.sources = source
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			syncs := 0
			s.fault = func(point string) error {
				if point != "directory_sync" {
					return nil
				}
				syncs++
				if syncs != 4 {
					return nil
				}
				switch mode {
				case "cp-cancel-same-head":
					source.reject = true
				case "new-deny-head":
					f.sources.sequence++
				case "changed-head-digest":
					f.sources.headHook = func(h *securityjournal.Head, _ int) { h.Digest = testDigest("replaced-head-digest") }
				case "authority-epoch":
					f.sources.epoch++
				case "context-cancel":
					cancel()
				}
				return nil
			}
			result, err := e.Execute(ctx, bytes.NewReader(testBytes(t, f.r)))
			if err != nil || result == nil || result.State != "failed" {
				t.Fatal("changed fence did not retain healthy unchanged base", result, err)
			}
			if d.calls["activate"] != 0 || d.calls["reload"] != 0 {
				t.Fatal("effect escaped changed authority during fsync", mode, d.calls)
			}
			if mode == "cp-cancel-same-head" && f.sources.starts != 3 {
				t.Fatal("missing post-fsync current control authorization", f.sources.starts)
			}
			state, err := s.Status(context.Background())
			if err != nil || state.HighWater != 8 || state.Active != d.base || state.MinimumDenySequence != 5 || state.RecoveryRequired {
				t.Fatal("changed fence lost sequence/base/floor", state, err)
			}
		})
	}
}

func TestExecutionActivationCannotOutliveFreshProof(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	f.sources.proofHook = func(p *StartProof) { p.ExpiresAt = f.sources.now.Add(250 * time.Millisecond).Format(time.RFC3339Nano) }
	d.onActivate = func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			t.Error("activation retained the long operation deadline after the short signed proof expired")
			return ErrStale
		}
	}
	out, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if err != nil || out == nil || out.State != "recovered" || d.calls["activate"] != 1 || d.calls["reload"] != 0 {
		t.Fatal("expired activation failed to preserve exact healthy base", out, err, d.calls)
	}
	state, err := s.Status(context.Background())
	if err != nil || state.Active != d.base || state.HighWater != 8 || state.RecoveryRequired {
		t.Fatal("deadline recovery lost baseline or consumed sequence", state, err)
	}
}
