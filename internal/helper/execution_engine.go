package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
)

// Executor runs only through an explicit installer adapter and a separate
// execution ledger. It never upgrades a historical Gate admission to success.
type Executor struct {
	store      *ExecutionStore
	gate       *Gate
	driver     ExecutionDriver
	now        func() time.Time
	receiptKey ed25519.PrivateKey
}

func NewExecutor(s *ExecutionStore, t Trust, sources Sources, d ExecutionDriver, receiptKey ed25519.PrivateKey) (*Executor, error) {
	if s == nil || s.Store == nil || d == nil {
		return nil, ErrInvalid
	}
	pub, err := executionReceiptKey(s.anchor)
	if err != nil || len(receiptKey) != ed25519.PrivateKeySize || !bytes.Equal(receiptKey, ed25519.NewKeyFromSeed(receiptKey.Seed())) || !bytes.Equal(pub, receiptKey.Public().(ed25519.PublicKey)) || bytes.Equal(pub, t.PermitKey) || bytes.Equal(pub, t.ControlKey) || bytes.Equal(pub, t.JournalKey) {
		return nil, ErrInvalid
	}
	gate, err := NewGate(s.Store, t, sources)
	if err != nil {
		return nil, err
	}
	return &Executor{store: s, gate: gate, driver: d, now: time.Now, receiptKey: bytes.Clone(receiptKey)}, nil
}

type executionAuthorization struct {
	head    securityjournal.Head
	proof   StartProof
	raw     []byte
	started time.Time
}

func (e *Executor) authorize(ctx context.Context, r Request, digest string, s ExecutionState) (executionAuthorization, error) {
	var out executionAuthorization
	e.gate.now = e.now
	if checkPlan(r, e.store.anchor.Installation, e.gate.trust, e.now().UTC()) != nil || !verifyPermit(r.Permit, e.gate.trust) {
		return out, ErrUnauthorized
	}
	out.started = e.now()
	h1, err := e.gate.head(ctx)
	if err != nil {
		return out, err
	}
	if !liveWindow(r.Task, h1, e.now().UTC()) || h1.Epoch < s.AuthorityEpoch || h1.Sequence < s.MinimumDenySequence || h1.Sequence < r.Task.Payload.MinimumDenySequence || h1.Sequence < r.Permit.Recovery.MinimumDenySequence {
		return out, ErrStale
	}
	c, err := challenge()
	if err != nil {
		return out, err
	}
	q := StartQuery{APIVersion: StartVersion, Challenge: c, RequestDigest: digest, InstallationDigest: e.store.Store.digest, Head: pin(h1)}
	raw, err := e.gate.sources.Authorize(ctx, q)
	if err != nil {
		return out, ErrUnauthorized
	}
	proof, err := e.gate.liveProof(raw, q, r.Task)
	if err != nil {
		return out, err
	}
	h2, err := e.gate.head(ctx)
	if err != nil {
		return out, err
	}
	if !h2.SameState(h1) || h2.RecordedAt.Before(h1.RecordedAt) || !h2.RecordedAt.Before(h1.RecordedAt.Add(MaxStartTTL)) || !liveWindow(r.Task, h2, e.now().UTC()) || !e.now().Before(out.started.Add(MaxStartTTL)) {
		return out, ErrStale
	}
	out.head, out.proof, out.raw = h2, proof, bytes.Clone(raw)
	return out, nil
}

func (e *Executor) authorizationLive(ctx context.Context, r Request, a executionAuthorization) error {
	if ctx.Err() != nil || !e.now().Before(a.started.Add(MaxStartTTL)) || !liveWindow(r.Task, a.head, e.now().UTC()) {
		return ErrUnauthorized
	}
	if _, err := e.gate.liveProof(a.raw, a.proof.Query, r.Task); err != nil {
		return err
	}
	return nil
}

func (e *Executor) verifiedCurrent(ctx context.Context, want ExecutionGeneration) error {
	observed, err := e.driver.Snapshot(ctx)
	if err != nil || observed != want || e.driver.Verify(ctx, want) != nil {
		return ErrOwnedTree
	}
	again, err := e.driver.Snapshot(ctx)
	if err != nil || again != want || ctx.Err() != nil {
		return ErrOwnedTree
	}
	return nil
}

// Execute returns an immutable terminal outcome. Exact terminal replay performs
// no transport, filesystem or runtime operation, even after the permit expires.
// An interrupted current attempt requires explicit RecoverPending, never blind
// resumption from a caller's retry.
func (e *Executor) Execute(ctx context.Context, input io.Reader) (*ExecutionReceipt, error) {
	if e == nil || e.store == nil || e.now == nil || ctx == nil {
		return nil, ErrState
	}
	r, err := Decode(input)
	if err != nil {
		return nil, err
	}
	digest, err := configmodel.Digest(*r)
	if err != nil {
		return nil, ErrInvalid
	}
	s, err := e.store.lockState(ctx)
	if err != nil {
		return nil, err
	}
	defer e.store.mu.Unlock()
	for _, record := range s.Records {
		old := record.Receipt
		if old.TaskID == r.Task.ID || record.IdempotencyKey == r.Task.IdempotencyKey {
			if old.TaskID != r.Task.ID || record.IdempotencyKey != r.Task.IdempotencyKey || old.RequestDigest != digest {
				return nil, ErrConflict
			}
			result := old
			return &result, nil
		}
	}
	if s.Attempt != nil {
		old := s.Attempt.Request.Task
		if (old.ID == r.Task.ID || old.IdempotencyKey == r.Task.IdempotencyKey) && (old.ID != r.Task.ID || old.IdempotencyKey != r.Task.IdempotencyKey || s.Attempt.RequestDigest != digest) {
			return nil, ErrConflict
		}
		return nil, ErrPending
	}
	if s.RecoveryRequired {
		return nil, ErrPending
	}
	if len(s.Records) >= MaxExecutionRecords {
		return nil, ErrState
	}
	t := r.Task
	currentInstall := e.store.anchor.Installation
	currentInstall.Baseline = s.Active.Baseline
	if err = checkInstallation(*r, currentInstall, e.store.Store.digest); err != nil {
		return nil, err
	}
	if t.NodeDeploymentSequence <= s.HighWater || t.Preconditions.ExpectedNodeDeploymentSequence != s.HighWater || t.AuthorityEpoch < s.AuthorityEpoch || t.WriterEpoch < s.WriterEpoch {
		return nil, ErrStale
	}
	run, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	if e.verifiedCurrent(run, s.Active) != nil {
		return nil, ErrOwnedTree
	}
	authctx, authcancel := context.WithTimeout(run, MaxStartTTL)
	a, err := e.authorize(authctx, *r, digest, s)
	if err == nil {
		err = e.verifiedCurrent(authctx, s.Active)
	}
	if err == nil {
		err = e.authorizationLive(authctx, *r, a)
	}
	authcancel()
	if err != nil {
		return nil, err
	}
	// Consume sequence and floors durably before staging. A failed attempt never
	// gives its sequence back, while the serving base remains the last healthy one.
	s.HighWater, s.AuthorityEpoch, s.WriterEpoch, s.MinimumDenySequence = t.NodeDeploymentSequence, t.AuthorityEpoch, t.WriterEpoch, a.head.Sequence
	s.Attempt = &ExecutionAttempt{Request: *r, RequestDigest: digest, Base: s.Active, Stage: "preparing", AcceptedAt: e.now().UTC().Format(time.RFC3339Nano), AdmissionHead: a.head, AdmissionProof: a.proof}
	if err = e.store.writeSnapshot(s); err != nil {
		return nil, err
	}
	target, err := e.driver.Prepare(run, *r, s.Active)
	if err != nil || !executionTargetMatches(target, t) {
		return e.beforeEffectFailure(&s)
	}
	s.Attempt.Target = &target
	s.Attempt.Stage = "prepared"
	if err = e.store.writeSnapshot(s); err != nil {
		return nil, err
	}
	if run.Err() != nil || e.driver.Validate(run, target) != nil {
		return e.beforeEffectFailure(&s)
	}
	s.Attempt.Stage = "validated"
	if err = e.store.writeSnapshot(s); err != nil {
		return nil, err
	}
	// Syntax success is not authority. Collect a fresh signed proof bracketed by
	// independent identical journal heads at the actual activation boundary.
	authctx, authcancel = context.WithTimeout(run, MaxStartTTL)
	a, err = e.authorize(authctx, *r, digest, s)
	if err == nil {
		err = e.verifiedCurrent(authctx, s.Active)
	}
	if err == nil {
		err = e.authorizationLive(authctx, *r, a)
	}
	if err != nil {
		authcancel()
		return e.beforeEffectFailure(&s)
	}
	s.MinimumDenySequence = a.head.Sequence
	s.Attempt.EffectHead = &a.head
	s.Attempt.EffectProof = &a.proof
	s.Attempt.Stage = "activating"
	if err = e.store.writeSnapshot(s); err != nil {
		authcancel()
		return nil, err
	}
	// fsync may have blocked while a revoke, cancellation or journal update
	// invalidated the saved proof. Recheck the tree, then collect a NEW live
	// authorization fence after durability, with no following ledger fsync.
	// Its head must equal the persisted effect head: a newer deny floor cannot
	// authorize effects while only the older floor is durable after a crash.
	err = e.authorizationLive(authctx, *r, a)
	authcancel()
	effectAuth := a
	if err == nil {
		fencectx, fencecancel := context.WithTimeout(run, MaxStartTTL)
		err = e.verifiedCurrent(fencectx, s.Active)
		if err == nil {
			var fence executionAuthorization
			fence, err = e.authorize(fencectx, *r, digest, s)
			if err == nil && !fence.head.SameState(a.head) {
				err = ErrStale
			}
			if err == nil {
				err = e.authorizationLive(fencectx, *r, fence)
				effectAuth = fence
			}
		}
		fencecancel()
	}
	if err != nil {
		return e.beforeEffectFailure(&s)
	}
	// A driver can spend time rehashing trees before its atomic mutation. Give
	// it the authorization deadline, not the longer whole-operation deadline;
	// it must check this context immediately before changing the active pointer.
	deadline := effectAuth.started.Add(MaxStartTTL)
	for _, value := range []string{effectAuth.proof.ExpiresAt, r.Task.ExpiresAt, r.SignedPlan.Plan.ExpiresAt} {
		bound, parseErr := utc(value)
		if parseErr != nil {
			return e.beforeEffectFailure(&s)
		}
		if bound.Before(deadline) {
			deadline = bound
		}
	}
	effect, effectCancel := context.WithTimeout(run, deadline.Sub(e.now()))
	err = e.driver.Activate(effect, s.Attempt.Base, target)
	effectCancel()
	if err != nil {
		return e.reconcile(&s)
	}
	s.Attempt.Stage = "reloading"
	if err = e.store.writeSnapshot(s); err != nil {
		e.recoverAfterPersistenceFailure(&s)
		return nil, err
	}
	if e.driver.Reload(run, target) != nil {
		return e.reconcile(&s)
	}
	s.Attempt.Stage = "verifying"
	if err = e.store.writeSnapshot(s); err != nil {
		e.recoverAfterPersistenceFailure(&s)
		return nil, err
	}
	if e.verifiedCurrent(run, target) != nil {
		return e.reconcile(&s)
	}
	return e.finish(&s, "succeeded", target)
}

// A broken durable ledger cannot publish a terminal outcome or accept more
// work. Still bound the runtime hazard after activation: preserve a verified
// healthy target, otherwise restore only the already-authorized exact base.
// The poisoned handle remains unusable; restart reconciles its durable stage.
func (e *Executor) recoverAfterPersistenceFailure(s *ExecutionState) {
	ctx, cancel := context.WithTimeout(context.Background(), executionRecoveryTimeout)
	at := s.Attempt
	if at == nil || at.Target == nil {
		cancel()
		return
	}
	if e.verifiedCurrent(ctx, *at.Target) == nil || e.verifiedCurrent(ctx, at.Base) == nil {
		cancel()
		return
	}
	if e.driver.Recover(ctx, *at.Target, at.Base) == nil && e.verifiedCurrent(ctx, at.Base) == nil {
		cancel()
		return
	}
	cancel()
	// The ledger is poisoned: containment still bounds the local hazard, but no
	// durable recovery/receipt is claimed. Reopen must reconcile its saved stage.
	_ = e.contain()
}

func (e *Executor) contain() error {
	ctx, cancel := context.WithTimeout(context.Background(), executionContainmentTimeout)
	defer cancel()
	return e.driver.Contain(ctx)
}

func (e *Executor) requireRecovery(s *ExecutionState, reason string) (*ExecutionReceipt, error) {
	s.RecoveryRequired = true
	s.Attempt.Stage = "recovery_required"
	s.Attempt.Containment = &ExecutionContainment{Reason: reason, State: "pending", RecordedAt: e.now().UTC().Format(time.RFC3339Nano)}
	persistErr := e.store.writeSnapshot(*s)
	containErr := e.contain()
	if persistErr != nil {
		return nil, persistErr
	}
	if containErr != nil {
		s.Attempt.Containment.State = "failed"
		s.Attempt.Containment.ErrorCode = "containment_failed"
	} else {
		s.Attempt.Containment.State = "succeeded"
	}
	s.Attempt.Containment.RecordedAt = e.now().UTC().Format(time.RFC3339Nano)
	if err := e.store.writeSnapshot(*s); err != nil {
		return nil, err
	}
	return nil, ErrPending
}

func (e *Executor) beforeEffectFailure(s *ExecutionState) (*ExecutionReceipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), executionRecoveryTimeout)
	defer cancel()
	if e.verifiedCurrent(ctx, s.Attempt.Base) == nil {
		return e.finish(s, "failed", s.Attempt.Base)
	}
	return e.requireRecovery(s, "unverified_before_activation")
}

func (e *Executor) reconcile(s *ExecutionState) (*ExecutionReceipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), executionRecoveryTimeout)
	defer cancel()
	at := s.Attempt
	if at == nil {
		return nil, ErrState
	}
	// A healthy target survives lost responses, cancellation and CP partitions.
	// A reload exit code alone cannot select this branch.
	if at.Target != nil && e.verifiedCurrent(ctx, *at.Target) == nil {
		return e.finish(s, "succeeded", *at.Target)
	}
	if e.verifiedCurrent(ctx, at.Base) == nil {
		return e.finish(s, "recovered", at.Base)
	}
	if at.Target != nil && e.driver.Recover(ctx, *at.Target, at.Base) == nil && e.verifiedCurrent(ctx, at.Base) == nil {
		return e.finish(s, "recovered", at.Base)
	}
	return e.requireRecovery(s, "unverified_after_activation")
}

func (e *Executor) finish(s *ExecutionState, state string, active ExecutionGeneration) (*ExecutionReceipt, error) {
	at := s.Attempt
	if at == nil || s.ReceiptSequence == securityjournal.MaxUInt63 {
		return nil, ErrState
	}
	id, err := challenge()
	if err != nil {
		return nil, err
	}
	receipt := ExecutionReceipt{APIVersion: ExecutionReceiptVersion, Purpose: "local_execution_outcome", ReceiptID: "execution-" + id, ReceiptSequence: s.ReceiptSequence + 1, NodeID: e.store.anchor.Installation.NodeID, TaskID: at.Request.Task.ID, RequestDigest: at.RequestDigest, NodeDeploymentSequence: at.Request.Task.NodeDeploymentSequence, Active: active, State: state, RecordedAt: e.now().UTC().Format(time.RFC3339Nano)}
	receipt, err = signExecutionReceipt(receipt, e.store.anchor.ReceiptKeyID, e.receiptKey)
	if err != nil {
		return nil, err
	}
	s.Active, s.LastHealthy = active, active
	s.ReceiptSequence = receipt.ReceiptSequence
	s.RecoveryRequired = false
	s.Records = append(s.Records, ExecutionRecord{IdempotencyKey: at.Request.Task.IdempotencyKey, Receipt: receipt})
	s.Attempt = nil
	if err = e.store.writeSnapshot(*s); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// RecoverPending is local reconciliation of an already-authorized attempt. It
// cannot accept a target, new plan, path or replacement recovery base from its
// caller. The independent bounded context completes recovery after cancellation.
func (e *Executor) RecoverPending(ctx context.Context) (*ExecutionReceipt, error) {
	if e == nil || e.store == nil || ctx == nil {
		return nil, ErrState
	}
	s, err := e.store.lockState(ctx)
	if err != nil {
		return nil, err
	}
	defer e.store.mu.Unlock()
	if s.Attempt == nil {
		return nil, ErrPending
	}
	if s.Attempt.Stage == "preparing" || s.Attempt.Stage == "prepared" || s.Attempt.Stage == "validated" {
		return e.beforeEffectFailure(&s)
	}
	return e.reconcile(&s)
}

func (s *ExecutionStore) Status(ctx context.Context) (*ExecutionState, error) {
	state, err := s.lockState(ctx)
	if err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	return &state, nil
}

func (s *ExecutionStore) Outbox(ctx context.Context) ([]ExecutionReceipt, error) {
	state, err := s.lockState(ctx)
	if err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	out := make([]ExecutionReceipt, 0)
	for _, record := range state.Records {
		if !record.Delivered {
			out = append(out, record.Receipt)
		}
	}
	return out, nil
}

// Acknowledge records only delivery of an existing receipt ID. It cannot change
// the observed state, active generation, sequence, or authorize another effect.
func (s *ExecutionStore) Acknowledge(ctx context.Context, receiptID string) error {
	state, err := s.lockState(ctx)
	if err != nil {
		return err
	}
	defer s.mu.Unlock()
	for i := range state.Records {
		if state.Records[i].Receipt.ReceiptID == receiptID {
			if state.Records[i].Delivered {
				return nil
			}
			state.Records[i].Delivered = true
			return s.writeSnapshot(state)
		}
	}
	return ErrInvalid
}
