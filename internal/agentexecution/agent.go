// Package agentexecution forwards control-plane tasks to the installed local
// root helper. It cannot authorize effects, acknowledge the helper's outbox or
// supply executable paths, service names or command arguments.
package agentexecution

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securityjournal"
)

var (
	ErrInvalid     = errors.New("agent_execution_invalid")
	ErrUnavailable = errors.New("agent_execution_unavailable")
)

type Control interface {
	ExecutionPending(context.Context) ([]helper.Request, error)
}

type LocalHelper interface {
	Execute(context.Context, helper.Request) (*helper.ExecutionReceipt, error)
}

type Agent struct {
	control Control
	local   LocalHelper
	serial  chan struct{}
}

func New(control Control, local LocalHelper) (*Agent, error) {
	if control == nil || local == nil {
		return nil, ErrInvalid
	}
	return &Agent{control: control, local: local, serial: make(chan struct{}, 1)}, nil
}

// RunOnce fetches at most one immutable task. Concurrent callers are serialized
// and cancellation while waiting never starts another local operation. A retry
// reuses the control-plane task unchanged; no new identifier is generated here.
func (a *Agent) RunOnce(ctx context.Context) (*helper.ExecutionReceipt, error) {
	if a == nil || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case a.serial <- struct{}{}:
		defer func() { <-a.serial }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	items, err := a.control.ExecutionPending(call)
	if err != nil {
		return nil, transportError(call)
	}
	if len(items) > 1 {
		return nil, ErrInvalid
	}
	if len(items) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(items[0])
	if err != nil {
		return nil, ErrInvalid
	}
	request, err := helper.Decode(bytes.NewReader(raw))
	if err != nil || request.SignedPlan == nil {
		return nil, ErrInvalid
	}
	digest, err := configmodel.Digest(*request)
	if err != nil {
		return nil, ErrInvalid
	}
	if call.Err() != nil {
		return nil, call.Err()
	}
	receipt, err := a.local.Execute(call, *request)
	if err != nil {
		return nil, transportError(call)
	}
	if receipt == nil || !receiptMatches(*receipt, request.Task, digest) {
		return nil, ErrInvalid
	}
	// Do not deliver or ACK this receipt: the root helper owns its durable outbox
	// and authenticates the control-plane response on its own pinned transport.
	out := *receipt
	return &out, nil
}

func transportError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

func receiptMatches(r helper.ExecutionReceipt, t helper.Task, digest string) bool {
	if r.APIVersion != helper.ExecutionReceiptVersion || r.Purpose != "local_execution_outcome" || r.TaskID != t.ID || r.NodeID != t.NodeID || r.RequestDigest != digest || r.NodeDeploymentSequence != t.NodeDeploymentSequence || r.ReceiptSequence == 0 || r.ReceiptSequence > securityjournal.MaxUInt63 || !configmodel.ValidID(r.ReceiptID) || !configmodel.ValidID(r.KeyID) || !configmodel.ValidID(r.Active.GenerationID) || !configmodel.ValidID(r.Active.Baseline.RevisionID) || !configmodel.ValidDigest(r.Active.Baseline.BundleDigest) || !configmodel.ValidDigest(r.Active.TreeDigest) || r.Active.Baseline.NodeDeploymentSequence > r.NodeDeploymentSequence {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil || len(signature) != 64 || base64.RawURLEncoding.EncodeToString(signature) != r.Signature {
		return false
	}
	recorded, err := time.Parse(time.RFC3339Nano, r.RecordedAt)
	if err != nil || recorded.IsZero() || recorded.Location() != time.UTC || recorded.Format(time.RFC3339Nano) != r.RecordedAt {
		return false
	}
	switch r.State {
	case "succeeded":
		return !r.RecoveryRequired && r.Active.Baseline.RevisionID == t.Payload.TargetRevisionID && r.Active.Baseline.BundleDigest == t.Payload.BundleDigest && r.Active.Baseline.NodeDeploymentSequence == t.NodeDeploymentSequence && r.Active.GenerationID == t.Payload.DeploymentGeneration
	case "failed", "recovered":
		// The accepted sequence advances on failure while the serving baseline
		// retains its older successful sequence. The task pins the accepted
		// high-water mark, not necessarily the baseline's generation sequence.
		return !r.RecoveryRequired && r.Active.Baseline.RevisionID == t.Preconditions.BaseRevisionID && r.Active.Baseline.BundleDigest == t.Payload.RecoveryBaseBundleDigest && r.Active.Baseline.NodeDeploymentSequence <= t.Preconditions.ExpectedNodeDeploymentSequence
	case "recovery_required":
		return r.RecoveryRequired
	default:
		return false
	}
}
