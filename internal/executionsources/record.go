package executionsources

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// Record accepts actual delayed outcomes after plan cancellation or expiry. It
// does not reauthorize execution, require a fresh plan or pretend the current
// release proves what happened previously. Only the exact stored task, pinned
// root receipt identity and monotonic baseline CAS can change baseline state.
func (s *Service) Record(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, target rolloutexecution.TargetSnapshot, r helper.ExecutionReceipt) error {
	c, err := s.config(ctx)
	if err != nil {
		return err
	}
	b, ok := c.bindings[r.NodeID]
	if !ok || hash(b.Anchor.Installation) != hash(target.Installation) || b.Anchor.ReceiptKeyID != target.ReceiptKeyID || b.Anchor.ReceiptPublicKey != target.ReceiptPublicKey {
		return ErrStale
	}
	key, err := publicKey(b.Anchor.ReceiptPublicKey)
	if err != nil || helper.VerifyExecutionReceipt(r, b.Anchor.ReceiptKeyID, key) != nil {
		return storage.ErrPermissionDenied
	}
	var requestRaw, targetRaw, requestPin string
	if err = securitystate.One(ctx, tx, `SELECT request_json,target_json,request_digest FROM execution_tasks WHERE id=? AND node_id=?`, []any{r.TaskID, r.NodeID}, func(rows storage.IdentityRows) error { return rows.Scan(&requestRaw, &targetRaw, &requestPin) }); err != nil {
		return err
	}
	request, err := decodeRequest(requestRaw)
	if err != nil {
		return err
	}
	var saved rolloutexecution.TargetSnapshot
	if decodeCanonical(targetRaw, &saved, 65536) != nil || hash(saved) != hash(target) || requestPin != hash(request) || requestPin != r.RequestDigest {
		return ErrStale
	}
	t := request.Task
	installation := b.Anchor.Installation
	if t.ID != r.TaskID || t.NodeID != r.NodeID || t.NodeDeploymentSequence != r.NodeDeploymentSequence || t.AuthorityEpoch != installation.AuthorityEpoch || t.WriterEpoch != installation.WriterEpoch || request.Permit.InstallationDigest != hash(installation) || t.Preconditions.BaseRevisionID != target.Baseline.Baseline.RevisionID || t.Preconditions.ExpectedNodeDeploymentSequence != target.AcceptedSequence || t.Payload.RecoveryBaseBundleDigest != target.Baseline.Baseline.BundleDigest {
		return ErrStale
	}
	at, e := parseUTC(r.RecordedAt)
	issued, e2 := parseUTC(t.IssuedAt)
	if e != nil || e2 != nil || at.Before(issued) || at.After(h.RecordedAt.Add(30*time.Second)) {
		return ErrStale
	}
	// Return a saved acknowledgement without changing an already advanced
	// baseline. A duplicate with different signed bytes is equivocation.
	var prior string
	e = securitystate.One(ctx, tx, `SELECT receipt_digest FROM execution_source_outcomes WHERE receipt_id=? AND node_id=?`, []any{r.ReceiptID, r.NodeID}, func(rows storage.IdentityRows) error { return rows.Scan(&prior) })
	if e == nil {
		if prior != hash(r) {
			return ErrStale
		}
		return nil
	}
	if e != storage.ErrNotFound {
		return e
	}
	old, err := readBaseline(ctx, tx, r.NodeID, b.Anchor)
	if err != nil {
		return err
	}
	if old.Frozen || old.Active != target.Baseline || old.Accepted != target.AcceptedSequence || r.NodeDeploymentSequence <= old.Accepted || r.ReceiptSequence != old.Receipt+1 {
		return ErrStale
	}
	if old.Epoch != t.AuthorityEpoch || old.Writer != t.WriterEpoch {
		return ErrStale
	}
	switch r.State {
	case "succeeded":
		if r.RecoveryRequired || r.Active.Baseline.RevisionID != t.Payload.TargetRevisionID || r.Active.Baseline.BundleDigest != t.Payload.BundleDigest || r.Active.Baseline.NodeDeploymentSequence != t.NodeDeploymentSequence || r.Active.GenerationID != t.Payload.DeploymentGeneration || r.Active.TreeDigest != target.TargetTreeDigest {
			return ErrStale
		}
	case "failed", "recovered":
		if r.RecoveryRequired || r.Active != target.Baseline {
			return ErrStale
		}
	case "recovery_required":
		if !r.RecoveryRequired || r.Active != target.Baseline {
			return ErrStale
		}
	default:
		return ErrStale
	}
	raw, err := configmodel.CanonicalJSON(r)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO execution_source_outcomes(receipt_id,node_id,task_id,receipt_digest,receipt_json,received_at) VALUES(?,?,?,?,?,?)`, r.ReceiptID, r.NodeID, r.TaskID, hash(r), string(raw), h.RecordedAt); err != nil {
		return err
	}
	next := *old
	next.Active = r.Active
	next.Accepted = r.NodeDeploymentSequence
	next.Receipt = r.ReceiptSequence
	next.Frozen = r.RecoveryRequired
	next.VerifiedAt = h.RecordedAt
	next.ProofKind = "receipt"
	next.ProofID = r.ReceiptID
	if t.Payload.MinimumDenySequence > next.Deny {
		next.Deny = t.Payload.MinimumDenySequence
	}
	if err = updateBaseline(ctx, tx, r.NodeID, old, next); err != nil {
		return err
	}
	return s.witness(ctx)
}
