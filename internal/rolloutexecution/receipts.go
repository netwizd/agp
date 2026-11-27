package rolloutexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func taskReceipt(ctx context.Context, tx storage.IdentityTx, id string) (*helper.ExecutionReceipt, error) {
	var raw, pin string
	err := securitystate.One(ctx, tx, `SELECT receipt_json,receipt_digest FROM execution_receipts WHERE task_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw, &pin) })
	if err != nil {
		return nil, err
	}
	var receipt helper.ExecutionReceipt
	if len(raw) > 65536 || json.Unmarshal([]byte(raw), &receipt) != nil || digest(receipt) != pin || receipt.TaskID != id {
		return nil, ErrUnavailable
	}
	return &receipt, nil
}

func successfulTaskReceipt(task storedTask, r helper.ExecutionReceipt) error {
	key, err := base64.RawURLEncoding.DecodeString(task.target.ReceiptPublicKey)
	if err != nil || helper.VerifyExecutionReceipt(r, task.target.ReceiptKeyID, ed25519.PublicKey(key)) != nil {
		return ErrUnavailable
	}
	t := task.request.Task
	if r.State != "succeeded" || r.TaskID != t.ID || r.NodeID != t.NodeID || r.RequestDigest != task.requestDigest || r.NodeDeploymentSequence != t.NodeDeploymentSequence || r.Active.Baseline.RevisionID != t.Payload.TargetRevisionID || r.Active.Baseline.BundleDigest != t.Payload.BundleDigest || r.Active.Baseline.NodeDeploymentSequence != t.NodeDeploymentSequence || r.Active.GenerationID != t.Payload.DeploymentGeneration || r.Active.TreeDigest != task.target.TargetTreeDigest {
		return ErrUnavailable
	}
	return nil
}

// RecordReceiptPeer stores signed helper outcomes, including cancelled or
// expired tasks that actually ran. An ordinary agent acknowledgement or a
// management user's JSON can never update a verified baseline.
func (s *Service) RecordReceiptPeer(ctx context.Context, peer *tls.ConnectionState, r helper.ExecutionReceipt) error {
	if r.APIVersion != helper.ExecutionReceiptVersion || r.Purpose != "local_execution_outcome" || !configmodel.ValidID(r.ReceiptID) || !configmodel.ValidID(r.TaskID) || !configmodel.ValidID(r.NodeID) || !configmodel.ValidDigest(r.RequestDigest) || r.ReceiptSequence == 0 || r.ReceiptSequence > securityjournalMax || r.NodeDeploymentSequence == 0 || r.NodeDeploymentSequence > securityjournalMax || r.Signature == "" || r.KeyID == "" {
		return ErrInvalid
	}
	raw, err := canonical(r)
	if err != nil || len(raw) > 65536 {
		return ErrInvalid
	}
	return s.peerOperation(ctx, peer, nil, func(o *operation, node string) error {
		if node != r.NodeID {
			return storage.ErrPermissionDenied
		}
		if err := checkNode(o.ctx, o.tx, node); err != nil {
			return err
		}
		task, e := readTask(o.ctx, o.tx, taskByID, r.TaskID)
		if e != nil {
			return e
		}
		t := task.request.Task
		key, e := base64.RawURLEncoding.DecodeString(task.target.ReceiptPublicKey)
		if e != nil || len(key) != ed25519.PublicKeySize || helper.VerifyExecutionReceipt(r, task.target.ReceiptKeyID, ed25519.PublicKey(key)) != nil {
			return storage.ErrPermissionDenied
		}
		if t.NodeID != node || task.requestDigest != r.RequestDigest || t.NodeDeploymentSequence != r.NodeDeploymentSequence || t.AuthorityEpoch != o.head.Epoch {
			return ErrStale
		}
		at, e := time.Parse(time.RFC3339Nano, r.RecordedAt)
		if e != nil || at.IsZero() || at.Before(parseTime(t.IssuedAt)) || at.After(time.Now().UTC().Add(30*time.Second)) {
			return ErrInvalid
		}
		if !configmodel.ValidID(r.Active.Baseline.RevisionID) || !configmodel.ValidID(r.Active.GenerationID) || !configmodel.ValidDigest(r.Active.Baseline.BundleDigest) || !configmodel.ValidDigest(r.Active.TreeDigest) || r.Active.Baseline.NodeDeploymentSequence > r.NodeDeploymentSequence {
			return ErrInvalid
		}
		switch r.State {
		case "succeeded":
			if r.RecoveryRequired || r.Active.Baseline.RevisionID != t.Payload.TargetRevisionID || r.Active.Baseline.BundleDigest != t.Payload.BundleDigest || r.Active.Baseline.NodeDeploymentSequence != t.NodeDeploymentSequence || r.Active.GenerationID != t.Payload.DeploymentGeneration || r.Active.TreeDigest != task.target.TargetTreeDigest {
				return ErrInvalid
			}
		case "failed", "recovered":
			if r.RecoveryRequired || r.Active != task.target.Baseline {
				return ErrInvalid
			}
		case "recovery_required":
			if !r.RecoveryRequired || r.Active != task.target.Baseline {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		prior, e := taskReceipt(o.ctx, o.tx, r.TaskID)
		if e == nil {
			if digest(prior) != digest(r) {
				return ErrConflict
			}
			return nil
		}
		if e != storage.ErrNotFound {
			return e
		}
		if task.state != "dispatched" {
			return ErrConflict
		}
		var accepted, allocated, lastReceipt int64
		e = securitystate.One(o.ctx, o.tx, `SELECT accepted_sequence,allocated_sequence,receipt_sequence FROM execution_node_counters WHERE node_id=?`, []any{node}, func(row storage.IdentityRows) error { return row.Scan(&accepted, &allocated, &lastReceipt) })
		if e != nil {
			return e
		}
		if uint64(accepted) > uint64(r.NodeDeploymentSequence) || allocated < int64(r.NodeDeploymentSequence) || lastReceipt >= int64(r.ReceiptSequence) {
			return ErrStale
		}
		// The trusted source verifies the root-held helper receipt signature and
		// current installation/floors before writing any healthy baseline. The
		// immutable receipt and those writes share this exact transaction.
		if e = s.sources.Record(o.ctx, o.tx, o.head, task.target, r); e != nil {
			return e
		}
		_, e = o.tx.Exec(o.ctx, `INSERT INTO execution_receipts(receipt_id,task_id,node_id,receipt_sequence,receipt_digest,receipt_json,received_at) VALUES(?,?,?,?,?,?,?)`, r.ReceiptID, r.TaskID, node, int64(r.ReceiptSequence), digest(r), string(raw), o.head.RecordedAt)
		if e != nil {
			return e
		}
		if _, e = o.tx.Exec(o.ctx, `UPDATE execution_node_counters SET accepted_sequence=?,receipt_sequence=? WHERE node_id=?`, int64(r.NodeDeploymentSequence), int64(r.ReceiptSequence), node); e != nil {
			return e
		}
		if _, e = o.tx.Exec(o.ctx, `UPDATE execution_tasks SET state=?,completed_at=? WHERE id=? AND state='dispatched'`, r.State, o.head.RecordedAt, r.TaskID); e != nil {
			return e
		}
		p, e := readPlan(o.ctx, o.tx, t.PlanID)
		if e != nil {
			return e
		}
		if p.view.State != "cancelled" {
			state := "running"
			if r.State != "succeeded" {
				state = "failed"
				if r.RecoveryRequired {
					state = "recovery_required"
				}
			} else {
				var successes int64
				if e = securitystate.One(o.ctx, o.tx, `SELECT COUNT(*) FROM execution_tasks WHERE plan_id=? AND state='succeeded'`, []any{t.PlanID}, func(row storage.IdentityRows) error { return row.Scan(&successes) }); e != nil {
					return e
				}
				if successes == int64(len(p.snapshot.Targets)) {
					state = "succeeded"
				}
			}
			if _, e = o.tx.Exec(o.ctx, `UPDATE execution_plans SET state=? WHERE id=?`, state, t.PlanID); e != nil {
				return e
			}
		}
		return audit(o.ctx, o.tx, "execution.receipt.recorded", node, t.PlanID)
	})
}

const securityjournalMax = 1<<63 - 1
