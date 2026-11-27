package executionsources

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func readBaseline(ctx context.Context, tx storage.IdentityTx, node string, a helper.ExecutionAnchor) (*baselineRecord, error) {
	if err := notFrozen(ctx, tx, node); err != nil {
		return nil, err
	}
	r := &baselineRecord{}
	var raw string
	var accepted, receipt, epoch, writer, deny int64
	err := securitystate.One(ctx, tx, `SELECT anchor_digest,active_json,accepted_sequence,receipt_sequence,authority_epoch,writer_epoch,deny_sequence,frozen,proof_kind,proof_id,verified_at,row_version,boot_digest,capture_id FROM execution_verified_baselines WHERE node_id=?`, []any{node}, func(rows storage.IdentityRows) error {
		return rows.Scan(&r.AnchorDigest, &raw, &accepted, &receipt, &epoch, &writer, &deny, &r.Frozen, &r.ProofKind, &r.ProofID, &r.VerifiedAt, &r.Version, &r.BootDigest, &r.CaptureID)
	})
	if err != nil {
		return nil, err
	}
	r.Accepted = securityjournal.UInt63(accepted)
	r.Receipt = securityjournal.UInt63(receipt)
	r.Epoch = securityjournal.UInt63(epoch)
	r.Writer = securityjournal.UInt63(writer)
	r.Deny = securityjournal.UInt63(deny)
	i := a.Installation
	if r.AnchorDigest != hash(a) || decodeCanonical(raw, &r.Active, 16384) != nil || accepted < 0 || receipt < 0 || epoch < int64(i.AuthorityEpoch) || writer < int64(i.WriterEpoch) || deny < int64(i.MinimumDenySequence) || r.Active.Baseline.NodeDeploymentSequence > r.Accepted || r.Accepted < i.Baseline.NodeDeploymentSequence || r.VerifiedAt.IsZero() || r.Version < 1 {
		return nil, ErrUnavailable
	}
	key, e := publicKey(a.ReceiptPublicKey)
	if e != nil {
		return nil, e
	}
	var captureRaw string
	if e = securitystate.One(ctx, tx, `SELECT capture_json FROM execution_baseline_captures WHERE id=? AND node_id=?`, []any{r.CaptureID, node}, func(rows storage.IdentityRows) error { return rows.Scan(&captureRaw) }); e != nil {
		return nil, e
	}
	var lastCapture helper.BaselineCapture
	if decodeCanonical(captureRaw, &lastCapture, 65536) != nil || helper.VerifyBaselineCapture(lastCapture, a.ReceiptKeyID, key) != nil || lastCapture.Query.AnchorDigest != r.AnchorDigest || lastCapture.Query.NodeID != node || lastCapture.BootDigest != r.BootDigest {
		return nil, ErrUnavailable
	}
	var proof, pin string
	var received time.Time
	switch r.ProofKind {
	case "capture":
		e = securitystate.One(ctx, tx, `SELECT capture_json,capture_digest,received_at FROM execution_baseline_captures WHERE id=? AND node_id=?`, []any{r.ProofID, node}, func(rows storage.IdentityRows) error { return rows.Scan(&proof, &pin, &received) })
		if e != nil {
			return nil, e
		}
		var capture helper.BaselineCapture
		if decodeCanonical(proof, &capture, 65536) != nil || hash(capture) != pin || helper.VerifyBaselineCapture(capture, a.ReceiptKeyID, key) != nil || capture.Query.AnchorDigest != r.AnchorDigest || capture.Query.NodeID != node || capture.Active != r.Active || capture.HighWater != r.Accepted || capture.ReceiptSequence != r.Receipt || capture.AuthorityEpoch != r.Epoch || capture.WriterEpoch != r.Writer || capture.MinimumDenySequence != r.Deny {
			return nil, ErrUnavailable
		}
	case "receipt":
		e = securitystate.One(ctx, tx, `SELECT receipt_json,receipt_digest,received_at FROM execution_source_outcomes WHERE receipt_id=? AND node_id=?`, []any{r.ProofID, node}, func(rows storage.IdentityRows) error { return rows.Scan(&proof, &pin, &received) })
		if e != nil {
			return nil, e
		}
		var receipt helper.ExecutionReceipt
		if decodeCanonical(proof, &receipt, 65536) != nil || hash(receipt) != pin || helper.VerifyExecutionReceipt(receipt, a.ReceiptKeyID, key) != nil || receipt.NodeID != node || receipt.Active != r.Active || receipt.NodeDeploymentSequence != r.Accepted || receipt.ReceiptSequence != r.Receipt || receipt.RecoveryRequired && !r.Frozen {
			return nil, ErrUnavailable
		}
	default:
		return nil, ErrUnavailable
	}
	if !received.Equal(r.VerifiedAt) {
		return nil, ErrUnavailable
	}
	return r, nil
}

func insertBaseline(ctx context.Context, tx storage.IdentityTx, node string, r baselineRecord) error {
	raw, e := configmodel.CanonicalJSON(r.Active)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO execution_verified_baselines(node_id,anchor_digest,active_json,accepted_sequence,receipt_sequence,authority_epoch,writer_epoch,deny_sequence,frozen,proof_kind,proof_id,verified_at,boot_digest,capture_id,row_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)`, node, r.AnchorDigest, string(raw), int64(r.Accepted), int64(r.Receipt), int64(r.Epoch), int64(r.Writer), int64(r.Deny), r.Frozen, r.ProofKind, r.ProofID, r.VerifiedAt, r.BootDigest, r.CaptureID)
	return e
}
func updateBaseline(ctx context.Context, tx storage.IdentityTx, node string, old *baselineRecord, next baselineRecord) error {
	raw, e := configmodel.CanonicalJSON(next.Active)
	if e != nil {
		return e
	}
	n, e := tx.Exec(ctx, `UPDATE execution_verified_baselines SET active_json=?,accepted_sequence=?,receipt_sequence=?,authority_epoch=?,writer_epoch=?,deny_sequence=?,frozen=?,proof_kind=?,proof_id=?,verified_at=?,boot_digest=?,capture_id=?,row_version=row_version+1 WHERE node_id=? AND anchor_digest=? AND row_version=?`, string(raw), int64(next.Accepted), int64(next.Receipt), int64(next.Epoch), int64(next.Writer), int64(next.Deny), next.Frozen, next.ProofKind, next.ProofID, next.VerifiedAt, next.BootDigest, next.CaptureID, node, old.AnchorDigest, old.Version)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrStale
	}
	return nil
}

func (s *Service) peer(ctx context.Context, peer *tls.ConnectionState, fn func(storage.IdentityTx, securityjournal.Head, *trustedConfig, string) error) error {
	if s == nil || ctx == nil || peer == nil {
		return storage.ErrPermissionDenied
	}
	return s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		c, e := s.config(ctx)
		if e != nil {
			return e
		}
		node, e := s.inventory.AuthenticateAgent(ctx, tx, h, peer)
		if e != nil {
			return e
		}
		if _, ok := c.bindings[node]; !ok {
			return storage.ErrPermissionDenied
		}
		if e = fn(tx, h, c, node); e != nil {
			return e
		}
		// Registry/config replacement during durable work is not hidden by a
		// keep-alive connection or an earlier callback result.
		fresh, e := s.current.Head(ctx)
		if e != nil || !h.SameState(fresh) {
			return ErrStale
		}
		current, e := s.config(ctx)
		if e != nil || hash(current.config) != hash(c.config) {
			return ErrStale
		}
		again, e := s.inventory.AuthenticateAgent(ctx, tx, fresh, peer)
		if e != nil || again != node {
			return storage.ErrPermissionDenied
		}
		return s.witness(ctx)
	})
}

// ChallengePeer creates a one-use nonce for the authenticated installed node.
// It is not an execution task and cannot cause initialization or activation.
func (s *Service) ChallengePeer(ctx context.Context, peer *tls.ConnectionState) (out *helper.BaselineChallenge, err error) {
	err = s.peer(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, c *trustedConfig, node string) error {
		a := c.bindings[node].Anchor
		if a.Installation.AuthorityID != h.AuthorityID || a.Installation.AuthorityEpoch != h.Epoch {
			return ErrStale
		}
		var nonce [32]byte
		if _, e := rand.Read(nonce[:]); e != nil {
			return ErrUnavailable
		}
		q := helper.BaselineChallenge{APIVersion: helper.BaselineChallengeVersion, ID: securitystate.ID("baseline"), Challenge: base64.RawURLEncoding.EncodeToString(nonce[:]), NodeID: node, AnchorDigest: hash(a), AuthorityID: h.AuthorityID, AuthorityEpoch: h.Epoch, IssuedAt: utc(h.RecordedAt), ExpiresAt: utc(h.RecordedAt.Add(BaselineFreshness))}
		raw, e := configmodel.CanonicalJSON(q)
		if e != nil {
			return e
		}
		head, e := configmodel.CanonicalJSON(h)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO execution_baseline_challenges(id,node_id,anchor_digest,query_json,head_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, q.ID, node, q.AnchorDigest, string(raw), string(head), h.RecordedAt, h.RecordedAt.Add(BaselineFreshness))
		if e == nil {
			out = &q
		}
		return e
	})
	return
}

// CapturePeer can establish only the installed initial baseline, or reconfirm
// the exact already proven receipt chain. A valid but divergent root report
// freezes the node for operator recovery instead of resetting its counters.
func (s *Service) CapturePeer(ctx context.Context, peer *tls.ConnectionState, capture helper.BaselineCapture) error {
	var afterCommit error
	err := s.peer(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, c *trustedConfig, node string) error {
		a := c.bindings[node].Anchor
		key, e := publicKey(a.ReceiptPublicKey)
		if e != nil || helper.VerifyBaselineCapture(capture, a.ReceiptKeyID, key) != nil || capture.Query.NodeID != node || capture.Query.AnchorDigest != hash(a) {
			return storage.ErrPermissionDenied
		}
		var queryRaw, headRaw, used string
		var created, expires time.Time
		e = securitystate.One(ctx, tx, `SELECT query_json,head_json,created_at,expires_at,capture_digest FROM execution_baseline_challenges WHERE id=? AND node_id=? AND anchor_digest=?`, []any{capture.Query.ID, node, hash(a)}, func(r storage.IdentityRows) error { return r.Scan(&queryRaw, &headRaw, &created, &expires, &used) })
		if e != nil {
			return e
		}
		var q helper.BaselineChallenge
		var issuedHead securityjournal.Head
		if decodeCanonical(queryRaw, &q, 16384) != nil || decodeCanonical(headRaw, &issuedHead, 16384) != nil || hash(q) != hash(capture.Query) {
			return ErrCapture
		}
		pin := hash(capture)
		if used != "" {
			if used != pin {
				return ErrStale
			}
			var prior string
			e = securitystate.One(ctx, tx, `SELECT capture_digest FROM execution_baseline_captures WHERE id=? AND node_id=?`, []any{q.ID, node}, func(r storage.IdentityRows) error { return r.Scan(&prior) })
			if e != nil || prior != pin {
				return ErrStale
			}
			return nil
		}
		at, e := parseUTC(capture.RecordedAt)
		if e != nil || h.RecordedAt.Before(created) || !h.RecordedAt.Before(expires) || at.Before(created) || at.After(h.RecordedAt.Add(30*time.Second)) || capture.Query.AuthorityID != h.AuthorityID || capture.Query.AuthorityEpoch != h.Epoch || capture.AuthorityEpoch != h.Epoch || capture.WriterEpoch != c.config.WriterEpoch || capture.Head.AuthorityID != h.AuthorityID || capture.Head.Epoch != h.Epoch || capture.Head.Sequence < issuedHead.Sequence || capture.Head.Sequence > h.Sequence || capture.MinimumDenySequence > capture.Head.Sequence {
			return ErrCapture
		}
		if capture.Head.Sequence == h.Sequence && capture.Head.Digest != h.Digest || capture.Head.Sequence == issuedHead.Sequence && capture.Head.Digest != issuedHead.Digest {
			return ErrCapture
		}
		if e = s.captureInventory(ctx, tx, h, a.Installation, capture.BootDigest); e != nil {
			return e
		}
		old, e := readBaseline(ctx, tx, node, a)
		if e != nil && e != storage.ErrNotFound {
			return e
		}
		known := true
		if old == nil {
			known = capture.Active.Baseline == a.Installation.Baseline && capture.HighWater == a.Installation.Baseline.NodeDeploymentSequence && capture.ReceiptSequence == 0 && capture.AuthorityEpoch == a.Installation.AuthorityEpoch && capture.WriterEpoch == a.Installation.WriterEpoch && capture.MinimumDenySequence >= a.Installation.MinimumDenySequence
		} else {
			known = !old.Frozen && capture.Active == old.Active && capture.HighWater == old.Accepted && capture.ReceiptSequence == old.Receipt && capture.AuthorityEpoch >= old.Epoch && capture.WriterEpoch >= old.Writer && capture.MinimumDenySequence >= old.Deny
		}
		raw, e := configmodel.CanonicalJSON(capture)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO execution_baseline_captures(id,node_id,capture_digest,capture_json,received_at) VALUES(?,?,?,?,?)`, q.ID, node, pin, string(raw), h.RecordedAt); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE execution_baseline_challenges SET capture_digest=? WHERE id=? AND capture_digest=''`, pin, q.ID); e != nil {
			return e
		}
		if !known {
			waiting, e := knownPendingCapture(ctx, tx, capture, old)
			if e != nil {
				return e
			}
			if waiting {
				afterCommit = ErrCapture
				return securitystate.Audit(ctx, tx, "execution.baseline.receipt_pending", node, map[string]any{"challengeId": q.ID})
			}
			// An unknown initial tree cannot create a positive baseline. Existing
			// state is frozen without adopting the divergent generation/counter.
			if _, e = tx.Exec(ctx, `INSERT INTO execution_source_freezes(node_id,anchor_digest,challenge_id,created_at) VALUES(?,?,?,?)`, node, hash(a), q.ID, h.RecordedAt); e != nil {
				return e
			}
			if old != nil && !old.Frozen {
				n, e := tx.Exec(ctx, `UPDATE execution_verified_baselines SET frozen=TRUE,row_version=row_version+1 WHERE node_id=? AND row_version=?`, node, old.Version)
				if e != nil {
					return e
				}
				if n != 1 {
					return ErrStale
				}
			}
			afterCommit = ErrCapture
			return securitystate.Audit(ctx, tx, "execution.baseline.diverged", node, map[string]any{"challengeId": q.ID})
		}
		next := baselineRecord{AnchorDigest: hash(a), Active: capture.Active, Accepted: capture.HighWater, Receipt: capture.ReceiptSequence, Epoch: capture.AuthorityEpoch, Writer: capture.WriterEpoch, Deny: capture.MinimumDenySequence, VerifiedAt: h.RecordedAt, ProofKind: "capture", ProofID: q.ID, BootDigest: capture.BootDigest, CaptureID: q.ID}
		if old == nil {
			e = insertBaseline(ctx, tx, node, next)
		} else {
			e = updateBaseline(ctx, tx, node, old, next)
		}
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "execution.baseline.captured", node, map[string]any{"challengeId": q.ID, "captureDigest": pin})
	})
	if err != nil {
		return err
	}
	return afterCommit
}

func (s *Service) captureInventory(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, i helper.Installation, bootDigest string) error {
	nodes, e := s.inventory.CurrentNodes(ctx, tx, h.Epoch, i.SiteID)
	if e != nil {
		return e
	}
	for _, n := range nodes {
		if n.ID == i.NodeID {
			if n.IdentityDigest != i.IdentityDigest || n.CapabilityDigest != i.CapabilityDigest {
				return ErrStale
			}
			var raw string
			if e = securitystate.One(ctx, tx, `SELECT observation_json FROM fleet_inventory_receipts WHERE id=? AND node_id=?`, []any{n.ReceiptID, n.ID}, func(r storage.IdentityRows) error { return r.Scan(&raw) }); e != nil {
				return e
			}
			var observation inventory.Observation
			if inventory.Decode(strings.NewReader(raw), &observation) != nil || configmodel.DigestBytes([]byte(observation.BootID)) != bootDigest {
				return ErrCapture
			}
			return nil
		}
	}
	return ErrCapture
}

// A root report can race delivery of the terminal outbox. It must wait for
// that exact signed receipt, but an already known task is not an unknown tree.
func knownPendingCapture(ctx context.Context, tx storage.IdentityTx, c helper.BaselineCapture, old *baselineRecord) (bool, error) {
	if old == nil || c.HighWater <= old.Accepted || c.ReceiptSequence != old.Receipt+1 {
		return false, nil
	}
	var requestRaw, targetRaw string
	e := securitystate.One(ctx, tx, `SELECT request_json,target_json FROM execution_tasks WHERE node_id=? AND sequence=? AND state='dispatched'`, []any{c.Query.NodeID, int64(c.HighWater)}, func(r storage.IdentityRows) error { return r.Scan(&requestRaw, &targetRaw) })
	if e == storage.ErrNotFound {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	r, e := decodeRequest(requestRaw)
	if e != nil {
		return false, e
	}
	var t rolloutexecution.TargetSnapshot
	if decodeCanonical(targetRaw, &t, 65536) != nil || t.Baseline != old.Active || t.AcceptedSequence != old.Accepted || r.Task.NodeDeploymentSequence != c.HighWater {
		return false, ErrUnavailable
	}
	if c.Active == old.Active {
		return true, nil
	}
	return c.Active.Baseline.RevisionID == r.Task.Payload.TargetRevisionID && c.Active.Baseline.BundleDigest == r.Task.Payload.BundleDigest && c.Active.Baseline.NodeDeploymentSequence == r.Task.NodeDeploymentSequence && c.Active.GenerationID == r.Task.Payload.DeploymentGeneration && c.Active.TreeDigest == t.TargetTreeDigest, nil
}

func decodeRequest(raw string) (helper.Request, error) {
	var r helper.Request
	e := decodeCanonical(strings.TrimSpace(raw), &r, helper.MaxRequestBytes)
	return r, e
}

func notFrozen(ctx context.Context, tx storage.IdentityTx, node string) error {
	ids, e := securitystate.Strings(ctx, tx, `SELECT node_id FROM execution_source_freezes WHERE node_id=?`, node)
	if e != nil {
		return e
	}
	if len(ids) > 0 {
		return ErrCapture
	}
	return nil
}
