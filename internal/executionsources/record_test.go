package executionsources

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (f *fixture) saveTask(id string, sequence helper.UInt63, target rolloutexecution.TargetSnapshot) helper.Request {
	f.t.Helper()
	ctx := context.Background()
	r := helper.Request{Task: helper.Task{APIVersion: "agp.task/v1alpha1", ID: id, NodeID: "node_one", Kind: "apply_config", AuthorityEpoch: 1, WriterEpoch: 1, NodeDeploymentSequence: sequence, IssuedAt: utc(f.now), ExpiresAt: utc(f.now.Add(time.Minute)), Preconditions: helper.Preconditions{BaseRevisionID: target.Baseline.Baseline.RevisionID, ExpectedNodeDeploymentSequence: target.AcceptedSequence}, Payload: helper.Payload{TargetRevisionID: "revision_target", BundleDigest: target.BundleDigest, DeploymentGeneration: target.DeploymentGeneration, RecoveryBaseBundleDigest: target.Baseline.Baseline.BundleDigest, SecretVersionIDs: target.SecretVersionIDs}}, Permit: helper.Permit{InstallationDigest: hash(target.Installation)}}
	raw, _ := configmodel.CanonicalJSON(r)
	traw, _ := configmodel.CanonicalJSON(target)
	f.mustTx(func(tx storage.IdentityTx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO execution_plans(id,plan_digest,plan_json,snapshot_json,creator_fingerprint,authority_epoch,created_at,expires_at,state) VALUES(?,?,'{}','{}','fixture',1,?,?,'cancelled')`, "plan_"+id, hash("plan_"+id), f.now, f.now.Add(time.Minute)); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO execution_tasks(id,plan_id,node_id,sequence,request_digest,request_json,target_json,state,issued_at,expires_at) VALUES(?,?,'node_one',?,?,?,?,'dispatched',?,?)`, id, "plan_"+id, int64(sequence), hash(r), string(raw), string(traw), f.now, f.now.Add(time.Minute))
		return e
	})
	return r
}
func (f *fixture) receipt(id string, request helper.Request, receiptSequence helper.UInt63, state string, active helper.ExecutionGeneration) helper.ExecutionReceipt {
	r := helper.ExecutionReceipt{APIVersion: helper.ExecutionReceiptVersion, Purpose: "local_execution_outcome", ReceiptID: id, ReceiptSequence: receiptSequence, NodeID: "node_one", TaskID: request.Task.ID, RequestDigest: hash(request), NodeDeploymentSequence: request.Task.NodeDeploymentSequence, Active: active, State: state, RecoveryRequired: state == "recovery_required", RecordedAt: utc(f.now.Add(30 * time.Second)), KeyID: "root_receipt"}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.rootKey, []byte("AGP-HELPER-EXECUTION-RECEIPT-v1\n"+hash(r))))
	return r
}
func (f *fixture) record(target rolloutexecution.TargetSnapshot, r helper.ExecutionReceipt) error {
	return f.tx(func(tx storage.IdentityTx) error {
		return f.service.Record(context.Background(), tx, f.current.head, target, r)
	})
}

func TestSourceOutcomesSQLite(t *testing.T)   { testSourceOutcomes(t, false) }
func TestSourceOutcomesPostgres(t *testing.T) { testSourceOutcomes(t, true) }
func testSourceOutcomes(t *testing.T, pg bool) {
	f := newFixture(t, pg)
	ctx := context.Background()
	if _, e := f.capture(f.baseline, 1, 0); e != nil {
		t.Fatal(e)
	}
	f.qualify()
	snapshot, e := f.resolve()
	if e != nil {
		t.Fatal(e)
	}
	target := snapshot.Targets[0]
	request := f.saveTask("task_success", 2, target)
	active := helper.ExecutionGeneration{Baseline: helper.Baseline{RevisionID: "revision_target", BundleDigest: target.BundleDigest, NodeDeploymentSequence: 2}, GenerationID: target.DeploymentGeneration, TreeDigest: target.TargetTreeDigest}
	r := f.receipt("receipt_success", request, 1, "succeeded", active)
	if _, e = f.capture(active, 2, 1); e == nil {
		t.Fatal("capture replaced missing receipt chain")
	}
	f.mustTx(func(tx storage.IdentityTx) error {
		var n int64
		if e := securitystate.One(ctx, tx, `SELECT COUNT(*) FROM execution_source_freezes`, nil, func(r storage.IdentityRows) error { return r.Scan(&n) }); e != nil {
			return e
		}
		if n != 0 {
			t.Fatal("known in-flight task was frozen")
		}
		return nil
	})
	for _, mutate := range []func(*helper.ExecutionReceipt){func(r *helper.ExecutionReceipt) { r.Active.TreeDigest = hash("other") }, func(r *helper.ExecutionReceipt) { r.RequestDigest = hash("another request") }, func(r *helper.ExecutionReceipt) { r.Active.Baseline.NodeDeploymentSequence = 1 }, func(r *helper.ExecutionReceipt) { r.ReceiptSequence = 3 }} {
		bad := r
		mutate(&bad)
		bad.Signature = ""
		bad.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.rootKey, []byte("AGP-HELPER-EXECUTION-RECEIPT-v1\n"+hash(bad))))
		if e = f.record(target, bad); e == nil {
			t.Fatal("signed but unbound outcome changed baseline")
		}
	}
	// Expired qualification and a cancelled plan must not erase a real result.
	f.current.head.RecordedAt = f.now.Add(2 * time.Hour)
	keys := f.cfg.QualificationKeys
	f.cfg.QualificationKeys = map[string]string{}
	if e = f.record(target, r); e != nil {
		t.Fatal("late cancelled/expired outcome", e)
	}
	f.cfg.QualificationKeys = keys
	if e = f.record(target, r); e != nil {
		t.Fatal("exact outcome replay", e)
	}
	f.mustTx(func(tx storage.IdentityTx) error {
		b, e := readBaseline(ctx, tx, "node_one", f.cfg.Bindings[0].Anchor)
		if e != nil {
			return e
		}
		if b.Active != active || b.Accepted != 2 || b.Receipt != 1 {
			t.Fatal("wrong promoted baseline", b)
		}
		return nil
	})
	// Refresh time/evidence for the next operation. The saved source snapshot
	// now binds the proven target as base and cannot replay the old sequence.
	next := target
	next.Baseline = active
	next.AcceptedSequence = 2
	// Mark prior task terminal as the rollout service would do in the same TX.
	f.mustTx(func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `UPDATE execution_tasks SET state='succeeded',completed_at=? WHERE id='task_success'`, f.current.head.RecordedAt)
		return e
	})
	request2 := f.saveTask("task_recovered", 3, next)
	f.current.head.RecordedAt = f.now.Add(3 * time.Hour)
	recovered := f.receipt("receipt_recovered", request2, 2, "recovered", active)
	if e = f.record(next, recovered); e != nil {
		t.Fatal("exact base recovery result", e)
	}
	f.mustTx(func(tx storage.IdentityTx) error {
		b, e := readBaseline(ctx, tx, "node_one", f.cfg.Bindings[0].Anchor)
		if e != nil {
			return e
		}
		if b.Active != active || b.Accepted != 3 || b.Active.Baseline.NodeDeploymentSequence != 2 || b.Receipt != 2 {
			t.Fatal("failed acceptance lowered highwater or promoted failed target", b)
		}
		return nil
	})
	for _, q := range []string{`DELETE FROM execution_source_outcomes`, `UPDATE execution_source_outcomes SET receipt_digest='forged'`, `UPDATE execution_verified_baselines SET receipt_sequence=0,row_version=row_version+1`, `UPDATE execution_verified_baselines SET verified_at=?,row_version=row_version+1`} {
		e = f.tx(func(tx storage.IdentityTx) error {
			var e error
			if strings.Contains(q, "?") {
				_, e = tx.Exec(ctx, q, f.now)
			} else {
				_, e = tx.Exec(ctx, q)
			}
			return e
		})
		if e == nil {
			t.Fatal("outcome SQL guard missing", q)
		}
	}
}

func TestUnknownInitialCaptureCannotBeResetSQLite(t *testing.T)   { testUnknownInitialCapture(t, false) }
func TestUnknownInitialCaptureCannotBeResetPostgres(t *testing.T) { testUnknownInitialCapture(t, true) }
func testUnknownInitialCapture(t *testing.T, pg bool) {
	f := newFixture(t, pg)
	unknown := f.baseline
	unknown.Baseline.RevisionID = "unknown_revision"
	if _, e := f.capture(unknown, 1, 0); e == nil {
		t.Fatal("unknown initial baseline admitted")
	}
	if _, e := f.capture(f.baseline, 1, 0); e == nil {
		t.Fatal("initial unknown runtime was reset by a new capture")
	}
}
