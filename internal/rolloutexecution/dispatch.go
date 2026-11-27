package rolloutexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type storedTask struct {
	request              helper.Request
	target               TargetSnapshot
	state, requestDigest string
	completed            sql.NullTime
}

func readTasks(ctx context.Context, tx storage.IdentityTx, plan string) ([]storedTask, error) {
	rows, err := tx.Query(ctx, `SELECT request_json,target_json,state,request_digest,completed_at FROM execution_tasks WHERE plan_id=? ORDER BY node_id`, plan)
	if err != nil {
		return nil, err
	}
	out := []storedTask{}
	for rows.Next() {
		var raw, target string
		v := storedTask{}
		if err = rows.Scan(&raw, &target, &v.state, &v.requestDigest, &v.completed); err != nil {
			break
		}
		if len(raw) > helper.MaxRequestBytes || len(target) > 65536 || json.Unmarshal([]byte(raw), &v.request) != nil || json.Unmarshal([]byte(target), &v.target) != nil || digest(v.request) != v.requestDigest || v.request.SignedPlan == nil || v.request.Task.PlanID != plan {
			err = ErrUnavailable
			break
		}
		out = append(out, v)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return out, err
}
func readTask(ctx context.Context, tx storage.IdentityTx, query string, args ...any) (*storedTask, error) {
	var raw, target string
	v := &storedTask{}
	err := securitystate.One(ctx, tx, query, args, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &target, &v.state, &v.requestDigest, &v.completed)
	})
	if err != nil {
		return nil, err
	}
	if len(raw) > helper.MaxRequestBytes || len(target) > 65536 || json.Unmarshal([]byte(raw), &v.request) != nil || json.Unmarshal([]byte(target), &v.target) != nil || digest(v.request) != v.requestDigest || v.request.SignedPlan == nil {
		return nil, ErrUnavailable
	}
	return v, nil
}

const taskByDigest = `SELECT request_json,target_json,state,request_digest,completed_at FROM execution_tasks WHERE request_digest=?`
const taskByID = `SELECT request_json,target_json,state,request_digest,completed_at FROM execution_tasks WHERE id=?`

func (o *operation) rollout(p *storedPlan) (*subject, error) {
	var id, fp, hash, permission string
	err := securitystate.One(o.ctx, o.tx, `SELECT dispatcher_id,dispatcher_fingerprint,dispatcher_token_hash,permission FROM execution_rollouts WHERE plan_id=?`, []any{p.view.Plan.ID}, func(r storage.IdentityRows) error { return r.Scan(&id, &fp, &hash, &permission) })
	if err != nil {
		return nil, err
	}
	if permission != dispatchPermission(p.view.Plan.Kind) {
		return nil, ErrUnavailable
	}
	dispatcher, err := o.s.actor(o.ctx, o.tx, o.head, Actor{TokenHash: hash, Origin: o.s.origin}, true)
	if err != nil {
		return nil, err
	}
	if dispatcher.id != id || dispatcher.fingerprint != fp {
		return nil, ErrStale
	}
	if err = o.need(id, permission, p.snapshot.Targets); err != nil {
		return nil, err
	}
	o.expiries = append(o.expiries, dispatcher.mfa.Add(5*time.Minute))
	o.sessions = append(o.sessions, sessionBinding{actor: Actor{TokenHash: hash, Origin: o.s.origin}, id: id, mfa: dispatcher.mfa})
	return dispatcher, nil
}
func sign(v any, purpose string, key ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(purpose+"\n"+digest(v))))
}
func (s *Service) task(p *storedPlan, target TargetSnapshot, approval *Approval, sequence securityjournal.UInt63, h securityjournal.Head, mfa time.Time) (*helper.Request, error) {
	plan := p.view.Plan
	now := h.RecordedAt.UTC()
	expires := now.Add(helper.MaxPermitTTL)
	for _, bound := range []time.Time{parseTime(plan.ExpiresAt), approval.ExpiresAt, mfa.Add(5 * time.Minute)} {
		if bound.Before(expires) {
			expires = bound
		}
	}
	if !expires.After(now) {
		return nil, ErrStale
	}
	i := target.Installation
	task := helper.Task{APIVersion: "agp.task/v1alpha1", ID: securitystate.ID("task"), NodeID: i.NodeID, Kind: plan.Kind, IdempotencyKey: securitystate.ID("execution"), AuthorityEpoch: h.Epoch, WriterEpoch: i.WriterEpoch, NodeDeploymentSequence: sequence, IssuedAt: utc(now), ExpiresAt: utc(expires), PlanID: plan.ID, PlanDigest: plan.PlanDigest, Preconditions: helper.Preconditions{BaseRevisionID: target.Baseline.Baseline.RevisionID, ExpectedNodeDeploymentSequence: target.AcceptedSequence, CapabilityDigest: i.CapabilityDigest}, Payload: helper.Payload{TargetRevisionID: plan.RevisionID, DeploymentGeneration: target.DeploymentGeneration, BundleDigest: target.BundleDigest, SecretVersionIDs: append([]string{}, target.SecretVersionIDs...), MinimumDenySequence: h.Sequence, RecoveryBaseBundleDigest: target.Baseline.Baseline.BundleDigest}}
	taskDigest, err := helper.TaskDigest(task)
	if err != nil {
		return nil, err
	}
	permit := helper.Permit{APIVersion: helper.PermitVersion, KeyID: s.keys.PermitKeyID, TaskDigest: taskDigest, InstallationDigest: digest(i), IdentityDigest: i.IdentityDigest, OwnershipDigest: i.OwnershipDigest, ComponentProfileDigest: i.ComponentProfileDigest, ReleaseManifestDigest: i.ReleaseManifestDigest, TupleDigest: i.TupleDigest, CompilerDigest: i.CompilerDigest, Approval: helper.Approval{SiteID: plan.SiteID, CreatedBy: plan.CreatedBy, ApprovedBy: approval.ApprovedBy, ApprovalDigest: approval.ApprovalDigest}, Recovery: helper.Recovery{BaseRevisionID: target.Baseline.Baseline.RevisionID, BaseBundleDigest: target.Baseline.Baseline.BundleDigest, OwnershipDigest: i.OwnershipDigest, MinimumDenySequence: h.Sequence}}
	permit.Signature = sign(permit, "AGP-HELPER-PERMIT-v1", s.keys.PermitKey)
	task.PermitDigest, err = helper.PermitDigest(permit)
	if err != nil {
		return nil, err
	}
	signed, err := deploymentplan.Sign(plan, s.keys.PermitKeyID, s.keys.PermitKey)
	if err != nil {
		return nil, err
	}
	r := &helper.Request{Task: task, Permit: permit, SignedPlan: signed}
	raw, err := canonical(r)
	if err != nil {
		return nil, err
	}
	if _, err = helper.Decode(bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *Service) Dispatch(ctx context.Context, a Actor, id, key string) (out []helper.Request, err error) {
	if !configmodel.ValidID(id) {
		return nil, ErrInvalid
	}
	ids, err := s.selectParticipants(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = s.transact(ctx, a, ids, true, func(o *operation) error {
		p, e := readPlan(o.ctx, o.tx, id)
		if e != nil {
			return e
		}
		if e = o.planCurrent(p, true); e != nil {
			return e
		}
		if p.view.State != "approved" && p.view.State != "running" {
			return ErrConflict
		}
		permission := dispatchPermission(p.view.Plan.Kind)
		if e = o.need(o.actor.id, permission, p.snapshot.Targets); e != nil {
			return e
		}
		fp := digest([]string{id, p.view.Plan.PlanDigest})
		saved, e := request(o.ctx, o.tx, o.actor.id, "dispatch", key, fp)
		if e != nil {
			return e
		}
		if saved != "" {
			task, e := readTask(o.ctx, o.tx, taskByID, saved)
			if e != nil {
				return e
			}
			if task.state != "dispatched" {
				return ErrStale
			}
			if e = o.target(task.target); e != nil {
				return e
			}
			if _, e = o.rollout(p); e != nil {
				return e
			}
			o.expiries = append(o.expiries, parseTime(task.request.Task.ExpiresAt))
			out = []helper.Request{task.request}
			return nil
		}
		var dispatcher, hash string
		e = securitystate.One(o.ctx, o.tx, `SELECT dispatcher_id,dispatcher_token_hash FROM execution_rollouts WHERE plan_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&dispatcher, &hash) })
		if e == storage.ErrNotFound {
			_, e = o.tx.Exec(o.ctx, `INSERT INTO execution_rollouts(plan_id,dispatcher_id,dispatcher_fingerprint,dispatcher_token_hash,permission,created_at) VALUES(?,?,?,?,?,?)`, id, o.actor.id, o.actor.fingerprint, a.TokenHash, permission, o.head.RecordedAt)
		} else if e == nil {
			if dispatcher != o.actor.id || hash != a.TokenHash {
				return ErrConflict
			}
			_, e = o.rollout(p)
		}
		if e != nil {
			return e
		}
		tasks, e := readTasks(o.ctx, o.tx, id)
		if e != nil {
			return e
		}
		done := map[string]bool{}
		for _, task := range tasks {
			if task.state != "succeeded" || !task.completed.Valid {
				return ErrConflict
			}
			if o.head.RecordedAt.Before(task.completed.Time.Add(time.Duration(p.view.Plan.RolloutPolicy.ObservationSeconds) * time.Second)) {
				return ErrStale
			}
			done[task.request.Task.NodeID] = true
		}
		ordered := append([]TargetSnapshot{}, p.snapshot.Targets...)
		canary := map[string]bool{}
		for _, node := range p.view.Plan.RolloutPolicy.CanaryNodeIDs {
			canary[node] = true
		}
		sort.SliceStable(ordered, func(i, j int) bool {
			a, b := canary[ordered[i].Installation.NodeID], canary[ordered[j].Installation.NodeID]
			if a != b {
				return a
			}
			return ordered[i].Installation.NodeID < ordered[j].Installation.NodeID
		})
		var next *TargetSnapshot
		for i := range ordered {
			if !done[ordered[i].Installation.NodeID] {
				next = &ordered[i]
				break
			}
		}
		if next == nil {
			return ErrConflict
		}
		if e = o.target(*next); e != nil {
			return e
		}
		node := next.Installation.NodeID
		var active int64
		if e = securitystate.One(o.ctx, o.tx, `SELECT COUNT(*) FROM execution_tasks WHERE node_id=? AND state IN ('dispatched','recovery_required')`, []any{node}, func(r storage.IdentityRows) error { return r.Scan(&active) }); e != nil {
			return e
		}
		if active != 0 {
			return ErrConflict
		}
		base := next.AcceptedSequence
		if _, e = o.tx.Exec(o.ctx, `INSERT INTO execution_node_counters(node_id,allocated_sequence,accepted_sequence) VALUES(?,?,?) ON CONFLICT(node_id) DO NOTHING`, node, int64(base), int64(base)); e != nil {
			return e
		}
		var allocated, accepted int64
		if e = securitystate.One(o.ctx, o.tx, `SELECT allocated_sequence,accepted_sequence FROM execution_node_counters WHERE node_id=?`, []any{node}, func(r storage.IdentityRows) error { return r.Scan(&allocated, &accepted) }); e != nil {
			return e
		}
		if allocated < 0 || accepted < 0 || uint64(accepted) > uint64(base) {
			return ErrStale
		}
		if uint64(allocated) < uint64(base) {
			allocated = int64(base)
		}
		if uint64(accepted) < uint64(base) {
			accepted = int64(base)
		}
		if uint64(allocated) >= uint64(securityjournal.MaxUInt63) {
			return ErrUnavailable
		}
		sequence := allocated + 1
		if _, e = o.tx.Exec(o.ctx, `UPDATE execution_node_counters SET allocated_sequence=?,accepted_sequence=? WHERE node_id=?`, sequence, accepted, node); e != nil {
			return e
		}
		r, e := s.task(p, *next, p.view.Approval, securityjournal.UInt63(sequence), o.head, o.actor.mfa)
		if e != nil {
			return e
		}
		raw, _ := canonical(r)
		targetRaw, _ := canonical(next)
		_, e = o.tx.Exec(o.ctx, `INSERT INTO execution_tasks(id,plan_id,node_id,sequence,request_digest,request_json,target_json,state,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,'dispatched',?,?)`, r.Task.ID, id, node, sequence, digest(r), string(raw), string(targetRaw), o.head.RecordedAt, parseTime(r.Task.ExpiresAt))
		if e != nil {
			return e
		}
		if _, e = o.tx.Exec(o.ctx, `UPDATE execution_plans SET state='running' WHERE id=? AND state IN ('approved','running')`, id); e != nil {
			return e
		}
		if e = remember(o.ctx, o.tx, o.actor.id, "dispatch", key, fp, r.Task.ID, o.head.RecordedAt); e != nil {
			return e
		}
		if e = audit(o.ctx, o.tx, "execution.task.dispatched", o.actor.id, id); e != nil {
			return e
		}
		o.expiries = append(o.expiries, parseTime(r.Task.ExpiresAt))
		out = []helper.Request{*r}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) Cancel(ctx context.Context, a Actor, id, key string) error {
	if !configmodel.ValidID(id) {
		return ErrInvalid
	}
	ids, err := s.selectParticipants(ctx, a, id)
	if err != nil {
		return err
	}
	return s.transact(ctx, a, ids, true, func(o *operation) error {
		p, e := readPlan(o.ctx, o.tx, id)
		if e != nil {
			return e
		}
		if e = o.need(o.actor.id, "rollouts.cancel", p.snapshot.Targets); e != nil {
			return e
		}
		fp := digest([]string{id, p.view.Plan.PlanDigest})
		saved, e := request(o.ctx, o.tx, o.actor.id, "cancel", key, fp)
		if e != nil {
			return e
		}
		if saved != "" {
			return nil
		}
		if p.view.State != "validated" && p.view.State != "approved" && p.view.State != "running" {
			return ErrConflict
		}
		if _, e = o.tx.Exec(o.ctx, `UPDATE execution_plans SET state='cancelled' WHERE id=?`, id); e != nil {
			return e
		}
		if e = remember(o.ctx, o.tx, o.actor.id, "cancel", key, fp, id, o.head.RecordedAt); e != nil {
			return e
		}
		return audit(o.ctx, o.tx, "execution.plan.cancelled", o.actor.id, id)
	})
}

func (s *Service) peerParticipants(ctx context.Context, peer *tls.ConnectionState, requestDigest string) ([]string, string, error) {
	if s == nil || s.agents == nil || peer == nil || !configmodel.ValidDigest(requestDigest) {
		return nil, "", ErrInvalid
	}
	var ids []string
	var hash string
	err := s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		node, e := s.agents(ctx, tx, h, peer)
		if e != nil {
			return e
		}
		task, e := readTask(ctx, tx, taskByDigest, requestDigest)
		if e != nil {
			return e
		}
		if task.request.Task.NodeID != node {
			return storage.ErrPermissionDenied
		}
		p, e := readPlan(ctx, tx, task.request.Task.PlanID)
		if e != nil {
			return e
		}
		ids = p.participants()
		approval, _, e := readApproval(ctx, tx, p.view.Plan.ID)
		if e != nil {
			return e
		}
		ids = append(ids, approval.ApprovedBy)
		var dispatcher string
		e = securitystate.One(ctx, tx, `SELECT dispatcher_id,dispatcher_token_hash FROM execution_rollouts WHERE plan_id=?`, []any{p.view.Plan.ID}, func(r storage.IdentityRows) error { return r.Scan(&dispatcher, &hash) })
		ids = append(ids, dispatcher)
		return e
	})
	return ids, hash, err
}
func (s *Service) AuthorizeStartPeer(ctx context.Context, peer *tls.ConnectionState, q helper.StartQuery) (out *helper.StartProof, err error) {
	if q.APIVersion != helper.StartVersion || !requestKey.MatchString(q.Challenge) || !configmodel.ValidDigest(q.InstallationDigest) {
		return nil, ErrInvalid
	}
	ids, hash, err := s.peerParticipants(ctx, peer, q.RequestDigest)
	if err != nil {
		return nil, err
	}
	err = securitystate.WithManagementSession(ctx, hash, s.current, func(authenticated context.Context) error {
		return s.peerOperation(authenticated, peer, ids, func(o *operation, node string) error {
			if q.Head.AuthorityID != o.head.AuthorityID || q.Head.Epoch != o.head.Epoch || q.Head.Sequence != o.head.Sequence || q.Head.Digest != o.head.Digest {
				return ErrStale
			}
			task, e := readTask(o.ctx, o.tx, taskByDigest, q.RequestDigest)
			if e != nil {
				return e
			}
			if task.state != "dispatched" || task.request.Task.NodeID != node || task.request.Permit.InstallationDigest != q.InstallationDigest {
				return ErrStale
			}
			p, e := readPlan(o.ctx, o.tx, task.request.Task.PlanID)
			if e != nil {
				return e
			}
			if p.view.State != "running" {
				return ErrStale
			}
			if e = o.planCurrent(p, true); e != nil {
				return e
			}
			dispatcher, e := o.rollout(p)
			if e != nil {
				return e
			}
			if e = o.target(task.target); e != nil {
				return e
			}
			if e = deploymentplan.Verify(*task.request.SignedPlan, s.keys.PermitKeyID, s.keys.PermitKey.Public().(ed25519.PublicKey), o.head.RecordedAt); e != nil {
				return e
			}
			expires := o.head.RecordedAt.Add(helper.MaxStartTTL)
			for _, bound := range []time.Time{parseTime(task.request.Task.ExpiresAt), p.view.Approval.ExpiresAt, dispatcher.mfa.Add(5 * time.Minute)} {
				if bound.Before(expires) {
					expires = bound
				}
			}
			proof := helper.StartProof{Query: q, KeyID: s.keys.ControlKeyID, WriterEpoch: task.request.Task.WriterEpoch, CheckedAt: utc(o.head.RecordedAt), ExpiresAt: utc(expires)}
			proof.Signature = sign(proof, "AGP-HELPER-START-v1", s.keys.ControlKey)
			o.expiries = append(o.expiries, expires)
			out = &proof
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Delivery does not authorize execution: the helper must obtain a new StartProof.
func (s *Service) PendingForPeer(ctx context.Context, peer *tls.ConnectionState) (out []helper.Request, err error) {
	out = []helper.Request{}
	err = s.peerOperation(ctx, peer, nil, func(o *operation, node string) error {
		if e := checkNode(o.ctx, o.tx, node); e != nil {
			return e
		}
		rows, e := o.tx.Query(o.ctx, `SELECT t.request_json,t.request_digest FROM execution_tasks t JOIN execution_plans p ON p.id=t.plan_id WHERE t.node_id=? AND t.state='dispatched' AND p.state='running' AND p.authority_epoch=? AND t.expires_at>? ORDER BY t.sequence LIMIT 2`, node, int64(o.head.Epoch), o.head.RecordedAt)
		if e != nil {
			return e
		}
		for rows.Next() {
			var raw, pin string
			if e = rows.Scan(&raw, &pin); e != nil {
				break
			}
			var r helper.Request
			if len(raw) > helper.MaxRequestBytes || json.Unmarshal([]byte(raw), &r) != nil || digest(r) != pin || r.Task.NodeID != node {
				e = ErrUnavailable
				break
			}
			out = append(out, r)
			o.expiries = append(o.expiries, parseTime(r.Task.ExpiresAt))
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if len(out) > 1 {
			return ErrUnavailable
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
