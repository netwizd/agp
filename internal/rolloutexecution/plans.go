package rolloutexecution

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func verifyPlan(p deploymentplan.Plan) error { return deploymentplan.VerifyDigest(p) }
func creationPermission(kind string) string {
	if kind == "rollback_config" {
		return "rollouts.rollback"
	}
	return "config.edit"
}
func dispatchPermission(kind string) string {
	if kind == "rollback_config" {
		return "rollouts.rollback"
	}
	return "rollouts.create"
}
func selection(in Create, kind string) (Selection, error) {
	if !configmodel.ValidID(in.SiteID) || !configmodel.ValidID(in.RevisionID) || len(in.NodeIDs) < 1 || len(in.NodeIDs) > 500 || len(unique(in.NodeIDs)) != len(in.NodeIDs) {
		return Selection{}, ErrInvalid
	}
	for _, id := range in.NodeIDs {
		if !configmodel.ValidID(id) {
			return Selection{}, ErrInvalid
		}
	}
	if deploymentplan.ValidateRollout(in.Policy, in.NodeIDs) != nil {
		return Selection{}, ErrInvalid
	}
	if in.Policy.MaxParallel != 1 || in.Policy.MaxUnavailable != 1 || in.Policy.FailureAction != "pause" {
		return Selection{}, ErrUnsupported
	}
	return Selection{Kind: kind, SiteID: in.SiteID, RevisionID: in.RevisionID, NodeIDs: unique(in.NodeIDs)}, nil
}
func normalizeSnapshot(v *Snapshot, selected Selection, h securityjournal.Head) (*Snapshot, error) {
	if v == nil {
		return nil, ErrUnavailable
	}
	raw, err := canonical(v)
	if err != nil || len(raw) > 4194304 {
		return nil, ErrUnavailable
	}
	var out Snapshot
	if json.Unmarshal(raw, &out) != nil || len(out.Targets) != len(selected.NodeIDs) || len(out.Authors) < 1 || len(out.Authors) > 128 {
		return nil, ErrUnavailable
	}
	for _, id := range out.Authors {
		if !configmodel.ValidID(id) {
			return nil, ErrUnavailable
		}
	}
	out.Authors = unique(out.Authors)
	sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].Installation.NodeID < out.Targets[j].Installation.NodeID })
	for n := range out.Targets {
		t := &out.Targets[n]
		i := t.Installation
		if i.NodeID != selected.NodeIDs[n] || i.SiteID != selected.SiteID || i.AuthorityID != h.AuthorityID || i.AuthorityEpoch != h.Epoch || i.WriterEpoch == 0 || i.WriterEpoch > securityjournal.MaxUInt63 || i.MinimumDenySequence > h.Sequence || t.AcceptedSequence >= securityjournal.MaxUInt63 || i.APIVersion != "agp.helper-installation/v1alpha1" || !configmodel.ValidID(i.Baseline.RevisionID) || !configmodel.ValidID(t.Baseline.Baseline.RevisionID) || !configmodel.ValidID(t.Baseline.GenerationID) || t.Baseline.Baseline.NodeDeploymentSequence > t.AcceptedSequence || i.Baseline.NodeDeploymentSequence > t.AcceptedSequence || !configmodel.ValidID(t.DeploymentGeneration) || t.NodeGroupIDs == nil || len(t.NodeGroupIDs) > 100 || t.SecretVersionIDs == nil || len(t.SecretVersionIDs) > 100 {
			return nil, ErrUnavailable
		}
		for _, d := range []string{i.IdentityDigest, i.OwnershipDigest, i.CapabilityDigest, i.ComponentProfileDigest, i.ReleaseManifestDigest, i.TupleDigest, i.CompilerDigest, i.TrustDigest, i.Baseline.BundleDigest, t.Baseline.Baseline.BundleDigest, t.Baseline.TreeDigest, t.BundleDigest, t.TargetTreeDigest, t.SourceDigest} {
			if !configmodel.ValidDigest(d) {
				return nil, ErrUnavailable
			}
		}
		for _, list := range [][]string{t.NodeGroupIDs, t.SecretVersionIDs} {
			if len(unique(list)) != len(list) {
				return nil, ErrUnavailable
			}
			for _, id := range list {
				if !configmodel.ValidID(id) {
					return nil, ErrUnavailable
				}
			}
		}
		t.NodeGroupIDs = unique(t.NodeGroupIDs)
		t.SecretVersionIDs = unique(t.SecretVersionIDs)
		profile := false
		for _, input := range out.ResolvedInputs {
			if input.Kind == "component_profile" && input.Digest == i.ComponentProfileDigest {
				profile = true
			}
		}
		if !profile {
			return nil, ErrUnavailable
		}
	}
	sort.Slice(out.ResolvedInputs, func(i, j int) bool {
		return out.ResolvedInputs[i].Kind+"/"+out.ResolvedInputs[i].ID < out.ResolvedInputs[j].Kind+"/"+out.ResolvedInputs[j].ID
	})
	return &out, nil
}
func (s *Service) Create(ctx context.Context, a Actor, key string, in Create) (*ExecutionPlan, error) {
	return s.create(ctx, a, key, "apply_config", "", in)
}
func (s *Service) Rollback(ctx context.Context, a Actor, key, previous string, in Create) (*ExecutionPlan, error) {
	if !configmodel.ValidID(previous) {
		return nil, ErrInvalid
	}
	return s.create(ctx, a, key, "rollback_config", previous, in)
}
func (s *Service) create(ctx context.Context, a Actor, key, kind, parent string, in Create) (out *ExecutionPlan, err error) {
	selected, err := selection(in, kind)
	if err != nil {
		return nil, err
	}
	if !requestKey.MatchString(key) {
		return nil, ErrInvalid
	}
	var candidate *Snapshot
	// Source selection is read-only. Directory refresh then occurs outside the
	// writer, before a single final mutation callback repeats exact source pins.
	err = s.transact(ctx, a, nil, true, func(o *operation) error {
		v, e := s.sources.Resolve(o.ctx, o.tx, o.head, selected)
		if e != nil {
			return e
		}
		candidate, e = normalizeSnapshot(v, selected, o.head)
		if e != nil {
			return e
		}
		if e = o.need(o.actor.id, creationPermission(kind), candidate.Targets); e != nil {
			return e
		}
		return o.need(o.actor.id, "config.read", candidate.Targets)
	})
	if err != nil {
		return nil, err
	}
	fp := digest([]any{"execution.create/v1", kind, parent, in})
	err = s.transact(ctx, a, candidate.Authors, true, func(o *operation) error {
		v, e := s.sources.Resolve(o.ctx, o.tx, o.head, selected)
		if e != nil {
			return e
		}
		frozen, e := normalizeSnapshot(v, selected, o.head)
		if e != nil {
			return e
		}
		if digest(frozen) != digest(candidate) {
			return ErrStale
		}
		if e = o.need(o.actor.id, creationPermission(kind), frozen.Targets); e != nil {
			return e
		}
		if e = o.need(o.actor.id, "config.read", frozen.Targets); e != nil {
			return e
		}
		if parent != "" {
			prior, e := readPlan(o.ctx, o.tx, parent)
			if e != nil {
				return e
			}
			if prior.view.Approval == nil {
				approval, _, e := readApproval(o.ctx, o.tx, parent)
				if e != nil {
					return e
				}
				prior.view.Approval = approval
			}
			if prior.view.Plan.SiteID != in.SiteID {
				return ErrInvalid
			}
			for _, target := range frozen.Targets {
				found := false
				for _, previous := range prior.view.Plan.Targets {
					if previous.NodeID == target.Installation.NodeID && previous.BaseRevisionID == in.RevisionID && previous.BaseBundleDigest == target.BundleDigest {
						found = true
					}
				}
				if !found {
					return ErrStale
				}
			}
		}
		saved, e := request(o.ctx, o.tx, o.actor.id, "create", key, fp)
		if e != nil {
			return e
		}
		if saved != "" {
			p, e := readPlan(o.ctx, o.tx, saved)
			if e != nil {
				return e
			}
			if e = o.planCurrent(p, false); e != nil {
				return e
			}
			out = &p.view
			return nil
		}
		now := o.head.RecordedAt.UTC()
		if !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(MaxPlanTTL)) {
			return ErrInvalid
		}
		p := deploymentplan.Plan{APIVersion: deploymentplan.Version1, ID: securitystate.ID("plan"), Kind: kind, SiteID: in.SiteID, RevisionID: in.RevisionID, CreatedBy: o.actor.id, CreatedAt: utc(now), ExpiresAt: utc(in.ExpiresAt), Targets: []deploymentplan.Target{}, RolloutPolicy: in.Policy, CompilerVersion: frozen.CompilerVersion, MinimumDenySequence: o.head.Sequence, Reason: in.Reason, ResolvedInputs: append([]deploymentplan.ResolvedInput{}, frozen.ResolvedInputs...), AuthorityEpoch: o.head.Epoch}
		p.ResolvedInputs = append(p.ResolvedInputs, deploymentplan.ResolvedInput{Kind: "assignment_resolution", ID: "execution_sources", Digest: digest(frozen)})
		for _, target := range frozen.Targets {
			if e = o.target(target); e != nil {
				return e
			}
			i := target.Installation
			p.Targets = append(p.Targets, deploymentplan.Target{NodeID: i.NodeID, BaseRevisionID: target.Baseline.Baseline.RevisionID, ExpectedNodeDeploymentSequence: target.AcceptedSequence, CapabilityDigest: i.CapabilityDigest, BundleDigest: target.BundleDigest, SecretVersionIDs: target.SecretVersionIDs, BaseBundleDigest: target.Baseline.Baseline.BundleDigest})
		}
		normalized, e := deploymentplan.Normalize(p)
		if e != nil {
			return e
		}
		planRaw, e := canonical(normalized)
		if e != nil {
			return e
		}
		snapshotRaw, e := canonical(frozen)
		if e != nil {
			return e
		}
		var parentValue any
		if parent != "" {
			parentValue = parent
		}
		_, e = o.tx.Exec(o.ctx, `INSERT INTO execution_plans(id,plan_digest,plan_json,snapshot_json,creator_fingerprint,parent_plan_id,authority_epoch,created_at,expires_at,state) VALUES(?,?,?,?,?,?,?,?,?,'validated')`, normalized.ID, normalized.PlanDigest, string(planRaw), string(snapshotRaw), o.actor.fingerprint, parentValue, int64(o.head.Epoch), now, in.ExpiresAt.UTC())
		if e != nil {
			return e
		}
		if e = remember(o.ctx, o.tx, o.actor.id, "create", key, fp, normalized.ID, now); e != nil {
			return e
		}
		if e = audit(o.ctx, o.tx, "execution.plan.created", o.actor.id, normalized.ID); e != nil {
			return e
		}
		o.expiries = append(o.expiries, in.ExpiresAt)
		out = &ExecutionPlan{Plan: *normalized, State: "validated", ParentPlanID: parent, Tasks: []TaskView{}, Current: true}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func readApproval(ctx context.Context, tx storage.IdentityTx, id string) (*Approval, map[string]string, error) {
	var raw, participants, pin string
	err := securitystate.One(ctx, tx, `SELECT approval_json,participants_json,approval_digest FROM execution_approvals WHERE plan_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw, &participants, &pin) })
	if err != nil {
		return nil, nil, err
	}
	var a Approval
	var people map[string]string
	if len(raw) > 65536 || len(participants) > 131072 || json.Unmarshal([]byte(raw), &a) != nil || json.Unmarshal([]byte(participants), &people) != nil || a.PlanID != id || a.ApprovalDigest != pin || len(people) < 2 || len(people) > 130 {
		return nil, nil, ErrUnavailable
	}
	copy := a
	copy.ApprovalDigest = ""
	if digest([]any{"execution.approval/v1", copy, people}) != pin {
		return nil, nil, ErrUnavailable
	}
	return &a, people, nil
}
func (o *operation) planCurrent(p *storedPlan, approved bool) error {
	plan := p.view.Plan
	if plan.AuthorityEpoch != o.head.Epoch || !o.head.RecordedAt.Before(parseTime(plan.ExpiresAt)) || plan.MinimumDenySequence > o.head.Sequence {
		return ErrStale
	}
	o.expiries = append(o.expiries, parseTime(plan.ExpiresAt))
	for _, id := range p.participants() {
		permission := "config.edit"
		if id == plan.CreatedBy {
			permission = creationPermission(plan.Kind)
		}
		if err := o.need(id, permission, p.snapshot.Targets); err != nil {
			return err
		}
	}
	creator, err := o.person(plan.CreatedBy)
	if err != nil {
		return err
	}
	if creator.fingerprint != p.creatorFingerprint {
		return ErrStale
	}
	if !approved {
		return nil
	}
	a, people, err := readApproval(o.ctx, o.tx, plan.ID)
	if err != nil {
		return err
	}
	if a.PlanDigest != plan.PlanDigest || !o.head.RecordedAt.Before(a.ExpiresAt) {
		return ErrStale
	}
	for id, fp := range people {
		person, err := o.person(id)
		if err != nil {
			return err
		}
		if person.fingerprint != fp {
			return ErrStale
		}
	}
	if err = o.need(a.ApprovedBy, "config.approve", p.snapshot.Targets); err != nil {
		return err
	}
	for _, id := range p.participants() {
		if err = identity.RequireDistinctPeople(o.ctx, o.tx, a.ApprovedBy, id); err != nil {
			return err
		}
	}
	o.expiries = append(o.expiries, a.ExpiresAt)
	p.view.Approval = a
	return nil
}
func (s *Service) Approve(ctx context.Context, a Actor, id, key, expected string) (out *Approval, err error) {
	if !configmodel.ValidID(id) || !configmodel.ValidDigest(expected) {
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
		if p.view.Plan.PlanDigest != expected {
			return ErrConflict
		}
		if e = o.planCurrent(p, false); e != nil {
			return e
		}
		if e = o.need(o.actor.id, "config.approve", p.snapshot.Targets); e != nil {
			return e
		}
		people := map[string]string{}
		for _, person := range p.participants() {
			if e = identity.RequireDistinctPeople(o.ctx, o.tx, o.actor.id, person); e != nil {
				return e
			}
			v, e := o.person(person)
			if e != nil {
				return e
			}
			people[person] = v.fingerprint
		}
		people[o.actor.id] = o.actor.fingerprint
		for _, t := range p.snapshot.Targets {
			if e = o.target(t); e != nil {
				return e
			}
		}
		fp := digest([]string{id, expected})
		saved, e := request(o.ctx, o.tx, o.actor.id, "approve", key, fp)
		if e != nil {
			return e
		}
		if saved != "" {
			approval, _, e := readApproval(o.ctx, o.tx, id)
			if e != nil {
				return e
			}
			if e = o.planCurrent(p, true); e != nil {
				return e
			}
			out = approval
			return nil
		}
		if p.view.State != "validated" {
			return ErrConflict
		}
		expires := parseTime(p.view.Plan.ExpiresAt)
		if mfa := o.actor.mfa.Add(5 * time.Minute); mfa.Before(expires) {
			expires = mfa
		}
		approval := Approval{ID: securitystate.ID("approval"), PlanID: id, PlanDigest: expected, ApprovedBy: o.actor.id, CreatedAt: o.head.RecordedAt, ExpiresAt: expires, MFAAt: o.actor.mfa}
		approval.ApprovalDigest = digest([]any{"execution.approval/v1", approval, people})
		raw, _ := canonical(approval)
		participants, _ := canonical(people)
		_, e = o.tx.Exec(o.ctx, `INSERT INTO execution_approvals(id,plan_id,approval_digest,approval_json,participants_json,approver_fingerprint,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, approval.ID, id, approval.ApprovalDigest, string(raw), string(participants), o.actor.fingerprint, o.head.RecordedAt, expires)
		if e != nil {
			return e
		}
		if _, e = o.tx.Exec(o.ctx, `UPDATE execution_plans SET state='approved' WHERE id=? AND state='validated'`, id); e != nil {
			return e
		}
		if e = remember(o.ctx, o.tx, o.actor.id, "approve", key, fp, approval.ID, o.head.RecordedAt); e != nil {
			return e
		}
		if e = audit(o.ctx, o.tx, "execution.plan.approved", o.actor.id, id); e != nil {
			return e
		}
		o.expiries = append(o.expiries, expires)
		out = &approval
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) Get(ctx context.Context, a Actor, id string) (out *ExecutionPlan, err error) {
	if !configmodel.ValidID(id) {
		return nil, ErrInvalid
	}
	ids, err := s.selectParticipants(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = s.transact(ctx, a, ids, false, func(o *operation) error {
		p, e := readPlan(o.ctx, o.tx, id)
		if e != nil {
			return e
		}
		if e = o.need(o.actor.id, "config.read", p.snapshot.Targets); e != nil {
			return e
		}
		p.view.Current = true
		tasks, e := readTasks(o.ctx, o.tx, id)
		if e != nil {
			return e
		}
		completed := map[string]bool{}
		for _, task := range tasks {
			if task.state != "succeeded" {
				continue
			}
			receipt, e := taskReceipt(o.ctx, o.tx, task.request.Task.ID)
			if e != nil {
				return e
			}
			if e = successfulTaskReceipt(task, *receipt); e != nil {
				return e
			}
			completed[task.request.Task.NodeID] = true
		}
		// Historical metadata does not assert present dispatch authority. Only
		// typed stale/revoked results become Current=false; source failures abort.
		probe := newOperation(s, o.ctx, o.tx, o.head)
		e = probe.planCurrent(p, p.view.State != "validated")
		if e == nil {
			for _, t := range p.snapshot.Targets {
				if completed[t.Installation.NodeID] {
					continue
				}
				e = probe.target(t)
				if e != nil {
					break
				}
			}
		}
		if e != nil {
			if errors.Is(e, ErrStale) || errors.Is(e, storage.ErrNotFound) || errors.Is(e, storage.ErrPermissionDenied) {
				p.view.Current = false
			} else {
				return e
			}
		} else {
			for id, witness := range probe.witnesses {
				o.witnesses[id] = witness
			}
			o.requirements = append(o.requirements, probe.requirements...)
			o.targets = probe.targets
			o.expiries = probe.expiries
		}
		if p.view.State == "cancelled" || p.view.State == "failed" || p.view.State == "succeeded" || p.view.State == "recovery_required" {
			p.view.Current = false
		}
		p.view.Access = &Access{Read: true, Approve: p.view.Current && p.view.State == "validated" && covers(o.actor.grants, "config.approve", p.snapshot.Targets), Dispatch: p.view.Current && (p.view.State == "approved" || p.view.State == "running") && covers(o.actor.grants, dispatchPermission(p.view.Plan.Kind), p.snapshot.Targets), Cancel: (p.view.State == "approved" || p.view.State == "running" || p.view.State == "validated") && covers(o.actor.grants, "rollouts.cancel", p.snapshot.Targets), Rollback: covers(o.actor.grants, "rollouts.rollback", p.snapshot.Targets)}
		if p.view.Access.Approve {
			for _, author := range p.participants() {
				if e = identity.RequireDistinctPeople(o.ctx, o.tx, o.actor.id, author); e != nil {
					if errors.Is(e, storage.ErrPermissionDenied) {
						p.view.Access.Approve = false
						break
					}
					return e
				}
			}
		}
		approval, _, e := readApproval(o.ctx, o.tx, id)
		if e != nil && e != storage.ErrNotFound {
			return e
		}
		p.view.Approval = approval
		for _, task := range tasks {
			view := TaskView{ID: task.request.Task.ID, NodeID: task.request.Task.NodeID, Sequence: task.request.Task.NodeDeploymentSequence, State: task.state}
			receipt, e := taskReceipt(o.ctx, o.tx, view.ID)
			if e != nil && e != storage.ErrNotFound {
				return e
			}
			view.Receipt = receipt
			p.view.Tasks = append(p.view.Tasks, view)
		}
		out = &p.view
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
