package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (r *RecoveryService) target(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal, id, action string) (*lifecycleTarget, error) {
	var target *lifecycleTarget
	var e error
	if action == "restart_activation" {
		target, e = r.identity.lifecycleRestartTarget(ctx, tx, h, p, id)
	} else {
		target, e = r.identity.lifecycleTarget(ctx, tx, h, p, id)
	}
	if e != nil {
		return nil, e
	}
	if p.ID == id || (action != "restart_activation" && target.View.LifecycleState != "active") || (action == "reset_password" && target.Directory) {
		return nil, storage.ErrPermissionDenied
	}
	if e = RequireDistinctPeople(ctx, tx, p.ID, id); e != nil {
		return nil, e
	}
	return target, nil
}
func recoveryPlannedSteps(ctx context.Context, tx storage.IdentityTx, target *lifecycleTarget, action string) ([]RecoveryStep, *RecoveryObservedFloors, error) {
	id := target.View.ID
	floors, e := recoveryFloors(ctx, tx, id)
	if e != nil {
		return nil, nil, e
	}
	sv, pv := target.SecurityVersion, target.PasswordVersion
	if action == "restart_activation" {
		sv = max(sv, uint64(floors.Principal))
		pv = max(pv, uint64(floors.Password))
	}
	nextSV, e := recoveryNext(sv)
	if e != nil {
		return nil, nil, e
	}
	steps := []RecoveryStep{{"raise_security_floor", id, "principal_" + id, securityjournal.UInt63(nextSV)}}
	switch action {
	case "reset_password", "restart_activation":
		nextPV, e := recoveryNext(pv)
		if e != nil {
			return nil, nil, e
		}
		steps = append(steps, RecoveryStep{"bump_authenticator_floor", id, PasswordID(id), securityjournal.UInt63(nextPV)})
	case "replace_mfa":
		var factor, batch uint64
		e = securitystate.One(ctx, tx, `SELECT version FROM mfa_factors WHERE principal_id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&factor) })
		if e != nil && !errors.Is(e, storage.ErrNotFound) {
			return nil, nil, e
		}
		e = securitystate.One(ctx, tx, `SELECT COALESCE(MAX(batch_version),0) FROM recovery_codes WHERE principal_id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&batch) })
		if e != nil {
			return nil, nil, e
		}
		factor, e = recoveryNext(max(factor, uint64(floors.Factor)))
		if e != nil {
			return nil, nil, e
		}
		batch, e = recoveryNext(max(batch, uint64(floors.Recovery)))
		if e != nil {
			return nil, nil, e
		}
		steps = append(steps, RecoveryStep{"bump_authenticator_floor", id, FactorID(id), securityjournal.UInt63(factor)}, RecoveryStep{"bump_authenticator_floor", id, RecoveryID(id), securityjournal.UInt63(batch)})
	default:
		return nil, nil, ErrLifecycleInvalid
	}

	return steps, floors, nil
}
func (r *RecoveryService) Plan(ctx context.Context, a LifecycleActor, targetID, key string, in RecoveryPlanRequest) (out *RecoverySecurityOperation, err error) {
	if !configmodel.ValidID(targetID) || in.TargetPrincipalID != targetID || in.ExpectedSecurityVersion == 0 || !directoryRequestKey.MatchString(key) || !directoryReason(in.Reason) || (in.AllowedAction != "replace_mfa" && in.AllowedAction != "reset_password" && in.AllowedAction != "restart_activation") {
		return nil, ErrLifecycleInvalid
	}
	var checked context.Context
	err = r.current(ctx, a, true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		var e error
		if in.AllowedAction == "restart_activation" {
			_, e = r.identity.lifecycleRestartTarget(c, tx, h, p, targetID)
		} else {
			_, e = r.identity.lifecycleTargetMetadata(c, tx, h, p, targetID)
		}
		if e != nil {
			return e
		}
		checked = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	ctx, err = r.identity.lifecyclePeople(checked, []string{targetID})
	if err != nil {
		return nil, err
	}
	fingerprint, _ := configmodel.Digest(struct {
		Target  string
		Request RecoveryPlanRequest
	}{targetID, in})
	err = r.current(ctx, a, true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		var prior, id string
		e := securitystate.One(c, tx, `SELECT fingerprint,operation_id FROM identity_recovery_requests WHERE actor_id=? AND action='plan' AND request_key=?`, []any{p.ID, key}, func(row storage.IdentityRows) error { return row.Scan(&prior, &id) })
		if e == nil {
			if prior != fingerprint {
				return storage.ErrConflict
			}
			record, e := readRecoveryOperation(c, tx, id)
			if e != nil {
				return e
			}
			if record.operation.State == "pending" {
				if e = r.operationCurrent(c, tx, h, record, false); e != nil {
					return e
				}
			}
			out = &record.operation
			return nil
		}
		if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		target, e := r.target(c, tx, h, p, targetID, in.AllowedAction)
		if e != nil {
			return e
		}
		if uint64(in.ExpectedSecurityVersion) != target.SecurityVersion || !in.ExpiresAt.After(h.RecordedAt) || in.ExpiresAt.After(h.RecordedAt.Add(15*time.Minute)) {
			return ErrLifecycleStale
		}
		steps, floors, e := recoveryPlannedSteps(c, tx, target, in.AllowedAction)
		if e != nil {
			return e
		}
		request := IdentityRecoveryIntent{TargetPrincipalID: in.TargetPrincipalID, ExpectedSecurityVersion: in.ExpectedSecurityVersion, AllowedAction: in.AllowedAction, ExpiresAt: in.ExpiresAt, Reason: in.Reason, ExpectedPasswordVersion: securityjournal.UInt63(target.PasswordVersion), ExpectedAuthorityEpoch: h.Epoch, PolicyDigest: lifecyclePolicyDigest(), CustodianPrincipalID: p.ID, TargetFingerprint: target.Fingerprint, RestrictiveSteps: steps, ObservedFloors: floors}
		request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond)
		digest, e := configmodel.Digest(request)
		if e != nil {
			return e
		}
		out = &RecoverySecurityOperation{ID: securitystate.ID("recoveryop"), Family: "identity_recovery", RequestDigest: digest, State: "pending", ApprovalStatus: "pending", SubjectID: targetID, CreatedBy: p.ID, CreatedAt: h.RecordedAt.UTC().Truncate(time.Microsecond), RecoveryRequest: request}
		raw, e := recoveryJSON(out)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(c, `INSERT INTO identity_recovery_operations(id,target_id,request_digest,intent_json,creator_id,creator_fingerprint,state,approval_status,created_at) VALUES(?,?,?,?,?,?,'pending','pending',?)`, out.ID, targetID, digest, string(raw), p.ID, p.Fingerprint, out.CreatedAt); e != nil {
			return e
		}
		if _, e = tx.Exec(c, `INSERT INTO identity_recovery_requests(actor_id,action,request_key,fingerprint,operation_id,created_at) VALUES(?,'plan',?,?,?,?)`, p.ID, key, fingerprint, out.ID, h.RecordedAt); e != nil {
			return e
		}
		return securitystate.Audit(c, tx, "identity.recovery.planned", p.ID, map[string]any{"operationId": out.ID, "targetId": targetID, "requestDigest": digest, "action": in.AllowedAction})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r *RecoveryService) participants(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, record *recoveryRecord, approval bool) (*lifecyclePrincipal, string, error) {
	o := record.operation
	p, e := r.identity.lifecycleSubject(ctx, tx, h, o.CreatedBy, "users.privileged.manage", false)
	if e != nil {
		return nil, "", e
	}
	if p.Fingerprint != record.creatorFingerprint {
		return nil, "", ErrLifecycleStale
	}
	if !approval {
		return p, "", nil
	}
	var id, fp string
	var mfa, primary time.Time
	e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,mfa_at,primary_at FROM identity_recovery_approvals WHERE operation_id=? AND request_digest=?`, []any{o.ID, o.RequestDigest}, func(row storage.IdentityRows) error { return row.Scan(&id, &fp, &mfa, &primary) })
	if errors.Is(e, storage.ErrNotFound) {
		return nil, "", storage.ErrApprovalRequired
	}
	if e != nil {
		return nil, "", e
	}
	if id == o.CreatedBy || id == o.SubjectID {
		return nil, "", storage.ErrPermissionDenied
	}
	if e = RequireDistinctPeople(ctx, tx, id, o.CreatedBy); e != nil {
		return nil, "", e
	}
	if e = RequireDistinctPeople(ctx, tx, id, o.SubjectID); e != nil {
		return nil, "", e
	}
	reviewer, e := r.identity.lifecycleSubject(ctx, tx, h, id, "users.privileged.manage", true)
	if e != nil {
		return nil, "", e
	}
	if reviewer.Fingerprint != fp {
		return nil, "", ErrLifecycleStale
	}
	if o.State == "pending" && (h.RecordedAt.Before(mfa) || h.RecordedAt.Sub(mfa) > 5*time.Minute || h.RecordedAt.Before(primary) || h.RecordedAt.Sub(primary) > 5*time.Minute) {
		return nil, "", ErrLifecycleReauthRequired
	}
	return p, id, nil
}
func (r *RecoveryService) operationCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, record *recoveryRecord, approval bool) error {
	o := record.operation
	in := o.RecoveryRequest
	if o.State != "pending" || h.Epoch != in.ExpectedAuthorityEpoch || in.PolicyDigest != lifecyclePolicyDigest() || h.RecordedAt.Before(o.CreatedAt) || !h.RecordedAt.Before(in.ExpiresAt) {
		return ErrLifecycleStale
	}
	p, _, e := r.participants(ctx, tx, h, record, approval)
	if e != nil {
		return e
	}
	target, e := r.target(ctx, tx, h, p, o.SubjectID, in.AllowedAction)
	if e != nil {
		return e
	}
	if target.Fingerprint != in.TargetFingerprint || target.SecurityVersion != uint64(in.ExpectedSecurityVersion) || target.PasswordVersion != uint64(in.ExpectedPasswordVersion) {
		return ErrLifecycleStale
	}
	steps, floors, e := recoveryPlannedSteps(ctx, tx, target, in.AllowedAction)
	if e != nil {
		return e
	}
	digest, _ := configmodel.Digest(struct {
		Steps  []RecoveryStep
		Floors *RecoveryObservedFloors
	}{steps, floors})
	expected, _ := configmodel.Digest(struct {
		Steps  []RecoveryStep
		Floors *RecoveryObservedFloors
	}{in.RestrictiveSteps, in.ObservedFloors})
	if digest != expected {
		return ErrLifecycleStale
	}
	return nil
}
func (r *RecoveryService) GetOperation(ctx context.Context, a LifecycleActor, id string) (out *RecoverySecurityOperation, err error) {
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = r.current(ctx, a, false, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, _ *lifecyclePrincipal) error {
		record, e := readRecoveryOperation(c, tx, id)
		if e != nil {
			return e
		}
		out = &record.operation
		if out.State == "pending" {
			e = r.operationCurrent(c, tx, h, record, out.ApprovalStatus == "approved")
			if errors.Is(e, ErrProof) || errors.Is(e, ErrLifecycleStale) || errors.Is(e, storage.ErrPermissionDenied) {
				out.ApprovalStatus = "expired"
				return nil
			}
			return e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r *RecoveryService) ApproveOperationRequest(ctx context.Context, a LifecycleActor, id, key, digest, reason string) (out *DirectoryApprovalView, err error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) || !configmodel.ValidDigest(digest) {
		return nil, ErrLifecycleInvalid
	}
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = r.current(ctx, a, true, true, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		record, e := readRecoveryOperation(c, tx, id)
		if e != nil {
			return e
		}
		o := record.operation
		if digest != o.RequestDigest {
			return ErrLifecycleStale
		}
		if p.ID == o.CreatedBy || p.ID == o.SubjectID {
			return storage.ErrPermissionDenied
		}
		if e = RequireDistinctPeople(c, tx, p.ID, o.CreatedBy); e != nil {
			return e
		}
		if e = RequireDistinctPeople(c, tx, p.ID, o.SubjectID); e != nil {
			return e
		}
		if e = r.operationCurrent(c, tx, h, record, false); e != nil {
			return e
		}
		if _, e = r.target(c, tx, h, p, o.SubjectID, o.RecoveryRequest.AllowedAction); e != nil {
			return e
		}
		if e = recoveryActionRequest(c, tx, h, p.ID, "approve:"+id, key, id, digest, reason); e != nil {
			return e
		}
		var approvalID, reviewer, priorReason string
		e = securitystate.One(c, tx, `SELECT id,reviewer_id,reason FROM identity_recovery_approvals WHERE operation_id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&approvalID, &reviewer, &priorReason) })
		if e == nil {
			if reviewer != p.ID || priorReason != reason {
				return storage.ErrConflict
			}
			if e = r.operationCurrent(c, tx, h, record, true); e != nil {
				return e
			}
		} else {
			if !errors.Is(e, storage.ErrNotFound) {
				return e
			}
			approvalID = securitystate.ID("approval")
			if _, e = tx.Exec(c, `INSERT INTO identity_recovery_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,mfa_at,primary_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?)`, approvalID, id, digest, p.ID, p.Fingerprint, p.MFAAt, p.PrimaryAt, h.RecordedAt, reason); e != nil {
				return e
			}
			if _, e = tx.Exec(c, `UPDATE identity_recovery_operations SET approval_status='approved' WHERE id=? AND state='pending'`, id); e != nil {
				return e
			}
		}
		out = &DirectoryApprovalView{ApprovalID: approvalID, OperationID: id, RequestDigest: digest, ApprovedBy: p.ID}
		return securitystate.Audit(c, tx, "identity.recovery.approved", p.ID, map[string]any{"operationId": id, "requestDigest": digest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type recoveryExecution struct {
	OperationID      string    `json:"operationId"`
	RequestDigest    string    `json:"requestDigest"`
	ActorID          string    `json:"actorId"`
	ReviewerID       string    `json:"reviewerId"`
	Epoch            uint64    `json:"epoch"`
	ActorFingerprint string    `json:"actorFingerprint"`
	ActorTokenHash   string    `json:"actorTokenHash"`
	ActorOrigin      string    `json:"actorOrigin"`
	PrimaryAt        time.Time `json:"primaryAt"`
	MFAAt            time.Time `json:"mfaAt"`
}

func (r *RecoveryService) ExecuteOperationRequest(ctx context.Context, a LifecycleActor, id, key, digest, reason string) (out *RecoverySecurityOperation, err error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) || !configmodel.ValidDigest(digest) {
		return nil, ErrLifecycleInvalid
	}
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	already := false
	err = r.current(ctx, a, true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		record, e := readRecoveryOperation(c, tx, id)
		if e != nil {
			return e
		}
		if record.operation.RequestDigest != digest {
			return ErrLifecycleStale
		}
		if record.operation.State == "applied" {
			out = &record.operation
			already = true
			return nil
		}
		if e = r.operationCurrent(c, tx, h, record, true); e != nil {
			return e
		}
		if _, e = r.target(c, tx, h, p, record.operation.SubjectID, record.operation.RecoveryRequest.AllowedAction); e != nil {
			return e
		}
		return recoveryActionRequest(c, tx, h, p.ID, "execute:"+id, key, id, digest, reason)
	})
	if err != nil {
		return nil, err
	}
	if already {
		return out, nil
	}
	err = r.identity.Coordinator.WithManagementSession(ctx, a.TokenHash, func(c context.Context) error {
		return r.identity.Coordinator.ExecuteDynamic(c, "identity_recovery", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
			actor, e := r.identity.lifecycleActor(c, tx, h, a, "users.privileged.manage", true, false)
			if e != nil {
				return nil, nil, e
			}
			record, e := readRecoveryOperation(c, tx, id)
			if e != nil {
				return nil, nil, e
			}
			if record.operation.RequestDigest != digest {
				return nil, nil, ErrLifecycleStale
			}
			if e = r.operationCurrent(c, tx, h, record, true); e != nil {
				return nil, nil, e
			}
			if _, e = r.target(c, tx, h, actor, record.operation.SubjectID, record.operation.RecoveryRequest.AllowedAction); e != nil {
				return nil, nil, e
			}
			_, reviewer, e := r.participants(c, tx, h, record, true)
			if e != nil {
				return nil, nil, e
			}
			raw, e := recoveryJSON(recoveryExecution{OperationID: id, RequestDigest: digest, ActorID: actor.ID, ReviewerID: reviewer, Epoch: uint64(h.Epoch), ActorFingerprint: actor.Fingerprint, ActorTokenHash: a.TokenHash, ActorOrigin: a.Origin, PrimaryAt: actor.PrimaryAt, MFAAt: actor.MFAAt})
			return raw, recoveryRequests(actor.ID, record.operation.RecoveryRequest.RestrictiveSteps), e
		})
	})
	if err != nil {
		return nil, err
	}
	err = r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		record, e := readRecoveryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		out = &record.operation
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *RecoveryService) materializeOperation(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in recoveryExecution
	if json.Unmarshal(raw, &in) != nil {
		return ErrLifecycleStale
	}
	record, e := readRecoveryOperation(ctx, tx, in.OperationID)
	if e != nil {
		return e
	}
	o := record.operation
	c := o.RecoveryRequest
	if o.State == "applied" || o.State == "recovery_required" {
		return nil
	}
	if o.RequestDigest != in.RequestDigest || in.Epoch != uint64(c.ExpectedAuthorityEpoch) {
		return ErrLifecycleStale
	}
	h, e := recoveryHead(ctx, r.identity, in.Epoch)
	if e != nil {
		return e
	}
	valid := h.RecordedAt.Before(c.ExpiresAt) && c.PolicyDigest == lifecyclePolicyDigest()
	exactTarget := true
	exactFloors := true
	creator, reviewer, peopleErr := r.participants(ctx, tx, h, record, true)
	if peopleErr != nil || reviewer != in.ReviewerID {
		valid = false
	}
	executor, executorErr := r.identity.lifecycleActor(ctx, tx, h, LifecycleActor{TokenHash: in.ActorTokenHash, Origin: in.ActorOrigin}, "users.privileged.manage", true, false)
	if executorErr != nil || executor.ID != in.ActorID || executor.Fingerprint != in.ActorFingerprint || executor.ID == o.SubjectID || !executor.PrimaryAt.Equal(in.PrimaryAt) || !executor.MFAAt.Equal(in.MFAAt) {
		valid = false
	}
	for _, participant := range []string{o.CreatedBy, in.ActorID} {
		if err := RequireDistinctPeople(ctx, tx, participant, o.SubjectID); err != nil {
			if !errors.Is(err, storage.ErrPermissionDenied) {
				return err
			}
			valid = false
		}
	}

	target, e := lifecycleRawUser(ctx, tx, h, o.SubjectID)
	if e != nil {
		return e
	}
	if target.Fingerprint != c.TargetFingerprint || target.View.Blocked || target.SecurityVersion != uint64(c.ExpectedSecurityVersion) || target.PasswordVersion != uint64(c.ExpectedPasswordVersion) {
		valid = false
		exactTarget = false
	}
	for _, step := range c.RestrictiveSteps {
		floor, e := securitystate.Floor(ctx, tx, step.PrincipalID, step.AuthenticatorID)
		if e != nil {
			return e
		}
		if floor != uint64(step.MinimumVersion) {
			valid = false
			exactFloors = false
		}
	}
	// Floors not touched by this operation remain part of its exact intent.
	// A concurrent replay/factor/password fence cannot be silently discarded.
	if c.ObservedFloors == nil {
		valid = false
		exactFloors = false
	} else {
		expected := map[string]uint64{"principal_" + o.SubjectID: uint64(c.ObservedFloors.Principal), PasswordID(o.SubjectID): uint64(c.ObservedFloors.Password), FactorID(o.SubjectID): uint64(c.ObservedFloors.Factor), RecoveryID(o.SubjectID): uint64(c.ObservedFloors.Recovery), ReplayID(o.SubjectID): uint64(c.ObservedFloors.Replay)}
		for _, step := range c.RestrictiveSteps {
			expected[step.AuthenticatorID] = uint64(step.MinimumVersion)
		}
		for id, value := range expected {
			floor, e := securitystate.Floor(ctx, tx, o.SubjectID, id)
			if e != nil {
				return e
			}
			if floor != value {
				valid = false
				exactFloors = false
			}
		}
	}
	// Only independently durable restrictions may be projected on an abort.
	// Their exact unchanged target and exact own floors permit another supervised
	// plan without blessing an old password or factor at a newer version.
	if valid {
		if creator == nil || r.identity.lifecycleTargetCeiling(ctx, tx, h, creator, target) != nil || executor == nil || r.identity.lifecycleTargetCeiling(ctx, tx, h, executor, target) != nil {
			valid = false
		}
		if _, proofErr := DirectorySubjectFingerprint(ctx, tx, h, o.SubjectID); proofErr != nil {
			valid = false
		}
	}
	if !valid {
		if exactTarget && exactFloors {
			if e = r.projectOperationRestrictions(ctx, tx, h, record, target); e != nil {
				return e
			}
		}
		_, e = tx.Exec(ctx, `UPDATE identity_recovery_operations SET state='recovery_required' WHERE id=?`, o.ID)
		return e
	}
	postSV, postPV := target.SecurityVersion, target.PasswordVersion
	for _, step := range c.RestrictiveSteps {
		if step.AuthenticatorID == "principal_"+o.SubjectID {
			postSV = uint64(step.MinimumVersion)
		}
		if step.AuthenticatorID == PasswordID(o.SubjectID) {
			postPV = uint64(step.MinimumVersion)
		}
	}
	switch c.AllowedAction {
	case "replace_mfa":
		if _, e = tx.Exec(ctx, `UPDATE mfa_factors SET revoked=TRUE WHERE principal_id=?`, o.SubjectID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM recovery_codes WHERE principal_id=?`, o.SubjectID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE users SET security_version=? WHERE id=? AND security_version=?`, int64(postSV), o.SubjectID, int64(target.SecurityVersion))
	case "reset_password":
		_, e = tx.Exec(ctx, `UPDATE users SET password_hash='',security_version=?,password_version=? WHERE id=? AND identity_kind='local' AND security_version=? AND password_version=?`, int64(postSV), int64(postPV), o.SubjectID, int64(target.SecurityVersion), int64(target.PasswordVersion))
	case "restart_activation":
		if r.identity.invitations == nil {
			return ErrLifecycleUnavailable
		}
		if e = r.identity.invitations.CancelPrincipalTx(ctx, tx, o.SubjectID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE mfa_factors SET revoked=TRUE WHERE principal_id=?`, o.SubjectID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM recovery_codes WHERE principal_id=?`, o.SubjectID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE users SET password_hash='',security_version=?,password_version=? WHERE id=? AND lifecycle_state='invited' AND identity_kind='local' AND security_version=? AND password_version=?`, int64(postSV), int64(postPV), o.SubjectID, int64(target.SecurityVersion), int64(target.PasswordVersion))
	default:
		return ErrLifecycleStale
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE principal_id=? AND state NOT IN ('completed','cancelled','expired')`, o.SubjectID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_recovery_operations SET state='applied',post_security_version=?,post_password_version=? WHERE id=? AND state='pending'`, int64(postSV), int64(postPV), o.ID); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.recovery.applied", in.ActorID, map[string]any{"operationId": o.ID, "requestDigest": o.RequestDigest, "action": c.AllowedAction, "reviewerId": in.ReviewerID})
}

func (r *RecoveryService) IssueTicket(ctx context.Context, a LifecycleActor, id string) (out *RecoveryTicketView, err error) {
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = r.current(ctx, a, true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		record, e := readRecoveryOperation(c, tx, id)
		if e != nil {
			return e
		}
		o := record.operation
		in := o.RecoveryRequest
		if o.State != "applied" || in.AllowedAction == "restart_activation" || p.ID != in.CustodianPrincipalID || p.Fingerprint != record.creatorFingerprint || h.Epoch != in.ExpectedAuthorityEpoch || !h.RecordedAt.Before(in.ExpiresAt) || in.PolicyDigest != lifecyclePolicyDigest() {
			return ErrLifecycleStale
		}
		if _, _, e = r.participants(c, tx, h, record, true); e != nil {
			return e
		}
		target, e := r.target(c, tx, h, p, o.SubjectID, in.AllowedAction)
		if e != nil {
			return e
		}
		if target.SecurityVersion != record.postSV || target.PasswordVersion != record.postPV {
			return ErrLifecycleStale
		}
		prior, e := securitystate.Strings(c, tx, `SELECT id FROM identity_one_time_tokens WHERE authorization_operation_id=?`, id)
		if e != nil {
			return e
		}
		if len(prior) != 0 {
			return storage.ErrConflict
		}
		raw, hash, e := auth.NewToken()
		if e != nil {
			return e
		}
		expires := minTime(in.ExpiresAt, h.RecordedAt.Add(15*time.Minute))
		purpose := "reset_password"
		if in.AllowedAction == "replace_mfa" {
			purpose = "recover_mfa"
		}
		token := &lifecycleToken{ID: securitystate.ID("ticket"), PrincipalID: o.SubjectID, Purpose: purpose, ProofKind: "supervised", TokenHash: hash, GuardID: securitystate.ID("guard_setup"), GuardVersion: 1, Epoch: uint64(h.Epoch), SecurityVersion: record.postSV, PasswordVersion: record.postPV, PolicyDigest: lifecyclePolicyDigest(), IssuerID: p.ID, IssuerFingerprint: p.Fingerprint, Generation: 1, AuthorizationOperationID: id, AllowedAction: in.AllowedAction, CreatedAt: h.RecordedAt, ExpiresAt: expires}
		if e = insertLifecycleToken(c, tx, token); e != nil {
			return e
		}
		out = &RecoveryTicketView{Ticket: raw, ExpiresAt: expires}
		return securitystate.Audit(c, tx, "identity.recovery.ticket_issued", p.ID, map[string]any{"operationId": id, "targetId": o.SubjectID, "action": in.AllowedAction})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// projectOperationRestrictions never publishes a credential or ticket.
func (r *RecoveryService) projectOperationRestrictions(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, record *recoveryRecord, target *lifecycleTarget) error {
	o := record.operation
	in := o.RecoveryRequest
	sv, pv := target.SecurityVersion, target.PasswordVersion
	for _, step := range in.RestrictiveSteps {
		if step.AuthenticatorID == "principal_"+o.SubjectID {
			sv = uint64(step.MinimumVersion)
		}
		if step.AuthenticatorID == PasswordID(o.SubjectID) {
			pv = uint64(step.MinimumVersion)
		}
	}
	var e error
	switch in.AllowedAction {
	case "replace_mfa":
		if _, e = tx.Exec(ctx, `UPDATE mfa_factors SET revoked=TRUE WHERE principal_id=?`, o.SubjectID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM recovery_codes WHERE principal_id=?`, o.SubjectID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE users SET security_version=? WHERE id=? AND security_version=? AND password_version=?`, int64(sv), o.SubjectID, int64(target.SecurityVersion), int64(target.PasswordVersion))
	case "reset_password", "restart_activation":
		if in.AllowedAction == "restart_activation" {
			if r.identity.invitations == nil {
				return ErrLifecycleUnavailable
			}
			if e = r.identity.invitations.CancelPrincipalTx(ctx, tx, o.SubjectID); e != nil {
				return e
			}
		}
		_, e = tx.Exec(ctx, `UPDATE users SET password_hash='',security_version=?,password_version=? WHERE id=? AND identity_kind='local' AND security_version=? AND password_version=?`, int64(sv), int64(pv), o.SubjectID, int64(target.SecurityVersion), int64(target.PasswordVersion))
	default:
		return ErrLifecycleStale
	}
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE principal_id=? AND state NOT IN ('completed','cancelled','expired')`, o.SubjectID)
	return e
}
