package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (r *RoleBindingService) grantTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal, id string) (*lifecycleTarget, error) {
	t, e := r.identity.lifecycleTarget(ctx, tx, h, p, id)
	if e != nil {
		return nil, e
	}
	if t.View.LifecycleState != "active" {
		return nil, storage.ErrPermissionDenied
	}
	return t, nil
}
func roleScope(in *RoleGrantRequest) RoleScopeSnapshot {
	return RoleScopeSnapshot{ScopeType: in.ScopeType, ScopeID: in.ScopeID, Closure: in.ScopeClosure, Sources: in.ScopeSourceVersions, Digest: in.ScopeClosureDigest}
}
func (r *RoleBindingService) checkGrantAuthority(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal, rec *roleRecord) error {
	in := rec.operation.RoleGrantRequest
	if in == nil {
		return ErrLifecycleStale
	}
	t, e := r.grantTarget(ctx, tx, h, p, in.PrincipalID)
	if e != nil {
		return e
	}
	if t.Fingerprint != in.TargetFingerprint || t.SecurityVersion != uint64(in.ExpectedSecurityVersion) || t.PasswordVersion != uint64(in.ExpectedPasswordVersion) {
		return ErrLifecycleStale
	}
	return r.identity.requireRoleScopeCeiling(ctx, tx, h, p.ID, in.Permissions, roleScope(in))
}
func (r *RoleBindingService) operationCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, rec *roleRecord, approval bool) error {
	o := rec.operation
	in := o.RoleGrantRequest
	if o.State != "pending" || o.Family != "grant_role_binding" || in == nil || in.ExpectedAuthorityEpoch != h.Epoch || in.PolicyDigest != rolePolicyDigest() || in.GrantExpiresAt != nil || len(in.ScopeClosure) > 131072 || len(in.ScopeSourceVersions) > 131072 || h.RecordedAt.Before(o.CreatedAt) || !h.RecordedAt.Before(in.ExpiresAt) {
		return fmt.Errorf("%w: window or policy changed", ErrLifecycleStale)
	}
	role, e := securitystate.ReadRoleDefinitionTx(ctx, tx, in.RoleID)
	if e != nil {
		return e
	}
	d, e := configmodel.Digest(role.Permissions)
	if e != nil {
		return e
	}
	expected, e := configmodel.Digest(in.Permissions)
	if e != nil {
		return e
	}
	if role.Version != in.RoleVersion || role.Digest != in.RoleDigest || d != expected {
		return fmt.Errorf("%w: role definition changed", ErrLifecycleStale)
	}
	scope, e := r.identity.resolveRoleScope(ctx, tx, h, in.ScopeType, in.ScopeID)
	if e != nil {
		return e
	}
	d, e = configmodel.Digest(scope)
	if e != nil {
		return e
	}
	expected, e = configmodel.Digest(roleScope(in))
	if e != nil || d != expected {
		return fmt.Errorf("%w: scope sources changed", ErrLifecycleStale)
	}
	creator, e := r.historicalActor(ctx, tx, h, LifecycleActor{TokenHash: rec.creatorTokenHash, Origin: rec.creatorOrigin}, false)
	if e != nil {
		return e
	}
	if creator.ID != o.CreatedBy || creator.Fingerprint != rec.creatorFingerprint || !creator.PrimaryAt.Equal(rec.creatorPrimaryAt) || !creator.MFAAt.Equal(rec.creatorMFAAt) {
		return fmt.Errorf("%w: creator evidence changed", ErrLifecycleStale)
	}

	if e = r.checkGrantAuthority(ctx, tx, h, creator, rec); e != nil {
		return e
	}
	if !approval {
		return nil
	}
	var reviewerID, fp, token, origin string
	var primary, mfa time.Time
	e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,reviewer_token_hash,reviewer_origin,primary_at,mfa_at FROM role_grant_approvals WHERE operation_id=? AND request_digest=?`, []any{o.ID, o.RequestDigest}, func(row storage.IdentityRows) error {
		return row.Scan(&reviewerID, &fp, &token, &origin, &primary, &mfa)
	})
	if errors.Is(e, storage.ErrNotFound) {
		return storage.ErrApprovalRequired
	}
	if e != nil {
		return e
	}
	if reviewerID == o.CreatedBy || reviewerID == o.SubjectID {
		return storage.ErrPermissionDenied
	}
	if e = RequireDistinctPeople(ctx, tx, reviewerID, o.CreatedBy); e != nil {
		return e
	}
	if e = RequireDistinctPeople(ctx, tx, reviewerID, o.SubjectID); e != nil {
		return e
	}
	reviewer, e := r.historicalActor(ctx, tx, h, LifecycleActor{TokenHash: token, Origin: origin}, true)
	if e != nil {
		return e
	}
	if reviewer.ID != reviewerID || reviewer.Fingerprint != fp || !primary.Equal(reviewer.PrimaryAt) || !mfa.Equal(reviewer.MFAAt) {
		return fmt.Errorf("%w: reviewer evidence changed", ErrLifecycleStale)
	}
	return r.checkGrantAuthority(ctx, tx, h, reviewer, rec)
}

// Create freezes an immutable intent, never an effective grant or a global
// journal barrier. Each subsequent phase rechecks its historical participants.
func (r *RoleBindingService) Create(ctx context.Context, a LifecycleActor, key string, in RoleBindingRequest) (out *RoleSecurityOperation, err error) {
	if !configmodel.ValidID(in.PrincipalID) || !configmodel.ValidID(in.RoleID) || !validRoleScope(in.ScopeType, in.ScopeID) || !directoryRequestKey.MatchString(key) {
		return nil, ErrLifecycleInvalid
	}
	var checked context.Context
	err = r.current(ctx, a, "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		t, e := r.identity.lifecycleTargetMetadata(c, tx, h, p, in.PrincipalID)
		if e != nil {
			return e
		}
		if t.View.LifecycleState != "active" {
			return storage.ErrPermissionDenied
		}
		checked = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	ctx, err = r.identity.lifecyclePeople(checked, []string{in.PrincipalID})
	if err != nil {
		return nil, err
	}
	fp, err := roleRequestFingerprint(in)
	if err != nil {
		return nil, err
	}
	err = r.current(ctx, a, "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		if e := securitystate.EnsureBuiltinRolesTx(c, tx); e != nil {
			return e
		}
		id, e := roleRequestPrior(c, tx, p.ID, "create", key, fp)
		if e == nil {
			rec, e := readRoleOperation(c, tx, id)
			if e != nil {
				return e
			}
			if rec.operation.State == "pending" {
				if e = r.operationCurrent(c, tx, h, rec, false); e != nil {
					return e
				}
			}
			out = &rec.operation
			return nil
		}
		if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		t, e := r.grantTarget(c, tx, h, p, in.PrincipalID)
		if e != nil {
			return e
		}

		role, e := securitystate.ReadRoleDefinitionTx(c, tx, in.RoleID)
		if e != nil {
			return e
		}
		allowed := false
		for _, v := range role.AllowedScopes {
			if v == in.ScopeType {
				allowed = true
			}
		}
		if !allowed {
			return storage.ErrPermissionDenied
		}
		scope, e := r.identity.resolveRoleScope(c, tx, h, in.ScopeType, in.ScopeID)
		if e != nil {
			return e
		}
		if e = r.identity.requireRoleScopeCeiling(c, tx, h, p.ID, role.Permissions, scope); e != nil {
			return e
		}
		now := h.RecordedAt.UTC().Truncate(time.Microsecond)
		request := &RoleGrantRequest{BindingID: securitystate.ID("rbinding"), PrincipalID: in.PrincipalID, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, Permissions: role.Permissions, ScopeType: scope.ScopeType, ScopeID: scope.ScopeID, ScopeClosure: scope.Closure, ScopeSourceVersions: scope.Sources, ScopeClosureDigest: scope.Digest, ExpectedSecurityVersion: securityjournal.UInt63(t.SecurityVersion), ExpectedPasswordVersion: securityjournal.UInt63(t.PasswordVersion), TargetFingerprint: t.Fingerprint, ExpectedAuthorityEpoch: h.Epoch, PreparedSequence: h.Sequence, PreparedDigest: h.Digest, PolicyDigest: rolePolicyDigest(), ExpiresAt: now.Add(5 * time.Minute)}
		digest, e := configmodel.Digest(request)
		if e != nil {
			return e
		}
		out = &RoleSecurityOperation{ID: securitystate.ID("roleop"), Family: "grant_role_binding", RequestDigest: digest, State: "pending", ApprovalStatus: "pending", SubjectID: in.PrincipalID, CreatedBy: p.ID, CreatedAt: now, RoleGrantRequest: request}
		if e = r.insertOperation(c, tx, out, p, a); e != nil {
			return e
		}
		if e = roleSaveRequest(c, tx, h, p.ID, "create", key, fp, out.ID); e != nil {
			return e
		}
		return securitystate.Audit(c, tx, "identity.role_grant.planned", p.ID, map[string]any{"operationId": out.ID, "bindingId": request.BindingID, "requestDigest": digest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r *RoleBindingService) insertOperation(ctx context.Context, tx storage.IdentityTx, o *RoleSecurityOperation, p *lifecyclePrincipal, a LifecycleActor) error {
	raw, e := roleJSON(o)
	if e == nil && len(raw) > maxRoleIntentBytes {
		return ErrLifecycleInvalid
	}
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO role_grant_operations(id,target_id,request_digest,intent_json,creator_id,creator_fingerprint,creator_token_hash,creator_origin,creator_primary_at,creator_mfa_at,state,approval_status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?)`, o.ID, o.SubjectID, o.RequestDigest, string(raw), p.ID, p.Fingerprint, a.TokenHash, a.Origin, p.PrimaryAt, p.MFAAt, o.ApprovalStatus, o.CreatedAt)
	return e
}
func (r *RoleBindingService) GetOperation(ctx context.Context, a LifecycleActor, id string) (out *RoleSecurityOperation, err error) {
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = r.current(ctx, a, "users.privileged.manage", false, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, _ *lifecyclePrincipal) error {
		rec, e := readRoleOperation(c, tx, id)
		if e != nil {
			return e
		}
		out = &rec.operation
		if out.State == "pending" && out.Family == "grant_role_binding" {
			e = r.operationCurrent(c, tx, h, rec, out.ApprovalStatus == "approved")
			if errors.Is(e, ErrLifecycleStale) || errors.Is(e, ErrProof) || errors.Is(e, storage.ErrPermissionDenied) || errors.Is(e, ErrLifecycleReauthRequired) {
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
func (r *RoleBindingService) ApproveOperationRequest(ctx context.Context, a LifecycleActor, id, key, digest, reason string) (out *DirectoryApprovalView, err error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) || !configmodel.ValidDigest(digest) {
		return nil, ErrLifecycleInvalid
	}
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	err = r.current(ctx, a, "users.privileged.manage", true, true, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		rec, e := readRoleOperation(c, tx, id)
		if e != nil {
			return e
		}
		o := rec.operation
		if o.Family != "grant_role_binding" || o.RequestDigest != digest {
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
		if e = r.operationCurrent(c, tx, h, rec, false); e != nil {
			return e
		}
		if e = r.checkGrantAuthority(c, tx, h, p, rec); e != nil {
			return e
		}
		if _, e = roleActionRequest(c, tx, h, p.ID, "approve:"+id, key, id, digest, reason); e != nil {
			return e
		}
		var approvalID, reviewer, priorReason string
		e = securitystate.One(c, tx, `SELECT id,reviewer_id,reason FROM role_grant_approvals WHERE operation_id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&approvalID, &reviewer, &priorReason) })
		if e == nil {
			if reviewer != p.ID || priorReason != reason {
				return storage.ErrConflict
			}
			if e = r.operationCurrent(c, tx, h, rec, true); e != nil {
				return e
			}
		} else {
			if !errors.Is(e, storage.ErrNotFound) {
				return e
			}
			approvalID = securitystate.ID("approval")
			if _, e = tx.Exec(c, `INSERT INTO role_grant_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,reviewer_token_hash,reviewer_origin,primary_at,mfa_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, approvalID, id, digest, p.ID, p.Fingerprint, a.TokenHash, a.Origin, p.PrimaryAt, p.MFAAt, h.RecordedAt, reason); e != nil {
				return e
			}
			if _, e = tx.Exec(c, `UPDATE role_grant_operations SET approval_status='approved' WHERE id=? AND state='pending'`, id); e != nil {
				return e
			}
		}
		out = &DirectoryApprovalView{ApprovalID: approvalID, OperationID: id, RequestDigest: digest, ApprovedBy: p.ID}
		return securitystate.Audit(c, tx, "identity.role_grant.approved", p.ID, map[string]any{"operationId": id, "requestDigest": digest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExecuteOperationRequest publishes the binding and public outcome atomically
// under the current independent head. There is no positive journal replay.
func (r *RoleBindingService) ExecuteOperationRequest(ctx context.Context, a LifecycleActor, id, key, digest, reason string) (out *RoleSecurityOperation, err error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) || !configmodel.ValidDigest(digest) {
		return nil, ErrLifecycleInvalid
	}
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	var restriction bool
	err = r.current(ctx, a, "users.privileged.manage", false, false, func(c context.Context, tx storage.IdentityTx, _ securityjournal.Head, _ *lifecyclePrincipal) error {
		rec, e := readRoleOperation(c, tx, id)
		if e != nil {
			return e
		}
		restriction = rec.operation.Family == "restriction"
		return nil
	})
	if err != nil {
		return nil, err
	}
	if restriction {
		return r.executeRevoke(ctx, a, id, key, digest, reason)
	}
	err = r.current(ctx, a, "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		rec, e := readRoleOperation(c, tx, id)
		if e != nil {
			return e
		}
		if rec.operation.RequestDigest != digest || rec.operation.Family != "grant_role_binding" {
			return ErrLifecycleStale
		}
		if rec.operation.State == "applied" {
			prior, e := roleActionRequest(c, tx, h, p.ID, "execute:"+id, key, id, digest, reason)
			if e != nil {
				return e
			}
			if !prior {
				return storage.ErrConflict
			}
			out = &rec.operation
			return nil
		}
		if e = r.operationCurrent(c, tx, h, rec, true); e != nil {
			return e
		}
		if e = r.checkGrantAuthority(c, tx, h, p, rec); e != nil {
			return e
		}
		if _, e = roleActionRequest(c, tx, h, p.ID, "execute:"+id, key, id, digest, reason); e != nil {
			return e
		}
		h, e = r.finalGrantHead(c, tx, h, rec, a, p)
		if e != nil {
			return e
		}
		in := rec.operation.RoleGrantRequest
		binding := securitystate.RoleBinding{ID: in.BindingID, PrincipalID: in.PrincipalID, RoleID: in.RoleID, RoleVersion: in.RoleVersion, RoleDigest: in.RoleDigest, ScopeType: in.ScopeType, ScopeID: in.ScopeID, Revision: 1, AuthorityEpoch: h.Epoch, CreatedAt: h.RecordedAt.UTC().Truncate(time.Microsecond), ExpiresAt: in.GrantExpiresAt}
		if e = securitystate.PublishRoleBindingTx(c, tx, h, binding); e != nil {
			return e
		}
		if _, e = tx.Exec(c, `UPDATE role_grant_operations SET state='applied' WHERE id=? AND state='pending'`, id); e != nil {
			return e
		}
		out = &rec.operation
		out.State = "applied"
		return securitystate.Audit(c, tx, "identity.role_grant.applied", p.ID, map[string]any{"operationId": id, "bindingId": in.BindingID, "requestDigest": digest, "journalMode": "none_positive_grant"})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
