package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (r *RoleBindingService) revokeAuthority(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal, b securitystate.RoleBinding) error {
	t, e := lifecycleRawUser(ctx, tx, h, b.PrincipalID)
	if e != nil {
		return e
	}
	if e = r.identity.lifecycleTargetCeiling(ctx, tx, h, p, t); e != nil {
		return e
	}
	if _, e = DirectorySubjectFingerprint(ctx, tx, h, b.PrincipalID); e != nil {
		return e
	}
	role, e := securitystate.ReadRoleDefinitionDigestTx(ctx, tx, b.RoleDigest)
	if e != nil {
		return e
	}
	scope, e := r.identity.resolveRoleScope(ctx, tx, h, b.ScopeType, b.ScopeID)
	if e != nil {
		return e
	}
	return r.identity.requireRoleScopeCeiling(ctx, tx, h, p.ID, role.Permissions, scope)
}

// Revoke records and journals one exact incarnation. Losing its response can
// only repeat that incarnation's tombstone, never revoke a later replacement.
func (r *RoleBindingService) Revoke(ctx context.Context, a LifecycleActor, id, key string, expected securityjournal.UInt63, reason string) (out *RoleSecurityOperation, err error) {
	if !configmodel.ValidID(id) || expected == 0 || !directoryRequestKey.MatchString(key) || !directoryReason(reason) {
		return nil, ErrLifecycleInvalid
	}
	var checked context.Context
	var principal string
	err = r.current(ctx, a, "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, _ securityjournal.Head, _ *lifecyclePrincipal) error {
		b, e := securitystate.ReadRoleBindingTx(c, tx, id)
		if e != nil {
			return e
		}
		principal = b.PrincipalID
		checked = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	ctx, err = r.identity.lifecyclePeople(checked, []string{principal})
	if err != nil {
		return nil, err
	}
	fp, e := roleRequestFingerprint(struct {
		Binding  string
		Revision securityjournal.UInt63
		Reason   string
	}{id, expected, reason})
	if e != nil {
		return nil, e
	}
	err = r.current(ctx, a, "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		prior, e := roleRequestPrior(c, tx, p.ID, "revoke:"+id, key, fp)
		if e == nil {
			rec, e := readRoleOperation(c, tx, prior)
			if e != nil {
				return e
			}
			out = &rec.operation
			return nil
		}
		if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		b, e := securitystate.ReadRoleBindingTx(c, tx, id)
		if e != nil {
			return e
		}
		if b.Revision != expected || b.RevokedAt != nil {
			return ErrLifecycleStale
		}
		if e = r.revokeAuthority(c, tx, h, p, b); e != nil {
			return e
		}
		in := &RoleBindingRevokeRequest{BindingID: id, PrincipalID: b.PrincipalID, ExpectedRevision: expected, RoleDigest: b.RoleDigest, ExpectedAuthorityEpoch: h.Epoch, Reason: reason}
		digest, e := configmodel.Digest(in)
		if e != nil {
			return e
		}
		out = &RoleSecurityOperation{ID: securitystate.ID("roleop"), Family: "restriction", RequestDigest: digest, State: "pending", ApprovalStatus: "not_required", SubjectID: b.PrincipalID, CreatedBy: p.ID, CreatedAt: h.RecordedAt.UTC().Truncate(time.Microsecond), RoleBindingRevokeRequest: in}
		if e = r.insertOperation(c, tx, out, p, a); e != nil {
			return e
		}
		return roleSaveRequest(c, tx, h, p.ID, "revoke:"+id, key, fp, out.ID)
	})
	if err != nil {
		return nil, err
	}
	if out.State == "applied" {
		return out, nil
	}
	return r.executeRevoke(ctx, a, out.ID, key, out.RequestDigest, reason)
}

type roleRevokeExecution struct {
	OperationID   string                 `json:"operationId"`
	RequestDigest string                 `json:"requestDigest"`
	BindingID     string                 `json:"bindingId"`
	PrincipalID   string                 `json:"principalId"`
	Epoch         securityjournal.UInt63 `json:"epoch"`
	ActorID       string                 `json:"actorId"`
}

func (r *RoleBindingService) executeRevoke(ctx context.Context, a LifecycleActor, id, key, digest, reason string) (out *RoleSecurityOperation, err error) {
	ctx, err = r.people(ctx, a, id)
	if err != nil {
		return nil, err
	}
	already := false
	err = r.current(ctx, a, "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		rec, e := readRoleOperation(c, tx, id)
		if e != nil {
			return e
		}
		if rec.operation.Family != "restriction" || rec.operation.RequestDigest != digest {
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
			already = true
			out = &rec.operation
			return nil
		}
		in := rec.operation.RoleBindingRevokeRequest
		if in.ExpectedAuthorityEpoch != h.Epoch {
			return ErrLifecycleStale
		}
		b, e := securitystate.ReadRoleBindingTx(c, tx, in.BindingID)
		if e != nil {
			return e
		}
		if b.Revision != in.ExpectedRevision || b.RevokedAt != nil || b.RoleDigest != in.RoleDigest || b.PrincipalID != in.PrincipalID {
			return ErrLifecycleStale
		}
		if e = r.revokeAuthority(c, tx, h, p, b); e != nil {
			return e
		}
		_, e = roleActionRequest(c, tx, h, p.ID, "execute:"+id, key, id, digest, reason)
		return e
	})
	if err != nil {
		return nil, err
	}
	if already {
		return out, nil
	}
	err = r.identity.Coordinator.WithManagementSession(ctx, a.TokenHash, func(c context.Context) error {
		return r.identity.Coordinator.ExecuteDynamic(c, "role_binding_revoke", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
			p, e := r.identity.lifecycleActor(c, tx, h, a, "users.privileged.manage", true, false)
			if e != nil {
				return nil, nil, e
			}
			rec, e := readRoleOperation(c, tx, id)
			if e != nil {
				return nil, nil, e
			}
			in := rec.operation.RoleBindingRevokeRequest
			if rec.operation.State != "pending" || in == nil || rec.operation.RequestDigest != digest || in.ExpectedAuthorityEpoch != h.Epoch {
				return nil, nil, ErrLifecycleStale
			}
			b, e := securitystate.ReadRoleBindingTx(c, tx, in.BindingID)
			if e != nil {
				return nil, nil, e
			}
			if b.Revision != in.ExpectedRevision || b.RevokedAt != nil || b.RoleDigest != in.RoleDigest || b.PrincipalID != in.PrincipalID {
				return nil, nil, ErrLifecycleStale
			}
			if e = r.revokeAuthority(c, tx, h, p, b); e != nil {
				return nil, nil, e
			}
			raw, e := roleJSON(roleRevokeExecution{OperationID: id, RequestDigest: digest, BindingID: in.BindingID, PrincipalID: in.PrincipalID, Epoch: h.Epoch, ActorID: p.ID})
			return raw, []securityjournal.AppendRequest{{Kind: "revoke_role_binding", TargetType: "grant", TargetID: in.BindingID, ActorID: p.ID, Payload: securityjournal.Payload{GrantID: in.BindingID}}}, e
		})
	})
	if err != nil {
		return nil, err
	}
	err = r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		rec, e := readRoleOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		out = &rec.operation
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r *RoleBindingService) materializeRevoke(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in roleRevokeExecution
	if configmodel.StrictJSON(strings.NewReader(string(raw)), &in, 64<<10) != nil {
		return ErrLifecycleStale
	}
	rec, e := readRoleOperation(ctx, tx, in.OperationID)
	if errors.Is(e, storage.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	o := rec.operation
	revoke := o.RoleBindingRevokeRequest
	if o.Family != "restriction" || revoke == nil || o.RequestDigest != in.RequestDigest || revoke.BindingID != in.BindingID || revoke.PrincipalID != in.PrincipalID || revoke.ExpectedAuthorityEpoch != in.Epoch {
		return ErrLifecycleStale
	}
	if o.State == "applied" {
		return nil
	}
	if _, e = tx.Exec(ctx, `UPDATE role_grant_operations SET state='applied' WHERE id=? AND state='pending'`, in.OperationID); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.role_binding.revoked", in.ActorID, map[string]any{"operationId": in.OperationID, "bindingId": in.BindingID, "requestDigest": in.RequestDigest})
}
