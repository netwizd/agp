package identity

import (
	"context"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type DirectoryApprovalView struct {
	ApprovalID    string `json:"approvalId"`
	OperationID   string `json:"operationId"`
	RequestDigest string `json:"requestDigest"`
	ApprovedBy    string `json:"approvedBy"`
}

func directoryActionRequest(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor, action, key, digest, reason string) error {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) {
		return ErrDirectoryInvalid
	}
	fp, e := configmodel.Digest(struct{ Digest, Reason string }{digest, reason})
	if e != nil {
		return e
	}
	var prior string
	e = securitystate.One(ctx, tx, `SELECT fingerprint FROM directory_provider_action_requests WHERE actor_id=? AND action=? AND request_key=?`, []any{actor, action, key}, func(r storage.IdentityRows) error { return r.Scan(&prior) })
	if e == nil {
		if prior != fp {
			return storage.ErrConflict
		}
		return nil
	}
	if e != storage.ErrNotFound {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO directory_provider_action_requests(actor_id,action,request_key,fingerprint,created_at) VALUES(?,?,?,?,?)`, actor, action, key, fp, h.RecordedAt)
	return e
}
func (s *DirectoryService) ApproveOperationView(ctx context.Context, a DirectoryActor, id, digest, reason string) (*DirectoryApprovalView, error) {
	checked, e := s.operationPeopleContext(ctx, a, id, true, true)
	if e != nil {
		return nil, e
	}
	ctx = checked
	if _, e := s.ApproveOperation(ctx, a, id, digest, reason); e != nil {
		return nil, e
	}
	return s.directoryApprovalView(ctx, a, id, digest)
}
func (s *DirectoryService) ApproveOperationRequest(ctx context.Context, a DirectoryActor, id, key, digest, reason string) (*DirectoryApprovalView, error) {
	if !directoryRequestKey.MatchString(key) {
		return nil, ErrDirectoryInvalid
	}
	checked, e := s.operationPeopleContext(ctx, a, id, true, true)
	if e != nil {
		return nil, e
	}
	ctx = checked
	if _, e := s.approveOperation(ctx, a, id, digest, reason, key); e != nil {
		return nil, e
	}
	return s.directoryApprovalView(ctx, a, id, digest)
}
func (s *DirectoryService) directoryApprovalView(ctx context.Context, a DirectoryActor, id, digest string) (out *DirectoryApprovalView, err error) {
	err = s.current(ctx, a, true, true, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != digest {
			return ErrDirectoryStale
		}
		if e = s.currentDirectoryOperation(ctx, tx, h, r, true); e != nil {
			return e
		}
		out = &DirectoryApprovalView{OperationID: id, RequestDigest: digest}
		e = securitystate.One(ctx, tx, `SELECT id,reviewer_id FROM directory_provider_approvals WHERE operation_id=? AND request_digest=?`, []any{id, digest}, func(r storage.IdentityRows) error { return r.Scan(&out.ApprovalID, &out.ApprovedBy) })
		if e != nil {
			return e
		}
		if out.ApprovedBy != p.id {
			return storage.ErrPermissionDenied
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) ExecuteOperationRequest(ctx context.Context, a DirectoryActor, id, key, digest, reason string) (*ProviderSecurityOperation, error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) {
		return nil, ErrDirectoryInvalid
	}
	checked, e := s.operationPeopleContext(ctx, a, id, true, false)
	if e != nil {
		return nil, e
	}
	ctx = checked
	e = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != digest {
			return ErrDirectoryStale
		}
		if r.operation.State != "applied" {
			if e = s.currentDirectoryOperation(ctx, tx, h, r, true); e != nil {
				return e
			}
		}
		if e = directoryActionRequest(ctx, tx, h, p.id, "execute:"+id, key, digest, reason); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.directory.execution_requested", p.id, map[string]any{"operationId": id, "requestDigest": digest, "reason": reason})
	})
	if e != nil {
		return nil, e
	}
	return s.ExecuteOperation(ctx, a, id, digest)
}
