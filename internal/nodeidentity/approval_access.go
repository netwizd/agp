package nodeidentity

import (
	"context"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// This private witness uses the existing request ledger. It is never returned
// by an enrollment DTO, and a saved deadline is never a substitute for a fresh
// session/directory check at issuance.
type enrollmentApprovalEvidence struct {
	Version              int                    `json:"version"`
	Actor                string                 `json:"actor"`
	EnrollmentID         string                 `json:"enrollmentId"`
	NodeID               string                 `json:"nodeId"`
	TokenHash            string                 `json:"tokenHash"`
	Origin               string                 `json:"origin"`
	Epoch                securityjournal.UInt63 `json:"epoch"`
	ExpiresAt            time.Time              `json:"expiresAt"`
	AccessFingerprint    string                 `json:"accessFingerprint"`
	DirectoryFingerprint string                 `json:"directoryFingerprint"`
}

func enrollmentEvidence(ctx context.Context, tx storage.IdentityTx, r *enrollmentRow) (enrollmentApprovalEvidence, string, error) {
	var evidence enrollmentApprovalEvidence
	var raw, fingerprint string
	var epoch uint64
	err := securitystate.One(ctx, tx, `SELECT result_json,request_digest,authority_epoch FROM node_identity_requests WHERE actor_id=? AND operation='enrollment_approval_evidence' AND request_key=?`, []any{r.ApprovedBy, r.ID}, func(rows storage.IdentityRows) error { return rows.Scan(&raw, &fingerprint, &epoch) })
	if err != nil {
		return evidence, "", err
	}
	if decodeJSON(raw, &evidence) != nil || evidence.Version != 1 || evidence.Actor != r.ApprovedBy || evidence.EnrollmentID != r.ID || evidence.NodeID != r.NodeID || evidence.Epoch != securityjournal.UInt63(epoch) || int64(evidence.Epoch) != r.Epoch || evidence.TokenHash == "" || evidence.Origin == "" || evidence.ExpiresAt.IsZero() || !digestPattern.MatchString(evidence.AccessFingerprint) || (evidence.DirectoryFingerprint != "" && !digestPattern.MatchString(evidence.DirectoryFingerprint)) {
		return evidence, "", ErrDenied
	}
	return evidence, fingerprint, nil
}

// Management proof refresh must run outside the writer transaction. The main
// issuance transaction rereads every pin; this preflight authorizes no action.
func (s *Service) withEnrollmentApproval(ctx context.Context, in EnrollmentSubmission, fn func(context.Context) error) error {
	var token string
	var limited error
	err := s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if e := limit(ctx, tx, "enrollment_global", h.RecordedAt, 120); e != nil {
			limited = e
			return nil
		}
		if e := limit(ctx, tx, "enrollment_"+hash([]byte(in.EnrollmentToken)), h.RecordedAt, 15); e != nil {
			limited = e
			return nil
		}
		r, err := enrollmentBy(ctx, tx, "token_hash", hash([]byte(in.EnrollmentToken)))
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.NodeID != in.NodeID || r.State != "approved" {
			return nil
		}
		evidence, _, err := enrollmentEvidence(ctx, tx, r)
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		token = evidence.TokenHash
		return nil
	})
	if err != nil {
		return err
	}
	if limited != nil {
		return limited
	}
	if token == "" {
		return fn(ctx)
	}
	return securitystate.WithManagementSession(ctx, token, s.current, fn)
}

func (s *Service) approvalAccess(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, r *enrollmentRow) (*inventory.NodeAccess, time.Time, error) {
	if r.ApprovedBy == "" || r.ApprovalSecurityVersion == 0 || r.ApprovalPasswordVersion == 0 {
		return nil, time.Time{}, ErrDenied
	}
	evidence, saved, err := enrollmentEvidence(ctx, tx, r)
	legacy := errors.Is(err, storage.ErrNotFound)
	if err != nil && !legacy {
		return nil, time.Time{}, err
	}
	var access *inventory.NodeAccess
	if legacy {
		access, err = inventory.ReadNodeSubjectAccess(ctx, tx, h, r.ApprovedBy, "nodes.enroll")
	} else {
		if evidence.Origin != s.origin || !h.RecordedAt.Before(evidence.ExpiresAt) {
			return nil, time.Time{}, ErrDenied
		}
		access, err = inventory.ReadNodeAccess(ctx, tx, h, s.current, evidence.TokenHash, evidence.Origin, "nodes.enroll", true)
	}
	if errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, storage.ErrNotFound) {
		return nil, time.Time{}, ErrDenied
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if access.ID != r.ApprovedBy {
		return nil, time.Time{}, ErrDenied
	}
	if err = requireNode(ctx, tx, access, r.NodeID); err != nil {
		return nil, time.Time{}, err
	}
	var admin bool
	var kind string
	var sv, pv uint64
	err = securitystate.One(ctx, tx, `SELECT is_admin,identity_kind,security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL AND lifecycle_state='active'`, []any{r.ApprovedBy}, func(rows storage.IdentityRows) error { return rows.Scan(&admin, &kind, &sv, &pv) })
	if errors.Is(err, storage.ErrNotFound) {
		return nil, time.Time{}, ErrDenied
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if sv != r.ApprovalSecurityVersion || pv != r.ApprovalPasswordVersion {
		return nil, time.Time{}, ErrDenied
	}
	deadline := r.ExpiresAt
	if legacy {
		if !admin || kind != "local" || r.ApprovalDigest != legacyEnrollmentApproval(r.ApprovedBy, r.ID, r.PublicKeyDigest, r.RequestDigest, sv, pv, h.Epoch) {
			return nil, time.Time{}, ErrDenied
		}
		if err = access.FinishSubject(ctx, tx, s.current); err != nil {
			return nil, time.Time{}, err
		}
	} else {
		directory, err := identity.DirectorySubjectFingerprint(ctx, tx, h, r.ApprovedBy)
		if err != nil {
			return nil, time.Time{}, err
		}
		want := enrollmentApprovalDigest(r.ApprovedBy, r.ID, r.PublicKeyDigest, r.RequestDigest, sv, pv, h.Epoch, digest(evidence))
		if saved != want || r.ApprovalDigest != want || evidence.AccessFingerprint != access.Fingerprint() || evidence.DirectoryFingerprint != directory {
			return nil, time.Time{}, ErrDenied
		}
		if err = access.Finish(ctx, tx, s.current, evidence.TokenHash, evidence.Origin, true); err != nil {
			return nil, time.Time{}, err
		}
		deadline = access.AuthorizationDeadline(evidence.ExpiresAt)
		proofUntil, err := identity.DirectorySubjectProofDeadline(ctx, tx, h, r.ApprovedBy)
		if err != nil {
			return nil, time.Time{}, err
		}
		if !proofUntil.IsZero() && proofUntil.Before(deadline) {
			deadline = proofUntil
		}
	}
	if r.ExpiresAt.Before(deadline) {
		deadline = r.ExpiresAt
	}
	return access, deadline, nil
}
