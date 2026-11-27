package configuration

import (
	"context"
	"encoding/json"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type wafValidationRecord struct {
	report            WafPolicyValidation
	epoch             int64
	authorFingerprint string
}

func loadWafPolicyValidation(ctx context.Context, tx storage.IdentityTx, id string) (*wafValidationRecord, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	v := &wafValidationRecord{}
	var raw, revisionID, proofDigest string
	var expires time.Time
	err := securitystate.One(ctx, tx, `SELECT policy_revision_id,authority_epoch,author_fingerprint,qualification_digest,report_json,expires_at FROM config_waf_policy_validations WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&revisionID, &v.epoch, &v.authorFingerprint, &proofDigest, &raw, &expires)
	})
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(raw), &v.report); err != nil {
		return nil, err
	}
	if v.report.ID != id || v.report.PolicyRevisionID != revisionID || v.report.Qualification == nil || digest(v.report.Qualification) != proofDigest || v.report.QualificationDigest != proofDigest || !v.report.ExpiresAt.Truncate(time.Microsecond).Equal(expires) || !v.report.Qualification.ExpiresAt.Equal(v.report.ExpiresAt) || !v.report.Valid {
		return nil, storage.ErrConflict
	}
	return v, nil
}
func (s *Service) wafValidationCurrent(ctx context.Context, tx storage.IdentityTx, p *Principal, r *wafPolicyRecord, v *wafValidationRecord) error {
	if v.epoch != p.Epoch || v.report.PolicyRevisionID != r.revision.ID || v.report.ContentDigest != r.revision.ContentDigest || !time.Now().Before(v.report.ExpiresAt) {
		return storage.ErrConflict
	}
	if e := wafPolicyHeadCurrent(ctx, tx, r); e != nil {
		return e
	}
	if e := wafSubjectPermission(ctx, tx, r.authorID, "config.edit", r.siteID, p.head); e != nil {
		return e
	}
	authorFingerprint, e := subjectFingerprint(ctx, tx, r.authorID, p.head)
	if e != nil {
		return e
	}
	if authorFingerprint != v.authorFingerprint {
		return storage.ErrConflict
	}
	return s.wafProofCurrent(ctx, r, v.report.Qualification)
}
func wafAccepted(ctx context.Context, tx storage.IdentityTx, id string) (*AcceptedOperation, error) {
	var reportID string
	var created time.Time
	err := securitystate.One(ctx, tx, `SELECT validation_id,created_at FROM config_waf_policy_operations WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&reportID, &created) })
	if err != nil {
		return nil, err
	}
	return &AcceptedOperation{OperationID: id, ResourceID: reportID, StatusURL: "/api/v2/operations/" + id, SubmittedAt: created}, nil
}

func (s *Service) ValidateWafPolicyRevision(ctx context.Context, a Actor, id, key string) (out *AcceptedOperation, err error) {
	op, fp := "waf.policy.validate:"+id, digest([]string{id})
	var original *wafPolicyRecord
	var authorFingerprint string
	var epoch int64
	// Native compilation can be slow. Capture its exact input under the current
	// identity fence, then recheck the fence, rights and stable policy head when
	// committing the proof. No transaction is held while compiling.
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "policy_write", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readWafPolicyRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.edit", r.siteID) != nil {
			return storage.ErrNotFound
		}
		if e = wafPolicyHeadCurrent(ctx, tx, r); e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			accepted, e := wafAccepted(ctx, tx, h.id)
			if e != nil {
				return e
			}
			v, e := loadWafPolicyValidation(ctx, tx, accepted.ResourceID)
			if e != nil {
				return e
			}
			if e = s.wafValidationCurrent(ctx, tx, p, r, v); e != nil {
				return e
			}
			out = accepted
			return nil
		}
		if s.wafQualifier == nil {
			return wafNativeRequired()
		}
		if e = wafSubjectPermission(ctx, tx, r.authorID, "config.edit", r.siteID, p.head); e != nil {
			return e
		}
		authorFingerprint, e = subjectFingerprint(ctx, tx, r.authorID, p.head)
		original, epoch = r, p.Epoch
		return e
	})
	if err != nil || out != nil {
		return
	}
	qualification, err := s.wafQualifier.ValidatePolicy(ctx, *original.policy)
	if err != nil {
		return nil, err
	}
	if err = s.wafProofCurrent(ctx, original, qualification); err != nil {
		return nil, err
	}
	// Own the proof value: a provider must not be able to mutate a saved report
	// through a retained pointer after validation returns.
	proof := *qualification
	report := WafPolicyValidation{ID: securitystate.ID("wvalidation"), PolicyRevisionID: id, ContentDigest: original.revision.ContentDigest, Qualification: &proof, QualificationDigest: digest(proof), Valid: true, Deployable: false, Issues: []configmodel.Issue{}, CreatedAt: time.Now().UTC(), ExpiresAt: proof.ExpiresAt}
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "policy_write", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readWafPolicyRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.edit", r.siteID) != nil {
			return storage.ErrNotFound
		}
		if epoch != p.Epoch {
			return storage.ErrConflict
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			accepted, e := wafAccepted(ctx, tx, h.id)
			if e != nil {
				return e
			}
			v, e := loadWafPolicyValidation(ctx, tx, accepted.ResourceID)
			if e != nil {
				return e
			}
			if e = s.wafValidationCurrent(ctx, tx, p, r, v); e != nil {
				return e
			}
			out = accepted
			return nil
		}
		v := &wafValidationRecord{report: report, epoch: epoch, authorFingerprint: authorFingerprint}
		if e = s.wafValidationCurrent(ctx, tx, p, r, v); e != nil {
			return e
		}
		raw, e := json.Marshal(report)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_validations(id,policy_revision_id,authority_epoch,author_fingerprint,qualification_digest,report_json,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, report.ID, id, p.Epoch, authorFingerprint, report.QualificationDigest, string(raw), p.ID, report.CreatedAt, report.ExpiresAt.Truncate(time.Microsecond))
		if e != nil {
			return e
		}
		operationID := securitystate.ID("operation")
		_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_operations(id,validation_id,state,created_at) VALUES(?,?,'succeeded',?)`, operationID, report.ID, report.CreatedAt)
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"waf_operation", operationID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.policy.validation.completed", p.ID, map[string]any{"policyRevisionId": id, "contentDigest": report.ContentDigest, "validationId": report.ID, "qualificationDigest": report.QualificationDigest, "deployable": false}); e != nil {
			return e
		}
		out, e = wafAccepted(ctx, tx, operationID)
		return e
	})
	return
}

func (s *Service) GetWafPolicyValidation(ctx context.Context, a Actor, id string) (out *WafPolicyValidation, err error) {
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "policy_validation", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadWafPolicyValidation(ctx, tx, id)
		if e != nil {
			return e
		}
		r, e := readWafPolicyRecord(ctx, tx, v.report.PolicyRevisionID)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.siteID) != nil {
			return storage.ErrNotFound
		}
		out = &v.report
		out.Current = s.wafValidationCurrent(ctx, tx, p, r, v) == nil
		return nil
	})
	return
}
func (s *Service) GetWafPolicyOperation(ctx context.Context, a Actor, id string) (out *Operation, err error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		var reportID string
		out = &Operation{ID: id}
		e := securitystate.One(ctx, tx, `SELECT validation_id,state,created_at FROM config_waf_policy_operations WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&reportID, &out.State, &out.CreatedAt) })
		if e != nil {
			return e
		}
		v, e := loadWafPolicyValidation(ctx, tx, reportID)
		if e != nil {
			return e
		}
		r, e := readWafPolicyRecord(ctx, tx, v.report.PolicyRevisionID)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.siteID) != nil {
			return storage.ErrNotFound
		}
		out.ResourceID, out.UpdatedAt = reportID, out.CreatedAt
		return nil
	})
	return
}

type wafApprovalRecord struct {
	id, revisionID, validationID, contentDigest, qualificationDigest, authorID, approverID, authorFingerprint, approverFingerprint string
	epoch                                                                                                                          int64
	created, expires, mfa                                                                                                          time.Time
}

func readWafApproval(ctx context.Context, tx storage.IdentityTx, id string) (*wafApprovalRecord, error) {
	v := &wafApprovalRecord{id: id}
	err := securitystate.One(ctx, tx, `SELECT policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at FROM config_waf_policy_approvals WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&v.revisionID, &v.validationID, &v.contentDigest, &v.qualificationDigest, &v.authorID, &v.approverID, &v.epoch, &v.authorFingerprint, &v.approverFingerprint, &v.created, &v.expires, &v.mfa)
	})
	return v, err
}
func (s *Service) currentWafApproval(ctx context.Context, tx storage.IdentityTx, p *Principal, r *wafPolicyRecord, id string) (out *wafApprovalRecord, err error) {
	defer func() { err = subjectFailure(tx, err) }()
	v, err := readWafApproval(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if v.revisionID != r.revision.ID || v.contentDigest != r.revision.ContentDigest || v.authorID != r.authorID || v.authorID == v.approverID || v.epoch != p.Epoch || !time.Now().Before(v.expires) || v.expires.Sub(v.created) > 30*time.Minute || v.mfa.Before(v.created.Add(-5*time.Minute)) || v.mfa.After(v.created) {
		return nil, storage.ErrConflict
	}
	if err := currentReviewPeople(ctx, tx, v.approverID, v.authorID); err != nil {
		return nil, err
	}
	if err = wafSubjectPermission(ctx, tx, v.approverID, "config.approve", r.siteID, p.head); err != nil {
		return nil, err
	}
	if err = wafSubjectPermission(ctx, tx, v.approverID, "config.read", r.siteID, p.head); err != nil {
		return nil, err
	}
	approverFP, err := subjectFingerprint(ctx, tx, v.approverID, p.head)
	if err != nil {
		return nil, err
	}
	authorFP, err := subjectFingerprint(ctx, tx, v.authorID, p.head)
	if err != nil {
		return nil, err
	}
	if approverFP != v.approverFingerprint || authorFP != v.authorFingerprint {
		return nil, storage.ErrConflict
	}
	validation, err := loadWafPolicyValidation(ctx, tx, v.validationID)
	if err != nil {
		return nil, err
	}
	if validation.report.QualificationDigest != v.qualificationDigest || v.expires.After(validation.report.ExpiresAt) {
		return nil, storage.ErrConflict
	}
	if err = s.wafValidationCurrent(ctx, tx, p, r, validation); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Service) ApproveWafPolicyRevision(ctx context.Context, a Actor, id, key string, in WafPolicyApprovalRequest) (out *WafPolicyApproval, err error) {
	if !configmodel.ValidDigest(in.ContentDigest) || !wafValidReason(in.Reason) {
		return nil, ErrInvalidRequest
	}
	op, fp := "waf.policy.approve:"+id, digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "policy_write", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readWafPolicyRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.approve", r.siteID) != nil || p.Require("config.read", r.siteID) != nil {
			return storage.ErrPermissionDenied
		}
		if p.ID == r.authorID {
			return storage.ErrPermissionDenied
		}
		if e = distinctReviewPeople(ctx, tx, p.ID, r.authorID); e != nil {
			return e
		}
		if in.ContentDigest != r.revision.ContentDigest {
			return storage.ErrConflict
		}
		if e = wafPolicyHeadCurrent(ctx, tx, r); e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			v, e := s.currentWafApproval(ctx, tx, p, r, h.id)
			if e != nil {
				return e
			}
			out = &WafPolicyApproval{ApprovalID: v.id, ContentDigest: v.contentDigest}
			return nil
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_waf_policy_validations WHERE policy_revision_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, id)
		if e != nil {
			return e
		}
		var validation *wafValidationRecord
		for _, validationID := range ids {
			v, e := loadWafPolicyValidation(ctx, tx, validationID)
			if e != nil {
				return e
			}
			if e = s.wafValidationCurrent(ctx, tx, p, r, v); e == nil {
				validation = v
				break
			}
		}
		if validation == nil {
			return wafNativeRequired()
		}
		authorFP, e := subjectFingerprint(ctx, tx, r.authorID, p.head)
		if e != nil {
			return e
		}
		approverFP, e := subjectFingerprint(ctx, tx, p.ID, p.head)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		if p.MFAAt.After(now) {
			return storage.ErrPermissionDenied
		}
		expires := now.Add(30 * time.Minute)
		if validation.report.ExpiresAt.Before(expires) {
			expires = validation.report.ExpiresAt
		}
		approvalID := securitystate.ID("wapproval")
		_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_approvals(id,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, approvalID, id, validation.report.ID, in.ContentDigest, validation.report.QualificationDigest, r.authorID, p.ID, p.Epoch, authorFP, approverFP, now, expires, p.MFAAt, in.Reason)
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"waf_approval", approvalID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.policy.approved", p.ID, map[string]any{"policyRevisionId": id, "contentDigest": in.ContentDigest, "approvalId": approvalID, "qualificationDigest": validation.report.QualificationDigest, "authorId": r.authorID, "expiresAt": expires}); e != nil {
			return e
		}
		out = &WafPolicyApproval{ApprovalID: approvalID, ContentDigest: in.ContentDigest}
		return nil
	})
	return
}

func (s *Service) PublishWafPolicyRevision(ctx context.Context, a Actor, id, key string, in WafPolicyPublicationRequest) (out *WafPolicyRevision, err error) {
	if !configmodel.ValidDigest(in.ContentDigest) {
		return nil, ErrInvalidRequest
	}
	op, fp := "waf.policy.publish:"+id, digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "policy_publish", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readWafPolicyRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.approve", r.siteID) != nil || p.Require("config.read", r.siteID) != nil {
			return storage.ErrPermissionDenied
		}
		if in.ContentDigest != r.revision.ContentDigest {
			return storage.ErrConflict
		}
		if e = wafPolicyHeadCurrent(ctx, tx, r); e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			var approvalID string
			var epoch int64
			e = securitystate.One(ctx, tx, `SELECT approval_id,authority_epoch FROM config_waf_policy_publications WHERE id=? AND policy_revision_id=?`, []any{h.id, id}, func(rows storage.IdentityRows) error { return rows.Scan(&approvalID, &epoch) })
			if e != nil {
				return e
			}
			if epoch != p.Epoch {
				return storage.ErrConflict
			}
			if _, e = s.currentWafApproval(ctx, tx, p, r, approvalID); e != nil {
				return e
			}
			out = &r.revision
			out.State = "published"
			return nil
		}
		// A second request key cannot silently substitute a different approval
		// for the proof recorded in an existing immutable publication.
		prior, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_waf_policy_publications WHERE policy_revision_id=?`, id)
		if e != nil {
			return e
		}
		if len(prior) > 0 {
			var originalApproval string
			var originalEpoch int64
			e = securitystate.One(ctx, tx, `SELECT approval_id,authority_epoch FROM config_waf_policy_publications WHERE id=?`, []any{prior[0]}, func(rows storage.IdentityRows) error { return rows.Scan(&originalApproval, &originalEpoch) })
			if e != nil {
				return e
			}
			if originalEpoch != p.Epoch {
				return storage.ErrConflict
			}
			if _, e = s.currentWafApproval(ctx, tx, p, r, originalApproval); e != nil {
				return e
			}
			if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"waf_publication", prior[0], 0}); e != nil {
				return e
			}
			out = &r.revision
			out.State = "published"
			return nil
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_waf_policy_approvals WHERE policy_revision_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, id)
		if e != nil {
			return e
		}
		var approval *wafApprovalRecord
		for _, approvalID := range ids {
			v, e := s.currentWafApproval(ctx, tx, p, r, approvalID)
			if e == nil {
				approval = v
				break
			}
		}
		if approval == nil {
			return storage.ErrConflict
		}
		publicationID := securitystate.ID("wpublication")
		_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_publications(id,policy_revision_id,approval_id,authority_epoch,content_digest,qualification_digest,published_by,created_at,mfa_at) VALUES(?,?,?,?,?,?,?,?,?)`, publicationID, id, approval.id, p.Epoch, in.ContentDigest, approval.qualificationDigest, p.ID, time.Now().UTC(), p.MFAAt)
		if e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.policy.published", p.ID, map[string]any{"policyRevisionId": id, "contentDigest": in.ContentDigest, "publicationId": publicationID, "approvalId": approval.id, "qualificationDigest": approval.qualificationDigest, "apply": false}); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"waf_publication", publicationID, 0}); e != nil {
			return e
		}
		out = &r.revision
		out.State = "published"
		return nil
	})
	return
}
