package configuration

import (
	"context"
	"encoding/json"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type zoneValidationRecord struct {
	report            ZoneValidation
	epoch             int64
	authorFingerprint string
}

func loadZoneValidation(ctx context.Context, tx storage.IdentityTx, id string) (*zoneValidationRecord, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	out := &zoneValidationRecord{}
	var raw, revision, dependency string
	var expires time.Time
	e := securitystate.One(ctx, tx, `SELECT zone_revision_id,authority_epoch,author_fingerprint,dependency_digest,report_json,expires_at FROM config_zone_validations WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&revision, &out.epoch, &out.authorFingerprint, &dependency, &raw, &expires)
	})
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(raw), &out.report); e != nil {
		return nil, e
	}
	r := out.report
	if r.ID != id || r.ZoneRevisionID != revision || r.DependencyDigest != dependency || !configmodel.ValidDigest(dependency) || r.Qualification == nil || !r.Valid || r.Deployable || !r.ExpiresAt.Truncate(time.Microsecond).Equal(expires) || r.ExpiresAt.After(r.CreatedAt.Add(30*time.Minute)) || !r.ExpiresAt.After(r.CreatedAt) {
		return nil, storage.ErrConflict
	}
	return out, nil
}
func (s *Service) zoneValidationCurrent(ctx context.Context, tx storage.IdentityTx, p *Principal, r *zoneRecord, v *zoneValidationRecord) error {
	if v.epoch != p.Epoch || v.report.ZoneRevisionID != r.revision.ID || v.report.ContentDigest != r.revision.ContentDigest || !time.Now().Before(v.report.ExpiresAt) {
		return storage.ErrConflict
	}
	if e := zoneHeadCurrent(ctx, tx, r); e != nil {
		return e
	}
	if e := wafSubjectPermission(ctx, tx, r.author, "config.edit", r.revision.SiteID, p.head); e != nil {
		return e
	}
	fp, e := subjectFingerprint(ctx, tx, r.author, p.head)
	if e != nil {
		return e
	}
	if fp != v.authorFingerprint {
		return storage.ErrConflict
	}
	policy, dependency, e := s.zoneDependency(ctx, tx, p, r)
	if e != nil {
		return e
	}
	if dependency != v.report.DependencyDigest || policy.record.revision.ID != v.report.PolicyRevisionID || policy.publicationID != v.report.PolicyPublicationID || digest(policy.proof) != digest(v.report.Qualification) {
		return storage.ErrConflict
	}
	return nil
}
func zoneAccepted(ctx context.Context, tx storage.IdentityTx, id string) (*AcceptedOperation, error) {
	var report string
	var created time.Time
	e := securitystate.One(ctx, tx, `SELECT validation_id,created_at FROM config_zone_operations WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&report, &created) })
	if e != nil {
		return nil, e
	}
	return &AcceptedOperation{OperationID: id, ResourceID: report, StatusURL: "/api/v2/operations/" + id, SubmittedAt: created}, nil
}
func (s *Service) ValidateZoneRevision(ctx context.Context, a Actor, id, key string) (out *AcceptedOperation, err error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	op, fp := "zone.validate:"+id, digest([]string{id})
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "zone_write", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := loadZoneRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.edit", r.revision.SiteID) != nil {
			return storage.ErrNotFound
		}
		if e = zoneHeadCurrent(ctx, tx, r); e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			accepted, e := zoneAccepted(ctx, tx, h.id)
			if e != nil {
				return e
			}
			v, e := loadZoneValidation(ctx, tx, accepted.ResourceID)
			if e != nil {
				return e
			}
			if e = s.zoneValidationCurrent(ctx, tx, p, r, v); e != nil {
				return e
			}
			out = accepted
			return nil
		}
		if e = wafSubjectPermission(ctx, tx, r.author, "config.edit", r.revision.SiteID, p.head); e != nil {
			return e
		}
		authorFP, e := subjectFingerprint(ctx, tx, r.author, p.head)
		if e != nil {
			return e
		}
		policy, dependency, e := s.zoneDependency(ctx, tx, p, r)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		expires := now.Add(30 * time.Minute)
		if policy.proof.ExpiresAt.Before(expires) {
			expires = policy.proof.ExpiresAt
		}
		if !expires.After(now) {
			return storage.ErrConflict
		}
		proof := policy.proof
		report := ZoneValidation{ID: securitystate.ID("zvalidation"), ZoneRevisionID: id, ContentDigest: r.revision.ContentDigest, PolicyRevisionID: policy.record.revision.ID, PolicyPublicationID: policy.publicationID, Qualification: &proof, DependencyDigest: dependency, Valid: true, Deployable: false, Issues: []configmodel.Issue{}, CreatedAt: now, ExpiresAt: expires}
		raw, e := json.Marshal(report)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_zone_validations(id,zone_revision_id,authority_epoch,author_fingerprint,dependency_digest,report_json,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, report.ID, id, p.Epoch, authorFP, dependency, string(raw), p.ID, now, expires.Truncate(time.Microsecond)); e != nil {
			return e
		}
		operation := securitystate.ID("operation")
		if _, e = tx.Exec(ctx, `INSERT INTO config_zone_operations(id,validation_id,created_at) VALUES(?,?,?)`, operation, report.ID, now); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"zone_operation", operation, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.zone.validation.completed", p.ID, map[string]any{"zoneRevisionId": id, "validationId": report.ID, "contentDigest": report.ContentDigest, "dependencyDigest": dependency, "deployable": false}); e != nil {
			return e
		}
		out, e = zoneAccepted(ctx, tx, operation)
		return e
	})
	return
}
func (s *Service) GetZoneValidation(ctx context.Context, a Actor, id string) (out *ZoneValidation, err error) {
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "zone_validation", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadZoneValidation(ctx, tx, id)
		if e != nil {
			return e
		}
		r, e := loadZoneRecord(ctx, tx, v.report.ZoneRevisionID)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.revision.SiteID) != nil {
			return storage.ErrNotFound
		}
		out = &v.report
		out.Current = s.zoneValidationCurrent(ctx, tx, p, r, v) == nil
		return nil
	})
	return
}
func (s *Service) GetZoneOperation(ctx context.Context, a Actor, id string) (out *Operation, err error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		accepted, e := zoneAccepted(ctx, tx, id)
		if e == storage.ErrNotFound {
			var resolutionID string
			e = securitystate.One(ctx, tx, `SELECT id FROM config_zone_resolutions WHERE operation_id=?`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&resolutionID) })
			if e == nil {
				v, e := loadZoneResolution(ctx, tx, resolutionID)
				if e != nil {
					return e
				}
				if e = p.RequireSiteSnapshot(ctx, tx, "config.read", v.report.BaseConfigRevisionID, v.report.SiteID); e != nil {
					return storage.ErrNotFound
				}
				out = &Operation{ID: id, ResourceID: resolutionID, State: "succeeded", CreatedAt: v.created, UpdatedAt: v.created}
				return nil
			}
			if e != storage.ErrNotFound {
				return e
			}
			var changeID string
			e = securitystate.One(ctx, tx, `SELECT id FROM config_zone_changes WHERE operation_id=?`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&changeID) })
			if e != nil {
				return e
			}
			v, _, created, e := loadZoneChange(ctx, tx, changeID)
			if e != nil {
				return e
			}
			r, e := loadZoneResolution(ctx, tx, v.Request.ResolutionID)
			if e != nil {
				return e
			}
			if e = p.RequireSiteSnapshot(ctx, tx, "config.read", r.report.BaseConfigRevisionID, r.report.SiteID); e != nil {
				return storage.ErrNotFound
			}
			out = &Operation{ID: id, ResourceID: changeID, State: "succeeded", CreatedAt: created, UpdatedAt: created}
			return nil
		}
		if e != nil {
			return e
		}
		v, e := loadZoneValidation(ctx, tx, accepted.ResourceID)
		if e != nil {
			return e
		}
		r, e := loadZoneRecord(ctx, tx, v.report.ZoneRevisionID)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.revision.SiteID) != nil {
			return storage.ErrNotFound
		}
		out = &Operation{ID: id, ResourceID: accepted.ResourceID, State: "succeeded", CreatedAt: accepted.SubmittedAt, UpdatedAt: accepted.SubmittedAt}
		return nil
	})
	return
}
func readZoneApproval(ctx context.Context, tx storage.IdentityTx, id string) (*wafApprovalRecord, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	v := &wafApprovalRecord{id: id}
	e := securitystate.One(ctx, tx, `SELECT zone_revision_id,validation_id,content_digest,dependency_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at FROM config_zone_approvals WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&v.revisionID, &v.validationID, &v.contentDigest, &v.qualificationDigest, &v.authorID, &v.approverID, &v.epoch, &v.authorFingerprint, &v.approverFingerprint, &v.created, &v.expires, &v.mfa)
	})
	return v, e
}
func (s *Service) currentZoneApproval(ctx context.Context, tx storage.IdentityTx, p *Principal, r *zoneRecord, id string) (out *wafApprovalRecord, err error) {
	defer func() { err = subjectFailure(tx, err) }()
	v, e := readZoneApproval(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	if v.revisionID != r.revision.ID || v.contentDigest != r.revision.ContentDigest || v.authorID != r.author || v.authorID == v.approverID || v.epoch != p.Epoch || !time.Now().Before(v.expires) || v.expires.Sub(v.created) > 30*time.Minute || v.mfa.Before(v.created.Add(-5*time.Minute)) || v.mfa.After(v.created) {
		return nil, storage.ErrConflict
	}
	if err := currentReviewPeople(ctx, tx, v.approverID, v.authorID); err != nil {
		return nil, err
	}
	for _, permission := range []string{"config.approve", "config.read"} {
		if e = wafSubjectPermission(ctx, tx, v.approverID, permission, r.revision.SiteID, p.head); e != nil {
			return nil, e
		}
	}
	author, e := subjectFingerprint(ctx, tx, v.authorID, p.head)
	if e != nil {
		return nil, e
	}
	approver, e := subjectFingerprint(ctx, tx, v.approverID, p.head)
	if e != nil {
		return nil, e
	}
	if author != v.authorFingerprint || approver != v.approverFingerprint {
		return nil, storage.ErrConflict
	}
	validation, e := loadZoneValidation(ctx, tx, v.validationID)
	if e != nil {
		return nil, e
	}
	if v.qualificationDigest != validation.report.DependencyDigest || v.expires.After(validation.report.ExpiresAt) {
		return nil, storage.ErrConflict
	}
	if e = s.zoneValidationCurrent(ctx, tx, p, r, validation); e != nil {
		return nil, e
	}
	return v, nil
}
func (s *Service) ApproveZoneRevision(ctx context.Context, a Actor, id, key string, in WafPolicyApprovalRequest) (out *WafPolicyApproval, err error) {
	if !configmodel.ValidDigest(in.ContentDigest) || !wafValidReason(in.Reason) {
		return nil, ErrInvalidRequest
	}
	op, fp := "zone.approve:"+id, digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "zone_write", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := loadZoneRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.revision.SiteID) != nil {
			return storage.ErrNotFound
		}
		if p.Require("config.approve", r.revision.SiteID) != nil || p.ID == r.author {
			return storage.ErrPermissionDenied
		}
		if e = distinctReviewPeople(ctx, tx, p.ID, r.author); e != nil {
			return e
		}
		if in.ContentDigest != r.revision.ContentDigest {
			return storage.ErrConflict
		}
		if e = zoneHeadCurrent(ctx, tx, r); e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			v, e := s.currentZoneApproval(ctx, tx, p, r, h.id)
			if e != nil {
				return e
			}
			out = &WafPolicyApproval{ApprovalID: v.id, ContentDigest: v.contentDigest}
			return nil
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_zone_validations WHERE zone_revision_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, id)
		if e != nil {
			return e
		}
		var validation *zoneValidationRecord
		for _, validationID := range ids {
			v, e := loadZoneValidation(ctx, tx, validationID)
			if e != nil {
				return e
			}
			if s.zoneValidationCurrent(ctx, tx, p, r, v) == nil {
				validation = v
				break
			}
		}
		if validation == nil {
			return wafNativeRequired()
		}
		author, e := subjectFingerprint(ctx, tx, r.author, p.head)
		if e != nil {
			return e
		}
		approver, e := subjectFingerprint(ctx, tx, p.ID, p.head)
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
		approval := securitystate.ID("zapproval")
		if _, e = tx.Exec(ctx, `INSERT INTO config_zone_approvals(id,zone_revision_id,validation_id,content_digest,dependency_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, approval, id, validation.report.ID, in.ContentDigest, validation.report.DependencyDigest, r.author, p.ID, p.Epoch, author, approver, now, expires, p.MFAAt, in.Reason); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"zone_approval", approval, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.zone.approved", p.ID, map[string]any{"zoneRevisionId": id, "contentDigest": in.ContentDigest, "approvalId": approval, "dependencyDigest": validation.report.DependencyDigest, "authorId": r.author, "expiresAt": expires}); e != nil {
			return e
		}
		out = &WafPolicyApproval{ApprovalID: approval, ContentDigest: in.ContentDigest}
		return nil
	})
	return
}
func (s *Service) PublishZoneRevision(ctx context.Context, a Actor, id, key string, in WafPolicyPublicationRequest) (out *ZoneRevision, err error) {
	if !configmodel.ValidDigest(in.ContentDigest) {
		return nil, ErrInvalidRequest
	}
	op, fp := "zone.publish:"+id, digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "zone_publish", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		r, e := loadZoneRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.revision.SiteID) != nil {
			return storage.ErrNotFound
		}
		if p.Require("config.approve", r.revision.SiteID) != nil {
			return storage.ErrPermissionDenied
		}
		if in.ContentDigest != r.revision.ContentDigest {
			return storage.ErrConflict
		}
		if e = zoneHeadCurrent(ctx, tx, r); e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		publication := ""
		if h != nil {
			publication = h.id
		} else {
			ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_zone_publications WHERE zone_revision_id=?`, id)
			if e != nil {
				return e
			}
			if len(ids) > 0 {
				publication = ids[0]
			}
		}
		if publication != "" {
			var approval string
			var epoch int64
			e = securitystate.One(ctx, tx, `SELECT approval_id,authority_epoch FROM config_zone_publications WHERE id=? AND zone_revision_id=?`, []any{publication, id}, func(rows storage.IdentityRows) error { return rows.Scan(&approval, &epoch) })
			if e != nil {
				return e
			}
			if epoch != p.Epoch {
				return storage.ErrConflict
			}
			if _, e = s.currentZoneApproval(ctx, tx, p, r, approval); e != nil {
				return e
			}
			if h == nil {
				if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"zone_publication", publication, 0}); e != nil {
					return e
				}
			}
		} else {
			ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_zone_approvals WHERE zone_revision_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, id)
			if e != nil {
				return e
			}
			var approval *wafApprovalRecord
			for _, approvalID := range ids {
				if v, e := s.currentZoneApproval(ctx, tx, p, r, approvalID); e == nil {
					approval = v
					break
				}
			}
			if approval == nil {
				return storage.ErrConflict
			}
			publication = securitystate.ID("zpublication")
			if _, e = tx.Exec(ctx, `INSERT INTO config_zone_publications(id,zone_revision_id,approval_id,authority_epoch,content_digest,dependency_digest,published_by,created_at,mfa_at) VALUES(?,?,?,?,?,?,?,?,?)`, publication, id, approval.id, p.Epoch, in.ContentDigest, approval.qualificationDigest, p.ID, time.Now().UTC(), p.MFAAt); e != nil {
				return e
			}
			if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"zone_publication", publication, 0}); e != nil {
				return e
			}
			if e = securitystate.Audit(ctx, tx, "config.waf.zone.published", p.ID, map[string]any{"zoneRevisionId": id, "contentDigest": in.ContentDigest, "publicationId": publication, "approvalId": approval.id, "dependencyDigest": approval.qualificationDigest, "apply": false}); e != nil {
				return e
			}
		}
		out = r.revision
		out.State = "published"
		return nil
	})
	return
}
