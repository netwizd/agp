package configuration

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type AuthoringReview struct {
	ID            string    `json:"id"`
	Purpose       string    `json:"purpose"`
	PreviewID     string    `json:"previewId"`
	PreviewDigest string    `json:"previewDigest"`
	AuthorID      string    `json:"authorId"`
	ReviewerID    string    `json:"reviewerId"`
	CreatedAt     time.Time `json:"createdAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Status        string    `json:"status"`
}

func subjectFingerprint(ctx context.Context, tx storage.IdentityTx, id string, h securityjournal.Head) (string, error) {
	if evidence, ok := tx.(*subjectEvidenceTx); ok && evidence.proofContext != nil {
		ctx = evidence.proofContext
	}
	witness, err := configurationSubject(ctx, tx, id, h)
	if err != nil {
		return "", subjectFailure(tx, err)
	}
	if evidence, ok := tx.(*subjectEvidenceTx); ok {
		if evidence.subjects == nil {
			evidence.subjects = map[string]configurationSubjectWitness{}
		}
		evidence.subjects[id] = witness
	}
	return witness.fingerprint, nil
}
func subjectCanSite(ctx context.Context, tx storage.IdentityTx, id, site string, h securityjournal.Head) error {
	return wafSubjectPermission(ctx, tx, id, "config.edit", site, h)
}

type reviewContext struct {
	author, previewAuthor, site, previewDigest, base, catalog, zone, report string
	expires                                                                 time.Time
}

func loadReviewContext(ctx context.Context, tx storage.IdentityTx, id string) (v reviewContext, e error) {
	e = securitystate.One(ctx, tx, `SELECT r.created_by,v.created_by,v.site_id,v.preview_digest,v.base_revision_id,v.catalog_id,v.zone_revision_id,v.report_json,v.expires_at FROM config_zone_previews v JOIN config_zone_revisions r ON r.id=v.zone_revision_id WHERE v.id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&v.author, &v.previewAuthor, &v.site, &v.previewDigest, &v.base, &v.catalog, &v.zone, &v.report, &v.expires)
	})
	return
}
func (s *Service) reviewFresh(ctx context.Context, tx storage.IdentityTx, v reviewContext) (err error) {
	defer func() { err = subjectFailure(tx, err) }()
	var report struct {
		HeadsDigest    string `json:"headsDigest"`
		ResolverDigest string `json:"resolverDigest"`
	}
	if e := json.Unmarshal([]byte(v.report), &report); e != nil {
		return e
	}
	currentResolver, e := s.zoneResolverDigest()
	if e != nil {
		return e
	}
	if report.ResolverDigest != currentResolver {
		return storage.ErrConflict
	}
	heads, e := zoneHeadsDigest(ctx, tx, v.site)
	if e != nil {
		return e
	}
	if report.HeadsDigest == "" || heads != report.HeadsDigest {
		return storage.ErrConflict
	}
	if !time.Now().Before(v.expires) {
		return storage.ErrConflict
	}
	head, _, e := readHead(ctx, tx)
	if e != nil {
		return e
	}
	if head != v.base {
		return storage.ErrConflict
	}
	latest, e := loadCatalog(ctx, tx, "")
	if e != nil {
		return e
	}
	if latest == nil || latest.Catalog.ID != v.catalog {
		return storage.ErrConflict
	}
	var zoneHead string
	e = securitystate.One(ctx, tx, `SELECT h.revision_id FROM config_zone_heads h JOIN config_zone_revisions r ON r.zone_id=h.zone_id WHERE r.id=?`, []any{v.zone}, func(r storage.IdentityRows) error { return r.Scan(&zoneHead) })
	if e != nil {
		return e
	}
	if zoneHead != v.zone {
		return storage.ErrConflict
	}
	return nil
}
func (s *Service) ReviewZonePreview(ctx context.Context, a Actor, id, key, previewDigest, reason string) (out *AuthoringReview, err error) {
	if !validID.MatchString(id) || utf8.RuneCountInString(strings.TrimSpace(reason)) < 8 || utf8.RuneCountInString(reason) > 1024 || len(reason) > 4096 {
		return nil, ErrInvalidRequest
	}
	fp := digest([]string{id, previewDigest, reason})
	op := "zone.draft_review:" + id
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "zone_preview", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadReviewContext(ctx, tx, id)
		if e != nil {
			return e
		}
		if e = p.RequireSiteSnapshot(ctx, tx, "config.edit", v.base, v.site); e != nil {
			return storage.ErrNotFound
		}
		if p.ID == v.author || p.ID == v.previewAuthor || v.previewDigest != previewDigest {
			return storage.ErrPermissionDenied
		}
		if e = distinctReviewPeople(ctx, tx, p.ID, v.author, v.previewAuthor); e != nil {
			return e
		}
		if e = subjectCanSite(ctx, tx, v.author, v.site, p.head); e != nil {
			return e
		}
		if e = s.reviewFresh(ctx, tx, v); e != nil {
			return e
		}
		var report struct {
			AuthoringValid bool `json:"authoringValid"`
		}
		if e = json.Unmarshal([]byte(v.report), &report); e != nil {
			return e
		}
		if !report.AuthoringValid {
			return storage.ErrConflict
		}
		authorFP, e := subjectFingerprint(ctx, tx, v.author, p.head)
		if e != nil {
			return e
		}
		reviewerFP, e := subjectFingerprint(ctx, tx, p.ID, p.head)
		if e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			var epoch int64
			var af, rf string
			e = securitystate.One(ctx, tx, `SELECT authority_epoch,author_fingerprint,reviewer_fingerprint FROM config_authoring_reviews WHERE id=?`, []any{h.id}, func(r storage.IdentityRows) error { return r.Scan(&epoch, &af, &rf) })
			if e != nil {
				return e
			}
			if epoch != p.Epoch || af != authorFP || rf != reviewerFP {
				return storage.ErrConflict
			}
			out, e = readAuthoringReview(ctx, tx, h.id)
			return e
		}
		now := time.Now().UTC()
		out = &AuthoringReview{ID: securitystate.ID("review"), Purpose: "draft_review", PreviewID: id, PreviewDigest: previewDigest, AuthorID: v.author, ReviewerID: p.ID, CreatedAt: now, ExpiresAt: v.expires, Status: "current"}
		raw, e := json.Marshal(out)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_authoring_reviews(id,preview_id,author_id,reviewer_id,authority_epoch,author_fingerprint,reviewer_fingerprint,review_json,created_at,expires_at,mfa_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, out.ID, id, v.author, p.ID, p.Epoch, authorFP, reviewerFP, string(raw), now, v.expires, p.MFAAt, reason); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"draft_review", out.ID, 0}); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "waf.zone.draft_reviewed", p.ID, map[string]any{"reviewId": out.ID, "previewId": id, "purpose": "draft_review", "epoch": strconv.FormatInt(p.Epoch, 10), "previewDigest": previewDigest})
	})
	return
}
func readAuthoringReview(ctx context.Context, tx storage.IdentityTx, id string) (*AuthoringReview, error) {
	var raw string
	e := securitystate.One(ctx, tx, `SELECT review_json FROM config_authoring_reviews WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
	if e != nil {
		return nil, e
	}
	var out AuthoringReview
	e = json.Unmarshal([]byte(raw), &out)
	return &out, e
}
func (s *Service) ZoneReviews(ctx context.Context, a Actor, id string) (out []AuthoringReview, err error) {
	out = []AuthoringReview{}
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "zone_reviews", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadReviewContext(ctx, tx, id)
		if e != nil {
			return e
		}
		if e = p.RequireSiteSnapshot(ctx, tx, "config.read", v.base, v.site); e != nil {
			return storage.ErrNotFound
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_authoring_reviews WHERE preview_id=? ORDER BY created_at DESC,id DESC LIMIT 200`, id)
		if e != nil {
			return e
		}
		for _, rid := range ids {
			r, e := readAuthoringReview(ctx, tx, rid)
			if e != nil {
				return e
			}
			var epoch int64
			var af, rf string
			e = securitystate.One(ctx, tx, `SELECT authority_epoch,author_fingerprint,reviewer_fingerprint FROM config_authoring_reviews WHERE id=?`, []any{rid}, func(rows storage.IdentityRows) error { return rows.Scan(&epoch, &af, &rf) })
			if e != nil {
				return e
			}
			nowAF, ae := subjectFingerprint(ctx, tx, r.AuthorID, p.head)
			nowRF, re := subjectFingerprint(ctx, tx, r.ReviewerID, p.head)
			people := currentReviewPeople(ctx, tx, r.ReviewerID, v.author, v.previewAuthor)
			if epoch != p.Epoch || ae != nil || re != nil || people != nil || af != nowAF || rf != nowRF || s.reviewFresh(ctx, tx, v) != nil {
				r.Status = "stale"
			}
			out = append(out, *r)
		}
		return nil
	})
	return
}
