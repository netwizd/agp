package configuration

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// directorySubjectSelection is internal server-selected provenance, not an API
// request. Selection runs in an authorized read transaction. Network proofs are
// obtained only after that transaction ends; the original command then executes
// once and rechecks every fingerprint against its actual final journal head.
// It intentionally does not replay a transaction callback: its captured Go
// results and other in-memory state cannot be rolled back with SQL.
type directorySubjectSelection struct {
	Kind, ID, SiteID, RevisionID, ReviewID, Cursor string
	RequestKey                                     string
	Limit                                          int
	ZoneRevisionIDs                                []string
}

// A 200-review response can have 201 distinct participants including its author.
// This bounds exact historical participants, never a scan of directory users.
const maxDirectoryHistoricalSubjects = 256
const maxDirectorySubjectRecords = 4096

type directorySubjectCollector struct {
	ctx      context.Context
	tx       storage.IdentityTx
	p        *Principal
	subjects map[string]bool
	visited  map[string]bool
	now      time.Time
}

func collectDirectorySubjects(ctx context.Context, tx storage.IdentityTx, p *Principal, selections ...*directorySubjectSelection) ([]string, error) {
	if ctx == nil || tx == nil || p == nil || len(selections) > maxDirectorySubjectRecords {
		return nil, ErrInvalidRequest
	}
	c := &directorySubjectCollector{ctx: ctx, tx: tx, p: p, subjects: map[string]bool{}, visited: map[string]bool{}, now: time.Now().UTC()}
	// Include facts still potentially current under either clock. The final
	// guard, rather than this selector, establishes current authority and time.
	if !p.head.RecordedAt.IsZero() && p.head.RecordedAt.Before(c.now) {
		c.now = p.head.RecordedAt
	}
	for _, selection := range selections {
		if selection == nil {
			return nil, ErrInvalidRequest
		}
		if err := c.selectRoot(*selection); err != nil {
			return nil, err
		}
	}
	ids := make([]string, 0, len(c.subjects))
	for id := range c.subjects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func (c *directorySubjectCollector) add(ids ...string) error {
	for _, id := range ids {
		if !validID.MatchString(id) {
			return ErrUnavailable
		}
		c.subjects[id] = true
		if len(c.subjects) > maxDirectoryHistoricalSubjects {
			return ErrUnavailable
		}
	}
	return c.ctx.Err()
}

func (c *directorySubjectCollector) scope(site string) error {
	if c.p.Require("config.read", site) != nil {
		return storage.ErrNotFound
	}
	return nil
}

func (c *directorySubjectCollector) selectRoot(s directorySubjectSelection) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if strings.HasSuffix(s.Kind, "_list") || s.Kind == "plan_create" || s.Kind == "policy_create" || s.Kind == "closure" {
		return c.selectCollection(s)
	}
	if !validID.MatchString(s.ID) {
		return ErrInvalidRequest
	}
	key := s.Kind + "/" + s.ID + "/" + s.ReviewID
	if c.visited[key] {
		return nil
	}
	c.visited[key] = true
	if len(c.visited) > maxDirectorySubjectRecords {
		return ErrUnavailable
	}
	switch s.Kind {
	case "policy_view", "policy_write", "policy_publish":
		return c.policy(s.ID, s.Kind)
	case "policy_validation":
		return c.indirect("SELECT policy_revision_id FROM config_waf_policy_validations WHERE id=?", s.ID, "policy_write")
	case "policy_operation":
		return c.indirect("SELECT validation_id FROM config_waf_policy_operations WHERE id=?", s.ID, "policy_validation")
	case "zone_view", "zone_write", "zone_publish", "published_zone":
		return c.zone(s.ID, s.Kind, s.SiteID)
	case "zone_resolve":
		var site string
		err := securitystate.One(c.ctx, c.tx, "SELECT site_id FROM config_zone_revisions WHERE id=?", []any{s.ID}, func(r storage.IdentityRows) error { return r.Scan(&site) })
		if err != nil {
			return err
		}
		return c.closure(s.RevisionID, site, append([]string{s.ID}, s.ZoneRevisionIDs...))
	case "zone_validation":
		return c.indirect("SELECT zone_revision_id FROM config_zone_validations WHERE id=?", s.ID, "zone_write")
	case "zone_operation":
		var validation string
		err := securitystate.One(c.ctx, c.tx, "SELECT validation_id FROM config_zone_operations WHERE id=?", []any{s.ID}, func(r storage.IdentityRows) error { return r.Scan(&validation) })
		if err == nil {
			return c.selectRoot(directorySubjectSelection{Kind: "zone_validation", ID: validation})
		}
		if err != storage.ErrNotFound {
			return err
		}
		var resolution string
		err = securitystate.One(c.ctx, c.tx, "SELECT id FROM config_zone_resolutions WHERE operation_id=?", []any{s.ID}, func(r storage.IdentityRows) error { return r.Scan(&resolution) })
		if err == nil {
			return c.selectRoot(directorySubjectSelection{Kind: "zone_resolution", ID: resolution})
		}
		if err != storage.ErrNotFound {
			return err
		}
		return c.indirect("SELECT id FROM config_zone_changes WHERE operation_id=?", s.ID, "zone_change")
	case "zone_preview", "zone_reviews":
		v, err := loadReviewContext(c.ctx, c.tx, s.ID)
		if err != nil {
			return err
		}
		if err = c.p.RequireSiteSnapshot(c.ctx, c.tx, "config.read", v.base, v.site); err != nil {
			return storage.ErrNotFound
		}
		if err = c.add(v.author); err != nil {
			return err
		}
		if s.Kind == "zone_reviews" {
			return c.pairs("SELECT author_id,reviewer_id FROM config_authoring_reviews WHERE preview_id=? ORDER BY created_at DESC,id DESC LIMIT 200", s.ID)
		}
		return nil
	case "zone_resolution":
		v, err := loadZoneResolution(c.ctx, c.tx, s.ID)
		if err != nil {
			return err
		}
		if err = c.p.RequireSiteSnapshot(c.ctx, c.tx, "config.read", v.report.BaseConfigRevisionID, v.report.SiteID); err != nil {
			return storage.ErrNotFound
		}
		if err = c.add(v.author); err != nil {
			return err
		}
		zones := []string{v.request.ZoneRevisionID}
		for _, replacement := range v.request.ReplacementAssignments {
			zones = append(zones, replacement.ZoneRevisionID)
		}
		return c.closure(v.report.BaseConfigRevisionID, v.report.SiteID, zones)
	case "zone_change":
		return c.indirect("SELECT resolution_id FROM config_zone_changes WHERE id=?", s.ID, "zone_resolution")
	case "plan_proposal", "plan_reviews", "plan_review":
		return c.plan(s)
	default:
		return ErrInvalidRequest
	}
}

func (c *directorySubjectCollector) indirect(query, id, kind string) error {
	var target string
	err := securitystate.One(c.ctx, c.tx, query, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&target) })
	if err != nil {
		return err
	}
	return c.selectRoot(directorySubjectSelection{Kind: kind, ID: target})
}

func (c *directorySubjectCollector) pairs(query string, args ...any) error {
	rows, err := c.tx.Query(c.ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		if err = rows.Scan(&a, &b); err != nil {
			return err
		}
		if err = c.add(a, b); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *directorySubjectCollector) policy(id, mode string) error {
	var author, site string
	err := securitystate.One(c.ctx, c.tx, "SELECT created_by,site_id FROM config_waf_policy_revisions WHERE id=?", []any{id}, func(r storage.IdentityRows) error { return r.Scan(&author, &site) })
	if err != nil {
		return err
	}
	if err = c.scope(site); err != nil {
		return err
	}
	if mode == "policy_view" {
		publications, e := securitystate.Strings(c.ctx, c.tx, "SELECT id FROM config_waf_policy_publications WHERE policy_revision_id=?", id)
		if e != nil || len(publications) > 0 {
			return e
		}
	}
	if err = c.add(author); err != nil {
		return err
	}
	if mode == "policy_write" {
		return nil
	}
	return c.lifecycleApprovals("config_waf_policy", "policy_revision_id", id, mode == "policy_publish")
}

func (c *directorySubjectCollector) lifecycleApprovals(prefix, revisionColumn, id string, publish bool) error {
	if publish {
		// Exact immutable publication provenance takes precedence over candidates.
		approvals, err := securitystate.Strings(c.ctx, c.tx, "SELECT approval_id FROM "+prefix+"_publications WHERE "+revisionColumn+"=?", id)
		if err != nil {
			return err
		}
		if len(approvals) > 0 {
			return c.pairs("SELECT author_id,approver_id FROM "+prefix+"_approvals WHERE id=?", approvals[0])
		}
		return c.pairs("SELECT author_id,approver_id FROM (SELECT author_id,approver_id,authority_epoch,expires_at FROM "+prefix+"_approvals WHERE "+revisionColumn+"=? ORDER BY created_at DESC,id DESC LIMIT 32) candidates WHERE authority_epoch=? AND expires_at>?", id, c.p.Epoch, c.now)
	}
	validations, err := securitystate.Strings(c.ctx, c.tx, "SELECT id FROM "+prefix+"_validations WHERE "+revisionColumn+"=? ORDER BY created_at DESC,id DESC LIMIT 32", id)
	if err != nil {
		return err
	}
	for _, validation := range validations {
		if err = c.pairs("SELECT author_id,approver_id FROM (SELECT author_id,approver_id,authority_epoch,expires_at FROM "+prefix+"_approvals WHERE validation_id=? ORDER BY created_at DESC,id DESC LIMIT 32) candidates WHERE authority_epoch=? AND expires_at>?", validation, c.p.Epoch, c.now); err != nil {
			return err
		}
	}
	return nil
}

func (c *directorySubjectCollector) zone(id, mode, expectedSite string) error {
	var author, owner, site string
	err := securitystate.One(c.ctx, c.tx, "SELECT created_by,owner_id,site_id FROM config_zone_revisions WHERE id=?", []any{id}, func(r storage.IdentityRows) error { return r.Scan(&author, &owner, &site) })
	if err != nil {
		return err
	}
	if expectedSite != "" && site != expectedSite {
		return storage.ErrNotFound
	}
	if err = c.scope(site); err != nil {
		return err
	}
	if mode == "published_zone" {
		// Publication consumption rechecks the owner dependency, not now-expired
		// historical author/approver credentials. This matches publishedZone.
		return c.add(owner)
	}
	if mode == "zone_view" {
		publications, e := securitystate.Strings(c.ctx, c.tx, "SELECT id FROM config_zone_publications WHERE zone_revision_id=?", id)
		if e != nil || len(publications) > 0 {
			return e
		}
	}
	if err = c.add(author, owner); err != nil {
		return err
	}
	if mode == "zone_write" {
		return nil
	}
	return c.lifecycleApprovals("config_zone", "zone_revision_id", id, mode == "zone_publish")
}

func (c *directorySubjectCollector) plan(s directorySubjectSelection) error {
	if c.p.Require("config.read", "") != nil {
		return storage.ErrPermissionDenied
	}
	v, err := readPlanProposal(c.ctx, c.tx, s.ID)
	if err != nil {
		return err
	}
	if err = c.add(v.proposal.AuthorID); err != nil {
		return err
	}
	if s.Kind == "plan_reviews" {
		ids, e := securitystate.Strings(c.ctx, c.tx, "SELECT reviewer_id FROM config_plan_proposal_reviews WHERE proposal_id=? ORDER BY created_at DESC,id DESC LIMIT 200", s.ID)
		if e != nil {
			return e
		}
		return c.add(ids...)
	}
	if s.Kind == "plan_review" {
		if !validID.MatchString(s.ReviewID) {
			return ErrInvalidRequest
		}
		var reviewer string
		err = securitystate.One(c.ctx, c.tx, "SELECT reviewer_id FROM config_plan_proposal_reviews WHERE id=? AND proposal_id=?", []any{s.ReviewID, s.ID}, func(r storage.IdentityRows) error { return r.Scan(&reviewer) })
		if err != nil {
			return err
		}
		return c.add(reviewer)
	}
	return nil
}

func (c *directorySubjectCollector) selectCollection(s directorySubjectSelection) error {
	switch s.Kind {
	case "policy_create":
		if !validKey.MatchString(s.RequestKey) {
			return ErrInvalidRequest
		}
		var id string
		err := securitystate.One(c.ctx, c.tx, "SELECT resource_id FROM config_requests WHERE actor_id=? AND operation='waf.policy.create' AND request_key=?", []any{c.p.ID, s.RequestKey}, func(r storage.IdentityRows) error { return r.Scan(&id) })
		if err == storage.ErrNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return c.selectRoot(directorySubjectSelection{Kind: "policy_view", ID: id})
	case "plan_create":
		// planSources consumes historical signed policy publications without
		// reauthorizing their authors. Only the current request actor is new.
		if c.p.Require("config.read", "") != nil || !validID.MatchString(s.RevisionID) || !validID.MatchString(s.SiteID) {
			return storage.ErrPermissionDenied
		}
		return nil
	case "closure":
		return c.closure(s.RevisionID, s.SiteID, s.ZoneRevisionIDs)
	case "plan_list":
		if c.p.Require("config.read", "") != nil {
			return storage.ErrPermissionDenied
		}
		if s.Limit < 1 || s.Limit > 50 || s.Cursor != "" && !validID.MatchString(s.Cursor) {
			return ErrInvalidRequest
		}
		query := "SELECT id FROM config_plan_proposals ORDER BY created_at DESC,id DESC LIMIT ?"
		args := []any{s.Limit}
		if s.Cursor != "" {
			prior, e := readPlanProposal(c.ctx, c.tx, s.Cursor)
			if e != nil {
				return e
			}
			query = "SELECT id FROM config_plan_proposals WHERE created_at<? OR (created_at=? AND id<?) ORDER BY created_at DESC,id DESC LIMIT ?"
			args = []any{prior.proposal.CreatedAt, prior.proposal.CreatedAt, s.Cursor, s.Limit}
		}
		ids, err := securitystate.Strings(c.ctx, c.tx, query, args...)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err = c.selectRoot(directorySubjectSelection{Kind: "plan_proposal", ID: id}); err != nil {
				return err
			}
		}
		return nil
	case "zones_list":
		if s.Limit < 1 || s.Limit > 200 || s.Cursor != "" && !validID.MatchString(s.Cursor) || s.SiteID != "" && !validID.MatchString(s.SiteID) {
			return ErrInvalidRequest
		}
		query := "SELECT revision_id FROM config_zone_heads WHERE zone_id>?"
		args := []any{s.Cursor}
		if s.SiteID != "" {
			if err := c.scope(s.SiteID); err != nil {
				return err
			}
			query += " AND site_id=?"
			args = append(args, s.SiteID)
		} else if global, sites := c.p.ReadSites("config.read"); !global {
			if len(sites) == 0 {
				return storage.ErrPermissionDenied
			}
			query += " AND site_id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(sites)), ",") + ")"
			for _, site := range sites {
				args = append(args, site)
			}
		}
		query += " ORDER BY zone_id LIMIT ?"
		args = append(args, s.Limit)
		ids, err := securitystate.Strings(c.ctx, c.tx, query, args...)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err = c.selectRoot(directorySubjectSelection{Kind: "zone_view", ID: id}); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrInvalidRequest
	}
}

func (c *directorySubjectCollector) closure(revision, site string, zones []string) error {
	if !validID.MatchString(revision) || !validID.MatchString(site) || len(zones) > 10001 {
		return ErrInvalidRequest
	}
	if err := c.p.RequireSiteSnapshot(c.ctx, c.tx, "config.read", revision, site); err != nil {
		return storage.ErrNotFound
	}
	// Original and replacement zones belong to the same complete Site effect.
	// Only sealed assignments of the selected revision are enumerated here.
	assigned, err := securitystate.Strings(c.ctx, c.tx, "SELECT DISTINCT a.zone_revision_id FROM config_revision_zone_assignments a JOIN config_gateways g ON g.revision_id=a.revision_id AND g.id=a.gateway_id WHERE a.revision_id=? AND g.site_id=? ORDER BY a.zone_revision_id", revision, site)
	if err != nil {
		return err
	}
	for _, id := range append(append([]string{}, zones...), assigned...) {
		if err = c.selectRoot(directorySubjectSelection{Kind: "published_zone", ID: id, SiteID: site}); err != nil {
			return err
		}
	}
	return nil
}
