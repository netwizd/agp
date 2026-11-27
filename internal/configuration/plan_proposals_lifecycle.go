package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Service) CreatePlanProposal(ctx context.Context, a Actor, key string, in PlanProposalCreate) (out *PlanProposal, err error) {
	in, err = normalizePlanCreate(in)
	if err != nil {
		return nil, err
	}
	fp := digest(in)
	err = s.transactPlan(ctx, a, true, "config.edit", func(tx storage.IdentityTx, p *Principal, now time.Time) error {
		h, e := request(ctx, tx, p.ID, "plan.proposal.create", key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			v, e := readPlanProposal(ctx, tx, h.id)
			if e != nil {
				return e
			}
			if e = s.planProposalCurrent(ctx, tx, p, v, now); e != nil {
				return e
			}
			out = &v.proposal
			return nil
		}
		sources, e := s.planSources(ctx, tx, p, in.RevisionID, in.SiteID, now)
		if e != nil {
			return e
		}
		authorFP, e := planSubject(ctx, tx, p.ID, p.head, "config.read", "config.edit")
		if e != nil {
			return e
		}
		byID := map[string]PlanProposalTarget{}
		for _, bundle := range sources.preview.Bundles {
			byID[bundle.NodeID] = PlanProposalTarget{NodeID: bundle.NodeID, CapabilityDigest: bundle.CapabilityDigest, PreviewBundleDigest: bundle.BundleDigest, GatewayIDs: bundle.GatewayIDs, SecretVersionIDs: bundle.SecretVersionIDs}
		}
		proposal := &PlanProposal{APIVersion: planProposalVersion, Purpose: "planning_review", Deployable: false, NoExecution: true, ID: securitystate.ID("proposal"), SiteID: in.SiteID, RevisionID: in.RevisionID, ConfigDigest: sources.preview.ConfigDigest, CompilerDigest: sources.preview.CompilerDigest, CompilerVersion: sources.preview.CompilerVersion, InventoryDigest: sources.inventoryDigest, CatalogID: sources.catalogID, CatalogDigest: sources.catalogDigest, DependencyDigest: sources.dependencyDigest, PreviewDigest: sources.preview.PreviewDigest, AuthorID: p.ID, AuthorityEpoch: strconv.FormatInt(p.Epoch, 10), CreatedAt: now.Truncate(time.Microsecond), ExpiresAt: sources.expiresAt, Reason: in.Reason, RolloutPolicy: in.RolloutPolicy, Targets: []PlanProposalTarget{}, ResolvedInputs: sources.preview.ResolvedInputs, Blockers: []string{"capture_baseline_required", "owned_tree_verification_required", "node_bundle_qualification_required", "execution_authorizer_required"}}
		for _, id := range in.TargetNodeIDs {
			target, ok := byID[id]
			if !ok || !sources.targetIDs[id] || !configmodel.ValidDigest(target.CapabilityDigest) || len(target.SecretVersionIDs) > 100 {
				return storage.ErrConflict
			}
			proposal.Targets = append(proposal.Targets, target)
		}
		seen := map[string]bool{}
		for _, b := range proposal.Blockers {
			seen[b] = true
		}
		for _, issue := range sources.preview.Issues {
			if !seen[issue.Code] {
				proposal.Blockers = append(proposal.Blockers, issue.Code)
				seen[issue.Code] = true
			}
		}
		proposal.ProposalDigest, e = proposalDigest(*proposal)
		if e != nil {
			return e
		}
		raw, e := configmodel.CanonicalJSON(proposal)
		if e != nil {
			return e
		}
		if len(raw) > 32<<20 {
			return ErrUnavailable
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_plan_proposals(id,site_id,revision_id,proposal_digest,authority_epoch,author_id,author_fingerprint,dependency_digest,proposal_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, proposal.ID, proposal.SiteID, proposal.RevisionID, proposal.ProposalDigest, p.Epoch, p.ID, authorFP, proposal.DependencyDigest, string(raw), proposal.CreatedAt, proposal.ExpiresAt); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, "plan.proposal.create", key, fp, responseHandle{"plan_proposal", proposal.ID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.plan_proposal.created", p.ID, map[string]any{"proposalId": proposal.ID, "proposalDigest": proposal.ProposalDigest, "siteId": proposal.SiteID, "purpose": "planning_review", "noExecution": true}); e != nil {
			return e
		}
		out = proposal
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func planStale(err error) bool {
	return errors.Is(err, storage.ErrConflict) || errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, storage.ErrNotFound) || errors.Is(err, ErrRevisionMismatch) || errors.Is(err, ErrUnavailable) || errors.Is(err, inventory.ErrNotFresh) || errors.Is(err, inventory.ErrIdentity)
}
func (s *Service) viewPlanProposal(ctx context.Context, tx storage.IdentityTx, p *Principal, v *storedPlanProposal, now time.Time, caches ...map[string]planSourcesResult) (*PlanProposalView, error) {
	e := s.planProposalCurrent(ctx, tx, p, v, now, caches...)
	if e != nil && !planStale(e) {
		return nil, e
	}
	return &PlanProposalView{Proposal: v.proposal, Current: e == nil}, nil
}
func (s *Service) GetPlanProposal(ctx context.Context, a Actor, id string) (out *PlanProposalView, err error) {
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "plan_proposal", ID: id})
	if err != nil {
		return
	}
	err = s.transactPlan(ctx, a, false, "config.read", func(tx storage.IdentityTx, p *Principal, now time.Time) error {
		v, e := readPlanProposal(ctx, tx, id)
		if e != nil {
			return e
		}
		out, e = s.viewPlanProposal(ctx, tx, p, v, now)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) ListPlanProposals(ctx context.Context, a Actor, limit int, cursor string) (out *PlanProposalPage, err error) {
	if limit < 1 || limit > 50 || (cursor != "" && !validID.MatchString(cursor)) {
		return nil, ErrInvalidRequest
	}
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "plan_list", Limit: limit, Cursor: cursor})
	if err != nil {
		return
	}
	err = s.transactPlan(ctx, a, false, "config.read", func(tx storage.IdentityTx, p *Principal, now time.Time) error {
		query := `SELECT id FROM config_plan_proposals ORDER BY created_at DESC,id DESC LIMIT ?`
		args := []any{limit + 1}
		if cursor != "" {
			v, e := readPlanProposal(ctx, tx, cursor)
			if e != nil {
				return e
			}
			query = `SELECT id FROM config_plan_proposals WHERE created_at<? OR (created_at=? AND id<?) ORDER BY created_at DESC,id DESC LIMIT ?`
			args = []any{v.proposal.CreatedAt, v.proposal.CreatedAt, cursor, limit + 1}
		}
		ids, e := securitystate.Strings(ctx, tx, query, args...)
		if e != nil {
			return e
		}
		page := &PlanProposalPage{Items: []PlanProposalView{}}
		sourceCache := map[string]planSourcesResult{}
		if len(ids) > limit {
			page.NextCursor = ids[limit-1]
			ids = ids[:limit]
		}
		for _, id := range ids {
			v, e := readPlanProposal(ctx, tx, id)
			if e != nil {
				return e
			}
			view, e := s.viewPlanProposal(ctx, tx, p, v, now, sourceCache)
			if e != nil {
				return e
			}
			page.Items = append(page.Items, *view)
		}
		out = page
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readPlanReview(ctx context.Context, tx storage.IdentityTx, id string) (*PlanProposalReview, string, error) {
	if !validID.MatchString(id) {
		return nil, "", ErrInvalidRequest
	}
	var raw, proposal, reviewer, fp, expected string
	var created time.Time
	e := securitystate.One(ctx, tx, `SELECT review_json,proposal_id,reviewer_id,reviewer_fingerprint,review_digest,created_at FROM config_plan_proposal_reviews WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &proposal, &reviewer, &fp, &expected, &created)
	})
	if e != nil {
		return nil, "", e
	}
	var review PlanProposalReview
	if len(raw) > 65536 {
		return nil, "", storage.ErrConflict
	}
	if e = json.Unmarshal([]byte(raw), &review); e != nil {
		return nil, "", e
	}
	actual, e := configmodel.Digest(review)
	if e != nil {
		return nil, "", e
	}
	canonical, e := configmodel.CanonicalJSON(review)
	if e != nil || string(canonical) != raw || review.ID != id || review.ProposalID != proposal || review.ReviewerID != reviewer || review.Purpose != "planning_review" || !review.Current || !review.CreatedAt.Equal(created) || actual != expected {
		return nil, "", storage.ErrConflict
	}
	return &review, fp, nil
}
func (s *Service) currentPlanReview(ctx context.Context, tx storage.IdentityTx, p *Principal, v *storedPlanProposal, r *PlanProposalReview, fp string, now time.Time) (err error) {
	defer func() { err = subjectFailure(tx, err) }()
	if r.ProposalID != v.proposal.ID || r.ProposalDigest != v.proposal.ProposalDigest || r.AuthorID != v.proposal.AuthorID || r.AuthorID == r.ReviewerID || !r.ExpiresAt.Equal(v.proposal.ExpiresAt) || r.CreatedAt.Before(v.proposal.CreatedAt) || now.Before(r.CreatedAt) || !now.Before(r.ExpiresAt) {
		return storage.ErrConflict
	}
	if err := currentReviewPeople(ctx, tx, r.ReviewerID, r.AuthorID); err != nil {
		return err
	}
	if e := s.planProposalCurrent(ctx, tx, p, v, now); e != nil {
		return e
	}
	current, e := planSubject(ctx, tx, r.ReviewerID, p.head, "config.read", "config.approve")
	if e != nil {
		return e
	}
	if current != fp {
		return storage.ErrConflict
	}
	return nil
}
func (s *Service) ReviewPlanProposal(ctx context.Context, a Actor, id, key string, in PlanProposalReviewRequest) (out *PlanProposalReview, err error) {
	if !validID.MatchString(id) || !configmodel.ValidDigest(in.ProposalDigest) || !planReasonValid(in.Reason) {
		return nil, ErrInvalidRequest
	}
	op := "plan.proposal.review:" + id
	fp := digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "plan_proposal", ID: id})
	if err != nil {
		return
	}
	err = s.transactPlan(ctx, a, true, "config.approve", func(tx storage.IdentityTx, p *Principal, now time.Time) error {
		v, e := readPlanProposal(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.ID == v.proposal.AuthorID {
			return storage.ErrPermissionDenied
		}
		if e = distinctReviewPeople(ctx, tx, p.ID, v.proposal.AuthorID); e != nil {
			return e
		}
		if v.proposal.ProposalDigest != in.ProposalDigest {
			return storage.ErrConflict
		}
		if e = s.planProposalCurrent(ctx, tx, p, v, now); e != nil {
			return e
		}
		reviewerFP, e := planSubject(ctx, tx, p.ID, p.head, "config.read", "config.approve")
		if e != nil {
			return e
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			r, stored, e := readPlanReview(ctx, tx, h.id)
			if e != nil {
				return e
			}
			if e = s.currentPlanReview(ctx, tx, p, v, r, stored, now); e != nil {
				return e
			}
			out = r
			return nil
		}
		existing, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_plan_proposal_reviews WHERE proposal_id=? AND reviewer_id=?`, id, p.ID)
		if e != nil {
			return e
		}
		if len(existing) > 0 {
			return storage.ErrConflict
		}
		r := &PlanProposalReview{ID: securitystate.ID("planreview"), ProposalID: id, ProposalDigest: in.ProposalDigest, AuthorID: v.proposal.AuthorID, ReviewerID: p.ID, Purpose: "planning_review", Current: true, CreatedAt: now.Truncate(time.Microsecond), ExpiresAt: v.proposal.ExpiresAt, Reason: in.Reason}
		raw, e := configmodel.CanonicalJSON(r)
		if e != nil {
			return e
		}
		rd, e := configmodel.Digest(r)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_plan_proposal_reviews(id,proposal_id,reviewer_id,reviewer_fingerprint,review_digest,review_json,created_at) VALUES(?,?,?,?,?,?,?)`, r.ID, id, p.ID, reviewerFP, rd, string(raw), r.CreatedAt); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"plan_proposal_review", r.ID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.plan_proposal.reviewed", p.ID, map[string]any{"proposalId": id, "reviewId": r.ID, "proposalDigest": r.ProposalDigest, "purpose": "planning_review", "noExecution": true}); e != nil {
			return e
		}
		out = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) PlanProposalReviews(ctx context.Context, a Actor, id string) (out []PlanProposalReview, err error) {
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "plan_reviews", ID: id})
	if err != nil {
		return
	}
	err = s.transactPlan(ctx, a, false, "config.read", func(tx storage.IdentityTx, p *Principal, now time.Time) error {
		v, e := readPlanProposal(ctx, tx, id)
		if e != nil {
			return e
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_plan_proposal_reviews WHERE proposal_id=? ORDER BY created_at DESC,id DESC LIMIT 200`, id)
		if e != nil {
			return e
		}
		reviews := []PlanProposalReview{}
		for _, rid := range ids {
			r, fp, e := readPlanReview(ctx, tx, rid)
			if e != nil {
				return e
			}
			e = s.currentPlanReview(ctx, tx, p, v, r, fp, now)
			if e != nil && !planStale(e) {
				return e
			}
			r.Current = e == nil
			reviews = append(reviews, *r)
		}
		out = reviews
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
