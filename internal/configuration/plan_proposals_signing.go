package configuration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// SignedPlanReview cannot be decoded as a deploymentplan.SignedPlan. Purpose,
// full immutable proposal and exact independent review are signed together.
type SignedPlanReview struct {
	APIVersion         string             `json:"apiVersion"`
	Purpose            string             `json:"purpose"`
	Deployable         bool               `json:"deployable"`
	NoExecution        bool               `json:"noExecution"`
	KeyID              string             `json:"keyId"`
	Proposal           PlanProposal       `json:"proposal"`
	Review             PlanProposalReview `json:"review"`
	SignatureAlgorithm string             `json:"signatureAlgorithm"`
	SignatureBase64    string             `json:"signatureBase64"`
}
type planReviewSigning struct {
	mu    sync.RWMutex
	keyID string
	key   ed25519.PrivateKey
}

// WithPlanReviewSigningKey is configuration-once; it retains no caller-owned
// memory and never authorizes signing execution plans, permits or start proofs.
func (s *Service) WithPlanReviewSigningKey(keyID string, key ed25519.PrivateKey) error {
	if s == nil || !validID.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return ErrInvalidRequest
	}
	s.planSigning.mu.Lock()
	defer s.planSigning.mu.Unlock()
	if s.planSigning.key != nil {
		return storage.ErrConflict
	}
	s.planSigning.keyID = keyID
	s.planSigning.key = append(ed25519.PrivateKey(nil), key...)
	return nil
}
func planReviewMessage(envelope SignedPlanReview) ([]byte, error) {
	envelope.SignatureBase64 = ""
	raw, e := configmodel.CanonicalJSON(envelope)
	if e != nil {
		return nil, e
	}
	return append([]byte("AGP-PLAN-REVIEW-v1\n"), raw...), nil
}
func (s *Service) SignPlanProposalReview(ctx context.Context, a Actor, id, reviewID, key string) (out *SignedPlanReview, err error) {
	if !validID.MatchString(id) || !validID.MatchString(reviewID) {
		return nil, ErrInvalidRequest
	}
	op := "plan.proposal.review.sign:" + reviewID
	fp := digest([]string{id, reviewID})
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "plan_review", ID: id, ReviewID: reviewID})
	if err != nil {
		return
	}
	err = s.transactPlan(ctx, a, true, "config.approve", func(tx storage.IdentityTx, p *Principal, now time.Time) error {
		v, e := readPlanProposal(ctx, tx, id)
		if e != nil {
			return e
		}
		r, reviewFP, e := readPlanReview(ctx, tx, reviewID)
		if e != nil {
			return e
		}
		if r.ReviewerID != p.ID {
			return storage.ErrPermissionDenied
		}
		if e = s.currentPlanReview(ctx, tx, p, v, r, reviewFP, now); e != nil {
			return e
		}
		s.planSigning.mu.RLock()
		defer s.planSigning.mu.RUnlock()
		signer := &s.planSigning
		if len(signer.key) != ed25519.PrivateKeySize {
			return ErrUnavailable
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			signed, e := readSignedPlanReview(ctx, tx, h.id, signer.keyID, signer.key.Public().(ed25519.PublicKey), v.proposal, *r)
			if e != nil {
				return e
			}
			out = signed
			return nil
		}
		existing, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_plan_proposal_signatures WHERE review_id=? AND key_id=?`, reviewID, signer.keyID)
		if e != nil {
			return e
		}
		signatureID := securitystate.ID("plansignature")
		if len(existing) > 0 {
			signed, e := readSignedPlanReview(ctx, tx, existing[0], signer.keyID, signer.key.Public().(ed25519.PublicKey), v.proposal, *r)
			if e != nil {
				return e
			}
			if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"signed_plan_review", existing[0], 0}); e != nil {
				return e
			}
			out = signed
			return nil
		}
		envelope := &SignedPlanReview{APIVersion: "agp.signed-plan-review/v1alpha1", Purpose: "planning_review", Deployable: false, NoExecution: true, KeyID: signer.keyID, Proposal: v.proposal, Review: *r, SignatureAlgorithm: "Ed25519"}
		message, e := planReviewMessage(*envelope)
		if e != nil {
			return e
		}
		envelope.SignatureBase64 = base64.StdEncoding.EncodeToString(ed25519.Sign(signer.key, message))
		raw, e := configmodel.CanonicalJSON(envelope)
		if e != nil {
			return e
		}
		ed, e := configmodel.Digest(envelope)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_plan_proposal_signatures(id,review_id,key_id,envelope_digest,envelope_json,created_at) VALUES(?,?,?,?,?,?)`, signatureID, reviewID, signer.keyID, ed, string(raw), now.Truncate(time.Microsecond)); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"signed_plan_review", signatureID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.plan_proposal.review_signed", p.ID, map[string]any{"proposalId": id, "reviewId": reviewID, "keyId": signer.keyID, "purpose": "planning_review", "noExecution": true}); e != nil {
			return e
		}
		out = envelope
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func readSignedPlanReview(ctx context.Context, tx storage.IdentityTx, id, keyID string, key ed25519.PublicKey, proposal PlanProposal, review PlanProposalReview) (*SignedPlanReview, error) {
	var raw, expected, storedReview, storedKey string
	e := securitystate.One(ctx, tx, `SELECT envelope_json,envelope_digest,review_id,key_id FROM config_plan_proposal_signatures WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw, &expected, &storedReview, &storedKey) })
	if e != nil {
		return nil, e
	}
	if len(raw) > (32<<20)+65536 {
		return nil, storage.ErrConflict
	}
	var out SignedPlanReview
	if e = json.Unmarshal([]byte(raw), &out); e != nil {
		return nil, storage.ErrConflict
	}
	canonical, e := configmodel.CanonicalJSON(out)
	if e != nil || string(canonical) != raw {
		return nil, storage.ErrConflict
	}
	actual, e := configmodel.Digest(out)
	if e != nil {
		return nil, e
	}
	if actual != expected || out.APIVersion != "agp.signed-plan-review/v1alpha1" || out.Purpose != "planning_review" || out.Deployable || !out.NoExecution || out.KeyID != keyID || storedKey != keyID || storedReview != review.ID || out.SignatureAlgorithm != "Ed25519" || digest(out.Proposal) != digest(proposal) || digest(out.Review) != digest(review) {
		return nil, storage.ErrConflict
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(out.SignatureBase64)
	if e != nil {
		return nil, storage.ErrConflict
	}
	message, e := planReviewMessage(out)
	if e != nil {
		return nil, e
	}
	if !ed25519.Verify(key, message, signature) {
		return nil, storage.ErrConflict
	}
	return &out, nil
}
