package configuration

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

const planProposalVersion = "agp.plan-proposal/v1alpha1"

// A PlanProposal is a planning artifact. It deliberately lacks node baselines,
// deployment sequences, permits and every other execution authorization field.
type PlanProposal struct {
	APIVersion       string                       `json:"apiVersion"`
	Purpose          string                       `json:"purpose"`
	Deployable       bool                         `json:"deployable"`
	NoExecution      bool                         `json:"noExecution"`
	ID               string                       `json:"id"`
	ProposalDigest   string                       `json:"proposalDigest"`
	SiteID           string                       `json:"siteId"`
	RevisionID       string                       `json:"revisionId"`
	ConfigDigest     string                       `json:"configDigest"`
	CompilerDigest   string                       `json:"compilerDigest"`
	CompilerVersion  string                       `json:"compilerVersion"`
	InventoryDigest  string                       `json:"inventoryDigest"`
	CatalogID        string                       `json:"catalogSnapshotId"`
	CatalogDigest    string                       `json:"catalogDigest"`
	DependencyDigest string                       `json:"dependencyDigest"`
	PreviewDigest    string                       `json:"previewDigest"`
	AuthorID         string                       `json:"authorId"`
	AuthorityEpoch   string                       `json:"authorityEpoch"`
	CreatedAt        time.Time                    `json:"createdAt"`
	ExpiresAt        time.Time                    `json:"expiresAt"`
	Reason           string                       `json:"reason"`
	RolloutPolicy    deploymentplan.RolloutPolicy `json:"rolloutPolicy"`
	Targets          []PlanProposalTarget         `json:"targets"`
	ResolvedInputs   []compiler.Input             `json:"resolvedInputs"`
	Blockers         []string                     `json:"blockers"`
}
type PlanProposalTarget struct {
	NodeID              string   `json:"nodeId"`
	CapabilityDigest    string   `json:"capabilityDigest"`
	PreviewBundleDigest string   `json:"previewBundleDigest"`
	GatewayIDs          []string `json:"gatewayIds"`
	SecretVersionIDs    []string `json:"secretVersionIds"`
}
type PlanProposalCreate struct {
	RevisionID    string                       `json:"revisionId"`
	SiteID        string                       `json:"siteId"`
	TargetNodeIDs []string                     `json:"targetNodeIds"`
	RolloutPolicy deploymentplan.RolloutPolicy `json:"rolloutPolicy"`
	Reason        string                       `json:"reason"`
}
type PlanProposalView struct {
	Proposal PlanProposal `json:"proposal"`
	Current  bool         `json:"current"`
}
type PlanProposalPage struct {
	Items      []PlanProposalView `json:"items"`
	NextCursor string             `json:"nextCursor,omitempty"`
}
type PlanProposalReviewRequest struct {
	ProposalDigest string `json:"proposalDigest"`
	Reason         string `json:"reason"`
}
type PlanProposalReview struct {
	ID             string    `json:"id"`
	ProposalID     string    `json:"proposalId"`
	ProposalDigest string    `json:"proposalDigest"`
	AuthorID       string    `json:"authorId"`
	ReviewerID     string    `json:"reviewerId"`
	Purpose        string    `json:"purpose"`
	Current        bool      `json:"current"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Reason         string    `json:"reason"`
}

func planReasonValid(reason string) bool {
	return len(reason) <= 4096 && utf8.ValidString(reason) && utf8.RuneCountInString(strings.TrimSpace(reason)) >= 8 && utf8.RuneCountInString(reason) <= 1024
}
func normalizePlanCreate(in PlanProposalCreate) (PlanProposalCreate, error) {
	if !validID.MatchString(in.RevisionID) || !validID.MatchString(in.SiteID) || !planReasonValid(in.Reason) || len(in.TargetNodeIDs) < 1 || len(in.TargetNodeIDs) > 500 {
		return in, ErrInvalidRequest
	}
	in.TargetNodeIDs = append([]string{}, in.TargetNodeIDs...)
	sort.Strings(in.TargetNodeIDs)
	for i, id := range in.TargetNodeIDs {
		if !validID.MatchString(id) || (i > 0 && in.TargetNodeIDs[i-1] == id) {
			return in, ErrInvalidRequest
		}
	}
	r := &in.RolloutPolicy
	if len(r.CanaryNodeIDs) < 1 || len(r.CanaryNodeIDs) > 10 || r.MaxParallel < 1 || r.MaxParallel > 25 || r.MaxUnavailable < 0 || r.MaxUnavailable > 25 || r.ObservationSeconds < 30 || r.ObservationSeconds > 86400 || (r.FailureAction != "pause" && r.FailureAction != "rollback_wave") {
		return in, ErrInvalidRequest
	}
	r.CanaryNodeIDs = append([]string{}, r.CanaryNodeIDs...)
	sort.Strings(r.CanaryNodeIDs)
	for i, id := range r.CanaryNodeIDs {
		j := sort.SearchStrings(in.TargetNodeIDs, id)
		if j == len(in.TargetNodeIDs) || in.TargetNodeIDs[j] != id || (i > 0 && r.CanaryNodeIDs[i-1] == id) {
			return in, ErrInvalidRequest
		}
	}
	return in, nil
}

// This workflow uses the independently authenticated journal time. Global-only
// admission is intentional until Site-scoped full-node disclosure is qualified.
func (s *Service) transactPlan(ctx context.Context, a Actor, write bool, permission string, fn func(storage.IdentityTx, *Principal, time.Time) error) error {
	if s == nil || s.current == nil || s.origin == "" || a.Origin != s.origin || a.TokenHash == "" {
		return storage.ErrPermissionDenied
	}
	return securitystate.WithManagementSession(ctx, a.TokenHash, s.current, func(ctx context.Context) error {
		return s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			p, err := readConfigurationActor(ctx, tx, h, a, write, s.current, s.origin)
			if err != nil {
				return err
			}
			if err = p.Require("config.read", ""); err != nil {
				return err
			}
			if err = p.Require(permission, ""); err != nil {
				return err
			}
			evidence := &subjectEvidenceTx{IdentityTx: tx, proofContext: ctx, subjects: map[string]configurationSubjectWitness{}}
			return s.finishConfigurationEvidence(ctx, a, write, p, evidence, fn(evidence, p, h.RecordedAt.UTC()))
		})
	})
}
func planSubjectFloors(ctx context.Context, tx storage.IdentityTx, id string, sv, pv int64) error {
	if sv < 0 || pv < 0 {
		return storage.ErrPermissionDenied
	}
	for _, v := range []struct {
		id      string
		version int64
	}{{"principal_" + id, sv}, {"password_" + id, pv}} {
		floor, e := securitystate.Floor(ctx, tx, id, v.id)
		if e != nil {
			return e
		}
		if uint64(v.version) < floor {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}
func planSubject(ctx context.Context, tx storage.IdentityTx, id string, h securityjournal.Head, permissions ...string) (string, error) {
	var sv, pv int64
	e := securitystate.One(ctx, tx, `SELECT security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&sv, &pv) })
	if e != nil {
		return "", e
	}
	if e = planSubjectFloors(ctx, tx, id, sv, pv); e != nil {
		return "", e
	}
	for _, permission := range permissions {
		if e = wafSubjectPermission(ctx, tx, id, permission, "", h); e != nil {
			return "", e
		}
	}
	fp, e := subjectFingerprint(ctx, tx, id, h)
	if e != nil {
		return "", e
	}
	return digest([]any{fp, pv}), nil
}

func proposalDigest(v PlanProposal) (string, error) {
	v.ProposalDigest = ""
	return configmodel.Digest(v)
}

type storedPlanProposal struct {
	proposal          PlanProposal
	authorFingerprint string
	epoch             int64
}

func readPlanProposal(ctx context.Context, tx storage.IdentityTx, id string) (*storedPlanProposal, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	v := &storedPlanProposal{}
	var raw, expected, site, revision, author, dependency string
	var created, expires time.Time
	e := securitystate.One(ctx, tx, `SELECT proposal_json,proposal_digest,site_id,revision_id,author_id,author_fingerprint,authority_epoch,dependency_digest,created_at,expires_at FROM config_plan_proposals WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &expected, &site, &revision, &author, &v.authorFingerprint, &v.epoch, &dependency, &created, &expires)
	})
	if e != nil {
		return nil, e
	}
	if len(raw) > 32<<20 {
		return nil, storage.ErrConflict
	}
	if e = json.Unmarshal([]byte(raw), &v.proposal); e != nil {
		return nil, storage.ErrConflict
	}
	actual, e := proposalDigest(v.proposal)
	if e != nil {
		return nil, e
	}
	p := &v.proposal
	if actual != expected || p.ProposalDigest != expected || p.ID != id || p.SiteID != site || p.RevisionID != revision || p.AuthorID != author || p.DependencyDigest != dependency || p.AuthorityEpoch != strconv.FormatInt(v.epoch, 10) || p.APIVersion != planProposalVersion || p.Purpose != "planning_review" || !p.NoExecution || p.Deployable || !p.CreatedAt.Equal(created) || !p.ExpiresAt.Equal(expires) {
		return nil, storage.ErrConflict
	}
	canonical, e := configmodel.CanonicalJSON(p)
	if e != nil || string(canonical) != raw {
		return nil, storage.ErrConflict
	}
	return v, nil
}
