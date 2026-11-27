package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// WAFQualifier is implemented by the native qualification boundary. Current
// must check the trusted metadata floor, artifact integrity and expiry, not
// merely recognize a previously returned proof ID.
type WAFQualifier interface {
	ValidatePolicy(context.Context, configmodel.WafPolicy) (*WAFQualification, error)
	Current(context.Context, *WAFQualification) error
}

type WAFQualification struct {
	ID               string    `json:"id"`
	ContentDigest    string    `json:"contentDigest"`
	RulesetVersionID string    `json:"rulesetVersionId"`
	RulesetDigest    string    `json:"rulesetDigest"`
	ProfileID        string    `json:"profileId"`
	ProfileDigest    string    `json:"profileDigest"`
	TupleDigest      string    `json:"tupleDigest"`
	EvidenceDigest   string    `json:"evidenceDigest"`
	ManifestDigest   string    `json:"manifestDigest"`
	ReleaseSequence  string    `json:"releaseSequence"`
	CompilerDigest   string    `json:"compilerDigest"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type WafPolicyCreate struct {
	BaseRevisionID string               `json:"baseRevisionId,omitempty"`
	Content        json.RawMessage      `json:"content"`
	Derivation     *WafPolicyDerivation `json:"derivation,omitempty"`
}
type WafPolicyDerivation struct {
	GatewayID                       string `json:"gatewayId" v:"id"`
	SourceConfigRevisionID          string `json:"sourceConfigRevisionId" v:"id"`
	ZoneRevisionID                  string `json:"zoneRevisionId" v:"id"`
	BasePolicyRevisionID            string `json:"basePolicyRevisionId" v:"id"`
	PreviousDerivedPolicyRevisionID string `json:"previousDerivedPolicyRevisionId,omitempty" v:"id"`
}
type WafPolicyRevision struct {
	ID            string          `json:"id"`
	Content       json.RawMessage `json:"content"`
	ContentDigest string          `json:"contentDigest"`
	State         string          `json:"state"`
	Revision      string          `json:"revision"`
}
type WafPolicyApprovalRequest struct {
	ContentDigest string `json:"contentDigest" v:"digest"`
	Reason        string `json:"reason" v:"min=8,max=1024"`
}
type WafPolicyApproval struct {
	ApprovalID    string `json:"approvalId"`
	ContentDigest string `json:"contentDigest"`
}
type WafPolicyPublicationRequest struct {
	ContentDigest string `json:"contentDigest" v:"digest"`
}
type WafPolicyValidation struct {
	ID                  string              `json:"id"`
	PolicyRevisionID    string              `json:"policyRevisionId"`
	ContentDigest       string              `json:"contentDigest"`
	Qualification       *WAFQualification   `json:"qualification"`
	QualificationDigest string              `json:"qualificationDigest"`
	Valid               bool                `json:"valid"`
	Current             bool                `json:"current"`
	Deployable          bool                `json:"deployable"`
	Issues              []configmodel.Issue `json:"issues"`
	CreatedAt           time.Time           `json:"createdAt"`
	ExpiresAt           time.Time           `json:"expiresAt"`
}

type wafPolicyRecord struct {
	revision                   WafPolicyRevision
	policy                     *configmodel.WafPolicy
	policyID, siteID, authorID string
	number                     int64
}

func readWafPolicyRecord(ctx context.Context, tx storage.IdentityTx, id string) (*wafPolicyRecord, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	r := &wafPolicyRecord{}
	var raw string
	var number int64
	err := securitystate.One(ctx, tx, `SELECT id,policy_id,site_id,created_by,content_digest,canonical_json,revision_number FROM config_waf_policy_revisions WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&r.revision.ID, &r.policyID, &r.siteID, &r.authorID, &r.revision.ContentDigest, &raw, &number)
	})
	if err != nil {
		return nil, err
	}
	r.policy, err = configmodel.ParseWafPolicy(strings.NewReader(raw), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	canonical, err := configmodel.CanonicalJSON(r.policy)
	if err != nil {
		return nil, err
	}
	d, err := configmodel.Digest(r.policy)
	if err != nil {
		return nil, err
	}
	if d != r.revision.ContentDigest || string(canonical) != raw || r.policy.Metadata.ID != r.policyID || r.policy.Metadata.SiteID != r.siteID {
		return nil, fmt.Errorf("WAF policy revision integrity mismatch")
	}
	r.revision.Content, r.revision.Revision, r.revision.State = json.RawMessage(raw), strconv.FormatInt(number, 10), "draft"
	r.number = number
	return r, nil
}

func wafNativeRequired() error {
	return zoneIssue("", "native_qualification_required", "Current native WAF qualification is required")
}
func (s *Service) wafProofCurrent(ctx context.Context, r *wafPolicyRecord, q *WAFQualification) error {
	if s.wafQualifier == nil {
		return wafNativeRequired()
	}
	if q == nil || !configmodel.ValidID(q.ID) || q.ContentDigest != r.revision.ContentDigest || q.RulesetVersionID != r.policy.Spec.RulesetVersionID || !configmodel.ValidID(q.ProfileID) || !time.Now().Before(q.ExpiresAt) {
		return storage.ErrConflict
	}
	if _, e := parseVersion(q.ReleaseSequence); e != nil {
		return wafNativeRequired()
	}
	for _, d := range []string{q.ContentDigest, q.RulesetDigest, q.ProfileDigest, q.TupleDigest, q.EvidenceDigest, q.ManifestDigest, q.CompilerDigest} {
		if !configmodel.ValidDigest(d) {
			return storage.ErrConflict
		}
	}
	return s.wafQualifier.Current(ctx, q)
}
func wafPolicyHeadCurrent(ctx context.Context, tx storage.IdentityTx, r *wafPolicyRecord) error {
	var id string
	err := securitystate.One(ctx, tx, `SELECT revision_id FROM config_waf_policy_heads WHERE policy_id=? AND site_id=?`, []any{r.policyID, r.siteID}, func(rows storage.IdentityRows) error { return rows.Scan(&id) })
	if err != nil {
		return err
	}
	if id != r.revision.ID {
		return ErrRevisionMismatch
	}
	return nil
}
func wafSubjectPermission(ctx context.Context, tx storage.IdentityTx, id, permission, site string, h securityjournal.Head) error {
	var admin bool
	err := securitystate.One(ctx, tx, `SELECT is_admin FROM users WHERE id=? AND blocked_at IS NULL AND lifecycle_state='active'`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&admin) })
	if err == storage.ErrNotFound {
		return storage.ErrPermissionDenied
	}
	if err != nil {
		return subjectFailure(tx, err)
	}
	p := &Principal{ID: id, Admin: admin, Epoch: int64(h.Epoch), head: h}
	if err = p.loadGrants(ctx, tx, h); err != nil {
		return err
	}
	return p.Require(permission, site)
}

func (s *Service) CreateWafPolicyRevision(ctx context.Context, a Actor, key string, in WafPolicyCreate) (out *WafPolicyRevision, err error) {
	p, err := configmodel.ParseWafPolicy(bytes.NewReader(in.Content), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	if in.Derivation != nil {
		return nil, zoneIssue("/derivation", "unsupported_derivation", "Gateway-local derivation requires the separately qualified lineage workflow")
	}
	if len(p.Spec.Exceptions) != 0 {
		return nil, zoneIssue("/content/spec/exceptions", "unsupported_exceptions", "Base policy authoring currently supports an empty exception set; route-local exceptions require qualified lineage")
	}
	if in.BaseRevisionID != "" && !validID.MatchString(in.BaseRevisionID) {
		return nil, ErrInvalidRequest
	}
	canonical, err := configmodel.CanonicalJSON(p)
	if err != nil {
		return nil, err
	}
	contentDigest, err := configmodel.Digest(p)
	if err != nil {
		return nil, err
	}
	fp := digest([]string{in.BaseRevisionID, contentDigest})
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "policy_create", RequestKey: key})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, actor *Principal) error {
		if e := actor.Require("config.edit", p.Metadata.SiteID); e != nil {
			return e
		}
		h, e := request(ctx, tx, actor.ID, "waf.policy.create", key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			r, e := readWafPolicyRecord(ctx, tx, h.id)
			if e != nil {
				return e
			}
			if e = actor.Require("config.edit", r.siteID); e != nil {
				return storage.ErrNotFound
			}
			out, e = s.wafPolicyView(ctx, tx, actor, r)
			return e
		}
		var head, site string
		var version int64
		e = securitystate.One(ctx, tx, `SELECT revision_id,site_id,row_version FROM config_waf_policy_heads WHERE policy_id=?`, []any{p.Metadata.ID}, func(rows storage.IdentityRows) error { return rows.Scan(&head, &site, &version) })
		if e != nil && e != storage.ErrNotFound {
			return e
		}
		if head != "" && actor.Require("config.edit", site) != nil {
			return storage.ErrNotFound
		}
		if head != in.BaseRevisionID {
			return ErrRevisionMismatch
		}
		if head != "" && site != p.Metadata.SiteID {
			return zoneIssue("/content/metadata/siteId", "policy_identity_immutable", "Policy Site cannot be reassigned")
		}
		if version == int64(^uint64(0)>>1) {
			return ErrUnavailable
		}
		id, now := securitystate.ID("wprev"), time.Now().UTC()
		_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_revisions(id,parent_id,policy_id,site_id,revision_number,content_digest,canonical_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, nullable(head), p.Metadata.ID, p.Metadata.SiteID, version+1, contentDigest, string(canonical), actor.ID, now)
		if e != nil {
			return e
		}
		if head == "" {
			_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_heads(policy_id,site_id,revision_id,row_version) VALUES(?,?,?,1)`, p.Metadata.ID, p.Metadata.SiteID, id)
		} else {
			var n int64
			n, e = tx.Exec(ctx, `UPDATE config_waf_policy_heads SET revision_id=?,row_version=? WHERE policy_id=? AND revision_id=? AND row_version=?`, id, version+1, p.Metadata.ID, head, version)
			if e == nil && n != 1 {
				return ErrRevisionMismatch
			}
		}
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, actor.ID, "waf.policy.create", key, fp, responseHandle{"waf_policy", id, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.policy.revision.created", actor.ID, map[string]any{"policyRevisionId": id, "policyId": p.Metadata.ID, "siteId": p.Metadata.SiteID, "contentDigest": contentDigest}); e != nil {
			return e
		}
		out = &WafPolicyRevision{ID: id, Content: canonical, ContentDigest: contentDigest, State: "draft", Revision: strconv.FormatInt(version+1, 10)}
		return nil
	})
	return
}

func (s *Service) GetWafPolicyRevision(ctx context.Context, a Actor, id string) (out *WafPolicyRevision, err error) {
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "policy_view", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readWafPolicyRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.read", r.siteID) != nil {
			return storage.ErrNotFound
		}
		out, e = s.wafPolicyView(ctx, tx, p, r)
		return e
	})
	return
}

// The body never carries mutable lifecycle state. This view derives state from
// separate immutable validation, approval and publication facts.
func (s *Service) wafPolicyView(ctx context.Context, tx storage.IdentityTx, p *Principal, r *wafPolicyRecord) (*WafPolicyRevision, error) {
	out := r.revision
	ids, err := securitystate.Strings(ctx, tx, `SELECT id FROM config_waf_policy_publications WHERE policy_revision_id=?`, r.revision.ID)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		out.State = "published"
		newer, e := securitystate.Strings(ctx, tx, `SELECT p.id FROM config_waf_policy_publications p JOIN config_waf_policy_revisions r ON r.id=p.policy_revision_id WHERE r.policy_id=? AND r.revision_number>? LIMIT 1`, r.policyID, r.number)
		if e != nil {
			return nil, e
		}
		if len(newer) > 0 {
			out.State = "superseded"
		}
		return &out, nil
	}
	if e := wafPolicyHeadCurrent(ctx, tx, r); e != nil {
		if e == ErrRevisionMismatch {
			out.State = "superseded"
			return &out, nil
		}
		return nil, e
	}
	validations, err := securitystate.Strings(ctx, tx, `SELECT id FROM config_waf_policy_validations WHERE policy_revision_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, r.revision.ID)
	if err != nil {
		return nil, err
	}
	for _, id := range validations {
		v, e := loadWafPolicyValidation(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		if s.wafValidationCurrent(ctx, tx, p, r, v) != nil {
			continue
		}
		out.State = "validated"
		approvals, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_waf_policy_approvals WHERE validation_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, id)
		if e != nil {
			return nil, e
		}
		for _, approval := range approvals {
			if _, e := s.currentWafApproval(ctx, tx, p, r, approval); e == nil {
				out.State = "approved"
				break
			}
		}
		break
	}
	return &out, nil
}

func wafValidReason(reason string) bool {
	return utf8.ValidString(reason) && len(reason) <= 4096 && utf8.RuneCountInString(strings.TrimSpace(reason)) >= 8 && utf8.RuneCountInString(reason) <= 1024
}
