package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// RoleScopeSnapshot contains authoritative ownership/configuration sources.
// It is frozen in the approved intent, then resolved again before publication.
type RoleScopeRef struct {
	ScopeType string `json:"scopeType"`
	ScopeID   string `json:"scopeId,omitempty"`
}
type RoleScopeSourceVersion struct {
	Kind     string                 `json:"kind"`
	ID       string                 `json:"id"`
	Revision securityjournal.UInt63 `json:"revision"`
	Digest   string                 `json:"digest,omitempty"`
}
type RoleScopeSnapshot struct {
	ScopeType string                   `json:"scopeType"`
	ScopeID   string                   `json:"scopeId,omitempty"`
	Closure   []RoleScopeRef           `json:"closure"`
	Sources   []RoleScopeSourceVersion `json:"sources"`
	Digest    string                   `json:"digest"`
}
type RoleBindingRequest struct {
	PrincipalID string `json:"principalId"`
	RoleID      string `json:"roleId"`
	ScopeType   string `json:"scopeType"`
	ScopeID     string `json:"scopeId,omitempty"`
}
type RoleGrantRequest struct {
	BindingID               string                   `json:"bindingId"`
	PrincipalID             string                   `json:"principalId"`
	RoleID                  string                   `json:"roleId"`
	RoleVersion             securityjournal.UInt63   `json:"roleVersion"`
	RoleDigest              string                   `json:"roleDigest"`
	Permissions             []string                 `json:"permissions"`
	ScopeType               string                   `json:"scopeType"`
	ScopeID                 string                   `json:"scopeId,omitempty"`
	ScopeClosure            []RoleScopeRef           `json:"scopeClosure"`
	ScopeSourceVersions     []RoleScopeSourceVersion `json:"scopeSourceVersions"`
	ScopeClosureDigest      string                   `json:"scopeClosureDigest"`
	ExpectedSecurityVersion securityjournal.UInt63   `json:"expectedSecurityVersion"`
	ExpectedPasswordVersion securityjournal.UInt63   `json:"expectedPasswordVersion"`
	TargetFingerprint       string                   `json:"targetFingerprint"`
	ExpectedAuthorityEpoch  securityjournal.UInt63   `json:"expectedAuthorityEpoch"`
	PreparedSequence        securityjournal.UInt63   `json:"preparedSequence"`
	PreparedDigest          string                   `json:"preparedDigest"`
	PolicyDigest            string                   `json:"policyDigest"`
	ExpiresAt               time.Time                `json:"expiresAt"`
	GrantExpiresAt          *time.Time               `json:"grantExpiresAt"`
}
type RoleBindingRevokeRequest struct {
	BindingID              string                 `json:"bindingId"`
	PrincipalID            string                 `json:"principalId"`
	ExpectedRevision       securityjournal.UInt63 `json:"expectedRevision"`
	RoleDigest             string                 `json:"roleDigest"`
	ExpectedAuthorityEpoch securityjournal.UInt63 `json:"expectedAuthorityEpoch"`
	Reason                 string                 `json:"reason"`
}
type RoleSecurityOperation struct {
	ID                       string                    `json:"id"`
	Family                   string                    `json:"family"`
	RequestDigest            string                    `json:"requestDigest"`
	State                    string                    `json:"state"`
	ApprovalStatus           string                    `json:"approvalStatus"`
	SubjectID                string                    `json:"subjectId"`
	CreatedBy                string                    `json:"createdBy"`
	CreatedAt                time.Time                 `json:"createdAt"`
	RoleGrantRequest         *RoleGrantRequest         `json:"roleGrantRequest,omitempty"`
	RoleBindingRevokeRequest *RoleBindingRevokeRequest `json:"roleBindingRevokeRequest,omitempty"`
}
type roleRecord struct {
	operation                                           RoleSecurityOperation
	creatorFingerprint, creatorTokenHash, creatorOrigin string
	creatorPrimaryAt, creatorMFAAt                      time.Time
}

const maxRoleIntentBytes = 64 << 20

type RoleBindingService struct{ identity *Service }

// NewRoleBindingService is startup-only. Positive grants use Current's single
// transaction; only restrictive revocation registers a journal materializer.
func NewRoleBindingService(s *Service) *RoleBindingService {
	r := &RoleBindingService{identity: s}
	if s != nil && s.Coordinator != nil {
		s.Coordinator.Register("role_binding_revoke", r.materializeRevoke)
	}
	return r
}
func rolePolicyDigest() string {
	v, _ := configmodel.Digest(struct{ Version string }{"role-grants-v1-active-quorum-scoped-5m"})
	return v
}
func roleJSON(v any) ([]byte, error) { return configmodel.CanonicalJSON(v) }
func validRoleScope(kind, id string) bool {
	if kind == "global" {
		return id == ""
	}
	switch kind {
	case "site", "node_group", "node", "resource":
		return configmodel.ValidID(id)
	}
	return false
}
func readRoleOperation(ctx context.Context, tx storage.IdentityTx, id string) (*roleRecord, error) {
	if !strings.HasPrefix(id, "roleop_") || !configmodel.ValidID(id) {
		return nil, ErrLifecycleInvalid
	}
	r := &roleRecord{}
	var raw, state, approval string
	e := securitystate.One(ctx, tx, `SELECT intent_json,creator_fingerprint,creator_token_hash,creator_origin,creator_primary_at,creator_mfa_at,state,approval_status FROM role_grant_operations WHERE id=?`, []any{id}, func(row storage.IdentityRows) error {
		return row.Scan(&raw, &r.creatorFingerprint, &r.creatorTokenHash, &r.creatorOrigin, &r.creatorPrimaryAt, &r.creatorMFAAt, &state, &approval)
	})
	if e != nil {
		return nil, e
	}
	// Canonical round-trip rejects missing/unknown/case-aliased/duplicate fields.
	// The public intent intentionally contains grantExpiresAt:null, which the
	// configuration parser forbids. Do not change that wire contract.
	if len(raw) > maxRoleIntentBytes || json.Unmarshal([]byte(raw), &r.operation) != nil {
		return nil, fmt.Errorf("%w: invalid immutable role record", ErrLifecycleStale)
	}
	o := &r.operation
	canonical, e := roleJSON(o)
	if e != nil || string(canonical) != raw || o.ID != id {
		return nil, fmt.Errorf("%w: invalid immutable role record", ErrLifecycleStale)
	}
	var intent any
	switch o.Family {
	case "grant_role_binding":
		if o.RoleGrantRequest == nil || o.RoleBindingRevokeRequest != nil || o.SubjectID != o.RoleGrantRequest.PrincipalID {
			return nil, fmt.Errorf("%w: invalid immutable role record", ErrLifecycleStale)
		}
		intent = o.RoleGrantRequest
	case "restriction":
		if o.RoleBindingRevokeRequest == nil || o.RoleGrantRequest != nil || o.SubjectID != o.RoleBindingRevokeRequest.PrincipalID {
			return nil, fmt.Errorf("%w: invalid immutable role record", ErrLifecycleStale)
		}
		intent = o.RoleBindingRevokeRequest
	default:
		return nil, fmt.Errorf("%w: invalid immutable role record", ErrLifecycleStale)
	}
	d, e := configmodel.Digest(intent)
	if e != nil || d != o.RequestDigest {
		return nil, fmt.Errorf("%w: invalid immutable role record", ErrLifecycleStale)
	}
	o.State, o.ApprovalStatus = state, approval
	return r, nil
}
func (r *RoleBindingService) current(ctx context.Context, a LifecycleActor, required string, fresh, approve bool, fn func(context.Context, storage.IdentityTx, securityjournal.Head, *lifecyclePrincipal) error) error {
	if r == nil || r.identity == nil {
		return ErrLifecycleUnavailable
	}
	s := r.identity
	return s.Coordinator.WithManagementSession(ctx, a.TokenHash, func(c context.Context) error {
		return s.Coordinator.Current(c, func(tx storage.IdentityTx, h securityjournal.Head) error {
			p, e := s.lifecycleActor(c, tx, h, a, required, fresh, approve)
			if e != nil {
				return e
			}
			return fn(c, tx, h, p)
		})
	})
}
func (r *RoleBindingService) people(ctx context.Context, a LifecycleActor, id string) (context.Context, error) {
	var subjects []string
	var checked context.Context
	e := r.current(ctx, a, "users.privileged.manage", false, false, func(c context.Context, tx storage.IdentityTx, _ securityjournal.Head, p *lifecyclePrincipal) error {
		rec, e := readRoleOperation(c, tx, id)
		if e != nil {
			return e
		}
		subjects = []string{rec.operation.CreatedBy, rec.operation.SubjectID, p.ID}
		reviewers, e := securitystate.Strings(c, tx, `SELECT reviewer_id FROM role_grant_approvals WHERE operation_id=?`, id)
		subjects = append(subjects, reviewers...)
		checked = c
		return e
	})
	if e != nil {
		return nil, e
	}
	return r.identity.lifecyclePeople(checked, recoveryDistinct(subjects))
}
func roleRequestFingerprint(v any) (string, error) { return configmodel.Digest(v) }
func roleRequestPrior(ctx context.Context, tx storage.IdentityTx, actor, action, key, fp string) (string, error) {
	var prior, id string
	e := securitystate.One(ctx, tx, `SELECT fingerprint,operation_id FROM role_grant_requests WHERE actor_id=? AND action=? AND request_key=?`, []any{actor, action, key}, func(row storage.IdentityRows) error { return row.Scan(&prior, &id) })
	if e != nil {
		return "", e
	}
	if prior != fp {
		return "", storage.ErrConflict
	}
	return id, nil
}
func roleSaveRequest(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor, action, key, fp, id string) error {
	_, e := tx.Exec(ctx, `INSERT INTO role_grant_requests(actor_id,action,request_key,fingerprint,operation_id,created_at) VALUES(?,?,?,?,?,?)`, actor, action, key, fp, id, h.RecordedAt)
	return e
}
func roleActionRequest(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor, action, key, id, digest, reason string) (bool, error) {
	fp, e := roleRequestFingerprint(struct{ ID, Digest, Reason string }{id, digest, reason})
	if e != nil {
		return false, e
	}
	prior, e := roleRequestPrior(ctx, tx, actor, action, key, fp)
	if e == nil {
		if prior != id {
			return false, storage.ErrConflict
		}
		return true, nil
	}
	if !errors.Is(e, storage.ErrNotFound) {
		return false, e
	}
	return false, roleSaveRequest(ctx, tx, h, actor, action, key, fp, id)
}
