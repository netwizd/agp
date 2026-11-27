package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type RecoveryService struct{ identity *Service }

// NewRecoveryService is startup-only. Email/directory dependencies are resolved
// at call time so construction order never invents an anonymous fallback.
func NewRecoveryService(s *Service) *RecoveryService {
	r := &RecoveryService{identity: s}
	if s != nil && s.Coordinator != nil {
		s.recovery = r
		s.Coordinator.Register("identity_recovery", r.materializeOperation)
		s.Coordinator.Register("identity_recovery_bind", r.materializeBind)
		s.Coordinator.Register("identity_recovery_totp", r.materializeTOTP)
		s.Coordinator.Register("identity_recovery_complete", r.materializeComplete)
		s.Coordinator.Register("identity_recovery_cancel", r.materializeCancel)
	}
	return r
}

type RecoveryStep struct {
	Kind            string                 `json:"kind"`
	PrincipalID     string                 `json:"principalId"`
	AuthenticatorID string                 `json:"authenticatorId"`
	MinimumVersion  securityjournal.UInt63 `json:"minimumVersion"`
}
type RecoveryObservedFloors struct {
	Principal securityjournal.UInt63 `json:"principal"`
	Password  securityjournal.UInt63 `json:"password"`
	Factor    securityjournal.UInt63 `json:"factor"`
	Recovery  securityjournal.UInt63 `json:"recovery"`
	Replay    securityjournal.UInt63 `json:"replay"`
}
type IdentityRecoveryIntent struct {
	TargetPrincipalID       string                  `json:"targetPrincipalId"`
	ExpectedSecurityVersion securityjournal.UInt63  `json:"expectedSecurityVersion"`
	AllowedAction           string                  `json:"allowedAction"`
	ExpiresAt               time.Time               `json:"expiresAt"`
	Reason                  string                  `json:"reason"`
	ExpectedPasswordVersion securityjournal.UInt63  `json:"expectedPasswordVersion"`
	ExpectedAuthorityEpoch  securityjournal.UInt63  `json:"expectedAuthorityEpoch"`
	PolicyDigest            string                  `json:"policyDigest"`
	CustodianPrincipalID    string                  `json:"custodianPrincipalId"`
	TargetFingerprint       string                  `json:"targetFingerprint"`
	RestrictiveSteps        []RecoveryStep          `json:"restrictiveSteps"`
	ObservedFloors          *RecoveryObservedFloors `json:"observedFloors,omitempty"`
}
type RecoverySecurityOperation struct {
	ID              string                 `json:"id"`
	Family          string                 `json:"family"`
	RequestDigest   string                 `json:"requestDigest"`
	State           string                 `json:"state"`
	ApprovalStatus  string                 `json:"approvalStatus"`
	SubjectID       string                 `json:"subjectId"`
	CreatedBy       string                 `json:"createdBy"`
	CreatedAt       time.Time              `json:"createdAt"`
	RecoveryRequest IdentityRecoveryIntent `json:"recoveryRequest"`
}
type recoveryRecord struct {
	operation          RecoverySecurityOperation
	creatorFingerprint string
	postSV, postPV     uint64
}

func recoveryNext(value uint64) (uint64, error) {
	if value >= uint64(securityjournal.MaxUInt63) {
		return 0, ErrLifecycleStale
	}
	return value + 1, nil
}
func recoveryFloors(ctx context.Context, tx storage.IdentityTx, id string) (*RecoveryObservedFloors, error) {
	f := &RecoveryObservedFloors{}
	for _, entry := range []struct {
		id  string
		out *securityjournal.UInt63
	}{{"principal_" + id, &f.Principal}, {PasswordID(id), &f.Password}, {FactorID(id), &f.Factor}, {RecoveryID(id), &f.Recovery}, {ReplayID(id), &f.Replay}} {
		value, e := securitystate.Floor(ctx, tx, id, entry.id)
		if e != nil {
			return nil, e
		}
		*entry.out = securityjournal.UInt63(value)
	}
	return f, nil
}
func readRecoveryOperation(ctx context.Context, tx storage.IdentityTx, id string) (*recoveryRecord, error) {
	if !strings.HasPrefix(id, "recoveryop_") || !configmodel.ValidID(id) {
		return nil, ErrLifecycleInvalid
	}
	r := &recoveryRecord{}
	var raw, state, approval string
	e := securitystate.One(ctx, tx, `SELECT intent_json,creator_fingerprint,state,approval_status,post_security_version,post_password_version FROM identity_recovery_operations WHERE id=?`, []any{id}, func(row storage.IdentityRows) error {
		return row.Scan(&raw, &r.creatorFingerprint, &state, &approval, &r.postSV, &r.postPV)
	})
	if e != nil {
		return nil, e
	}
	if configmodel.StrictJSON(strings.NewReader(raw), &r.operation, 64<<10) != nil {
		return nil, ErrLifecycleStale
	}
	o := &r.operation
	actual, e := configmodel.Digest(o.RecoveryRequest)
	canonical, ce := configmodel.CanonicalJSON(o)
	if e != nil || ce != nil || string(canonical) != raw || o.ID != id || o.Family != "identity_recovery" || o.SubjectID != o.RecoveryRequest.TargetPrincipalID || o.CreatedBy != o.RecoveryRequest.CustodianPrincipalID || actual != o.RequestDigest {
		return nil, ErrLifecycleStale
	}
	o.State, o.ApprovalStatus = state, approval
	return r, nil
}

func (r *RecoveryService) current(ctx context.Context, a LifecycleActor, fresh, approve bool, fn func(context.Context, storage.IdentityTx, securityjournal.Head, *lifecyclePrincipal) error) error {
	if r == nil || r.identity == nil {
		return ErrLifecycleUnavailable
	}
	s := r.identity
	return s.Coordinator.WithManagementSession(ctx, a.TokenHash, func(checked context.Context) error {
		return s.Coordinator.Current(checked, func(tx storage.IdentityTx, h securityjournal.Head) error {
			p, e := s.lifecycleActor(checked, tx, h, a, "users.privileged.manage", fresh, approve)
			if e != nil {
				return e
			}
			return fn(checked, tx, h, p)
		})
	})
}
func (r *RecoveryService) people(ctx context.Context, a LifecycleActor, id string) (context.Context, error) {
	var subjects []string
	var freshContext context.Context
	e := r.current(ctx, a, false, false, func(checked context.Context, tx storage.IdentityTx, _ securityjournal.Head, actor *lifecyclePrincipal) error {
		record, e := readRecoveryOperation(checked, tx, id)
		if e != nil {
			return e
		}
		subjects = []string{record.operation.CreatedBy, record.operation.SubjectID, actor.ID}
		reviewers, e := securitystate.Strings(checked, tx, `SELECT reviewer_id FROM identity_recovery_approvals WHERE operation_id=?`, id)
		if e != nil {
			return e
		}
		subjects = append(subjects, reviewers...)
		freshContext = checked
		return nil
	})
	if e != nil {
		return nil, e
	}
	return r.identity.lifecyclePeople(freshContext, recoveryDistinct(subjects))
}
func recoveryRequests(actor string, steps []RecoveryStep) []securityjournal.AppendRequest {
	requests := make([]securityjournal.AppendRequest, 0, len(steps))
	for _, step := range steps {
		request := securitystate.FloorRequest(actor, step.PrincipalID, step.AuthenticatorID, uint64(step.MinimumVersion))
		if step.Kind == "raise_security_floor" {
			request.Kind = "raise_security_floor"
			request.TargetType = "principal"
			request.TargetID = step.PrincipalID
			request.Payload.AuthenticatorID = ""
		}
		requests = append(requests, request)
	}
	return requests
}
func recoveryActionRequest(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor, action, key, id, digest, reason string) error {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) {
		return ErrLifecycleInvalid
	}
	fingerprint, e := configmodel.Digest(struct{ ID, Digest, Reason string }{id, digest, reason})
	if e != nil {
		return e
	}
	var prior string
	e = securitystate.One(ctx, tx, `SELECT fingerprint FROM identity_recovery_requests WHERE actor_id=? AND action=? AND request_key=?`, []any{actor, action, key}, func(row storage.IdentityRows) error { return row.Scan(&prior) })
	if e == nil {
		if prior != fingerprint {
			return storage.ErrConflict
		}
		return nil
	}
	if !errors.Is(e, storage.ErrNotFound) {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO identity_recovery_requests(actor_id,action,request_key,fingerprint,operation_id,created_at) VALUES(?,?,?,?,?,?)`, actor, action, key, fingerprint, id, h.RecordedAt)
	return e
}

// RequestPasswordReset deliberately returns the same success for every target
// eligibility/delivery outcome. Only target-independent source/global overload
// escapes; anonymous issuance never changes a human floor or existing session.
func (r *RecoveryService) RequestPasswordReset(ctx context.Context, origin, sourceIP string, in PasswordResetRequest) error {
	if r == nil || r.identity == nil {
		return ErrLifecycleUnavailable
	}
	s := r.identity
	if origin != s.Profile.LoginOrigin && origin != s.Profile.ManagementOrigin {
		return ErrProof
	}
	if len(sourceIP) > 256 {
		return ErrLifecycleInvalid
	}
	var overload error
	e := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		for _, bucket := range []struct {
			name string
			max  int
		}{{"reset_global", 1000}, {"reset_source_" + auth.TokenHash(sourceIP), 60}} {
			if e := limitN(ctx, tx, bucket.name, h.RecordedAt, bucket.max); e != nil {
				if errors.Is(e, ErrLimited) {
					overload = e
					return nil
				}
				return e
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	if overload != nil {
		return overload
	}
	username := strings.ToLower(strings.TrimSpace(in.Username))
	address, invalid := emailAddress(in.Email)
	if invalid != nil || username == "" || len(username) > 128 || s.email == nil || s.invitations == nil {
		return nil
	}
	// Deliberately suppress target-specific infrastructure/eligibility failures.
	_ = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var principal string
		if e := securitystate.One(ctx, tx, `SELECT id FROM users WHERE username=? AND identity_kind='local' AND lifecycle_state='active' AND blocked_at IS NULL`, []any{username}, func(row storage.IdentityRows) error { return row.Scan(&principal) }); e != nil {
			return e
		}
		target, e := lifecycleRawUser(ctx, tx, h, principal)
		if e != nil || target.View.Privileged || target.Directory {
			return ErrProof
		}
		if e = checkLifecyclePrincipalVersions(ctx, tx, principal, target.SecurityVersion, target.PasswordVersion); e != nil {
			return e
		}
		var factorVersion uint64
		if e = securitystate.One(ctx, tx, `SELECT version FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{principal}, func(row storage.IdentityRows) error { return row.Scan(&factorVersion) }); e != nil {
			return e
		}
		floor, e := securitystate.Floor(ctx, tx, principal, FactorID(principal))
		if e != nil || factorVersion < floor {
			return ErrProof
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_contacts WHERE principal_id=? AND verified=TRUE ORDER BY id LIMIT 17`, principal)
		if e != nil || len(ids) > 16 {
			return ErrProof
		}
		for _, id := range ids {
			contact, e := s.email.readContact(ctx, tx, id, principal)
			if e != nil {
				return e
			}
			plain, e := s.email.address(contact)
			if e != nil {
				return e
			}
			matched := string(plain) == address
			clear(plain)
			if !matched {
				continue
			}
			for keyID, key := range s.email.keys.peppers {
				bucket := "reset_target_" + keyID + "_" + emailMAC(key, "AGP-RESET-TARGET-v1", strings.ToLower(address))
				if e = emailBudget(ctx, tx, bucket, h.RecordedAt, 5); e != nil {
					return e
				}
			}
			raw, hash, e := auth.NewToken()
			if e != nil {
				return e
			}
			token := &lifecycleToken{ID: securitystate.ID("reset"), PrincipalID: principal, Purpose: "reset_password", ProofKind: "email", TokenHash: hash, GuardID: securitystate.ID("guard_setup"), GuardVersion: 1, Epoch: uint64(h.Epoch), SecurityVersion: target.SecurityVersion, PasswordVersion: target.PasswordVersion, PolicyDigest: lifecyclePolicyDigest(), ContactID: contact.ID, ContactVersion: uint64(contact.AuthenticatorVersion), Generation: 1, AllowedAction: "reset_password", CreatedAt: h.RecordedAt, ExpiresAt: h.RecordedAt.Add(15 * time.Minute)}
			if e = insertLifecycleToken(ctx, tx, token); e != nil {
				return e
			}
			_, e = s.invitations.QueueEmailTokenTx(ctx, tx, h, token, raw)
			return e
		}
		return ErrProof
	})
	return nil
}

func recoveryHead(ctx context.Context, s *Service, epoch uint64) (securityjournal.Head, error) {
	if s == nil || s.Coordinator == nil || s.Coordinator.Authority == nil {
		return securityjournal.Head{}, ErrLifecycleUnavailable
	}
	h, e := s.Coordinator.Authority.Head(ctx)
	if e != nil || h.RecordedAt.IsZero() || uint64(h.Epoch) != epoch {
		return securityjournal.Head{}, ErrLifecycleUnavailable
	}
	return h, nil
}

func recoveryJSON(v any) (json.RawMessage, error) { return configmodel.CanonicalJSON(v) }

func recoveryDistinct(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, id := range values {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
