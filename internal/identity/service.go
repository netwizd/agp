package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

var ErrProof = errors.New("invalid_proof")
var ErrExpired = errors.New("flow_expired")
var ErrLimited = errors.New("rate_limited")

type FlowView struct {
	ID           string    `json:"id"`
	Purpose      string    `json:"purpose"`
	Audience     string    `json:"audience"`
	State        string    `json:"state"`
	NextStep     string    `json:"nextStep"`
	ExpiresAt    time.Time `json:"expiresAt"`
	MFASatisfied bool      `json:"mfaSatisfied"`
	ContactID    string    `json:"contactId,omitempty"`
}
type flow struct {
	FlowView
	Origin, BindingHash, CSRFHash, PrincipalID, SourceSessionID string
	SecurityVersion, PasswordVersion, Epoch                     uint64
	Primary, MFA, Recovery                                      bool
	Attempts                                                    int
	MFAAt                                                       sql.NullTime
	PrimaryAt                                                   sql.NullTime
}
type FlowAuth struct{ ID, Binding, CSRF, Origin string }
type Transition struct {
	View    FlowView
	Binding string
}
type Enrollment struct {
	EnrollmentID    string    `json:"enrollmentId"`
	ProvisioningURI string    `json:"provisioningUri"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type EnrollmentResult struct {
	Flow          FlowView  `json:"flow"`
	RecoveryCodes []string  `json:"recoveryCodes,omitempty"`
	IssuedAt      time.Time `json:"issuedAt"`
}
type Completion struct {
	View                    FlowView
	SessionToken, CSRFToken string
	Session                 domain.Session
}
type Service struct {
	Store              storage.Store
	Coordinator        *securitystate.Coordinator
	Keys               *Keyring
	Profile            domain.SessionProfile
	Now                func() time.Time
	dummy              string
	verifyPassword     func(string, string) (bool, error)
	passwordSlots      chan struct{}
	directory          *DirectoryService
	directoryConnector *ADConnector
	email              *EmailService
	invitations        activationLifecycle
	recovery           recoveryLifecycle
	roleBindings       *RoleBindingService
}

func New(store storage.Store, coordinator *securitystate.Coordinator, keys *Keyring, profile domain.SessionProfile) (*Service, error) {
	dummy, err := auth.HashPassword("unavailable-local-principal-secret", auth.DefaultArgon2idParams)
	if err != nil {
		return nil, err
	}
	s := &Service{Store: store, Coordinator: coordinator, Keys: keys, Profile: profile, Now: func() time.Time { return time.Now().UTC() }, dummy: dummy, verifyPassword: auth.VerifyPassword, passwordSlots: make(chan struct{}, 2)}
	coordinator.Register("mfa_enrollment", s.materializeEnrollment)
	coordinator.Register("mfa_recovery", s.materializeRecovery)
	coordinator.Register("totp_proof", s.materializeTOTP)
	coordinator.Register("step_up_completion", s.materializeCompletion)
	coordinator.Register("logout", func(context.Context, storage.IdentityTx, json.RawMessage) error { return nil })
	NewInvitationService(s)
	NewRecoveryService(s)
	s.roleBindings = NewRoleBindingService(s)
	coordinator.RegisterIdentityTargetGuard(s.legacyIdentityTargetAuthorization)
	return s, nil
}
func (f *flow) view() FlowView {
	v := f.FlowView
	v.MFASatisfied = f.MFA && (f.Purpose == "login" || f.Purpose == "step_up") && (f.State == "ready" || f.State == "completed")
	return v
}
func loadFlow(ctx context.Context, tx storage.IdentityTx, id string) (*flow, error) {
	f := &flow{}
	err := securitystate.One(ctx, tx, `SELECT id,purpose,audience,origin,binding_hash,csrf_hash,principal_id,security_version,password_version,epoch,state,next_step,primary_verified,mfa_verified,source_session_id,expires_at,attempts,mfa_at,recovery_authorized,primary_verified_at FROM identity_flows WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&f.ID, &f.Purpose, &f.Audience, &f.Origin, &f.BindingHash, &f.CSRFHash, &f.PrincipalID, &f.SecurityVersion, &f.PasswordVersion, &f.Epoch, &f.State, &f.NextStep, &f.Primary, &f.MFA, &f.SourceSessionID, &f.ExpiresAt, &f.Attempts, &f.MFAAt, &f.Recovery, &f.PrimaryAt)
	})
	return f, err
}
func (s *Service) checked(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a FlowAuth) (*flow, error) {
	f, err := loadFlow(ctx, tx, a.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrProof
	}
	if err != nil {
		return nil, err
	}
	if f.Origin != a.Origin || !auth.ConstantTimeEqualHash(a.Binding, f.BindingHash) || (a.CSRF != "" && !auth.ConstantTimeEqualHash(a.CSRF, f.CSRFHash)) {
		return nil, ErrProof
	}
	if f.Epoch != uint64(h.Epoch) || !s.Now().Before(f.ExpiresAt) {
		return nil, ErrExpired
	}
	if f.State == "cancelled" || f.State == "expired" {
		return nil, ErrExpired
	}
	if f.Attempts >= 5 {
		return nil, ErrLimited
	}
	if f.Purpose == "activate" {
		if s.invitations == nil {
			return nil, ErrLifecycleUnavailable
		}
		if err := s.invitations.CheckFlowTx(ctx, tx, h, f); err != nil {
			return nil, err
		}
		return f, nil
	}
	if f.Purpose == "recover" && s.recovery != nil {
		if err := s.recovery.CheckFlowTx(ctx, tx, h, f); err != nil {
			return nil, err
		}
	}
	if f.PrincipalID != "" {
		if err := checkPrincipal(ctx, tx, f.PrincipalID, f.SecurityVersion, f.PasswordVersion); err != nil {
			return nil, err
		}
	}
	if f.PrincipalID != "" {
		if err := directoryCheckProjection(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return nil, err
		}
	}
	return f, nil
}
func checkPrincipal(ctx context.Context, tx storage.IdentityTx, id string, securityVersion, passwordVersion uint64) error {
	var sv, pv uint64
	var blocked sql.NullTime
	var state string
	err := securitystate.One(ctx, tx, `SELECT security_version,password_version,blocked_at,lifecycle_state FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&sv, &pv, &blocked, &state) })
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if err != nil || state != "active" || blocked.Valid || sv != securityVersion || pv != passwordVersion {
		return ErrProof
	}
	floor, err := securitystate.Floor(ctx, tx, id, PasswordID(id))
	if err != nil {
		return err
	}
	if pv < floor {
		return ErrProof
	}
	floor, err = securitystate.Floor(ctx, tx, id, "principal_"+id)
	if err != nil {
		return err
	}
	if sv < floor {
		return ErrProof
	}
	return nil
}
func (s *Service) Start(ctx context.Context, purpose, audience, origin, csrf, sourceHash string) (Transition, error) {
	return s.StartWithSource(ctx, purpose, audience, origin, csrf, sourceHash, "internal")
}
func (s *Service) StartWithSource(ctx context.Context, purpose, audience, origin, csrf, sourceHash, sourceIP string) (Transition, error) {
	var out Transition
	if purpose == "activate" {
		if s.invitations == nil {
			return out, ErrLifecycleUnavailable
		}
		return s.invitations.StartActivate(ctx, audience, origin, csrf, sourceIP)
	}
	if purpose == "verify_email" {
		if s.email == nil {
			return out, ErrEmailUnavailable
		}
		return s.email.StartFlow(ctx, audience, origin, csrf, sourceHash, sourceIP)
	}
	if purpose == "recover" && audience != "setup" {
		return out, ErrProof
	}
	if purpose != "login" && purpose != "recover" && purpose != "step_up" {
		return out, ErrProof
	}
	if origin == s.Profile.ManagementOrigin {
		if audience != "management" && !(purpose == "recover" && audience == "setup") {
			return out, ErrProof
		}
	} else if origin == s.Profile.LoginOrigin {
		if audience != "login" && !(purpose == "recover" && audience == "setup") {
			return out, ErrProof
		}
	} else {
		return out, ErrProof
	}
	binding, bindingHash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	id := securitystate.ID("flow")
	expires := s.Now().Add(5 * time.Minute)
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if e := s.cleanupIdentityTx(ctx, tx, h); e != nil {
			return e
		}
		for _, entry := range []struct {
			bucket string
			max    int
		}{{"flow_global", 1000}, {"flow_source_" + auth.TokenHash(sourceIP), 60}} {
			if err := limitN(ctx, tx, entry.bucket, s.Now(), entry.max); err != nil {
				return err
			}
		}
		sourceID := ""
		if purpose == "step_up" {
			var storedOrigin, storedAudience string
			var epoch uint64
			var expires time.Time
			err := securitystate.One(ctx, tx, `SELECT id,audience,audience_origin,authority_epoch,expires_at FROM sessions WHERE token_hash=? AND revoked_at IS NULL`, []any{sourceHash}, func(r storage.IdentityRows) error {
				return r.Scan(&sourceID, &storedAudience, &storedOrigin, &epoch, &expires)
			})
			if err != nil || epoch != uint64(h.Epoch) || storedOrigin != origin || storedAudience != audience || !s.Now().Before(expires) {
				return ErrProof
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_flows(id,purpose,audience,origin,binding_hash,csrf_hash,epoch,state,next_step,source_session_id,expires_at) VALUES(?,?,?,?,?,?,?,'pending_primary','primary',?,?)`, id, purpose, audience, origin, bindingHash, auth.TokenHash(csrf), int64(h.Epoch), sourceID, expires); err != nil {
			return err
		}
		out = Transition{View: FlowView{ID: id, Purpose: purpose, Audience: audience, State: "pending_primary", NextStep: "primary", ExpiresAt: expires}, Binding: binding}
		return nil
	})
	return out, err
}
func (s *Service) Get(ctx context.Context, a FlowAuth) (FlowView, error) {
	var out FlowView
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err == nil {
			out = f.view()
		}
		return err
	})
	return out, err
}
func (s *Service) Cancel(ctx context.Context, a FlowAuth) (FlowView, error) {
	var out FlowView
	// Select the typed cancellation using the authenticated flow. Each setup
	// cancellation owns its durable service-guard event before erasing staging.
	view, err := s.Get(ctx, a)
	if err != nil {
		return out, err
	}
	if view.Purpose == "activate" {
		if s.invitations == nil {
			return out, ErrLifecycleUnavailable
		}
		return s.invitations.CancelActivation(ctx, a)
	}
	if view.Purpose == "recover" && s.recovery != nil {
		return s.recovery.CancelRecovery(ctx, a)
	}
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if f.State == "completed" {
			return ErrProof
		}
		if err := CancelOIDCAuthorizations(ctx, tx, f.ID); err != nil {
			return err
		}
		if s.email != nil {
			if err := s.email.CancelFlow(ctx, tx, f.ID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=?`, f.ID); err != nil {
			return err
		}
		f.State = "cancelled"
		f.NextStep = "none"
		out = f.view()
		return nil
	})
	return out, err
}
func badAttempt(ctx context.Context, tx storage.IdentityTx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE identity_flows SET attempts=attempts+1 WHERE id=?`, id)
	return err
}
func limit(ctx context.Context, tx storage.IdentityTx, bucket string, now time.Time) error {
	return limitN(ctx, tx, bucket, now, 10)
}
func limitN(ctx context.Context, tx storage.IdentityTx, bucket string, now time.Time, max int) error {
	var start time.Time
	var attempts int
	err := securitystate.One(ctx, tx, `SELECT window_start,attempts FROM identity_limits WHERE bucket=?`, []any{bucket}, func(r storage.IdentityRows) error { return r.Scan(&start, &attempts) })
	if errors.Is(err, storage.ErrNotFound) {
		_, err = tx.Exec(ctx, `INSERT INTO identity_limits(bucket,window_start,attempts) VALUES(?,?,1)`, bucket, now)
		return err
	}
	if err != nil {
		return err
	}
	if now.Sub(start) >= time.Minute {
		_, err = tx.Exec(ctx, `UPDATE identity_limits SET window_start=?,attempts=1 WHERE bucket=?`, now, bucket)
		return err
	}
	if attempts >= max {
		return ErrLimited
	}
	_, err = tx.Exec(ctx, `UPDATE identity_limits SET attempts=attempts+1 WHERE bucket=?`, bucket)
	return err
}
func (s *Service) Primary(ctx context.Context, a FlowAuth, username, password, sourceIP string) (Transition, error) {
	var out Transition
	if len(password) > 1024 || len(username) > 128 {
		return out, ErrProof
	}
	username = strings.ToLower(strings.TrimSpace(username))
	var denial error
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_primary" || (f.Purpose != "login" && f.Purpose != "recover" && f.Purpose != "step_up") {
			return ErrProof
		}
		for _, bucket := range []string{"primary_source_" + auth.TokenHash(sourceIP), "primary_account_" + auth.TokenHash(username)} {
			if e = limit(ctx, tx, bucket, s.Now()); e != nil {
				if errors.Is(e, ErrLimited) {
					denial = e
					return nil
				}
				return e
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	if denial != nil {
		return out, denial
	}
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	case <-ctx.Done():
		return out, ctx.Err()
	default:
		return out, ErrLimited
	}
	user, findErr := s.Store.FindUserByUsername(ctx, username)
	if findErr != nil && !errors.Is(findErr, storage.ErrNotFound) {
		return out, findErr
	}
	encoded := s.dummy
	if findErr == nil && user.PasswordHash != "" {
		encoded = user.PasswordHash
	}
	valid, verifyErr := s.verifyPassword(password, encoded)
	valid = valid && verifyErr == nil && findErr == nil
	binding, bindingHash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if f.State != "pending_primary" || (f.Purpose != "login" && f.Purpose != "recover" && f.Purpose != "step_up") {
			return ErrProof
		}
		if !valid {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		var sv, pv uint64
		var blocked sql.NullTime
		var currentHash string
		err = securitystate.One(ctx, tx, `SELECT password_hash,security_version,password_version,blocked_at FROM users WHERE id=? AND identity_kind='local'`, []any{user.ID}, func(r storage.IdentityRows) error { return r.Scan(&currentHash, &sv, &pv, &blocked) })
		if err != nil || currentHash != encoded || blocked.Valid {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		if err := checkPrincipal(ctx, tx, user.ID, sv, pv); err != nil {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		if f.Purpose == "step_up" {
			var principal string
			err := securitystate.One(ctx, tx, `SELECT user_id FROM sessions WHERE id=? AND revoked_at IS NULL`, []any{f.SourceSessionID}, func(r storage.IdentityRows) error { return r.Scan(&principal) })
			if err != nil || principal != user.ID {
				return ErrProof
			}
		}
		if f.Audience == "management" {
			allowed, e := managementAdmissionTx(ctx, tx, h, user.ID)
			if e != nil {
				return e
			}
			if !allowed {
				denial = ErrProof
				return badAttempt(ctx, tx, f.ID)
			}
		}
		next := "totp"
		var verified, revoked bool
		factorErr := securitystate.One(ctx, tx, `SELECT verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{user.ID}, func(r storage.IdentityRows) error { return r.Scan(&verified, &revoked) })
		floor, err := securitystate.Floor(ctx, tx, user.ID, FactorID(user.ID))
		if err != nil {
			return err
		}
		if factorErr != nil && !errors.Is(factorErr, storage.ErrNotFound) {
			return factorErr
		}
		if factorErr != nil || !verified || revoked {
			if floor > 0 {
				next = "recovery"
			} else {
				next = "totp_enrollment"
			}
		}
		if f.Purpose == "recover" {
			next = "recovery"
		}
		newFlowID := securitystate.ID("flow")
		if _, err := tx.Exec(ctx, `UPDATE identity_flows SET id=?,principal_id=?,security_version=?,password_version=?,binding_hash=?,primary_verified=?,primary_verified_at=?,oidc_authentication=FALSE,state='pending_mfa',next_step=? WHERE id=?`, newFlowID, user.ID, int64(sv), int64(pv), bindingHash, true, s.Now(), next, f.ID); err != nil {
			return err
		}
		f.ID = newFlowID
		f.PrincipalID = user.ID
		f.SecurityVersion = sv
		f.PasswordVersion = pv
		f.Primary = true
		f.PrimaryAt = sql.NullTime{Time: s.Now(), Valid: true}
		f.State = "pending_mfa"
		f.NextStep = next
		out = Transition{View: f.view(), Binding: binding}
		return nil
	})
	if err != nil {
		return out, err
	}
	return out, denial
}

type totpIntent struct {
	FlowID, PrincipalID string
	Version             uint64
	Step                int64
	ProofAt             time.Time
}

func (s *Service) verifiedTOTP(ctx context.Context, tx storage.IdentityTx, f *flow, code string) (totpIntent, error) {
	var out totpIntent
	if !f.Primary || f.Purpose == "recover" || f.State != "pending_mfa" || f.NextStep != "totp" {
		return out, ErrProof
	}
	var sealed Sealed
	var version uint64
	var last int64
	var verified, revoked bool
	if err := securitystate.One(ctx, tx, `SELECT ciphertext,key_id,nonce,version,last_step,verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{f.PrincipalID}, func(r storage.IdentityRows) error {
		return r.Scan(&sealed.Ciphertext, &sealed.KeyID, &sealed.Nonce, &version, &last, &verified, &revoked)
	}); err != nil {
		return out, ErrProof
	}
	floor, err := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
	if err != nil {
		return out, err
	}
	if version < floor || !verified || revoked {
		return out, ErrProof
	}
	replayFloor, err := securitystate.Floor(ctx, tx, f.PrincipalID, ReplayID(f.PrincipalID))
	if err != nil {
		return out, err
	}
	if replayFloor > 0 && uint64(last+1) < replayFloor {
		last = int64(replayFloor) - 1
	}
	seed, err := s.Keys.Open(sealed, factorAAD(f.PrincipalID, version))
	if err != nil {
		return out, err
	}
	step, ok := VerifyTOTP(seed, code, s.Now(), last)
	if !ok {
		return out, ErrProof
	}
	return totpIntent{FlowID: f.ID, PrincipalID: f.PrincipalID, Version: version, Step: step, ProofAt: s.Now()}, nil
}
func (s *Service) TOTPProof(ctx context.Context, a FlowAuth, code string) (FlowView, error) {
	var reset bool
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.Purpose == "activate" {
			return ErrProof
		}
		if f.Purpose == "recover" && s.recovery != nil {
			reset, e = s.recovery.IsPasswordResetTx(ctx, tx, f.ID)
			return e
		}
		return nil
	})
	if err != nil {
		return FlowView{}, err
	}
	if reset {
		return s.recovery.VerifyResetTOTP(ctx, a, code)
	}

	var out FlowView
	directoryProof, directoryErr := s.directoryFlowObservation(ctx, a)
	if directoryErr != nil {
		return out, directoryErr
	}
	var denial error
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return err
		}
		if err = limit(ctx, tx, "totp_"+f.PrincipalID, s.Now()); err != nil {
			if errors.Is(err, ErrLimited) {
				denial = err
				return nil
			}
			return err
		}
		_, err = s.verifiedTOTP(ctx, tx, f, code)
		if errors.Is(err, ErrProof) {
			denial = err
			return badAttempt(ctx, tx, f.ID)
		}
		return err
	})
	if err != nil {
		return out, err
	}
	if denial != nil {
		return out, denial
	}
	err = s.Coordinator.ExecuteDynamic(ctx, "totp_proof", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return nil, nil, err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return nil, nil, err
		}
		intent, err := s.verifiedTOTP(ctx, tx, f, code)
		if err != nil {
			return nil, nil, err
		}
		raw, err := json.Marshal(intent)
		return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, ReplayID(f.PrincipalID), uint64(intent.Step+1))}, err
	})
	if err != nil {
		return out, err
	}
	return s.Get(ctx, a)
}
func (s *Service) materializeTOTP(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var i totpIntent
	if err := json.Unmarshal(raw, &i); err != nil {
		return err
	}
	n, err := tx.Exec(ctx, `UPDATE mfa_factors SET last_step=? WHERE principal_id=? AND version=? AND last_step<?`, i.Step, i.PrincipalID, int64(i.Version), i.Step)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrProof
	}
	n, err = tx.Exec(ctx, `UPDATE identity_flows SET mfa_verified=?,mfa_at=?,state='ready',next_step='complete' WHERE id=? AND principal_id=? AND state='pending_mfa'`, true, i.ProofAt, i.FlowID, i.PrincipalID)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrProof
	}
	return securitystate.Audit(ctx, tx, "identity.mfa.proved", i.PrincipalID, map[string]any{"flow": i.FlowID})
}

// managementAdmissionTx admits scoped operators without projecting any scoped
// permission into a flat session. The current administrator flag is read under
// the same writer boundary; a pre-password user snapshot supplies no authority.
func managementAdmissionTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (bool, error) {
	allowed, _, e := managementAdmissionWitnessTx(ctx, tx, h, id)
	return allowed, e
}

// The witness is valid only in this locked writer transaction. A nil deadline
// means a current legacy administrator or an effective grant without expiry.
func managementAdmissionWitnessTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (bool, *time.Time, error) {
	grants, e := securitystate.ReadEffectiveGrants(ctx, tx, h, id)
	if e != nil {
		return false, nil, e
	}
	var admin bool
	e = securitystate.One(ctx, tx, `SELECT is_admin FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&admin) })
	if e != nil {
		return false, nil, e
	}
	if admin {
		return true, nil, nil
	}
	var latest time.Time
	for _, g := range grants.Entries {
		if g.ExpiresAt == nil {
			return true, nil, nil
		}
		if g.ExpiresAt.After(latest) {
			latest = *g.ExpiresAt
		}
	}
	if latest.IsZero() {
		return false, nil, nil
	}
	return true, &latest, nil
}

// Cleanup bounds unauthenticated ephemeral state. It runs under the global
// identity transaction and cannot remove a flow while a journal intent is
// pending, because admission is blocked by the coordinator barrier.
func Cleanup(ctx context.Context, tx storage.IdentityTx, now time.Time) error {
	if err := CleanupOIDCAuthorizations(ctx, tx, now); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM mfa_enrollments WHERE expires_at<=?`, `DELETE FROM identity_flows WHERE expires_at<=?`, `DELETE FROM handoffs WHERE expires_at<=?`, `DELETE FROM identity_limits WHERE window_start<?`} {
		cutoff := now
		if strings.Contains(q, "identity_limits") {
			cutoff = now.Add(-2 * time.Minute)
		}
		if _, err := tx.Exec(ctx, q, cutoff); err != nil {
			return err
		}
	}
	return nil
}
