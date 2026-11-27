package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type inviteStage struct {
	flowID, tokenID, targetFingerprint, passwordPHC, enrollmentID string
	sealed                                                        Sealed
	version                                                       uint64
	emailConfirmed                                                bool
	step                                                          int64
	proofAt                                                       sql.NullTime
	codeHashes, state                                             string
	created, expires                                              time.Time
}

func readInviteStage(ctx context.Context, tx storage.IdentityTx, id string) (*inviteStage, error) {
	st := &inviteStage{}
	e := securitystate.One(ctx, tx, `SELECT flow_id,token_id,target_fingerprint,password_phc,email_confirmed,enrollment_id,factor_version,ciphertext,key_id,nonce,totp_step,proof_at,code_hashes_json,state,created_at,expires_at FROM identity_activation_stages WHERE flow_id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&st.flowID, &st.tokenID, &st.targetFingerprint, &st.passwordPHC, &st.emailConfirmed, &st.enrollmentID, &st.version, &st.sealed.Ciphertext, &st.sealed.KeyID, &st.sealed.Nonce, &st.step, &st.proofAt, &st.codeHashes, &st.state, &st.created, &st.expires)
	})
	return st, e
}

// checkReservedEmailTokenTx is shared by the two typed setup implementations.
// A reservation spends the issued guard once in the independent authority;
// only that exact +1 floor can authorize its already bound setup flow.
func checkReservedEmailTokenTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, f *flow) error {
	if t == nil || f == nil || t.ProofKind != "email" || t.ReservedAt == nil || t.ConsumedAt != nil || t.RevokedAt != nil || t.ReservedFlowID != f.ID || t.ReservedBindingHash != f.BindingHash || t.PrincipalID != f.PrincipalID || t.Epoch != f.Epoch || t.SecurityVersion != f.SecurityVersion || t.PasswordVersion != f.PasswordVersion || t.GuardVersion >= uint64(securityjournal.MaxUInt63) {
		return ErrProof
	}
	if e := checkLifecycleTokenTarget(ctx, tx, h, t); e != nil {
		return e
	}
	floor, e := securitystate.Floor(ctx, tx, t.GuardID, t.GuardID)
	if e != nil {
		return e
	}
	if floor != t.GuardVersion+1 {
		return ErrProof
	}
	return nil
}
func (s *InvitationService) flowAuth(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a FlowAuth) (*flow, error) {
	f, e := loadFlow(ctx, tx, a.ID)
	if e != nil {
		return nil, ErrProof
	}
	if a.CSRF == "" || f.Origin != a.Origin || !auth.ConstantTimeEqualHash(a.Binding, f.BindingHash) || !auth.ConstantTimeEqualHash(a.CSRF, f.CSRFHash) {
		return nil, ErrProof
	}
	if f.Purpose != "activate" || f.Audience != "setup" || f.Epoch != uint64(h.Epoch) || h.RecordedAt.IsZero() || !h.RecordedAt.Before(f.ExpiresAt) || f.State == "cancelled" || f.State == "expired" {
		return nil, ErrExpired
	}
	if f.Attempts >= 5 {
		return nil, ErrLimited
	}
	if f.PrincipalID != "" {
		if e = s.CheckFlowTx(ctx, tx, h, f); e != nil {
			return nil, e
		}
	}
	return f, nil
}
func (s *InvitationService) StartActivate(ctx context.Context, audience, origin, csrf, sourceIP string) (Transition, error) {
	var out Transition
	if !s.available() {
		return out, ErrLifecycleUnavailable
	}
	if audience != "setup" || (origin != s.identity.Profile.ManagementOrigin && origin != s.identity.Profile.LoginOrigin) || csrf == "" || len(csrf) > 256 || len(sourceIP) > 256 {
		return out, ErrProof
	}
	binding, hash, e := auth.NewToken()
	if e != nil {
		return out, e
	}
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if e := s.identity.cleanupIdentityTx(ctx, tx, h); e != nil {
			return e
		}

		if h.RecordedAt.IsZero() {
			return ErrLifecycleUnavailable
		}
		for _, b := range []struct {
			k string
			n int
		}{{"flow_global", 1000}, {"flow_source_" + auth.TokenHash(sourceIP), 60}} {
			if e = limitN(ctx, tx, b.k, h.RecordedAt, b.n); e != nil {
				return e
			}
		}
		id := securitystate.ID("flow")
		expiry := h.RecordedAt.Add(5 * time.Minute)
		_, e = tx.Exec(ctx, `INSERT INTO identity_flows(id,purpose,audience,origin,binding_hash,csrf_hash,epoch,state,next_step,expires_at,created_at) VALUES(?,'activate','setup',?,?,?,?,'pending_primary','primary',?,?)`, id, origin, hash, auth.TokenHash(csrf), int64(h.Epoch), expiry, h.RecordedAt)
		if e == nil {
			out = Transition{View: FlowView{ID: id, Purpose: "activate", Audience: "setup", State: "pending_primary", NextStep: "primary", ExpiresAt: expiry}, Binding: binding}
		}
		return e
	})
	return out, e
}

type inviteReservationIntent struct {
	FlowID, TokenID string
	Epoch           uint64
}

func (s *InvitationService) BindInvitation(ctx context.Context, a FlowAuth, raw, sourceIP string) (Transition, error) {
	var out Transition
	if !s.available() {
		return out, ErrLifecycleUnavailable
	}
	if !validLifecycleSecret(raw) || len(sourceIP) > 256 {
		return out, ErrProof
	}
	binding, hash, e := auth.NewToken()
	if e != nil {
		return out, e
	}
	e = s.identity.Coordinator.ExecuteDynamic(ctx, "invitation_reserve", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, nil, e
		}
		if f.PrincipalID != "" || f.State != "pending_primary" {
			return nil, nil, ErrProof
		}
		t, e := findLifecycleToken(ctx, tx, raw)
		if e != nil {
			return nil, nil, e
		}
		if t.Purpose != "activate" || t.AllowedAction != "activate" || t.GuardVersion >= uint64(securityjournal.MaxUInt63) {
			return nil, nil, ErrProof
		}
		if e = s.identity.lifecycleIssuerSnapshot(ctx, tx, h, t); e != nil {
			return nil, nil, e
		}
		if e = limitN(ctx, tx, "invite_claim_source_"+auth.TokenHash(sourceIP), h.RecordedAt, 20); e != nil {
			return nil, nil, e
		}
		target, e := lifecycleRawUser(ctx, tx, h, t.PrincipalID)
		if e != nil {
			return nil, nil, e
		}
		if target.Directory || target.View.Privileged || len(target.Permissions) > 0 || len(target.Grants) > 0 {
			return nil, nil, ErrProof
		}
		id := securitystate.ID("flow")
		if e = reserveEmailToken(ctx, tx, h, t, f, id, hash); e != nil {
			return nil, nil, e
		}
		expires := f.ExpiresAt
		if t.ExpiresAt.Before(expires) {
			expires = t.ExpiresAt
		}
		if _, e = tx.Exec(ctx, `INSERT INTO identity_flows(id,purpose,audience,origin,binding_hash,csrf_hash,principal_id,security_version,password_version,epoch,state,next_step,expires_at,created_at) VALUES(?,'activate','setup',?,?,?,?,?,?,?,'pending_mfa','password_setup',?,?)`, id, f.Origin, hash, f.CSRFHash, t.PrincipalID, int64(t.SecurityVersion), int64(t.PasswordVersion), int64(h.Epoch), expires, h.RecordedAt); e != nil {
			return nil, nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO identity_activation_stages(flow_id,token_id,target_fingerprint,state,created_at,expires_at) VALUES(?,?,?,'reserved',?,?)`, id, t.ID, target.Fingerprint, h.RecordedAt, expires); e != nil {
			return nil, nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=? AND state='pending_primary'`, f.ID); e != nil {
			return nil, nil, e
		}
		data, e := json.Marshal(inviteReservationIntent{id, t.ID, uint64(h.Epoch)})
		out = Transition{View: FlowView{ID: id, Purpose: "activate", Audience: "setup", State: "pending_mfa", NextStep: "password_setup", ExpiresAt: expires, ContactID: t.ContactID}, Binding: binding}
		return data, []securityjournal.AppendRequest{securitystate.FloorRequest(t.IssuerID, t.GuardID, t.GuardID, t.GuardVersion+1)}, e
	})
	if e != nil {
		return Transition{}, e
	}
	// Materialization can safely abort a stale positive intent after journal IO.
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := loadFlow(ctx, tx, out.View.ID)
		if e != nil {
			return e
		}
		return s.CheckFlowTx(ctx, tx, h, f)
	})
	if e != nil {
		return Transition{}, e
	}
	return out, nil
}
func (s *InvitationService) materializeReservation(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in inviteReservationIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	h, e := s.identity.Coordinator.Authority.Head(ctx)
	if e != nil {
		return e
	}
	f, e := loadFlow(ctx, tx, in.FlowID)
	if errors.Is(e, storage.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if in.Epoch != uint64(h.Epoch) || s.CheckFlowTx(ctx, tx, h, f) != nil {
		return s.CancelFlowTx(ctx, tx, f.ID)
	}
	return nil
}
func (s *InvitationService) CheckFlowTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow) error {
	if f == nil || f.Purpose != "activate" || f.Audience != "setup" || f.Epoch != uint64(h.Epoch) || h.RecordedAt.IsZero() || !h.RecordedAt.Before(f.ExpiresAt) || f.State == "cancelled" || f.State == "expired" || f.MFA || f.Primary || f.PrimaryAt.Valid {
		return ErrProof
	}
	if f.Origin != s.identity.Profile.LoginOrigin && f.Origin != s.identity.Profile.ManagementOrigin {
		return ErrProof
	}
	if f.PrincipalID == "" {
		if f.State != "pending_primary" || f.NextStep != "primary" || f.SecurityVersion != 0 || f.PasswordVersion != 0 || f.Primary || f.SourceSessionID != "" {
			return ErrProof
		}
		return nil
	}
	st, e := readInviteStage(ctx, tx, f.ID)
	if e != nil {
		return ErrProof
	}
	t, e := readLifecycleToken(ctx, tx, st.tokenID)
	if e != nil {
		return e
	}
	f.ContactID = t.ContactID
	if t.PrincipalID != f.PrincipalID || t.Epoch != f.Epoch || t.Purpose != "activate" || t.AllowedAction != "activate" || st.state == "aborted" || !h.RecordedAt.Before(st.expires) {
		return ErrProof
	}
	if f.State == "completed" {
		if st.state != "completed" || t.ConsumedAt == nil || t.RevokedAt != nil || f.SecurityVersion != t.SecurityVersion+1 || f.PasswordVersion != t.PasswordVersion+1 {
			return ErrProof
		}
		return checkPrincipal(ctx, tx, t.PrincipalID, f.SecurityVersion, f.PasswordVersion)
	}
	if st.state == "completed" {
		return ErrProof
	}
	if e = checkReservedEmailTokenTx(ctx, tx, h, t, f); e != nil {
		return e
	}
	if e = s.identity.lifecycleIssuerSnapshot(ctx, tx, h, t); e != nil {
		return e
	}
	target, e := lifecycleRawUser(ctx, tx, h, t.PrincipalID)
	if e != nil {
		return e
	}
	if target.Directory || target.View.Privileged || target.Fingerprint != st.targetFingerprint || len(target.Permissions) > 0 || len(target.Grants) > 0 {
		return ErrProof
	}
	return nil
}
func (s *InvitationService) SetInitialPassword(ctx context.Context, a FlowAuth, password string) (FlowView, error) {
	var out FlowView
	if !s.available() {
		return out, ErrLifecycleUnavailable
	}
	if !lifecyclePasswordValid(password) {
		return out, ErrLifecycleInvalid
	}
	// Fail cheap before entering Argon2. The second transaction repeats every pin
	// after bounded hashing outside the writer lock.
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_mfa" || f.NextStep != "password_setup" {
			return ErrProof
		}
		return nil
	})
	if e != nil {
		return out, e
	}
	select {
	case s.identity.passwordSlots <- struct{}{}:
	case <-ctx.Done():
		return out, ctx.Err()
	}
	phc, e := auth.HashPassword(password, auth.DefaultArgon2idParams)
	<-s.identity.passwordSlots
	if e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_mfa" || f.NextStep != "password_setup" {
			return ErrProof
		}
		n, e := tx.Exec(ctx, `UPDATE identity_activation_stages SET password_phc=?,state='password' WHERE flow_id=? AND state='reserved' AND password_phc=''`, phc, f.ID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_flows SET next_step='email_code' WHERE id=?`, f.ID); e != nil {
			return e
		}
		f.NextStep = "email_code"
		out = f.view()
		return nil
	})
	return out, e
}
func (s *InvitationService) EmailContactTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow) (string, error) {
	if e := s.CheckFlowTx(ctx, tx, h, f); e != nil {
		return "", e
	}
	if f.State != "pending_mfa" || f.NextStep != "email_code" {
		return "", ErrProof
	}
	st, e := readInviteStage(ctx, tx, f.ID)
	if e != nil {
		return "", e
	}
	if st.state != "password" || st.passwordPHC == "" || st.emailConfirmed {
		return "", ErrProof
	}
	t, e := readLifecycleToken(ctx, tx, st.tokenID)
	if e != nil {
		return "", e
	}
	return t.ContactID, nil
}
func (s *InvitationService) ConfirmEmailTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, contactID string) error {
	id, e := s.EmailContactTx(ctx, tx, h, f)
	if e != nil {
		return e
	}
	if id != contactID {
		return ErrProof
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_contacts SET verified=TRUE,updated_at=? WHERE id=? AND principal_id=?`, h.RecordedAt, id, f.PrincipalID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_activation_stages SET email_confirmed=TRUE,state='email' WHERE flow_id=? AND state='password'`, f.ID); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE identity_flows SET next_step='totp_enrollment' WHERE id=? AND state='pending_mfa'`, f.ID)
	if e == nil {
		f.NextStep = "totp_enrollment"
	}
	return e
}
func (s *InvitationService) CancelFlowTx(ctx context.Context, tx storage.IdentityTx, id string) error {
	if _, e := tx.Exec(ctx, `UPDATE identity_activation_stages SET state='aborted',password_phc='',ciphertext='',key_id='',nonce='',code_hashes_json='[]' WHERE flow_id=? AND state NOT IN ('completed','aborted')`, id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=? AND purpose='activate' AND state NOT IN ('completed','cancelled','expired')`, id); e != nil {
		return e
	}
	return revokeLifecycleFlowTokens(ctx, tx, id, s.identity.Now())
}
func (s *InvitationService) CancelPrincipalTx(ctx context.Context, tx storage.IdentityTx, principal string) error {
	ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_flows WHERE principal_id=? AND purpose='activate' AND state NOT IN ('completed','cancelled','expired') ORDER BY id LIMIT 101`, principal)
	if e != nil {
		return e
	}
	if len(ids) > 100 {
		return ErrLifecycleUnavailable
	}
	for _, id := range ids {
		if e = s.CancelFlowTx(ctx, tx, id); e != nil {
			return e
		}
	}
	return nil
}

type inviteCancelIntent struct{ FlowID string }

func (s *InvitationService) CancelActivation(ctx context.Context, a FlowAuth) (FlowView, error) {
	var out FlowView
	if !s.available() {
		return out, ErrLifecycleUnavailable
	}
	e := s.identity.Coordinator.ExecuteDynamic(ctx, "invitation_cancel", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, nil, e
		}
		if f.State == "completed" {
			return nil, nil, ErrProof
		}
		requests := []securityjournal.AppendRequest{}
		if f.PrincipalID != "" {
			st, e := readInviteStage(ctx, tx, f.ID)
			if e != nil {
				return nil, nil, e
			}
			t, e := readLifecycleToken(ctx, tx, st.tokenID)
			if e != nil {
				return nil, nil, e
			}
			if t.GuardVersion >= uint64(securityjournal.MaxUInt63)-1 {
				return nil, nil, ErrProof
			}
			requests = append(requests, securitystate.FloorRequest("setup", t.GuardID, t.GuardID, t.GuardVersion+2))
		}
		data, e := json.Marshal(inviteCancelIntent{f.ID})
		out = f.view()
		out.State = "cancelled"
		out.NextStep = "none"
		return data, requests, e
	})
	return out, e
}
func (s *InvitationService) materializeCancellation(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in inviteCancelIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	return s.CancelFlowTx(ctx, tx, in.FlowID)
}
func (s *InvitationService) CleanupTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	if h.RecordedAt.IsZero() {
		return ErrLifecycleUnavailable
	}
	ids, e := securitystate.Strings(ctx, tx, `SELECT s.flow_id FROM identity_activation_stages s JOIN identity_flows f ON f.id=s.flow_id WHERE s.state NOT IN ('completed','aborted') AND (s.expires_at<=? OR f.epoch<>? OR f.state IN ('cancelled','expired')) ORDER BY s.flow_id LIMIT 500`, h.RecordedAt, int64(h.Epoch))
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = s.CancelFlowTx(ctx, tx, id); e != nil {
			return e
		}
	}
	jobs, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_invite_outbox WHERE state IN ('prepared','queued','sending') ORDER BY id LIMIT 1025`)
	if e != nil {
		return e
	}
	if len(jobs) > 1024 {
		return ErrLifecycleUnavailable
	}
	for _, id := range jobs {
		j, e := inviteReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		state := ""
		if j.epoch != uint64(h.Epoch) || !h.RecordedAt.Before(j.expires) {
			state = "expired"
		} else if j.state == "sending" {
			if _, present := s.claims.Load(j.claim); !present {
				state = "unknown"
			}
		} else if !s.vault.has(j.keyRef, h.RecordedAt) {
			state = "failed"
		}
		if state != "" {
			s.vault.drop(j.keyRef)
			if _, e = tx.Exec(ctx, `UPDATE identity_invite_outbox SET state=? WHERE id=? AND state IN ('prepared','queued','sending')`, state, id); e != nil {
				return e
			}
		}
	}
	s.vault.sweep(h.RecordedAt)
	return nil
}

// RunCleanup owns no detached goroutine: the runtime starts it with a service
// context and must cancel and join it before closing the store/key vault.
func (s *InvitationService) RunCleanup(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return s.CleanupTx(ctx, tx, h) }); e != nil && !errors.Is(e, context.Canceled) {
				return e
			}
		}
	}
}
