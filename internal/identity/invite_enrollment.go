package identity

import (
	"context"
	"encoding/json"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *InvitationService) StartActivationEnrollment(ctx context.Context, a FlowAuth) (Enrollment, error) {
	var out Enrollment
	if !s.available() || s.identity.Keys == nil {
		return out, ErrLifecycleUnavailable
	}
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_mfa" || f.NextStep != "totp_enrollment" {
			return ErrProof
		}
		st, e := readInviteStage(ctx, tx, f.ID)
		if e != nil {
			return e
		}
		if !st.emailConfirmed || st.passwordPHC == "" || (st.state != "email" && st.state != "enrollment") {
			return ErrProof
		}
		var live int
		if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&live) }); e != nil {
			return e
		}
		if live != 0 {
			return ErrProof
		}
		// Reissuing a setup QR abandons its previous candidate. A confirmed candidate
		// is never returned again and cannot be republished by a retry.
		var version uint64
		for _, id := range []string{FactorID(f.PrincipalID), RecoveryID(f.PrincipalID)} {
			floor, e := securitystate.Floor(ctx, tx, f.PrincipalID, id)
			if e != nil {
				return e
			}
			if floor > version {
				version = floor
			}
		}
		if st.version > version {
			version = st.version
		}
		if version >= uint64(securityjournal.MaxUInt63) {
			return ErrProof
		}
		version++
		seed, e := GenerateSeed()
		if e != nil {
			return e
		}
		defer clear(seed)
		sealed, e := s.identity.Keys.Seal(seed, factorAAD(f.PrincipalID, version))
		if e != nil {
			return e
		}
		id := securitystate.ID("enroll")
		if _, e = tx.Exec(ctx, `UPDATE identity_activation_stages SET enrollment_id=?,factor_version=?,ciphertext=?,key_id=?,nonce=?,state='enrollment' WHERE flow_id=? AND state IN ('email','enrollment')`, id, int64(version), sealed.Ciphertext, sealed.KeyID, sealed.Nonce, f.ID); e != nil {
			return e
		}
		var username string
		if e = securitystate.One(ctx, tx, `SELECT username FROM users WHERE id=?`, []any{f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&username) }); e != nil {
			return e
		}
		out = Enrollment{EnrollmentID: id, ProvisioningURI: ProvisioningURI(username, seed), ExpiresAt: f.ExpiresAt}
		return nil
	})
	return out, e
}
func (s *InvitationService) ConfirmActivationEnrollment(ctx context.Context, a FlowAuth, enrollmentID, code string) (EnrollmentResult, error) {
	var out EnrollmentResult
	if !s.available() || s.identity.Keys == nil {
		return out, ErrLifecycleUnavailable
	}
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		raw, hash, e := auth.NewToken()
		if e != nil {
			return out, e
		}
		codes[i] = raw
		hashes[i] = hash
	}
	var denial error
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_mfa" || f.NextStep != "totp_enrollment" {
			return ErrProof
		}
		st, e := readInviteStage(ctx, tx, f.ID)
		if e != nil {
			return e
		}
		if st.state != "enrollment" || st.enrollmentID != enrollmentID || st.passwordPHC == "" || !st.emailConfirmed || st.version == 0 {
			return ErrProof
		}
		if e = limit(ctx, tx, "invite_totp_"+f.PrincipalID, h.RecordedAt); e != nil {
			denial = e
			return nil
		}
		seed, e := s.identity.Keys.Open(st.sealed, factorAAD(f.PrincipalID, st.version))
		if e != nil {
			return e
		}
		defer clear(seed)
		step, ok := VerifyTOTP(seed, code, h.RecordedAt, -1)
		if !ok {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		replay, e := securitystate.Floor(ctx, tx, f.PrincipalID, ReplayID(f.PrincipalID))
		if e != nil {
			return e
		}
		if uint64(step+1) <= replay {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		raw, e := json.Marshal(hashes)
		if e != nil {
			return e
		}
		n, e := tx.Exec(ctx, `UPDATE identity_activation_stages SET totp_step=?,proof_at=?,code_hashes_json=?,state='ready' WHERE flow_id=? AND state='enrollment' AND enrollment_id=?`, step, h.RecordedAt, string(raw), f.ID, enrollmentID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='ready',next_step='complete',mfa_verified=FALSE,mfa_at=NULL WHERE id=?`, f.ID); e != nil {
			return e
		}
		f.State = "ready"
		f.NextStep = "complete"
		out = EnrollmentResult{Flow: f.view(), RecoveryCodes: codes, IssuedAt: h.RecordedAt}
		return nil
	})
	if e != nil {
		return EnrollmentResult{}, e
	}
	if denial != nil {
		return EnrollmentResult{}, denial
	}
	return out, nil
}
