package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type enrollmentIntent struct {
	FlowID       string    `json:"flowId"`
	PrincipalID  string    `json:"principalId"`
	EnrollmentID string    `json:"enrollmentId"`
	Version      uint64    `json:"version"`
	Step         int64     `json:"step"`
	ProofAt      time.Time `json:"proofAt"`
	Epoch        uint64    `json:"epoch"`
	Sealed       Sealed    `json:"sealed"`
	CodeHashes   []string  `json:"codeHashes"`
	Recovery     bool      `json:"recovery"`
}
type recoveryIntent struct{ FlowID, PrincipalID string }

func (s *Service) StartEnrollment(ctx context.Context, a FlowAuth) (out Enrollment, err error) {
	if s.recovery == nil {
		return out, ErrLifecycleUnavailable
	}
	err = s.recovery.WithMFAReplacementPeople(ctx, a, func(ctx context.Context) error { var e error; out, e = s.startEnrollment(ctx, a); return e })
	return out, err
}
func (s *Service) startEnrollment(ctx context.Context, a FlowAuth) (Enrollment, error) {
	var out Enrollment
	view, flowErr := s.Get(ctx, a)
	if flowErr != nil {
		return out, flowErr
	}
	if view.Purpose == "activate" {
		if s.invitations == nil {
			return out, ErrLifecycleUnavailable
		}
		return s.invitations.StartActivationEnrollment(ctx, a)
	}

	directoryProof, directoryErr := s.directoryFlowObservation(ctx, a)
	if directoryErr != nil {
		return out, directoryErr
	}
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return err
		}
		if !f.Primary || f.State != "pending_mfa" || ((f.Purpose == "recover" && !f.Recovery) || (f.Purpose != "recover" && f.NextStep != "totp_enrollment")) {
			return ErrProof
		}
		if f.Purpose == "recover" {
			if s.recovery == nil {
				return ErrLifecycleUnavailable
			}
			if err := s.recovery.AllowMFAReplacementTx(ctx, tx, h, f); err != nil {
				return err
			}
		}
		var version uint64
		var verified, revoked bool
		err = securitystate.One(ctx, tx, `SELECT version,verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&version, &verified, &revoked) })
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		floor, err := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
		if err != nil {
			return err
		}
		if !f.Recovery && (floor > 0 || (verified && !revoked)) {
			return ErrProof
		}
		if version < floor {
			version = floor
		}
		version++
		seed, err := GenerateSeed()
		if err != nil {
			return err
		}
		sealed, err := s.Keys.Seal(seed, factorAAD(f.PrincipalID, version))
		if err != nil {
			return err
		}
		id := securitystate.ID("enroll")
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE flow_id=?`, f.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mfa_enrollments(id,flow_id,principal_id,version,ciphertext,key_id,nonce,expires_at) VALUES(?,?,?,?,?,?,?,?)`, id, f.ID, f.PrincipalID, int64(version), sealed.Ciphertext, sealed.KeyID, sealed.Nonce, f.ExpiresAt); err != nil {
			return err
		}
		var username string
		if err := securitystate.One(ctx, tx, `SELECT username FROM users WHERE id=?`, []any{f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&username) }); err != nil {
			return err
		}
		out = Enrollment{EnrollmentID: id, ProvisioningURI: ProvisioningURI(username, seed), ExpiresAt: f.ExpiresAt}
		return nil
	})
	return out, err
}
func (s *Service) ConfirmEnrollment(ctx context.Context, a FlowAuth, enrollmentID, code string) (out EnrollmentResult, err error) {
	if s.recovery == nil {
		return out, ErrLifecycleUnavailable
	}
	err = s.recovery.WithMFAReplacementPeople(ctx, a, func(ctx context.Context) error {
		var e error
		out, e = s.confirmEnrollment(ctx, a, enrollmentID, code)
		return e
	})
	return out, err
}
func (s *Service) confirmEnrollment(ctx context.Context, a FlowAuth, enrollmentID, code string) (EnrollmentResult, error) {
	var out EnrollmentResult
	view, flowErr := s.Get(ctx, a)
	if flowErr != nil {
		return out, flowErr
	}
	if view.Purpose == "activate" {
		if s.invitations == nil {
			return out, ErrLifecycleUnavailable
		}
		return s.invitations.ConfirmActivationEnrollment(ctx, a, enrollmentID, code)
	}

	directoryProof, directoryErr := s.directoryFlowObservation(ctx, a)
	if directoryErr != nil {
		return out, directoryErr
	}
	var intent enrollmentIntent
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		raw, hash, err := auth.NewToken()
		if err != nil {
			return out, err
		}
		codes[i] = raw
		hashes[i] = hash
	}
	// Check and durable failed-attempt accounting happen before the coordinator
	// creates a restrictive operation. A rejected proof must still commit counters.
	var denial error
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return err
		}
		if !f.Primary || f.State != "pending_mfa" || (f.Purpose == "recover" && !f.Recovery) {
			return ErrProof
		}
		if err := limit(ctx, tx, "totp_"+f.PrincipalID, s.Now()); err != nil {
			denial = err
			return nil
		}
		var sealed Sealed
		var version uint64
		var expiry time.Time
		err = securitystate.One(ctx, tx, `SELECT version,ciphertext,key_id,nonce,expires_at FROM mfa_enrollments WHERE id=? AND flow_id=? AND principal_id=?`, []any{enrollmentID, f.ID, f.PrincipalID}, func(r storage.IdentityRows) error {
			return r.Scan(&version, &sealed.Ciphertext, &sealed.KeyID, &sealed.Nonce, &expiry)
		})
		if err != nil || !s.Now().Before(expiry) {
			return ErrProof
		}
		if f.Purpose == "recover" {
			if s.recovery == nil {
				return ErrLifecycleUnavailable
			}
			if err := s.recovery.AllowMFAReplacementTx(ctx, tx, h, f); err != nil {
				return err
			}
		}
		if err := enrollmentPermitted(ctx, tx, f, version); err != nil {
			return err
		}
		seed, err := s.Keys.Open(sealed, factorAAD(f.PrincipalID, version))
		if err != nil {
			return err
		}
		step, ok := VerifyTOTP(seed, code, s.Now(), -1)
		if !ok {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		replayFloor, err := securitystate.Floor(ctx, tx, f.PrincipalID, ReplayID(f.PrincipalID))
		if err != nil {
			return err
		}
		if uint64(step+1) <= replayFloor {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		intent = enrollmentIntent{FlowID: f.ID, PrincipalID: f.PrincipalID, EnrollmentID: enrollmentID, Version: version, Step: step, ProofAt: s.Now(), Epoch: uint64(h.Epoch), Sealed: sealed, CodeHashes: hashes, Recovery: f.Purpose == "recover"}
		return nil
	})
	if err != nil {
		return out, err
	}
	if denial != nil {
		return out, denial
	}
	// Retain the server-owned flow observation through the final writer. It is
	// intentionally volatile: recovered positive publication must collect new
	// evidence or retire safely without installing credentials.
	proofs := directoryPeopleProofs{}
	if previous, ok := ctx.Value(directoryPeopleProofKey{}).(directoryPeopleProofs); ok {
		for id, p := range previous {
			proofs[id] = p
		}
	}
	if directoryProof != nil {
		proofs[intent.PrincipalID] = directoryProof
	}
	ctx = context.WithValue(ctx, directoryPeopleProofKey{}, proofs)
	data, _ := json.Marshal(intent)
	err = s.Coordinator.Execute(ctx, securitystate.Intent{Kind: "mfa_enrollment", Data: data}, func(tx storage.IdentityTx, h securityjournal.Head) ([]securityjournal.AppendRequest, error) {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return nil, err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return nil, err
		}
		if f.State != "pending_mfa" || f.PrincipalID != intent.PrincipalID {
			return nil, ErrProof
		}
		var version uint64
		if err := securitystate.One(ctx, tx, `SELECT version FROM mfa_enrollments WHERE id=? AND flow_id=?`, []any{enrollmentID, f.ID}, func(r storage.IdentityRows) error { return r.Scan(&version) }); err != nil || version != intent.Version {
			return nil, ErrProof
		}
		if f.Purpose == "recover" {
			if s.recovery == nil {
				return nil, ErrLifecycleUnavailable
			}
			if err := s.recovery.AllowMFAReplacementTx(ctx, tx, h, f); err != nil {
				return nil, err
			}
		}
		if err := enrollmentPermitted(ctx, tx, f, version); err != nil {
			return nil, err
		}
		return []securityjournal.AppendRequest{securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, FactorID(f.PrincipalID), version), securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, RecoveryID(f.PrincipalID), version), securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, ReplayID(f.PrincipalID), uint64(intent.Step+1))}, nil
	})
	if err != nil {
		return out, err
	}
	a.CSRF = ""
	view, err = s.Get(ctx, a)
	if err != nil {
		return out, err
	}
	if view.State != "ready" || view.NextStep != "complete" {
		return out, ErrProof
	}
	out = EnrollmentResult{Flow: view, RecoveryCodes: codes, IssuedAt: s.Now()}
	return out, nil
}
func (s *Service) materializeEnrollment(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var intent enrollmentIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		return err
	}
	f, err := loadFlow(ctx, tx, intent.FlowID)
	if errors.Is(err, storage.ErrNotFound) {
		_, e := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE id=? AND flow_id=?`, intent.EnrollmentID, intent.FlowID)
		return e
	}
	if err != nil {
		return err
	}
	if f.State == "ready" || f.State == "completed" {
		return nil
	}
	h, err := s.Coordinator.Authority.Head(ctx)
	if err != nil {
		return err
	}
	if err = s.finalEnrollmentAuthority(ctx, tx, h, f, &intent); err != nil {
		switch {
		case errors.Is(err, ErrProof), errors.Is(err, ErrExpired), errors.Is(err, ErrDirectoryUnavailable), errors.Is(err, storage.ErrPermissionDenied), errors.Is(err, storage.ErrNotFound), errors.Is(err, ErrLifecycleStale):
			// The journal has already made this enrollment version unusable for a new
			// attempt. Retire only this staged candidate; keep the typed capability
			// pending. A retry needs a fresh seed/version above these retained floors.
			if _, e := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE id=? AND flow_id=?`, intent.EnrollmentID, intent.FlowID); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `UPDATE identity_flows SET next_step='totp_enrollment',mfa_verified=FALSE,mfa_at=NULL WHERE id=? AND principal_id=? AND state='pending_mfa'`, f.ID, intent.PrincipalID); e != nil {
				return e
			}
			return securitystate.Audit(ctx, tx, "identity.mfa.enrollment_aborted", intent.PrincipalID, map[string]any{"flowId": intent.FlowID, "version": intent.Version})
		default:
			return err
		}
	}
	sealed := intent.Sealed
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_factors(principal_id,authenticator_id,version,ciphertext,key_id,nonce,last_step,verified,revoked) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(principal_id) DO UPDATE SET version=excluded.version,ciphertext=excluded.ciphertext,key_id=excluded.key_id,nonce=excluded.nonce,last_step=excluded.last_step,verified=excluded.verified,revoked=excluded.revoked`, intent.PrincipalID, FactorID(intent.PrincipalID), int64(intent.Version), sealed.Ciphertext, sealed.KeyID, sealed.Nonce, intent.Step, true, false); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE principal_id=?`, intent.PrincipalID); err != nil {
		return err
	}
	for _, hash := range intent.CodeHashes {
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes(code_hash,principal_id,batch_version,epoch) VALUES(?,?,?,?)`, hash, intent.PrincipalID, int64(intent.Version), int64(intent.Epoch)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE id=?`, intent.EnrollmentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_flows SET mfa_verified=?,mfa_at=?,state='ready',next_step='complete' WHERE id=?`, !intent.Recovery, intent.ProofAt, intent.FlowID); err != nil {
		return err
	}
	return securitystate.Audit(ctx, tx, "identity.mfa.enrolled", intent.PrincipalID, map[string]any{"version": intent.Version, "recovery": intent.Recovery})
}
func (s *Service) RecoveryProof(ctx context.Context, a FlowAuth, code string) (FlowView, error) {
	var out FlowView
	directoryProof, directoryErr := s.directoryFlowObservation(ctx, a)
	if directoryErr != nil {
		return out, directoryErr
	}
	var intent recoveryIntent
	var version uint64
	var denial error
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return err
		}
		if f.Purpose != "recover" || !f.Primary || f.State != "pending_mfa" || f.Recovery {
			return ErrProof
		}
		if err := limit(ctx, tx, "recovery_"+f.PrincipalID, s.Now()); err != nil {
			denial = err
			return nil
		}
		var epoch uint64
		var consumed any
		err = securitystate.One(ctx, tx, `SELECT batch_version,epoch,consumed_at FROM recovery_codes WHERE code_hash=? AND principal_id=?`, []any{auth.TokenHash(code), f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&version, &epoch, &consumed) })
		if err != nil || epoch != uint64(h.Epoch) || consumed != nil {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		floor, err := securitystate.Floor(ctx, tx, f.PrincipalID, RecoveryID(f.PrincipalID))
		if err != nil {
			return err
		}
		if version < floor {
			denial = ErrProof
			return badAttempt(ctx, tx, f.ID)
		}
		intent = recoveryIntent{f.ID, f.PrincipalID}
		return nil
	})
	if err != nil {
		return out, err
	}
	if denial != nil {
		return out, denial
	}
	raw, _ := json.Marshal(intent)
	err = s.Coordinator.Execute(ctx, securitystate.Intent{Kind: "mfa_recovery", Data: raw}, func(tx storage.IdentityTx, h securityjournal.Head) ([]securityjournal.AppendRequest, error) {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return nil, err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return nil, err
		}
		if f.Purpose != "recover" || !f.Primary || f.Recovery {
			return nil, ErrProof
		}
		n, err := tx.Exec(ctx, `UPDATE recovery_codes SET consumed_at=? WHERE code_hash=? AND principal_id=? AND epoch=? AND consumed_at IS NULL`, s.Now(), auth.TokenHash(code), f.PrincipalID, int64(h.Epoch))
		if err != nil || n != 1 {
			return nil, ErrProof
		}
		factorFloor, err := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
		if err != nil {
			return nil, err
		}
		if factorFloor < version {
			factorFloor = version
		}
		return []securityjournal.AppendRequest{securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, FactorID(f.PrincipalID), factorFloor+1), securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, RecoveryID(f.PrincipalID), version+1)}, nil
	})
	if err != nil {
		return out, err
	}
	return s.Get(ctx, a)
}
func (s *Service) materializeRecovery(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var intent recoveryIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE mfa_factors SET revoked=? WHERE principal_id=?`, true, intent.PrincipalID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE principal_id=?`, intent.PrincipalID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE identity_flows SET recovery_authorized=?,mfa_verified=?,next_step='totp_enrollment' WHERE id=? AND purpose='recover' AND state='pending_mfa'`, true, false, intent.FlowID)
	if err != nil {
		return err
	}
	if s.recovery == nil {
		return ErrLifecycleUnavailable
	}
	f, err := loadFlow(ctx, tx, intent.FlowID)
	if err != nil {
		return err
	}
	h, err := s.Coordinator.Authority.Head(ctx)
	if err != nil {
		return err
	}
	if uint64(h.Epoch) != f.Epoch {
		return ErrProof
	}
	return s.recovery.AuthorizeLegacyMFAReplacementTx(ctx, tx, h, f)
}

func enrollmentPermitted(ctx context.Context, tx storage.IdentityTx, f *flow, version uint64) error {
	for _, authenticator := range []string{FactorID(f.PrincipalID), RecoveryID(f.PrincipalID)} {
		floor, err := securitystate.Floor(ctx, tx, f.PrincipalID, authenticator)
		if err != nil {
			return err
		}
		if version <= floor {
			return ErrProof
		}
	}
	var verified, revoked bool
	err := securitystate.One(ctx, tx, `SELECT verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&verified, &revoked) })
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if f.Purpose != "recover" && err == nil && verified && !revoked {
		return ErrProof
	}
	if f.Purpose == "recover" && !f.Recovery {
		return ErrProof
	}
	return nil
}

func (s *Service) finalEnrollmentAuthority(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, in *enrollmentIntent) error {
	if h.RecordedAt.IsZero() {
		return ErrLifecycleUnavailable
	}
	if f.State != "pending_mfa" || f.PrincipalID != in.PrincipalID || f.Epoch != in.Epoch || uint64(h.Epoch) != in.Epoch || !h.RecordedAt.Before(f.ExpiresAt) || f.Attempts >= 5 || !f.Primary || f.Purpose == "activate" || in.Recovery != (f.Purpose == "recover") || in.ProofAt.IsZero() || h.RecordedAt.Before(in.ProofAt) || h.RecordedAt.Sub(in.ProofAt) > 5*time.Minute || in.Step < 0 || in.Version == 0 {
		return ErrProof
	}
	if e := checkPrincipal(ctx, tx, f.PrincipalID, f.SecurityVersion, f.PasswordVersion); e != nil {
		return e
	}
	if e := directoryCheckProjection(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); e != nil {
		return e
	}
	if _, e := DirectorySubjectFingerprint(ctx, tx, h, f.PrincipalID); e != nil {
		return e
	}
	if in.Recovery {
		if s.recovery == nil {
			return ErrLifecycleUnavailable
		}
		if e := s.recovery.AllowMFAReplacementTx(ctx, tx, h, f); e != nil {
			return e
		}
	}
	for _, entry := range []struct {
		id      string
		version uint64
	}{{FactorID(in.PrincipalID), in.Version}, {RecoveryID(in.PrincipalID), in.Version}, {ReplayID(in.PrincipalID), uint64(in.Step + 1)}} {
		floor, e := securitystate.Floor(ctx, tx, in.PrincipalID, entry.id)
		if e != nil {
			return e
		}
		if floor != entry.version {
			return ErrProof
		}
	}
	return nil
}
