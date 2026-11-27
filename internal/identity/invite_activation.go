package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type inviteActivationIntent struct {
	FlowID, TokenID, PrincipalID, IssuerID, IssuerFingerprint, TargetFingerprint, StageDigest string
	Epoch, OldSV, OldPV, NewSV, NewPV, FactorVersion, GuardVersion                            uint64
	Step                                                                                      int64
	ProofAt                                                                                   time.Time
}

func inviteStageDigest(st *inviteStage) (string, error) {
	return configmodel.Digest(struct {
		Flow, Token, Target, PHC, Enrollment string
		Sealed                               Sealed
		Version                              uint64
		Email                                bool
		Step                                 int64
		ProofAt                              time.Time
		Hashes, State                        string
	}{st.flowID, st.tokenID, st.targetFingerprint, st.passwordPHC, st.enrollmentID, st.sealed, st.version, st.emailConfirmed, st.step, st.proofAt.Time, st.codeHashes, st.state})
}
func (s *InvitationService) CompleteActivation(ctx context.Context, a FlowAuth) (Completion, error) {
	var out Completion
	if !s.available() {
		return out, ErrLifecycleUnavailable
	}
	var people []string
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "ready" || f.NextStep != "complete" {
			return ErrProof
		}
		st, e := readInviteStage(ctx, tx, f.ID)
		if e != nil {
			return e
		}
		t, e := readLifecycleToken(ctx, tx, st.tokenID)
		if e != nil {
			return e
		}
		people = []string{t.IssuerID, t.PrincipalID}
		return nil
	})
	if e != nil {
		return out, e
	}
	ctx, e = s.identity.lifecyclePeople(ctx, people)
	if e != nil {
		return out, e
	}
	e = s.identity.Coordinator.ExecuteDynamic(ctx, "invitation_activate", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, e := s.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, nil, e
		}
		if f.State != "ready" || f.NextStep != "complete" {
			return nil, nil, ErrProof
		}
		st, e := readInviteStage(ctx, tx, f.ID)
		if e != nil {
			return nil, nil, e
		}
		t, e := readLifecycleToken(ctx, tx, st.tokenID)
		if e != nil {
			return nil, nil, e
		}
		if e = s.identity.lifecycleIssuerCurrent(ctx, tx, h, t); e != nil {
			return nil, nil, e
		}
		if e = activationCandidate(ctx, tx, h, f, st, t); e != nil {
			return nil, nil, e
		}
		if t.SecurityVersion >= uint64(securityjournal.MaxUInt63) || t.PasswordVersion >= uint64(securityjournal.MaxUInt63) || t.GuardVersion >= uint64(securityjournal.MaxUInt63)-1 {
			return nil, nil, ErrProof
		}
		digest, e := inviteStageDigest(st)
		if e != nil {
			return nil, nil, e
		}
		in := inviteActivationIntent{FlowID: f.ID, TokenID: t.ID, PrincipalID: t.PrincipalID, IssuerID: t.IssuerID, IssuerFingerprint: t.IssuerFingerprint, TargetFingerprint: st.targetFingerprint, StageDigest: digest, Epoch: uint64(h.Epoch), OldSV: t.SecurityVersion, OldPV: t.PasswordVersion, NewSV: t.SecurityVersion + 1, NewPV: t.PasswordVersion + 1, FactorVersion: st.version, GuardVersion: t.GuardVersion + 2, Step: st.step, ProofAt: st.proofAt.Time}
		requests := []securityjournal.AppendRequest{
			securitystate.FloorRequest(t.IssuerID, t.PrincipalID, "principal_"+t.PrincipalID, in.NewSV),
			securitystate.FloorRequest(t.IssuerID, t.PrincipalID, PasswordID(t.PrincipalID), in.NewPV),
			securitystate.FloorRequest(t.IssuerID, t.PrincipalID, FactorID(t.PrincipalID), in.FactorVersion),
			securitystate.FloorRequest(t.IssuerID, t.PrincipalID, RecoveryID(t.PrincipalID), in.FactorVersion),
			securitystate.FloorRequest(t.IssuerID, t.PrincipalID, ReplayID(t.PrincipalID), uint64(in.Step+1)),
			securitystate.FloorRequest(t.IssuerID, t.GuardID, t.GuardID, in.GuardVersion),
		}
		raw, e := json.Marshal(in)
		return raw, requests, e
	})
	if e != nil {
		return out, e
	}
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := loadFlow(ctx, tx, a.ID)
		if e != nil {
			return e
		}
		if f.State != "completed" {
			return ErrProof
		}
		if e = s.CheckFlowTx(ctx, tx, h, f); e != nil {
			return e
		}
		out.View = f.view()
		return nil
	})
	return out, e
}
func activationCandidate(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, st *inviteStage, t *lifecycleToken) error {
	if st.state != "ready" || !st.emailConfirmed || st.passwordPHC == "" || st.enrollmentID == "" || st.version == 0 || st.sealed.Ciphertext == "" || st.sealed.KeyID == "" || st.sealed.Nonce == "" || st.step < 0 || !st.proofAt.Valid || h.RecordedAt.Before(st.proofAt.Time) || h.RecordedAt.Sub(st.proofAt.Time) > 5*time.Minute {
		return ErrProof
	}
	var hashes []string
	if json.Unmarshal([]byte(st.codeHashes), &hashes) != nil || len(hashes) != 10 {
		return ErrProof
	}
	seen := map[string]bool{}
	for _, hash := range hashes {
		if len(hash) != 64 || seen[hash] {
			return ErrProof
		}
		seen[hash] = true
	}
	var password string
	var kind string
	if e := securitystate.One(ctx, tx, `SELECT password_hash,identity_kind FROM users WHERE id=?`, []any{t.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&password, &kind) }); e != nil {
		return e
	}
	if password != "" || kind != "local" {
		return ErrProof
	}
	var count int
	if e := securitystate.One(ctx, tx, `SELECT COUNT(*) FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{t.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&count) }); e != nil {
		return e
	}
	if count != 0 {
		return ErrProof
	}
	for _, id := range []string{FactorID(t.PrincipalID), RecoveryID(t.PrincipalID)} {
		floor, e := securitystate.Floor(ctx, tx, t.PrincipalID, id)
		if e != nil {
			return e
		}
		if st.version <= floor {
			return ErrProof
		}
	}
	replay, e := securitystate.Floor(ctx, tx, t.PrincipalID, ReplayID(t.PrincipalID))
	if e != nil {
		return e
	}
	if uint64(st.step+1) <= replay {
		return ErrProof
	}
	return nil
}
func (s *InvitationService) materializeActivation(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in inviteActivationIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	f, e := loadFlow(ctx, tx, in.FlowID)
	if errors.Is(e, storage.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	st, e := readInviteStage(ctx, tx, in.FlowID)
	if errors.Is(e, storage.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if st.state == "completed" && f.State == "completed" {
		return nil
	}
	h, e := s.identity.Coordinator.Authority.Head(ctx)
	if e != nil {
		return e
	}
	// The journal has already closed old credentials. A stale or recovered
	// positive intent must retire rather than make the global barrier permanent.
	if e = s.activationCurrent(ctx, tx, h, &in, f, st); e != nil {
		if e = s.CancelFlowTx(ctx, tx, f.ID); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.activation.aborted", in.IssuerID, map[string]any{"flowId": f.ID, "principalId": in.PrincipalID})
	}
	var hashes []string
	if e = json.Unmarshal([]byte(st.codeHashes), &hashes); e != nil {
		return e
	}
	n, e := tx.Exec(ctx, `UPDATE users SET password_hash=?,password_version=?,security_version=?,lifecycle_state='active',updated_at=? WHERE id=? AND lifecycle_state='invited' AND security_version=? AND password_version=? AND password_hash='' AND blocked_at IS NULL AND identity_kind='local'`, st.passwordPHC, int64(in.NewPV), int64(in.NewSV), h.RecordedAt, in.PrincipalID, int64(in.OldSV), int64(in.OldPV))
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrProof
	}
	if _, e = tx.Exec(ctx, `INSERT INTO mfa_factors(principal_id,authenticator_id,version,ciphertext,key_id,nonce,last_step,verified,revoked) VALUES(?,?,?,?,?,?,?,TRUE,FALSE) ON CONFLICT(principal_id) DO UPDATE SET version=excluded.version,ciphertext=excluded.ciphertext,key_id=excluded.key_id,nonce=excluded.nonce,last_step=excluded.last_step,verified=TRUE,revoked=FALSE`, in.PrincipalID, FactorID(in.PrincipalID), int64(in.FactorVersion), st.sealed.Ciphertext, st.sealed.KeyID, st.sealed.Nonce, in.Step); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `DELETE FROM recovery_codes WHERE principal_id=?`, in.PrincipalID); e != nil {
		return e
	}
	for _, hash := range hashes {
		if _, e = tx.Exec(ctx, `INSERT INTO recovery_codes(code_hash,principal_id,batch_version,epoch) VALUES(?,?,?,?)`, hash, in.PrincipalID, int64(in.FactorVersion), int64(in.Epoch)); e != nil {
			return e
		}
	}
	t, e := readLifecycleToken(ctx, tx, in.TokenID)
	if e != nil {
		return e
	}
	if e = consumeReservation(ctx, tx, h, t, f); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='completed',next_step='none',security_version=?,password_version=?,mfa_verified=FALSE,mfa_at=NULL,primary_verified=FALSE,primary_verified_at=NULL WHERE id=?`, int64(in.NewSV), int64(in.NewPV), f.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_activation_stages SET state='completed',password_phc='',ciphertext='',key_id='',nonce='',code_hashes_json='[]' WHERE flow_id=?`, f.ID); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.activation.completed", in.IssuerID, map[string]any{"principalId": in.PrincipalID, "flowId": f.ID})
}
func (s *InvitationService) activationCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, in *inviteActivationIntent, f *flow, st *inviteStage) error {
	if h.RecordedAt.IsZero() || uint64(h.Epoch) != in.Epoch || f.Epoch != in.Epoch || f.PrincipalID != in.PrincipalID || f.State != "ready" || f.NextStep != "complete" || !h.RecordedAt.Before(f.ExpiresAt) || !h.RecordedAt.Before(st.expires) || f.Attempts >= 5 || f.MFA || f.Primary || f.PrimaryAt.Valid || f.Audience != "setup" || f.Purpose != "activate" || st.tokenID != in.TokenID || st.targetFingerprint != in.TargetFingerprint || st.version != in.FactorVersion || st.step != in.Step || !st.proofAt.Valid || !st.proofAt.Time.Equal(in.ProofAt) || h.RecordedAt.Before(in.ProofAt) || h.RecordedAt.Sub(in.ProofAt) > 5*time.Minute {
		return ErrProof
	}
	digest, e := inviteStageDigest(st)
	if e != nil {
		return e
	}
	if digest != in.StageDigest || st.state != "ready" || !st.emailConfirmed {
		return ErrProof
	}
	t, e := readLifecycleToken(ctx, tx, in.TokenID)
	if e != nil {
		return e
	}
	if t.Epoch != in.Epoch || t.PrincipalID != in.PrincipalID || t.SecurityVersion != in.OldSV || t.PasswordVersion != in.OldPV || t.IssuerID != in.IssuerID || t.IssuerFingerprint != in.IssuerFingerprint || t.ReservedAt == nil || t.ReservedFlowID != f.ID || t.ReservedBindingHash != f.BindingHash || t.ConsumedAt != nil || t.RevokedAt != nil || !h.RecordedAt.Before(t.ExpiresAt) || t.PolicyDigest != lifecyclePolicyDigest() || in.NewSV != in.OldSV+1 || in.NewPV != in.OldPV+1 || in.GuardVersion != t.GuardVersion+2 {
		return ErrProof
	}
	target, e := lifecycleRawUser(ctx, tx, h, in.PrincipalID)
	if e != nil {
		return e
	}
	if target.Directory || target.View.Blocked || target.View.Privileged || target.View.LifecycleState != "invited" || target.SecurityVersion != in.OldSV || target.PasswordVersion != in.OldPV || target.Fingerprint != in.TargetFingerprint || len(target.Permissions) > 0 || len(target.Grants) > 0 {
		return ErrProof
	}
	// Only the historical issuer's current authority is checked here. Checking
	// the old target through lifecycleIssuerCurrent would reject our own floors.
	issuer, e := s.identity.lifecycleSubject(ctx, tx, h, in.IssuerID, "users.manage", false)
	if e != nil {
		return e
	}
	if issuer.Fingerprint != in.IssuerFingerprint {
		return ErrProof
	}
	for _, entry := range []struct {
		principal, id string
		version       uint64
	}{{in.PrincipalID, "principal_" + in.PrincipalID, in.NewSV}, {in.PrincipalID, PasswordID(in.PrincipalID), in.NewPV}, {in.PrincipalID, FactorID(in.PrincipalID), in.FactorVersion}, {in.PrincipalID, RecoveryID(in.PrincipalID), in.FactorVersion}, {in.PrincipalID, ReplayID(in.PrincipalID), uint64(in.Step + 1)}, {t.GuardID, t.GuardID, in.GuardVersion}} {
		floor, e := securitystate.Floor(ctx, tx, entry.principal, entry.id)
		if e != nil {
			return e
		}
		if floor != entry.version {
			return ErrProof
		}
	}
	var contactVersion uint64
	if e = securitystate.One(ctx, tx, `SELECT authenticator_version FROM identity_contacts WHERE id=? AND principal_id=? AND verified=TRUE`, []any{t.ContactID, t.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&contactVersion) }); e != nil {
		return e
	}
	if contactVersion != t.ContactVersion {
		return ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, t.PrincipalID, t.ContactID)
	if e != nil {
		return e
	}
	if contactVersion < floor {
		return ErrProof
	}
	var password, kind string
	if e = securitystate.One(ctx, tx, `SELECT password_hash,identity_kind FROM users WHERE id=?`, []any{in.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&password, &kind) }); e != nil {
		return e
	}
	if password != "" || kind != "local" {
		return ErrProof
	}
	var hashes []string
	if json.Unmarshal([]byte(st.codeHashes), &hashes) != nil || len(hashes) != 10 {
		return ErrProof
	}
	return nil
}
