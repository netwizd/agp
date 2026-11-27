package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type recoveryTOTPIntent struct {
	FlowID, PrincipalID string
	Epoch, Version      uint64
	Step                int64
	At                  time.Time
}

func (r *RecoveryService) resetTOTP(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, code string) (recoveryTOTPIntent, error) {
	var out recoveryTOTPIntent
	c, e := readRecoveryCapability(ctx, tx, f.ID)
	if e != nil {
		return out, e
	}
	if c.action != "reset_password" || c.proofKind != "email" || c.totp || f.State != "pending_mfa" || f.NextStep != "totp" {
		return out, ErrProof
	}
	if e = r.checkCapability(ctx, tx, h, f, c, false, false); e != nil {
		return out, e
	}
	var sealed Sealed
	var version uint64
	var last int64
	var verified, revoked bool
	if e = securitystate.One(ctx, tx, `SELECT ciphertext,key_id,nonce,version,last_step,verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{f.PrincipalID}, func(row storage.IdentityRows) error {
		return row.Scan(&sealed.Ciphertext, &sealed.KeyID, &sealed.Nonce, &version, &last, &verified, &revoked)
	}); e != nil {
		return out, ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
	if e != nil {
		return out, e
	}
	if !verified || revoked || version < floor {
		return out, ErrProof
	}
	floor, e = securitystate.Floor(ctx, tx, f.PrincipalID, ReplayID(f.PrincipalID))
	if e != nil {
		return out, e
	}
	if floor > 0 && uint64(last+1) < floor {
		last = int64(floor) - 1
	}
	seed, e := r.identity.Keys.Open(sealed, factorAAD(f.PrincipalID, version))
	if e != nil {
		return out, e
	}
	defer clear(seed)
	step, ok := VerifyTOTP(seed, code, h.RecordedAt, last)
	if !ok {
		return out, ErrProof
	}
	return recoveryTOTPIntent{f.ID, f.PrincipalID, uint64(h.Epoch), version, step, h.RecordedAt}, nil
}
func (r *RecoveryService) VerifyResetTOTP(ctx context.Context, a FlowAuth, code string) (FlowView, error) {
	var denial error
	e := r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := r.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if e = limit(ctx, tx, "totp_"+f.PrincipalID, h.RecordedAt); e != nil {
			if errors.Is(e, ErrLimited) {
				denial = e
				return nil
			}
			return e
		}
		_, e = r.resetTOTP(ctx, tx, h, f, code)
		if errors.Is(e, ErrProof) {
			denial = e
			return badAttempt(ctx, tx, f.ID)
		}
		return e
	})
	if e != nil {
		return FlowView{}, e
	}
	if denial != nil {
		return FlowView{}, denial
	}
	e = r.identity.Coordinator.ExecuteDynamic(ctx, "identity_recovery_totp", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, e := r.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, nil, e
		}
		in, e := r.resetTOTP(ctx, tx, h, f, code)
		if e != nil {
			return nil, nil, e
		}
		data, e := json.Marshal(in)
		return data, []securityjournal.AppendRequest{securitystate.FloorRequest(f.PrincipalID, f.PrincipalID, ReplayID(f.PrincipalID), uint64(in.Step+1))}, e
	})
	if e != nil {
		return FlowView{}, e
	}
	return r.identity.Get(ctx, a)
}
func (r *RecoveryService) materializeTOTP(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in recoveryTOTPIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	h, e := recoveryHead(ctx, r.identity, in.Epoch)
	if e != nil {
		return e
	}
	f, e := loadFlow(ctx, tx, in.FlowID)
	if e != nil {
		return e
	}
	c, e := readRecoveryCapability(ctx, tx, f.ID)
	if e != nil {
		return e
	}
	if c.totp {
		return nil
	}
	if c.action != "reset_password" || c.proofKind != "email" || f.PrincipalID != in.PrincipalID || r.checkCapability(ctx, tx, h, f, c, false, false) != nil {
		return r.CancelFlowTx(ctx, tx, f.ID)
	}
	floor, e := securitystate.Floor(ctx, tx, f.PrincipalID, ReplayID(f.PrincipalID))
	if e != nil {
		return e
	}
	if floor != uint64(in.Step+1) {
		return r.CancelFlowTx(ctx, tx, f.ID)
	}
	n, e := tx.Exec(ctx, `UPDATE mfa_factors SET last_step=? WHERE principal_id=? AND version=? AND last_step<? AND verified=TRUE AND revoked=FALSE`, in.Step, in.PrincipalID, int64(in.Version), in.Step)
	if e != nil {
		return e
	}
	if n != 1 {
		return r.CancelFlowTx(ctx, tx, f.ID)
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_recovery_capabilities SET totp_verified=TRUE,totp_factor_version=? WHERE flow_id=? AND state='pending'`, int64(in.Version), f.ID); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE identity_flows SET next_step='password_setup',mfa_at=? WHERE id=? AND state='pending_mfa'`, in.At, f.ID)
	return e
}
func (r *RecoveryService) SetResetPassword(ctx context.Context, a FlowAuth, password string) (FlowView, error) {
	var out FlowView
	if !lifecyclePasswordValid(password) {
		return out, ErrLifecycleInvalid
	}
	check := func(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) (*flow, error) {
		f, e := r.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, e
		}
		c, e := readRecoveryCapability(ctx, tx, f.ID)
		if e != nil {
			return nil, e
		}
		if c.action != "reset_password" || (c.proofKind == "email" && !c.totp) || f.State != "pending_mfa" || f.NextStep != "password_setup" || c.password != "" {
			return nil, ErrProof
		}
		return f, nil
	}
	e := r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { _, e := check(ctx, tx, h); return e })
	if e != nil {
		return out, e
	}
	select {
	case r.identity.passwordSlots <- struct{}{}:
	case <-ctx.Done():
		return out, ctx.Err()
	}
	phc, e := auth.HashPassword(password, auth.DefaultArgon2idParams)
	<-r.identity.passwordSlots
	if e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	e = r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := check(ctx, tx, h)
		if e != nil {
			return e
		}
		n, e := tx.Exec(ctx, `UPDATE identity_recovery_capabilities SET password_phc=? WHERE flow_id=? AND state='pending' AND password_phc=''`, phc, f.ID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='ready',next_step='complete' WHERE id=?`, f.ID); e != nil {
			return e
		}
		f.State = "ready"
		f.NextStep = "complete"
		out = f.view()
		return nil
	})
	return out, e
}

type recoveryCompletionIntent struct {
	FlowID, PrincipalID, Action, CapabilityDigest, PasswordPHC string
	Epoch, OldSV, OldPV, NewSV, NewPV, GuardVersion            uint64
}

func recoveryCapabilityDigest(c *recoveryCapability) (string, error) {
	return configmodel.Digest(struct {
		Flow, Token, Operation, Principal, Action, Proof, Guard string
		Bound, Epoch, SV, PV, TOTPVersion                       uint64
		Policy, Target                                          string
		TOTP                                                    bool
		Password, State                                         string
		Created, Expires                                        time.Time
	}{c.flowID, c.tokenID, c.operationID, c.principalID, c.action, c.proofKind, c.guardID, c.boundGuard, c.epoch, c.sv, c.pv, c.totpVersion, c.policy, c.targetFingerprint, c.totp, c.password, c.state, c.created, c.expires})
}
func (r *RecoveryService) CompletePasswordReset(ctx context.Context, a FlowAuth) (Completion, error) {
	return r.complete(ctx, a, "reset_password")
}
func (r *RecoveryService) CompleteMFAReplacement(ctx context.Context, a FlowAuth) (Completion, error) {
	return r.complete(ctx, a, "replace_mfa")
}
func (r *RecoveryService) completionCandidate(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, c *recoveryCapability, action string) error {
	if c.action != action || f.State != "ready" || f.NextStep != "complete" {
		return ErrProof
	}
	if e := r.checkCapability(ctx, tx, h, f, c, true, false); e != nil {
		return e
	}
	if action == "reset_password" {
		if c.password == "" || (c.proofKind == "email" && !c.totp) {
			return ErrProof
		}
		return nil
	}
	if !f.MFAAt.Valid || !f.Primary || h.RecordedAt.Before(f.MFAAt.Time) || h.RecordedAt.Sub(f.MFAAt.Time) > 5*time.Minute {
		return ErrProof
	}
	var version uint64
	if e := securitystate.One(ctx, tx, `SELECT version FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{f.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&version) }); e != nil {
		return e
	}
	floor, e := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
	if e != nil {
		return e
	}
	if version < floor {
		return ErrProof
	}
	return nil
}
func (r *RecoveryService) complete(ctx context.Context, a FlowAuth, action string) (out Completion, err error) {
	err = r.WithMFAReplacementPeople(ctx, a, func(fresh context.Context) error {
		ctx = fresh
		return r.identity.Coordinator.ExecuteDynamic(ctx, "identity_recovery_complete", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
			f, e := r.flowAuth(ctx, tx, h, a)
			if e != nil {
				return nil, nil, e
			}
			c, e := readRecoveryCapability(ctx, tx, f.ID)
			if e != nil {
				return nil, nil, e
			}
			if e = r.completionCandidate(ctx, tx, h, f, c, action); e != nil {
				return nil, nil, e
			}
			digest, e := recoveryCapabilityDigest(c)
			if e != nil {
				return nil, nil, e
			}
			next, e := recoveryNext(c.boundGuard)
			if e != nil {
				return nil, nil, e
			}
			in := recoveryCompletionIntent{FlowID: f.ID, PrincipalID: f.PrincipalID, Action: action, CapabilityDigest: digest, PasswordPHC: c.password, Epoch: uint64(h.Epoch), OldSV: c.sv, OldPV: c.pv, NewSV: c.sv, NewPV: c.pv, GuardVersion: next}
			requests := []securityjournal.AppendRequest{}
			if action == "reset_password" {
				in.NewSV, e = recoveryNext(c.sv)
				if e != nil {
					return nil, nil, e
				}
				in.NewPV, e = recoveryNext(c.pv)
				if e != nil {
					return nil, nil, e
				}
				requests = append(requests, securityjournal.AppendRequest{ActorID: "setup", Kind: "raise_security_floor", TargetType: "principal", TargetID: f.PrincipalID, Payload: securityjournal.Payload{PrincipalID: f.PrincipalID, MinimumVersion: securityjournal.UInt63(in.NewSV)}}, securitystate.FloorRequest("setup", f.PrincipalID, PasswordID(f.PrincipalID), in.NewPV))
			}
			requests = append(requests, securitystate.FloorRequest("setup", c.guardID, c.guardID, next))
			data, e := json.Marshal(in)
			return data, requests, e
		})
	})
	if err != nil {
		return out, err
	}
	err = r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		f, e := loadFlow(ctx, tx, a.ID)
		if e != nil {
			return e
		}
		c, e := readRecoveryCapability(ctx, tx, a.ID)
		if e != nil {
			return e
		}
		if f.State != "completed" || c.state != "completed" {
			return ErrLifecycleStale
		}
		out.View = f.view()
		return nil
	})
	return out, err
}
func (r *RecoveryService) materializeComplete(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in recoveryCompletionIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	h, e := recoveryHead(ctx, r.identity, in.Epoch)
	if e != nil {
		return e
	}
	f, e := loadFlow(ctx, tx, in.FlowID)
	if e != nil {
		return e
	}
	c, e := readRecoveryCapability(ctx, tx, in.FlowID)
	if e != nil {
		return e
	}
	if c.state == "completed" || c.state == "cancelled" {
		return nil
	}
	digest, e := recoveryCapabilityDigest(c)
	if e != nil {
		return e
	}
	valid := digest == in.CapabilityDigest && c.action == in.Action && c.principalID == in.PrincipalID && c.sv == in.OldSV && c.pv == in.OldPV && f.State == "ready" && f.NextStep == "complete" && in.GuardVersion == c.boundGuard+1 && r.checkCapability(ctx, tx, h, f, c, true, true) == nil
	if in.Action == "reset_password" {
		valid = valid && in.NewSV == in.OldSV+1 && in.NewPV == in.OldPV+1 && in.PasswordPHC != "" && in.PasswordPHC == c.password && (c.proofKind != "email" || c.totp)
		for id, value := range map[string]uint64{"principal_" + in.PrincipalID: in.NewSV, PasswordID(in.PrincipalID): in.NewPV} {
			floor, e := securitystate.Floor(ctx, tx, in.PrincipalID, id)
			if e != nil {
				return e
			}
			if floor != value {
				valid = false
			}
		}
	} else if in.Action == "replace_mfa" {
		if in.NewSV != in.OldSV || in.NewPV != in.OldPV || in.PasswordPHC != "" || !f.MFAAt.Valid {
			valid = false
		}
		var version uint64
		if e = securitystate.One(ctx, tx, `SELECT version FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{f.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&version) }); e != nil {
			valid = false
		}
		floor, e := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
		if e != nil {
			return e
		}
		if version < floor {
			valid = false
		}
	} else {
		valid = false
	}
	if !valid {
		// Never publish a new credential after a stale final read. On our exact
		// unchanged target, project only the already durable password restrictions.
		if in.Action == "reset_password" {
			if e = r.projectAbortedReset(ctx, tx, h, c, in); e != nil {
				return e
			}
		}
		return r.CancelFlowTx(ctx, tx, f.ID)
	}
	if c.proofKind == "email" {
		t, e := readLifecycleToken(ctx, tx, c.tokenID)
		if e != nil {
			return e
		}
		if e = consumeReservation(ctx, tx, h, t, f); e != nil {
			return e
		}
	}
	if in.Action == "reset_password" {
		n, e := tx.Exec(ctx, `UPDATE users SET password_hash=?,security_version=?,password_version=? WHERE id=? AND identity_kind='local' AND security_version=? AND password_version=? AND blocked_at IS NULL AND lifecycle_state='active'`, in.PasswordPHC, int64(in.NewSV), int64(in.NewPV), in.PrincipalID, int64(in.OldSV), int64(in.OldPV))
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrLifecycleStale
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_recovery_capabilities SET state='completed',password_phc='' WHERE flow_id=? AND state='pending'`, f.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='completed',next_step='none',security_version=?,password_version=?,mfa_verified=FALSE WHERE id=?`, int64(in.NewSV), int64(in.NewPV), f.ID); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.recovery.completed", f.PrincipalID, map[string]any{"flowId": f.ID, "action": in.Action, "operationId": c.operationID})
}
func (r *RecoveryService) projectAbortedReset(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, c *recoveryCapability, in recoveryCompletionIntent) error {
	target, e := lifecycleRawUser(ctx, tx, h, c.principalID)
	if e != nil {
		return e
	}
	if target.Fingerprint != c.targetFingerprint || target.SecurityVersion != in.OldSV || target.PasswordVersion != in.OldPV || target.Directory || in.NewSV != in.OldSV+1 || in.NewPV != in.OldPV+1 {
		return nil
	}
	for id, value := range map[string]uint64{"principal_" + in.PrincipalID: in.NewSV, PasswordID(in.PrincipalID): in.NewPV} {
		floor, e := securitystate.Floor(ctx, tx, in.PrincipalID, id)
		if e != nil {
			return e
		}
		if floor != value {
			return nil
		}
	}
	_, e = tx.Exec(ctx, `UPDATE users SET password_hash='',security_version=?,password_version=? WHERE id=? AND security_version=? AND password_version=?`, int64(in.NewSV), int64(in.NewPV), in.PrincipalID, int64(in.OldSV), int64(in.OldPV))
	return e
}

type recoveryCancelIntent struct{ FlowID string }

func (r *RecoveryService) CancelRecovery(ctx context.Context, a FlowAuth) (FlowView, error) {
	var out FlowView
	e := r.identity.Coordinator.ExecuteDynamic(ctx, "identity_recovery_cancel", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, e := r.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, nil, e
		}
		if f.State == "completed" {
			return nil, nil, ErrProof
		}
		requests := []securityjournal.AppendRequest{}
		c, e := readRecoveryCapability(ctx, tx, f.ID)
		if e == nil {
			next, e := recoveryNext(c.boundGuard)
			if e != nil {
				return nil, nil, e
			}
			requests = append(requests, securitystate.FloorRequest("setup", c.guardID, c.guardID, next))
		} else if !errors.Is(e, storage.ErrNotFound) {
			return nil, nil, e
		}
		out = f.view()
		out.State = "cancelled"
		out.NextStep = "none"
		data, e := json.Marshal(recoveryCancelIntent{f.ID})
		return data, requests, e
	})
	return out, e
}
func (r *RecoveryService) materializeCancel(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in recoveryCancelIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	return r.CancelFlowTx(ctx, tx, in.FlowID)
}
func (r *RecoveryService) CancelFlowTx(ctx context.Context, tx storage.IdentityTx, id string) error {
	if _, e := tx.Exec(ctx, `UPDATE identity_recovery_capabilities SET state='cancelled',password_phc='' WHERE flow_id=? AND state='pending'`, id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE flow_id=?`, id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=? AND purpose='recover' AND state NOT IN ('completed','cancelled','expired')`, id); e != nil {
		return e
	}
	return revokeLifecycleFlowTokens(ctx, tx, id, r.identity.Now())
}
func (r *RecoveryService) CleanupTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	if h.RecordedAt.IsZero() {
		return ErrLifecycleUnavailable
	}
	ids, e := securitystate.Strings(ctx, tx, `SELECT c.flow_id FROM identity_recovery_capabilities c JOIN identity_flows f ON f.id=c.flow_id WHERE c.state='pending' AND (c.expires_at<=? OR c.epoch<>? OR f.state IN ('cancelled','expired')) ORDER BY c.flow_id LIMIT 500`, h.RecordedAt, int64(h.Epoch))
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = r.CancelFlowTx(ctx, tx, id); e != nil {
			return e
		}
	}
	return nil
}
