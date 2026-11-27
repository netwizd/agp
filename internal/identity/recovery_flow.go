package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type recoveryCapability struct {
	flowID, tokenID, operationID, principalID, action, proofKind, guardID string
	boundGuard, epoch, sv, pv, totpVersion                                uint64
	policy, targetFingerprint                                             string
	totp                                                                  bool
	password, state                                                       string
	created, expires                                                      time.Time
}

func readRecoveryCapability(ctx context.Context, tx storage.IdentityTx, id string) (*recoveryCapability, error) {
	c := &recoveryCapability{}
	e := securitystate.One(ctx, tx, `SELECT flow_id,token_id,operation_id,principal_id,allowed_action,proof_kind,guard_id,bound_guard_version,epoch,security_version,password_version,policy_digest,target_fingerprint,totp_verified,totp_factor_version,password_phc,state,created_at,expires_at FROM identity_recovery_capabilities WHERE flow_id=?`, []any{id}, func(row storage.IdentityRows) error {
		return row.Scan(&c.flowID, &c.tokenID, &c.operationID, &c.principalID, &c.action, &c.proofKind, &c.guardID, &c.boundGuard, &c.epoch, &c.sv, &c.pv, &c.policy, &c.targetFingerprint, &c.totp, &c.totpVersion, &c.password, &c.state, &c.created, &c.expires)
	})
	return c, e
}
func insertRecoveryCapability(ctx context.Context, tx storage.IdentityTx, c *recoveryCapability) error {
	_, e := tx.Exec(ctx, `INSERT INTO identity_recovery_capabilities(flow_id,token_id,operation_id,principal_id,allowed_action,proof_kind,guard_id,bound_guard_version,epoch,security_version,password_version,policy_digest,target_fingerprint,totp_verified,password_phc,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`, c.flowID, c.tokenID, c.operationID, c.principalID, c.action, c.proofKind, c.guardID, int64(c.boundGuard), int64(c.epoch), int64(c.sv), int64(c.pv), c.policy, c.targetFingerprint, c.totp, c.password, c.created, c.expires)
	return e
}
func (r *RecoveryService) flowAuth(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a FlowAuth) (*flow, error) {
	if a.CSRF == "" {
		return nil, ErrProof
	}
	f, e := r.identity.checked(ctx, tx, h, a)
	if e != nil {
		return nil, e
	}
	if f.Purpose != "recover" || (f.Audience != "setup" && f.Audience != "login" && f.Audience != "management") || h.RecordedAt.IsZero() || !h.RecordedAt.Before(f.ExpiresAt) {
		return nil, ErrProof
	}
	return f, nil
}
func recoveryApproveMetadata(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id, fp string, approve bool) (*lifecyclePrincipal, error) {
	t, e := lifecycleRawUser(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	if t.View.Blocked || t.View.LifecycleState != "active" || t.Fingerprint != fp || !lifecycleHas(t.Permissions, "users.privileged.manage") {
		return nil, ErrProof
	}
	if e = checkLifecyclePrincipalVersions(ctx, tx, id, t.SecurityVersion, t.PasswordVersion); e != nil {
		return nil, e
	}
	var admin bool
	if e = securitystate.One(ctx, tx, `SELECT is_admin FROM users WHERE id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&admin) }); e != nil {
		return nil, e
	}
	if approve && !lifecycleHas(t.Permissions, authz.PermConfigApprove) {
		return nil, storage.ErrPermissionDenied
	}
	return &lifecyclePrincipal{ID: id, Fingerprint: fp, Admin: admin, Permissions: t.Permissions, Grants: t.Grants}, nil
}

// historical checks the frozen human quorum without requiring a request-local
// directory observation for GET. Positive publication additionally requires live.
func (r *RecoveryService) historical(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, target *lifecycleTarget, live bool) error {
	record, e := readRecoveryOperation(ctx, tx, t.AuthorizationOperationID)
	if e != nil {
		return e
	}
	o := record.operation
	in := o.RecoveryRequest
	if o.State != "applied" || o.SubjectID != t.PrincipalID || in.AllowedAction != t.AllowedAction || in.CustodianPrincipalID != t.IssuerID || record.creatorFingerprint != t.IssuerFingerprint || record.postSV != t.SecurityVersion || record.postPV != t.PasswordVersion || h.Epoch != in.ExpectedAuthorityEpoch || in.PolicyDigest != lifecyclePolicyDigest() || !h.RecordedAt.Before(in.ExpiresAt) {
		return ErrProof
	}
	creator, e := recoveryApproveMetadata(ctx, tx, h, o.CreatedBy, record.creatorFingerprint, false)
	if e != nil {
		return e
	}
	var reviewer, fp, digest string
	if e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,request_digest FROM identity_recovery_approvals WHERE operation_id=?`, []any{o.ID}, func(row storage.IdentityRows) error { return row.Scan(&reviewer, &fp, &digest) }); e != nil {
		return e
	}
	if reviewer == o.CreatedBy || reviewer == o.SubjectID || digest != o.RequestDigest {
		return ErrProof
	}
	if e = RequireDistinctPeople(ctx, tx, o.CreatedBy, o.SubjectID); e != nil {
		return e
	}
	if e = RequireDistinctPeople(ctx, tx, reviewer, o.CreatedBy); e != nil {
		return e
	}
	if e = RequireDistinctPeople(ctx, tx, reviewer, o.SubjectID); e != nil {
		return e
	}
	review, e := recoveryApproveMetadata(ctx, tx, h, reviewer, fp, true)
	if e != nil {
		return e
	}
	if e = r.identity.lifecycleTargetCeiling(ctx, tx, h, creator, target); e != nil {
		return e
	}
	if e = r.identity.lifecycleTargetCeiling(ctx, tx, h, review, target); e != nil {
		return e
	}
	if live {
		for _, id := range []string{o.CreatedBy, reviewer, o.SubjectID} {
			if _, e = DirectorySubjectFingerprint(ctx, tx, h, id); e != nil {
				return e
			}
		}
	}
	return nil
}
func resetOrdinaryTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, target *lifecycleTarget) error {
	if target.Directory || target.View.Privileged || t.IssuerID != "" || t.Purpose != "reset_password" || t.AllowedAction != "reset_password" || t.ProofKind != "email" || t.ContactID == "" {
		return ErrProof
	}
	var verified bool
	var version uint64
	if e := securitystate.One(ctx, tx, `SELECT verified,authenticator_version FROM identity_contacts WHERE id=? AND principal_id=?`, []any{t.ContactID, t.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&verified, &version) }); e != nil {
		return e
	}
	if !verified || version != t.ContactVersion {
		return ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, t.PrincipalID, t.ContactID)
	if e != nil {
		return e
	}
	if version < floor {
		return ErrProof
	}
	var factor uint64
	if e = securitystate.One(ctx, tx, `SELECT version FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{t.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&factor) }); e != nil {
		return e
	}
	floor, e = securitystate.Floor(ctx, tx, t.PrincipalID, FactorID(t.PrincipalID))
	if e != nil {
		return e
	}
	if factor < floor {
		return ErrProof
	}
	return nil
}
func (r *RecoveryService) checkCapability(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, c *recoveryCapability, live, spent bool) error {
	if f == nil || c == nil || f.Purpose != "recover" || !f.Recovery || c.state != "pending" || c.flowID != f.ID || c.principalID != f.PrincipalID || c.sv != f.SecurityVersion || c.pv != f.PasswordVersion || c.epoch != f.Epoch || c.epoch != uint64(h.Epoch) || c.policy != lifecyclePolicyDigest() || h.RecordedAt.IsZero() || h.RecordedAt.Before(c.created) || !h.RecordedAt.Before(c.expires) || !h.RecordedAt.Before(f.ExpiresAt) || f.State == "completed" || f.State == "cancelled" || f.State == "expired" {
		return ErrProof
	}
	if c.action != "replace_mfa" && c.action != "reset_password" {
		return ErrProof
	}
	expected := c.boundGuard
	if spent {
		var e error
		expected, e = recoveryNext(expected)
		if e != nil {
			return e
		}
	}
	floor, e := securitystate.Floor(ctx, tx, c.guardID, c.guardID)
	if e != nil {
		return e
	}
	if floor != expected {
		return ErrProof
	}
	target, e := lifecycleRawUser(ctx, tx, h, c.principalID)
	if e != nil {
		return e
	}
	if target.View.Blocked || target.View.LifecycleState != "active" || target.SecurityVersion != c.sv || target.PasswordVersion != c.pv || target.Fingerprint != c.targetFingerprint || (c.action == "reset_password" && target.Directory) {
		return ErrProof
	}
	if !spent || c.action != "reset_password" {
		if e = checkLifecyclePrincipalVersions(ctx, tx, c.principalID, c.sv, c.pv); e != nil {
			return e
		}
	}
	if c.proofKind == "recovery_code" {
		if c.action != "replace_mfa" || c.tokenID != "" || c.operationID != "" || !f.Primary || !f.PrimaryAt.Valid {
			return ErrProof
		}
		if live {
			_, e = DirectorySubjectFingerprint(ctx, tx, h, c.principalID)
		}
		return e
	}
	t, e := readLifecycleToken(ctx, tx, c.tokenID)
	if e != nil {
		return e
	}
	if t.PrincipalID != c.principalID || t.SecurityVersion != c.sv || t.PasswordVersion != c.pv || t.Epoch != c.epoch || t.PolicyDigest != c.policy || t.GuardID != c.guardID || t.GuardVersion >= uint64(securityjournal.MaxUInt63) || c.boundGuard != t.GuardVersion+1 || t.ProofKind != c.proofKind || t.AllowedAction != c.action || t.AuthorizationOperationID != c.operationID || t.ReservedAt == nil || t.ReservedFlowID != f.ID || t.ReservedBindingHash != f.BindingHash || t.RevokedAt != nil || !h.RecordedAt.Before(t.ExpiresAt) {
		return ErrProof
	}
	if c.proofKind == "email" {
		if t.ConsumedAt != nil {
			return ErrProof
		}
		if e = resetOrdinaryTarget(ctx, tx, h, t, target); e != nil {
			return e
		}
		f.ContactID = t.ContactID
		if c.totp {
			if c.totpVersion == 0 || !f.MFAAt.Valid || h.RecordedAt.Before(f.MFAAt.Time) || h.RecordedAt.Sub(f.MFAAt.Time) > 5*time.Minute {
				return ErrProof
			}
			var version uint64
			if e = securitystate.One(ctx, tx, `SELECT version FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`, []any{f.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&version) }); e != nil {
				return e
			}
			if version != c.totpVersion {
				return ErrProof
			}
		} else if c.totpVersion != 0 {
			return ErrProof
		}
	} else if c.proofKind == "supervised" {
		if t.ConsumedAt == nil {
			return ErrProof
		}
		if e = r.historical(ctx, tx, h, t, target, live); e != nil {
			return e
		}
	} else {
		return ErrProof
	}
	if live {
		_, e = DirectorySubjectFingerprint(ctx, tx, h, c.principalID)
	}
	return e
}
func (r *RecoveryService) CheckFlowTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow) error {
	c, e := readRecoveryCapability(ctx, tx, f.ID)
	if errors.Is(e, storage.ErrNotFound) {
		if f.Recovery {
			return ErrProof
		}
		return nil
	}
	if e != nil {
		return e
	}
	if f.State == "completed" {
		if c.state != "completed" || !f.Recovery || f.PrincipalID != c.principalID || f.Epoch != c.epoch || h.Epoch != securityjournal.UInt63(c.epoch) || c.boundGuard >= uint64(securityjournal.MaxUInt63) {
			return ErrProof
		}
		sv, pv := c.sv, c.pv
		if c.action == "reset_password" {
			sv++
			pv++
		}
		if f.SecurityVersion != sv || f.PasswordVersion != pv {
			return ErrProof
		}
		floor, e := securitystate.Floor(ctx, tx, c.guardID, c.guardID)
		if e != nil {
			return e
		}
		if floor != c.boundGuard+1 {
			return ErrProof
		}
		return checkPrincipal(ctx, tx, c.principalID, sv, pv)
	}
	return r.checkCapability(ctx, tx, h, f, c, false, false)
}
func (r *RecoveryService) IsPasswordResetTx(ctx context.Context, tx storage.IdentityTx, id string) (bool, error) {
	c, e := readRecoveryCapability(ctx, tx, id)
	if errors.Is(e, storage.ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return c.action == "reset_password", nil
}
func (r *RecoveryService) AllowMFAReplacementTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow) error {
	c, e := readRecoveryCapability(ctx, tx, f.ID)
	if e != nil {
		return e
	}
	if c.action != "replace_mfa" || !f.Primary {
		return ErrProof
	}
	return r.checkCapability(ctx, tx, h, f, c, true, false)
}
func (r *RecoveryService) WithMFAReplacementPeople(ctx context.Context, a FlowAuth, fn func(context.Context) error) error {
	var subjects []string
	e := r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := r.identity.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.Purpose != "recover" || !f.Recovery {
			return nil
		}
		c, e := readRecoveryCapability(ctx, tx, f.ID)
		if e != nil {
			return e
		}
		subjects = []string{c.principalID}
		if c.operationID != "" {
			o, e := readRecoveryOperation(ctx, tx, c.operationID)
			if e != nil {
				return e
			}
			reviewers, e := securitystate.Strings(ctx, tx, `SELECT reviewer_id FROM identity_recovery_approvals WHERE operation_id=?`, c.operationID)
			if e != nil {
				return e
			}
			subjects = append(subjects, o.operation.CreatedBy)
			subjects = append(subjects, reviewers...)
		}
		return nil
	})
	if e != nil {
		return e
	}
	if len(subjects) == 0 {
		return fn(ctx)
	}
	fresh, e := r.identity.lifecyclePeople(ctx, subjects)
	if e != nil {
		return e
	}
	return fn(fresh)
}

func (r *RecoveryService) AuthorizeLegacyMFAReplacementTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow) error {
	if f == nil || f.Purpose != "recover" || f.State != "pending_mfa" || !f.Primary || !f.PrimaryAt.Valid || !f.Recovery || f.MFA || f.NextStep != "totp_enrollment" || f.Epoch != uint64(h.Epoch) || !h.RecordedAt.Before(f.ExpiresAt) {
		return ErrProof
	}
	if e := checkPrincipal(ctx, tx, f.PrincipalID, f.SecurityVersion, f.PasswordVersion); e != nil {
		return e
	}
	var version uint64
	var revoked bool
	if e := securitystate.One(ctx, tx, `SELECT version,revoked FROM mfa_factors WHERE principal_id=?`, []any{f.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&version, &revoked) }); e != nil {
		return e
	}
	floor, e := securitystate.Floor(ctx, tx, f.PrincipalID, FactorID(f.PrincipalID))
	if e != nil {
		return e
	}
	if !revoked || floor <= version {
		return ErrProof
	}
	var count int
	if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM recovery_codes WHERE principal_id=?`, []any{f.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&count) }); e != nil {
		return e
	}
	if count != 0 {
		return ErrProof
	}
	// Stable across replaying the original pending mfa_recovery after a DB
	// restore. Generating a fresh guard during materialization would revive a
	// previously completed/cancelled capability under a different journal ID.
	guardID := "guard_setup_" + auth.TokenHash("AGP-LEGACY-MFA-CAPABILITY-v1\x00"+f.ID+"\x00"+f.PrincipalID+"\x00"+f.BindingHash+"\x00"+strconv.FormatUint(f.Epoch, 10))
	spent, e := securitystate.Floor(ctx, tx, guardID, guardID)
	if e != nil {
		return e
	}
	if spent != 0 {
		return r.CancelFlowTx(ctx, tx, f.ID)
	}
	if existing, e := readRecoveryCapability(ctx, tx, f.ID); e == nil {
		if existing.proofKind != "recovery_code" {
			return ErrProof
		}
		return r.checkCapability(ctx, tx, h, f, existing, false, false)
	} else if !errors.Is(e, storage.ErrNotFound) {
		return e
	}
	target, e := lifecycleRawUser(ctx, tx, h, f.PrincipalID)
	if e != nil {
		return e
	}
	return insertRecoveryCapability(ctx, tx, &recoveryCapability{flowID: f.ID, principalID: f.PrincipalID, action: "replace_mfa", proofKind: "recovery_code", guardID: guardID, epoch: f.Epoch, sv: f.SecurityVersion, pv: f.PasswordVersion, policy: lifecyclePolicyDigest(), targetFingerprint: target.Fingerprint, created: h.RecordedAt, expires: f.ExpiresAt})
}

type recoveryBindIntent struct {
	FlowID, TokenID string
	Epoch           uint64
}

func (r *RecoveryService) BindResetInvitation(ctx context.Context, a FlowAuth, raw, source string) (Transition, error) {
	return r.bind(ctx, a, raw, source, "email")
}
func (r *RecoveryService) ConsumeSupervisedTicket(ctx context.Context, a FlowAuth, raw, source string) (Transition, error) {
	return r.bind(ctx, a, raw, source, "supervised")
}
func (r *RecoveryService) bind(ctx context.Context, a FlowAuth, raw, source, kind string) (out Transition, err error) {
	if r == nil || r.identity == nil {
		return out, ErrLifecycleUnavailable
	}
	if !validLifecycleSecret(raw) || len(source) > 256 {
		return out, ErrProof
	}
	var people []string
	err = r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := r.flowAuth(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.Audience != "setup" || f.PrincipalID != "" || f.State != "pending_primary" {
			return ErrProof
		}
		t, e := findLifecycleToken(ctx, tx, raw)
		if e != nil {
			return e
		}
		if t.ProofKind != kind || t.AllowedAction == "activate" {
			return ErrProof
		}
		if e = checkUnconsumedLifecycleToken(ctx, tx, h, t); e != nil {
			return e
		}
		people = []string{t.PrincipalID}
		if kind == "supervised" {
			o, e := readRecoveryOperation(ctx, tx, t.AuthorizationOperationID)
			if e != nil {
				return e
			}
			people = append(people, o.operation.CreatedBy)
			ids, e := securitystate.Strings(ctx, tx, `SELECT reviewer_id FROM identity_recovery_approvals WHERE operation_id=?`, o.operation.ID)
			if e != nil {
				return e
			}
			people = append(people, ids...)
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	ctx, err = r.identity.lifecyclePeople(ctx, people)
	if err != nil {
		return out, err
	}
	binding, hash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	err = r.identity.Coordinator.ExecuteDynamic(ctx, "identity_recovery_bind", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, e := r.flowAuth(ctx, tx, h, a)
		if e != nil {
			return nil, nil, e
		}
		if f.Audience != "setup" || f.PrincipalID != "" || f.State != "pending_primary" {
			return nil, nil, ErrProof
		}
		t, e := findLifecycleToken(ctx, tx, raw)
		if e != nil {
			return nil, nil, e
		}
		if t.ProofKind != kind || t.AllowedAction == "activate" || t.GuardVersion >= uint64(securityjournal.MaxUInt63)-1 {
			return nil, nil, ErrProof
		}
		target, e := lifecycleRawUser(ctx, tx, h, t.PrincipalID)
		if e != nil {
			return nil, nil, e
		}
		if e = limitN(ctx, tx, "reset_claim_"+auth.TokenHash(source), h.RecordedAt, 20); e != nil {
			return nil, nil, e
		}
		if kind == "email" {
			if e = resetOrdinaryTarget(ctx, tx, h, t, target); e != nil {
				return nil, nil, e
			}
		} else {
			if e = r.historical(ctx, tx, h, t, target, true); e != nil {
				return nil, nil, e
			}
		}
		id := securitystate.ID("flow")
		if kind == "email" {
			e = reserveEmailToken(ctx, tx, h, t, f, id, hash)
		} else {
			e = consumeSupervisedTicket(ctx, tx, h, t, f, id, hash)
		}
		if e != nil {
			return nil, nil, e
		}
		expires := minTime(f.ExpiresAt, t.ExpiresAt)
		next := "totp"
		primary := false
		if kind == "supervised" {
			primary = true
			if t.AllowedAction == "replace_mfa" {
				next = "totp_enrollment"
			} else {
				next = "password_setup"
			}
		}
		if _, e = tx.Exec(ctx, `INSERT INTO identity_flows(id,purpose,audience,origin,binding_hash,csrf_hash,principal_id,security_version,password_version,epoch,state,next_step,primary_verified,recovery_authorized,expires_at,created_at) VALUES(?,'recover','setup',?,?,?,?,?,?,?,'pending_mfa',?,?,TRUE,?,?)`, id, f.Origin, hash, f.CSRFHash, t.PrincipalID, int64(t.SecurityVersion), int64(t.PasswordVersion), int64(h.Epoch), next, primary, expires, h.RecordedAt); e != nil {
			return nil, nil, e
		}
		if pin, e := directoryAuthPin(ctx, tx, h, t.PrincipalID); e != nil {
			return nil, nil, e
		} else if pin != nil {
			if e = writeDirectoryContext(ctx, tx, "identity_flows", id, pin.context); e != nil {
				return nil, nil, e
			}
		}
		c := &recoveryCapability{flowID: id, tokenID: t.ID, operationID: t.AuthorizationOperationID, principalID: t.PrincipalID, action: t.AllowedAction, proofKind: kind, guardID: t.GuardID, boundGuard: t.GuardVersion + 1, epoch: t.Epoch, sv: t.SecurityVersion, pv: t.PasswordVersion, policy: t.PolicyDigest, targetFingerprint: target.Fingerprint, created: h.RecordedAt, expires: expires}
		if e = insertRecoveryCapability(ctx, tx, c); e != nil {
			return nil, nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=?`, f.ID); e != nil {
			return nil, nil, e
		}
		out = Transition{View: FlowView{ID: id, Purpose: "recover", Audience: "setup", State: "pending_mfa", NextStep: next, ExpiresAt: expires, ContactID: t.ContactID}, Binding: binding}
		data, e := json.Marshal(recoveryBindIntent{id, t.ID, uint64(h.Epoch)})
		return data, []securityjournal.AppendRequest{securitystate.FloorRequest("setup", t.GuardID, t.GuardID, t.GuardVersion+1)}, e
	})
	if err != nil {
		return Transition{}, err
	}
	err = r.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := loadFlow(ctx, tx, out.View.ID)
		if e != nil {
			return e
		}
		return r.CheckFlowTx(ctx, tx, h, f)
	})
	if err != nil {
		return Transition{}, err
	}
	return out, nil
}
func (r *RecoveryService) materializeBind(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in recoveryBindIntent
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
	if c.tokenID != in.TokenID || r.checkCapability(ctx, tx, h, f, c, false, false) != nil {
		return r.CancelFlowTx(ctx, tx, f.ID)
	}
	return nil
}
