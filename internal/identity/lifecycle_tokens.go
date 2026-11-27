package identity

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func lifecyclePolicyDigest() string {
	d, _ := configmodel.Digest(struct {
		Version                                                                string
		InviteMFA, InviteEmailConfirmation, ResetTOTP, PrivilegedResetApproval bool
		PasswordMinimumBytes, PasswordMaximumBytes                             int
	}{"agp.identity-lifecycle/v1alpha1", true, true, true, true, 12, 1024})
	return d
}
func validLifecycleSecret(raw string) bool {
	b, e := base64.RawURLEncoding.DecodeString(raw)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == raw
}
func lifecyclePasswordValid(value string) bool {
	// No trimming or Unicode normalization: every supplied UTF-8 byte belongs to
	// the credential. The HTTP decoder separately rejects invalid UTF-8 JSON.
	return len(value) >= 12 && len(value) <= 1024 && utf8.ValidString(value)
}
func readLifecycleToken(ctx context.Context, tx storage.IdentityTx, id string) (*lifecycleToken, error) {
	t := &lifecycleToken{}
	var reserved, consumed, revoked sql.NullTime
	var operation sql.NullString
	e := securitystate.One(ctx, tx, `SELECT id,principal_id,purpose,proof_kind,token_hash,guard_id,guard_version,epoch,security_version,password_version,policy_digest,issuer_id,issuer_fingerprint,contact_id,contact_version,generation,authorization_operation_id,allowed_action,created_at,expires_at,reserved_flow_id,reserved_binding_hash,reserved_at,consumed_at,revoked_at FROM identity_one_time_tokens WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&t.ID, &t.PrincipalID, &t.Purpose, &t.ProofKind, &t.TokenHash, &t.GuardID, &t.GuardVersion, &t.Epoch, &t.SecurityVersion, &t.PasswordVersion, &t.PolicyDigest, &t.IssuerID, &t.IssuerFingerprint, &t.ContactID, &t.ContactVersion, &t.Generation, &operation, &t.AllowedAction, &t.CreatedAt, &t.ExpiresAt, &t.ReservedFlowID, &t.ReservedBindingHash, &reserved, &consumed, &revoked)
	})
	if e != nil {
		return nil, e
	}
	t.AuthorizationOperationID = operation.String
	if reserved.Valid {
		t.ReservedAt = &reserved.Time
	}
	if consumed.Valid {
		t.ConsumedAt = &consumed.Time
	}
	if revoked.Valid {
		t.RevokedAt = &revoked.Time
	}
	return t, nil
}
func findLifecycleToken(ctx context.Context, tx storage.IdentityTx, raw string) (*lifecycleToken, error) {
	if !validLifecycleSecret(raw) {
		return nil, ErrProof
	}
	var id string
	if e := securitystate.One(ctx, tx, `SELECT id FROM identity_one_time_tokens WHERE token_hash=?`, []any{auth.TokenHash(raw)}, func(r storage.IdentityRows) error { return r.Scan(&id) }); e != nil {
		if errors.Is(e, storage.ErrNotFound) {
			return nil, ErrProof
		}
		return nil, e
	}
	return readLifecycleToken(ctx, tx, id)
}
func insertLifecycleToken(ctx context.Context, tx storage.IdentityTx, t *lifecycleToken) error {
	if t == nil || !configmodel.ValidID(t.ID) || !strings.HasPrefix(t.GuardID, "guard_setup_") || t.GuardVersion == 0 || t.Epoch == 0 || t.PolicyDigest != lifecyclePolicyDigest() {
		return ErrLifecycleInvalid
	}
	var operation any
	if t.AuthorizationOperationID != "" {
		operation = t.AuthorizationOperationID
	}
	_, e := tx.Exec(ctx, `INSERT INTO identity_one_time_tokens(id,principal_id,purpose,proof_kind,token_hash,guard_id,guard_version,epoch,security_version,password_version,policy_digest,issuer_id,issuer_fingerprint,contact_id,contact_version,generation,authorization_operation_id,allowed_action,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, t.ID, t.PrincipalID, t.Purpose, t.ProofKind, t.TokenHash, t.GuardID, int64(t.GuardVersion), int64(t.Epoch), int64(t.SecurityVersion), int64(t.PasswordVersion), t.PolicyDigest, t.IssuerID, t.IssuerFingerprint, t.ContactID, int64(t.ContactVersion), int64(t.Generation), operation, t.AllowedAction, t.CreatedAt, t.ExpiresAt)
	return e
}

// checkLifecycleTokenTarget validates common pinned target authority. It does
// not authorize an exchange: callers must use one of the typed reservation or
// consumption methods and their exact proof/action checks.
func checkLifecycleTokenTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken) error {
	if t == nil || t.Epoch != uint64(h.Epoch) || h.RecordedAt.IsZero() || h.RecordedAt.Before(t.CreatedAt) || !h.RecordedAt.Before(t.ExpiresAt) || t.PolicyDigest != lifecyclePolicyDigest() {
		return ErrProof
	}
	var state string
	var sv, pv uint64
	var blocked sql.NullTime
	if e := securitystate.One(ctx, tx, `SELECT lifecycle_state,security_version,password_version,blocked_at FROM users WHERE id=?`, []any{t.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&state, &sv, &pv, &blocked) }); e != nil {
		if errors.Is(e, storage.ErrNotFound) {
			return ErrProof
		}
		return e
	}
	if blocked.Valid || sv != t.SecurityVersion || pv != t.PasswordVersion || (t.AllowedAction == "activate" && state != "invited") || (t.AllowedAction != "activate" && state != "active") {
		return ErrProof
	}
	for id, version := range map[string]uint64{"principal_" + t.PrincipalID: sv, PasswordID(t.PrincipalID): pv} {
		floor, e := securitystate.Floor(ctx, tx, t.PrincipalID, id)
		if e != nil {
			return e
		}
		if version < floor {
			return ErrProof
		}
	}
	if t.ContactID != "" {
		var version uint64
		if e := securitystate.One(ctx, tx, `SELECT authenticator_version FROM identity_contacts WHERE id=? AND principal_id=?`, []any{t.ContactID, t.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&version) }); e != nil {
			if errors.Is(e, storage.ErrNotFound) {
				return ErrProof
			}
			return e
		}
		if version != t.ContactVersion {
			return ErrProof
		}
		floor, e := securitystate.Floor(ctx, tx, t.PrincipalID, t.ContactID)
		if e != nil {
			return e
		}
		if version < floor {
			return ErrProof
		}
	}
	return nil
}
func checkUnconsumedLifecycleToken(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken) error {
	if e := checkLifecycleTokenTarget(ctx, tx, h, t); e != nil {
		return e
	}
	if t.ConsumedAt != nil || t.RevokedAt != nil {
		return ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, t.GuardID, t.GuardID)
	if e != nil {
		return e
	}
	if t.GuardVersion < floor {
		return ErrProof
	}
	return nil
}
func reserveEmailToken(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, f *flow, newID, bindingHash string) error {
	if t == nil || t.ProofKind != "email" || t.ReservedAt != nil || f == nil || f.State != "pending_primary" || (t.Purpose == "activate" && f.Purpose != "activate") || (t.Purpose == "reset_password" && f.Purpose != "recover") {
		return ErrProof
	}
	if e := checkUnconsumedLifecycleToken(ctx, tx, h, t); e != nil {
		return e
	}
	if !configmodel.ValidID(newID) || bindingHash == "" {
		return ErrProof
	}
	n, e := tx.Exec(ctx, `UPDATE identity_one_time_tokens SET reserved_flow_id=?,reserved_binding_hash=?,reserved_at=? WHERE id=? AND reserved_at IS NULL AND consumed_at IS NULL AND revoked_at IS NULL`, newID, bindingHash, h.RecordedAt, t.ID)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrProof
	}
	return nil
}
func consumeReservation(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, f *flow) error {
	if t == nil || t.ProofKind != "email" || t.ReservedAt == nil || f == nil || t.ReservedFlowID != f.ID || t.ReservedBindingHash != f.BindingHash || t.ConsumedAt != nil || t.RevokedAt != nil {
		return ErrProof
	}
	// Finalizers have already published restrictive target floors. They must
	// check their exact frozen intent rather than reauthorize an old target
	// snapshot against the newly raised principal/password floor here.
	n, e := tx.Exec(ctx, `UPDATE identity_one_time_tokens SET consumed_at=? WHERE id=? AND reserved_flow_id=? AND reserved_binding_hash=? AND consumed_at IS NULL AND revoked_at IS NULL`, h.RecordedAt, t.ID, f.ID, f.BindingHash)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrProof
	}
	return nil
}
func consumeSupervisedTicket(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, f *flow, newID, bindingHash string) error {
	if t == nil || t.ProofKind != "supervised" || t.AuthorizationOperationID == "" || t.ReservedAt != nil || f == nil || f.Purpose != "recover" || f.State != "pending_primary" || !configmodel.ValidID(newID) || bindingHash == "" {
		return ErrProof
	}
	if e := checkUnconsumedLifecycleToken(ctx, tx, h, t); e != nil {
		return e
	}
	n, e := tx.Exec(ctx, `UPDATE identity_one_time_tokens SET reserved_flow_id=?,reserved_binding_hash=?,reserved_at=?,consumed_at=? WHERE id=? AND reserved_at IS NULL AND consumed_at IS NULL AND revoked_at IS NULL`, newID, bindingHash, h.RecordedAt, h.RecordedAt, t.ID)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrProof
	}
	return nil
}
func revokeLifecycleFlowTokens(ctx context.Context, tx storage.IdentityTx, flowID string, now time.Time) error {
	_, e := tx.Exec(ctx, `UPDATE identity_one_time_tokens SET revoked_at=? WHERE reserved_flow_id=? AND consumed_at IS NULL AND revoked_at IS NULL`, now, flowID)
	return e
}
