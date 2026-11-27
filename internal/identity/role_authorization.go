package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// historicalActor revalidates a frozen participant session using the private
// multi-person observation. The single-request session proof belongs only to
// the current executor and cannot be used as a historical participant proof.
func (r *RoleBindingService) historicalActor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a LifecycleActor, approve bool) (*lifecyclePrincipal, error) {
	if a.Origin != r.identity.Profile.ManagementOrigin || a.TokenHash == "" || h.RecordedAt.IsZero() {
		return nil, storage.ErrPermissionDenied
	}
	var id, sessionID string
	var primary, mfa sql.NullTime
	now := h.RecordedAt.UTC()
	e := securitystate.One(ctx, tx, `SELECT s.user_id,s.id,s.primary_at,s.mfa_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND u.lifecycle_state='active' AND s.mfa_at IS NOT NULL AND s.mfa_at<=?`, []any{a.TokenHash, a.Origin, int64(h.Epoch), now, now.Add(-30 * time.Minute), now, now}, func(row storage.IdentityRows) error { return row.Scan(&id, &sessionID, &primary, &mfa) })
	if errors.Is(e, storage.ErrNotFound) {
		return nil, storage.ErrPermissionDenied
	}
	if e != nil {
		return nil, e
	}
	if e = liveSession(ctx, tx, sessionID, id, uint64(h.Epoch), now); e != nil {
		return nil, e
	}
	if !emailRecent(now, primary) || !emailRecent(now, mfa) {
		return nil, ErrLifecycleReauthRequired
	}
	if e = directoryCheckProjection(ctx, tx, h, id, "sessions", sessionID); e != nil {
		return nil, e
	}
	p, e := r.identity.lifecycleSubject(ctx, tx, h, id, "users.privileged.manage", approve)
	if e != nil {
		return nil, e
	}
	p.PrimaryAt, p.MFAAt = primary.Time, mfa.Time
	return p, nil
}

// finalGrantHead closes elapsed-time races after a potentially large scoped
// delegation check. The surrounding writer TX holds all CP source revisions;
// Current still compares the independent head again after publication.
func (r *RoleBindingService) finalGrantHead(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, rec *roleRecord, a LifecycleActor, executor *lifecyclePrincipal) (securityjournal.Head, error) {
	final, e := r.identity.Coordinator.Authority.Head(ctx)
	if e != nil || !h.SameState(final) || final.RecordedAt.IsZero() || final.RecordedAt.Before(h.RecordedAt) {
		return h, securitystate.ErrUnavailable
	}
	in := rec.operation.RoleGrantRequest
	if in == nil || !final.RecordedAt.Before(in.ExpiresAt) {
		return h, ErrLifecycleStale
	}
	creator, e := r.historicalActor(ctx, tx, final, LifecycleActor{TokenHash: rec.creatorTokenHash, Origin: rec.creatorOrigin}, false)
	if e != nil {
		return h, e
	}
	if creator.ID != rec.operation.CreatedBy || creator.Fingerprint != rec.creatorFingerprint || !creator.PrimaryAt.Equal(rec.creatorPrimaryAt) || !creator.MFAAt.Equal(rec.creatorMFAAt) {
		return h, ErrLifecycleStale
	}

	var id, fp, token, origin string
	var primary, mfa time.Time
	e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,reviewer_token_hash,reviewer_origin,primary_at,mfa_at FROM role_grant_approvals WHERE operation_id=? AND request_digest=?`, []any{rec.operation.ID, rec.operation.RequestDigest}, func(row storage.IdentityRows) error { return row.Scan(&id, &fp, &token, &origin, &primary, &mfa) })
	if e != nil {
		return h, e
	}
	p, e := r.historicalActor(ctx, tx, final, LifecycleActor{TokenHash: token, Origin: origin}, true)
	if e != nil {
		return h, e
	}
	if p.ID != id || id == rec.operation.CreatedBy || id == rec.operation.SubjectID || p.Fingerprint != fp || !p.PrimaryAt.Equal(primary) || !p.MFAAt.Equal(mfa) {
		return h, ErrLifecycleStale
	}
	if e = RequireDistinctPeople(ctx, tx, id, rec.operation.CreatedBy); e != nil {
		return h, e
	}
	if e = RequireDistinctPeople(ctx, tx, id, in.PrincipalID); e != nil {
		return h, e
	}
	p, e = r.identity.lifecycleActor(ctx, tx, final, a, "users.privileged.manage", true, false)
	if e != nil {
		return h, e
	}
	if p.ID != executor.ID || p.Fingerprint != executor.Fingerprint {
		return h, ErrLifecycleStale
	}
	target, e := lifecycleRawUser(ctx, tx, final, in.PrincipalID)
	if e != nil {
		return h, e
	}
	if target.View.Blocked || target.View.LifecycleState != "active" || target.Fingerprint != in.TargetFingerprint || target.SecurityVersion != uint64(in.ExpectedSecurityVersion) || target.PasswordVersion != uint64(in.ExpectedPasswordVersion) {
		return h, ErrLifecycleStale
	}
	if e = checkLifecyclePrincipalVersions(ctx, tx, in.PrincipalID, target.SecurityVersion, target.PasswordVersion); e != nil {
		return h, e
	}
	if _, e = DirectorySubjectFingerprint(ctx, tx, final, in.PrincipalID); e != nil {
		return h, e
	}
	return final, nil
}
