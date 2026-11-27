package securitystate

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// ProtectedIdentityTargetGuard is installed at startup by identity. The
// callback checks passive target metadata and authoritative typed scope
// containment without introducing an import cycle into this package.
type ProtectedIdentityTargetGuard func(context.Context, storage.IdentityTx, securityjournal.Head, string, domain.User, []string) error

func (c *Coordinator) RegisterIdentityTargetGuard(guard ProtectedIdentityTargetGuard) {
	c.identityTargetGuard = guard
}

type managementPrincipal struct {
	ID     string
	Admin  bool
	SV, PV uint64
	Grants EffectiveGrants
}

func readManagementPrincipal(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, hash string) (*managementPrincipal, error) {
	if hash == "" || h.Epoch == 0 || h.RecordedAt.IsZero() {
		return nil, storage.ErrPermissionDenied
	}
	p := &managementPrincipal{}
	now := h.RecordedAt.UTC()
	e := One(ctx, tx, `SELECT u.id,u.is_admin,u.security_version,u.password_version FROM sessions s JOIN users u ON u.id=s.user_id JOIN session_profiles p ON p.id=1 WHERE s.token_hash=? AND s.audience='management' AND s.audience_origin=p.management_origin AND s.authority_epoch=? AND s.security_version=u.security_version AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.mfa_at>=? AND s.mfa_at<=? AND u.blocked_at IS NULL AND u.lifecycle_state='active'`, []any{hash, int64(h.Epoch), now, now.Add(-30 * time.Minute), now, now.Add(-5 * time.Minute), now}, func(r storage.IdentityRows) error {
		return r.Scan(&p.ID, &p.Admin, &p.SV, &p.PV)
	})
	if errors.Is(e, storage.ErrNotFound) {
		return nil, storage.ErrPermissionDenied
	}
	if e != nil {
		return nil, e
	}
	p.Grants, e = ReadEffectiveGrants(ctx, tx, h, p.ID)
	return p, e
}

func (p *managementPrincipal) allows(permission string) bool {
	if authz.HasPermission(p.Grants.Global, permission) {
		return true
	}
	// Preserve actual legacy administrator rights, without inventing an
	// explicit independent approval grant or replacing a fresh view with All.
	return p.Admin && permission != authz.PermConfigApprove && authz.HasPermission(authz.AllPermissions(), permission)
}

type passiveIdentityAuthority struct {
	ID        string
	Admin     bool
	SV, PV    uint64
	Lifecycle string
	Blocked   sql.NullTime
	Grants    EffectiveGrants
}

type identityTargetWitness struct {
	fingerprint string
	entries     []EffectiveGrant
}

func passiveIdentityFingerprint(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (identityTargetWitness, error) {
	v := passiveIdentityAuthority{ID: id}
	e := One(ctx, tx, `SELECT is_admin,security_version,password_version,lifecycle_state,blocked_at FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&v.Admin, &v.SV, &v.PV, &v.Lifecycle, &v.Blocked)
	})
	if e != nil {
		return identityTargetWitness{}, e
	}
	v.Grants, e = ReadPrincipalGrantMetadata(ctx, tx, h, id)
	if e != nil {
		return identityTargetWitness{}, e
	}
	return identityTargetWitness{fingerprint: Digest(v), entries: v.Grants.Entries}, nil
}

type identityAuthorityWitness struct {
	actor   *managementPrincipal
	targets map[string]identityTargetWitness
}

func identityMutationPermission(kind storage.IdentityMutationKind) string {
	switch kind {
	case storage.IdentityCreateUser, storage.IdentityUpdateUser, storage.IdentityDeleteUser:
		return authz.PermUsersManage
	case storage.IdentityCreateGroup, storage.IdentityUpdateGroup, storage.IdentityDeleteGroup:
		return authz.PermGroupsManage
	case storage.IdentityRevokeSession:
		return authz.PermSessionsRevoke
	}
	return ""
}

func (s *protectedStore) freshIdentityAuthorization(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, hash string) (storage.IdentityMutationAuthorization, *identityAuthorityWitness, error) {
	p, e := readManagementPrincipal(ctx, tx, h, hash)
	if e != nil {
		return storage.IdentityMutationAuthorization{}, nil, e
	}
	w := &identityAuthorityWitness{actor: p, targets: map[string]identityTargetWitness{}}
	view := storage.IdentityMutationAuthorization{ActorID: p.ID, Now: h.RecordedAt, HasPermission: p.allows}
	view.CheckTarget = func(ctx context.Context, tx storage.IdentityTx, target domain.User, proposed []string) error {
		fp, e := passiveIdentityFingerprint(ctx, tx, h, target.ID)
		if e != nil {
			return e
		}
		w.targets[target.ID] = fp
		if s.c.identityTargetGuard != nil {
			return s.c.identityTargetGuard(ctx, tx, h, p.ID, target, proposed)
		}
		return fallbackIdentityTarget(ctx, tx, h, p, target, proposed)
	}
	return view, w, nil
}

// A missing hierarchy resolver never turns scoped permissions into globals.
// Standalone secure callers can cover global or exact typed targets; parent
// containment requires identity's registered authoritative resolver.
func fallbackIdentityTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor *managementPrincipal, target domain.User, proposed []string) error {
	metadata, e := ReadPrincipalGrantMetadata(ctx, tx, h, target.ID)
	if e != nil {
		return e
	}
	privileged := target.IsAdmin
	for _, g := range metadata.Entries {
		privileged = privileged || authz.IsPrivileged([]string{g.Permission})
	}
	if privileged && !actor.allows(authz.PermUsersPrivilegedManage) {
		return storage.ErrPermissionDenied
	}
	globals := append(append([]string{}, metadata.Global...), proposed...)
	if target.IsAdmin {
		for _, permission := range authz.AllPermissions() {
			if permission != authz.PermConfigApprove {
				globals = append(globals, permission)
			}
		}
	}
	for _, permission := range globals {
		if !actor.allows(permission) {
			return storage.ErrPermissionDenied
		}
	}
	for _, targetGrant := range metadata.Scoped {
		if actor.allows(targetGrant.Permission) {
			continue
		}
		covered := false
		for _, grant := range actor.Grants.Scoped {
			if grant.ScopeType == targetGrant.ScopeType && grant.ScopeID == targetGrant.ScopeID && authz.HasPermission([]string{grant.Permission}, targetGrant.Permission) {
				covered = true
				break
			}
		}
		if !covered {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}

// The witness is checked after expensive preflight, before the immutable
// restrictive command enters the durable barrier. Replay must not reauthorize
// a session or grant which that same command has intentionally revoked.
func (s *protectedStore) finalIdentityAuthority(ctx context.Context, tx storage.IdentityTx, before securityjournal.Head, hash string, w *identityAuthorityWitness) error {
	after, e := s.c.Head(ctx)
	if e != nil || !before.SameState(after) || after.RecordedAt.IsZero() || after.RecordedAt.Before(before.RecordedAt) {
		return ErrUnavailable
	}
	if e = s.c.CheckManagementSession(ctx, tx, after, hash); e != nil {
		return e
	}
	p, e := readManagementPrincipal(ctx, tx, after, hash)
	if e != nil {
		return e
	}
	if w == nil || w.actor == nil || Digest(p) != Digest(w.actor) {
		return storage.ErrPermissionDenied
	}
	targets := make([]identityTargetWitness, 0, len(w.targets))
	for id, expected := range w.targets {
		actual, e := passiveIdentityFingerprint(ctx, tx, after, id)
		if e != nil {
			return e
		}
		if actual.fingerprint != expected.fingerprint {
			return storage.ErrPermissionDenied
		}
		targets = append(targets, actual)
	}
	// A large role catalog or target set may consume the remaining lifetime
	// during the reads above. The writer keeps all rows stable; only immutable
	// expiry witnesses and the bounded session/directory gates need checking
	// after this last independent clock read, without loading every role again.
	last, e := s.c.Head(ctx)
	if e != nil || !after.SameState(last) || last.RecordedAt.IsZero() || last.RecordedAt.Before(after.RecordedAt) {
		return ErrUnavailable
	}
	if !identityGrantsUnexpired(p.Grants.Entries, last.RecordedAt) {
		return storage.ErrPermissionDenied
	}
	for _, target := range targets {
		if !identityGrantsUnexpired(target.entries, last.RecordedAt) {
			return storage.ErrPermissionDenied
		}
	}
	if e = s.c.CheckManagementSession(ctx, tx, last, hash); e != nil {
		return e
	}
	var live string
	e = One(ctx, tx, `SELECT s.id FROM sessions s WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.mfa_at>=? AND s.mfa_at<=? AND (s.source_session_id='' OR EXISTS(SELECT 1 FROM sessions source WHERE source.id=s.source_session_id AND source.user_id=s.user_id AND source.revoked_at IS NULL AND source.authority_epoch=s.authority_epoch AND source.security_version=s.security_version AND source.expires_at>? AND source.last_seen_at>=? AND source.last_seen_at<=?))`, []any{hash, last.RecordedAt, last.RecordedAt.Add(-30 * time.Minute), last.RecordedAt, last.RecordedAt.Add(-5 * time.Minute), last.RecordedAt, last.RecordedAt, last.RecordedAt.Add(-30 * time.Minute), last.RecordedAt}, func(r storage.IdentityRows) error { return r.Scan(&live) })
	if errors.Is(e, storage.ErrNotFound) {
		return storage.ErrPermissionDenied
	}
	return e
}

func identityGrantsUnexpired(entries []EffectiveGrant, now time.Time) bool {
	for _, grant := range entries {
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(now) {
			return false
		}
	}
	return true
}
