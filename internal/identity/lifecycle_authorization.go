package identity

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type lifecycleScopeGrant = securitystate.EffectiveGrant
type lifecyclePrincipal struct {
	ID, Fingerprint  string
	Admin            bool
	Permissions      []string
	Grants           []lifecycleScopeGrant
	PrimaryAt, MFAAt time.Time
}
type lifecycleTarget struct {
	View                             LifecycleUserView
	SecurityVersion, PasswordVersion uint64
	Fingerprint                      string
	Permissions                      []string
	Grants                           []lifecycleScopeGrant
	Directory                        bool
}

func canonicalLifecyclePermission(p string) string {
	return authz.CanonicalPermission(p)
}
func lifecyclePermissions(values []string) []string {
	m := map[string]bool{}
	for _, p := range values {
		m[canonicalLifecyclePermission(p)] = true
	}
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
func lifecycleHas(values []string, permission string) bool {
	return authz.HasPermission(values, canonicalLifecyclePermission(permission))
}

// identityGlobalPermissions preserves legacy administrative rights without
// manufacturing an explicit independent approval grant.
func identityGlobalPermissions(global []string, admin bool) []string {
	values := append([]string(nil), global...)
	if admin {
		for _, p := range authz.AllPermissions() {
			if p != authz.PermConfigApprove {
				values = append(values, p)
			}
		}
	}
	return lifecyclePermissions(values)
}
func lifecycleGrants(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) ([]lifecycleScopeGrant, error) {
	metadata, e := securitystate.ReadPrincipalGrantMetadata(ctx, tx, h, id)
	return metadata.Entries, e
}
func checkLifecyclePrincipalVersions(ctx context.Context, tx storage.IdentityTx, id string, sv, pv uint64) error {
	for authenticator, v := range map[string]uint64{"principal_" + id: sv, PasswordID(id): pv} {
		floor, e := securitystate.Floor(ctx, tx, id, authenticator)
		if e != nil {
			return e
		}
		if v < floor {
			return ErrProof
		}
	}
	return nil
}
func lifecycleRawUser(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (*lifecycleTarget, error) {
	t := &lifecycleTarget{}
	var admin bool
	var blocked sql.NullTime
	e := securitystate.One(ctx, tx, `SELECT id,username,display_name,is_admin,blocked_at,security_version,password_version,lifecycle_state FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&t.View.ID, &t.View.Username, &t.View.DisplayName, &admin, &blocked, &t.SecurityVersion, &t.PasswordVersion, &t.View.LifecycleState)
	})
	if e != nil {
		return nil, e
	}
	t.View.Blocked = blocked.Valid
	t.View.Privileged = admin
	t.View.Revision = securityjournal.UInt63(t.SecurityVersion)
	t.View.GroupIDs, e = securitystate.Strings(ctx, tx, `SELECT group_id FROM user_groups WHERE user_id=? ORDER BY group_id`, id)
	if e != nil {
		return nil, e
	}
	if t.View.GroupIDs == nil {
		t.View.GroupIDs = []string{}
	}
	metadata, e := securitystate.ReadPrincipalGrantMetadata(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	t.Permissions = identityGlobalPermissions(metadata.Global, admin)
	t.Grants = metadata.Entries
	for _, g := range t.Grants {
		if authz.IsPrivileged([]string{g.Permission}) {
			t.View.Privileged = true
		}
	}
	pin, e := directoryAuthPin(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	t.Directory = pin != nil
	// Metadata is used only for authorized preselection. The final fingerprint
	// below is usable as authority only after lifecycleTarget/Subject requires
	// fresh, server-owned directory evidence for this same immutable identity.
	var directoryDigest string
	if pin != nil {
		directoryDigest, e = configmodel.Digest(struct {
			Identity       DirectoryIdentityView
			ProviderDigest string
			Context        directoryContext
		}{pin.identity, pin.digest, pin.context})
		if e != nil {
			return nil, e
		}
	}
	t.Fingerprint, e = configmodel.Digest(struct {
		View        LifecycleUserView
		SV, PV      uint64
		Permissions []string
		Grants      []lifecycleScopeGrant
		Directory   string
	}{t.View, t.SecurityVersion, t.PasswordVersion, t.Permissions, t.Grants, directoryDigest})
	return t, e
}
func (s *Service) lifecycleSubject(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id, required string, approve bool) (*lifecyclePrincipal, error) {
	t, e := lifecycleRawUser(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	if t.View.Blocked || t.View.LifecycleState != "active" {
		return nil, storage.ErrPermissionDenied
	}
	if e = checkLifecyclePrincipalVersions(ctx, tx, id, t.SecurityVersion, t.PasswordVersion); e != nil {
		return nil, e
	}
	authority, e := securitystate.ReadEffectiveGrants(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	t.Grants = authority.Entries
	var admin bool
	if e = securitystate.One(ctx, tx, `SELECT is_admin FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&admin) }); e != nil {
		return nil, e
	}
	t.Permissions = identityGlobalPermissions(authority.Global, admin)
	if required != "" && !lifecycleHas(t.Permissions, required) {
		return nil, storage.ErrPermissionDenied
	}
	if approve && !lifecycleHas(t.Permissions, authz.PermConfigApprove) {
		return nil, storage.ErrPermissionDenied
	}
	if _, e = DirectorySubjectFingerprint(ctx, tx, h, id); e != nil {
		return nil, e
	}
	return &lifecyclePrincipal{ID: id, Fingerprint: t.Fingerprint, Admin: admin, Permissions: t.Permissions, Grants: t.Grants}, nil
}
func (s *Service) lifecycleActor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a LifecycleActor, required string, fresh, approve bool) (*lifecyclePrincipal, error) {
	if a.Origin != s.Profile.ManagementOrigin || a.TokenHash == "" || h.Epoch == 0 || h.RecordedAt.IsZero() {
		return nil, storage.ErrPermissionDenied
	}
	var id, sessionID string
	var primary, mfa sql.NullTime
	now := h.RecordedAt.UTC()
	e := securitystate.One(ctx, tx, `SELECT s.user_id,s.id,s.primary_at,s.mfa_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND u.lifecycle_state='active' AND s.mfa_at IS NOT NULL AND s.mfa_at<=?`, []any{a.TokenHash, a.Origin, int64(h.Epoch), now, now.Add(-30 * time.Minute), now, now}, func(r storage.IdentityRows) error { return r.Scan(&id, &sessionID, &primary, &mfa) })
	if errors.Is(e, storage.ErrNotFound) {
		return nil, storage.ErrPermissionDenied
	}
	if e != nil {
		return nil, e
	}
	if e = liveSession(ctx, tx, sessionID, id, uint64(h.Epoch), now); e != nil {
		return nil, e
	}
	if e = CheckDirectorySessionProjection(ctx, tx, h, a.TokenHash); e != nil {
		return nil, e
	}
	if fresh && (!emailRecent(now, primary) || !emailRecent(now, mfa)) {
		return nil, ErrLifecycleReauthRequired
	}
	p, e := s.lifecycleSubject(ctx, tx, h, id, required, approve)
	if e != nil {
		return nil, e
	}
	if primary.Valid {
		p.PrimaryAt = primary.Time
	}
	p.MFAAt = mfa.Time
	return p, nil
}
func (s *Service) lifecycleTargetMetadata(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a *lifecyclePrincipal, id string) (*lifecycleTarget, error) {
	if a == nil {
		return nil, storage.ErrPermissionDenied
	}
	t, e := lifecycleRawUser(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	if t.View.Blocked || (t.View.LifecycleState != "active" && t.View.LifecycleState != "invited") {
		return nil, storage.ErrPermissionDenied
	}
	if e = checkLifecyclePrincipalVersions(ctx, tx, id, t.SecurityVersion, t.PasswordVersion); e != nil {
		return nil, e
	}
	if e = s.lifecycleTargetCeiling(ctx, tx, h, a, t); e != nil {
		return nil, e
	}
	return t, nil
}
func (s *Service) lifecycleTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a *lifecyclePrincipal, id string) (*lifecycleTarget, error) {
	t, e := s.lifecycleTargetMetadata(ctx, tx, h, a, id)
	if e != nil {
		return nil, e
	}
	if _, e = DirectorySubjectFingerprint(ctx, tx, h, id); e != nil {
		return nil, e
	}
	return t, nil
}
func (s *Service) lifecyclePeople(ctx context.Context, subjects []string) (context.Context, error) {
	if len(subjects) > 4 {
		return nil, ErrLifecycleInvalid
	}
	if s.directory != nil {
		return s.directory.withDirectoryPeople(ctx, subjects)
	}
	// Bare local-only Service fixtures have no connector. They may proceed only
	// after authoritative selection proves every requested subject is local.
	e := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		for _, id := range subjects {
			if id == "" {
				continue
			}
			pin, e := directoryAuthPin(ctx, tx, h, id)
			if e != nil {
				return e
			}
			if pin != nil {
				return ErrDirectoryUnavailable
			}
		}
		return nil
	})
	return ctx, e
}

// lifecycleIssuerSnapshot invalidates a provisional setup when the issuing
// human's local authority/pins changed. It is not a live directory proof and
// cannot authorize publication of credentials or a normal session.
func (s *Service) lifecycleIssuerSnapshot(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken) error {
	if t == nil {
		return ErrProof
	}
	if t.IssuerID == "" {
		if t.Purpose == "reset_password" && t.ProofKind == "email" {
			return nil
		}
		return ErrProof
	}
	subject, err := lifecycleRawUser(ctx, tx, h, t.IssuerID)
	if err != nil {
		return err
	}
	if subject.View.Blocked || subject.View.LifecycleState != "active" || subject.Fingerprint != t.IssuerFingerprint {
		return ErrProof
	}
	if err = checkLifecyclePrincipalVersions(ctx, tx, t.IssuerID, subject.SecurityVersion, subject.PasswordVersion); err != nil {
		return err
	}
	required := authz.PermUsersManage
	if t.ProofKind == "supervised" {
		required = "users.privileged.manage"
	}
	if !lifecycleHas(subject.Permissions, required) {
		return storage.ErrPermissionDenied
	}
	var admin bool
	if err = securitystate.One(ctx, tx, `SELECT is_admin FROM users WHERE id=?`, []any{t.IssuerID}, func(r storage.IdentityRows) error { return r.Scan(&admin) }); err != nil {
		return err
	}
	_, err = s.lifecycleTargetMetadata(ctx, tx, h, &lifecyclePrincipal{ID: t.IssuerID, Fingerprint: subject.Fingerprint, Admin: admin, Permissions: subject.Permissions, Grants: subject.Grants}, t.PrincipalID)
	return err
}

// lifecycleIssuerCurrent is required in a final credential publication after
// lifecyclePeople obtained any historical issuer's fresh directory evidence.
func (s *Service) lifecycleIssuerCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken) error {
	if err := s.lifecycleIssuerSnapshot(ctx, tx, h, t); err != nil {
		return err
	}
	if t.IssuerID == "" {
		return nil
	}
	required := authz.PermUsersManage
	if t.ProofKind == "supervised" {
		required = "users.privileged.manage"
	}
	issuer, err := s.lifecycleSubject(ctx, tx, h, t.IssuerID, required, false)
	if err != nil {
		return err
	}
	if issuer.Fingerprint != t.IssuerFingerprint {
		return ErrProof
	}
	_, err = s.lifecycleTarget(ctx, tx, h, issuer, t.PrincipalID)
	return err
}

// lifecycleTargetCeiling resolves hierarchical delegation only when an exact
// or global grant cannot cover the target. Historical metadata never supplies
// actor authority: requireRoleScopeCeiling reloads the active actor and floors.
func (s *Service) lifecycleTargetCeiling(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a *lifecyclePrincipal, t *lifecycleTarget) error {
	if a == nil || t == nil {
		return storage.ErrPermissionDenied
	}
	if t.View.Privileged && !lifecycleHas(a.Permissions, "users.privileged.manage") {
		return storage.ErrPermissionDenied
	}
	globals := append([]string(nil), t.Permissions...)
	for _, g := range t.Grants {
		if g.ScopeType == "global" {
			globals = append(globals, g.Permission)
		}
	}
	if len(globals) > 0 {
		if e := s.requireRoleScopeCeiling(ctx, tx, h, a.ID, lifecyclePermissions(globals), RoleScopeSnapshot{ScopeType: "global"}); e != nil {
			return e
		}
	}
	// Global entries have already been checked in the flat global projection.
	// Group scoped permissions per object to avoid reloading the actor for every
	// permission while retaining exact typed boundaries and no global cache.
	type scopeKey struct{ kind, id string }
	grouped := map[scopeKey][]string{}
	for _, g := range t.Grants {
		if g.ScopeType != "global" {
			key := scopeKey{g.ScopeType, g.ScopeID}
			grouped[key] = append(grouped[key], g.Permission)
		}
	}
	keys := make([]scopeKey, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].id < keys[j].id
	})
	for _, key := range keys {
		if e := s.requireRoleScopeCeiling(ctx, tx, h, a.ID, lifecyclePermissions(grouped[key]), RoleScopeSnapshot{ScopeType: key.kind, ScopeID: key.id}); e != nil {
			return e
		}
	}
	return nil
}

// lifecycleRestartTarget is reserved for the separately approved repair of a
// failed initial activation. A row below restrictive floors is never eligible
// for a normal invitation or active-account recovery. The caller pins every
// observed floor in its immutable operation before executing the repair.
func (s *Service) lifecycleRestartTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a *lifecyclePrincipal, id string) (*lifecycleTarget, error) {
	t, e := lifecycleRawUser(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	if t.View.LifecycleState != "invited" || t.View.Blocked || t.Directory {
		return nil, storage.ErrPermissionDenied
	}
	if e = s.lifecycleTargetCeiling(ctx, tx, h, a, t); e != nil {
		return nil, e
	}
	// No directory identity is allowed for local pending-account activation;
	// this check still fails closed if evidence is added concurrently.
	if _, e = DirectorySubjectFingerprint(ctx, tx, h, id); e != nil {
		return nil, e
	}
	return t, nil
}
