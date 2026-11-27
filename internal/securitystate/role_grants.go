package securitystate

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// RoleDefinition is a registered immutable permission preset. Its digest covers
// the version, name, permissions and allowed scopes in their canonical order.
type RoleDefinition struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Version       securityjournal.UInt63 `json:"version"`
	Digest        string                 `json:"digest"`
	Permissions   []string               `json:"permissions"`
	AllowedScopes []string               `json:"allowedScopes"`
}

type RoleBinding struct {
	ID             string                 `json:"id"`
	PrincipalID    string                 `json:"principalId"`
	RoleID         string                 `json:"roleId"`
	RoleVersion    securityjournal.UInt63 `json:"roleVersion"`
	RoleDigest     string                 `json:"roleDigest"`
	ScopeType      string                 `json:"scopeType"`
	ScopeID        string                 `json:"scopeId,omitempty"`
	Revision       securityjournal.UInt63 `json:"revision"`
	AuthorityEpoch securityjournal.UInt63 `json:"authorityEpoch"`
	CreatedAt      time.Time              `json:"createdAt"`
	ExpiresAt      *time.Time             `json:"expiresAt"`
	RevokedAt      *time.Time             `json:"revokedAt"`
}

// EffectiveGrant retains incarnation evidence even for global permissions, so
// replacing a role with identical permissions invalidates historical proofs.
type EffectiveGrant struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principalId"`
	Permission  string     `json:"permission"`
	ScopeType   string     `json:"scopeType"`
	ScopeID     string     `json:"scopeId,omitempty"`
	RoleDigest  string     `json:"roleDigest,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt"`
}

type EffectiveGrants struct {
	Global  []string
	Scoped  []EffectiveGrant
	Entries []EffectiveGrant
}

var roleObjectID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func canonicalRolePermission(p string) string {
	if p == authz.PermUsersSuperAdminManage {
		return "users.privileged.manage"
	}
	return p
}

func roleDefinitionDigest(r RoleDefinition) (string, error) {
	// Digest is excluded rather than zeroed: this is the public JCS contract.
	return configmodel.Digest(struct {
		ID            string                 `json:"id"`
		Name          string                 `json:"name"`
		Version       securityjournal.UInt63 `json:"version"`
		Permissions   []string               `json:"permissions"`
		AllowedScopes []string               `json:"allowedScopes"`
	}{r.ID, r.Name, r.Version, r.Permissions, r.AllowedScopes})
}

// BuiltinRoleDefinitions returns new slices on every call. Administrative
// legacy flags are deliberately absent: they do not imply explicit approval.
func BuiltinRoleDefinitions() []RoleDefinition {
	permissions := append(authz.AllPermissions(), "nodes.read", "nodes.enroll", "nodes.revoke")
	seen := map[string]bool{}
	out := make([]RoleDefinition, 0, len(permissions))
	for _, permission := range permissions {
		permission = canonicalRolePermission(permission)
		if seen[permission] {
			continue
		}
		seen[permission] = true
		scopes := []string{"global"}
		switch permission {
		case "config.read", "config.edit", "config.approve", "resources.read", "resources.manage", "resources.diagnostics", "audit.read", "audit.export":
			scopes = []string{"global", "node", "node_group", "resource", "site"}
		case "nodes.read", "nodes.revoke", "rollouts.create", "rollouts.cancel", "rollouts.rollback":
			scopes = []string{"global", "node", "node_group", "site"}
		case "nodes.enroll":
			scopes = []string{"global", "site"}
		}
		r := RoleDefinition{ID: "role_" + strings.ReplaceAll(permission, ".", "_"), Name: permission, Version: 1, Permissions: []string{permission}, AllowedScopes: scopes}
		var err error
		r.Digest, err = roleDefinitionDigest(r)
		if err != nil {
			panic(fmt.Sprintf("canonical built-in role: %v", err))
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func registeredRole(r RoleDefinition) bool {
	digest, err := roleDefinitionDigest(r)
	if err != nil {
		return false
	}
	for _, preset := range BuiltinRoleDefinitions() {
		if preset.ID == r.ID && preset.Version == r.Version && preset.Digest == r.Digest && digest == r.Digest {
			return true
		}
	}
	return false
}

// RegisterRoleDefinitionTx installs only a code-registered immutable preset.
// Child mappings are sealed in the same transaction, never published partially.
func RegisterRoleDefinitionTx(ctx context.Context, tx storage.IdentityTx, r RoleDefinition) error {
	if !registeredRole(r) {
		return storage.ErrPermissionDenied
	}
	n, e := tx.Exec(ctx, `INSERT INTO role_definitions(role_digest,role_id,version,name,created_at,sealed) VALUES(?,?,?,?,?,FALSE) ON CONFLICT(role_digest) DO NOTHING`, r.Digest, r.ID, int64(r.Version), r.Name, time.Now().UTC())
	if e != nil {
		return e
	}
	if n == 0 {
		saved, e := ReadRoleDefinitionDigestTx(ctx, tx, r.Digest)
		if e != nil {
			return e
		}
		if saved.Digest != r.Digest {
			return ErrUnavailable
		}
		return nil
	}
	for _, p := range r.Permissions {
		if _, e = tx.Exec(ctx, `INSERT INTO role_definition_permissions(role_digest,permission) VALUES(?,?)`, r.Digest, p); e != nil {
			return e
		}
	}
	for _, scope := range r.AllowedScopes {
		if _, e = tx.Exec(ctx, `INSERT INTO role_definition_scopes(role_digest,scope_type) VALUES(?,?)`, r.Digest, scope); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE role_definitions SET sealed=TRUE WHERE role_digest=? AND sealed=FALSE`, r.Digest)
	return e
}
func EnsureBuiltinRolesTx(ctx context.Context, tx storage.IdentityTx) error {
	for _, r := range BuiltinRoleDefinitions() {
		if e := RegisterRoleDefinitionTx(ctx, tx, r); e != nil {
			return e
		}
	}
	return nil
}
func ReadRoleDefinitionTx(ctx context.Context, tx storage.IdentityTx, id string) (RoleDefinition, error) {
	var digest string
	e := One(ctx, tx, `SELECT role_digest FROM role_definitions WHERE role_id=? AND sealed=TRUE ORDER BY version DESC LIMIT 1`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&digest) })
	if e != nil {
		return RoleDefinition{}, e
	}
	return ReadRoleDefinitionDigestTx(ctx, tx, digest)
}
func ReadRoleDefinitionDigestTx(ctx context.Context, tx storage.IdentityTx, digest string) (RoleDefinition, error) {
	var r RoleDefinition
	e := One(ctx, tx, `SELECT role_id,name,version,role_digest FROM role_definitions WHERE role_digest=? AND sealed=TRUE`, []any{digest}, func(row storage.IdentityRows) error { return row.Scan(&r.ID, &r.Name, &r.Version, &r.Digest) })
	if e != nil {
		return r, e
	}
	r.Permissions, e = Strings(ctx, tx, `SELECT permission FROM role_definition_permissions WHERE role_digest=? ORDER BY permission`, digest)
	if e != nil {
		return r, e
	}
	r.AllowedScopes, e = Strings(ctx, tx, `SELECT scope_type FROM role_definition_scopes WHERE role_digest=? ORDER BY scope_type`, digest)
	if e != nil {
		return r, e
	}
	if !registeredRole(r) {
		return RoleDefinition{}, ErrUnavailable
	}
	return r, nil
}
func ListRoleDefinitionsTx(ctx context.Context, tx storage.IdentityTx) ([]RoleDefinition, error) {
	digests, e := Strings(ctx, tx, `SELECT role_digest FROM role_definitions WHERE sealed=TRUE ORDER BY role_id,version LIMIT 4097`)
	if e != nil {
		return nil, e
	}
	if len(digests) > 4096 {
		return nil, ErrUnavailable
	}
	out := make([]RoleDefinition, 0, len(digests))
	for _, digest := range digests {
		r, e := ReadRoleDefinitionDigestTx(ctx, tx, digest)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, nil
}

func validRoleScope(kind, id string) bool {
	switch kind {
	case "global":
		return id == ""
	case "site", "node_group", "node", "resource":
		return roleObjectID.MatchString(id)
	default:
		return false
	}
}

func rolePrincipalCurrent(ctx context.Context, tx storage.IdentityTx, id string) error {
	var blocked sql.NullTime
	var lifecycle string
	var sv, pv int64
	e := One(ctx, tx, `SELECT blocked_at,lifecycle_state,security_version,password_version FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&blocked, &lifecycle, &sv, &pv) })
	if e != nil {
		return e
	}
	if blocked.Valid || lifecycle != "active" || sv <= 0 || pv <= 0 {
		return storage.ErrPermissionDenied
	}
	for _, p := range []struct {
		key     string
		version int64
	}{{"principal_" + id, sv}, {"password_" + id, pv}} {
		floor, e := Floor(ctx, tx, id, p.key)
		if e != nil {
			return e
		}
		if uint64(p.version) < floor {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}
func roleHeadCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	if h.Epoch == 0 || h.Epoch > securityjournal.MaxUInt63 || h.RecordedAt.IsZero() {
		return ErrUnavailable
	}
	local, e := state(ctx, tx)
	if e != nil {
		return e
	}
	if !sameProjection(local, h) {
		return ErrUnavailable
	}
	return nil
}

// PublishRoleBindingTx performs only final positive-publication invariants. The
// workflow must recheck quorum, participant evidence and the exact scope closure
// in this same Coordinator.Current transaction; this helper grants no authority.
func PublishRoleBindingTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, b RoleBinding) error {
	if e := roleHeadCurrent(ctx, tx, h); e != nil {
		return e
	}
	if e := pending(ctx, tx); e != nil {
		return e
	}
	if !strings.HasPrefix(b.ID, "rbinding_") || !roleObjectID.MatchString(b.ID) || b.PrincipalID == "" || b.Revision != 1 || b.RevokedAt != nil || b.AuthorityEpoch != h.Epoch || b.CreatedAt.IsZero() || b.CreatedAt.After(h.RecordedAt) || !validRoleScope(b.ScopeType, b.ScopeID) {
		return storage.ErrPermissionDenied
	}
	if b.ExpiresAt != nil && (!b.ExpiresAt.After(h.RecordedAt) || !b.ExpiresAt.After(b.CreatedAt)) {
		return storage.ErrPermissionDenied
	}
	if e := rolePrincipalCurrent(ctx, tx, b.PrincipalID); e != nil {
		return e
	}
	definition, e := ReadRoleDefinitionDigestTx(ctx, tx, b.RoleDigest)
	if e != nil {
		return e
	}
	if definition.ID != b.RoleID || definition.Version != b.RoleVersion {
		return storage.ErrPermissionDenied
	}
	allowed := false
	for _, scope := range definition.AllowedScopes {
		if scope == b.ScopeType {
			allowed = true
		}
	}
	if !allowed {
		return storage.ErrPermissionDenied
	}
	denied, e := Strings(ctx, tx, `SELECT binding_id FROM role_binding_revocations WHERE binding_id=?`, b.ID)
	if e != nil {
		return e
	}
	if len(denied) > 0 {
		return storage.ErrPermissionDenied
	}
	_, e = tx.Exec(ctx, `INSERT INTO role_bindings(binding_id,principal_id,authority_epoch,role_digest,scope_type,scope_id,expires_at,revision,created_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,NULL)`, b.ID, b.PrincipalID, int64(b.AuthorityEpoch), b.RoleDigest, b.ScopeType, b.ScopeID, b.ExpiresAt, int64(b.Revision), b.CreatedAt)
	return e
}

func readRoleBindingRow(row storage.IdentityRows) (RoleBinding, error) {
	var b RoleBinding
	var expires, revoked sql.NullTime
	e := row.Scan(&b.ID, &b.PrincipalID, &b.RoleID, &b.RoleVersion, &b.RoleDigest, &b.ScopeType, &b.ScopeID, &b.Revision, &b.AuthorityEpoch, &b.CreatedAt, &expires, &revoked)
	if expires.Valid {
		b.ExpiresAt = &expires.Time
	}
	if revoked.Valid {
		b.RevokedAt = &revoked.Time
	}
	return b, e
}

const roleBindingSelect = `SELECT b.binding_id,b.principal_id,d.role_id,d.version,b.role_digest,b.scope_type,b.scope_id,b.revision,b.authority_epoch,b.created_at,b.expires_at,b.revoked_at FROM role_bindings b JOIN role_definitions d ON d.role_digest=b.role_digest`

func ReadRoleBindingTx(ctx context.Context, tx storage.IdentityTx, id string) (RoleBinding, error) {
	var b RoleBinding
	e := One(ctx, tx, roleBindingSelect+` WHERE b.binding_id=?`, []any{id}, func(row storage.IdentityRows) error { var e error; b, e = readRoleBindingRow(row); return e })
	return b, e
}
func ListRoleBindingsTx(ctx context.Context, tx storage.IdentityTx, principal string) ([]RoleBinding, error) {
	q := roleBindingSelect
	args := []any{}
	if principal != "" {
		q += ` WHERE b.principal_id=?`
		args = append(args, principal)
	}
	q += ` ORDER BY b.binding_id LIMIT 4097`
	rows, e := tx.Query(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []RoleBinding{}
	for rows.Next() {
		b, e := readRoleBindingRow(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(out) > 4096 {
		return nil, ErrUnavailable
	}
	return out, nil
}

// ReadEffectiveGrants preserves typed scopes. Global is the only projection
// suitable for legacy flat authorization; Scoped must never be flattened. The
// caller owns the Current boundary, or a previously authorized restrictive
// materializer with its own pending barrier and independently checked head.
func ReadEffectiveGrants(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string) (EffectiveGrants, error) {
	out := EffectiveGrants{Global: []string{}, Scoped: []EffectiveGrant{}, Entries: []EffectiveGrant{}}
	if e := roleHeadCurrent(ctx, tx, h); e != nil {
		return out, e
	}
	if e := rolePrincipalCurrent(ctx, tx, principal); e != nil {
		return out, e
	}
	return readPrincipalGrantProjection(ctx, tx, h, principal)
}

// ReadPrincipalGrantMetadata provides passive classification evidence for a
// principal, including invited, blocked or restored principals below a floor.
// It makes no claim that the principal may exercise or delegate these grants.
// Only current-epoch, unexpired and nonrevoked entries with valid catalog pins
// are returned. Authorization callers must use ReadEffectiveGrants instead.
func ReadPrincipalGrantMetadata(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string) (EffectiveGrants, error) {
	if e := roleHeadCurrent(ctx, tx, h); e != nil {
		return EffectiveGrants{}, e
	}
	return readPrincipalGrantProjection(ctx, tx, h, principal)
}
func readPrincipalGrantProjection(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string) (EffectiveGrants, error) {
	out := EffectiveGrants{Global: []string{}, Scoped: []EffectiveGrant{}, Entries: []EffectiveGrant{}}
	rows, e := tx.Query(ctx, `SELECT ug.group_id,gp.permission_id FROM user_groups ug JOIN group_permissions gp ON gp.group_id=ug.group_id WHERE ug.user_id=? ORDER BY ug.group_id,gp.permission_id LIMIT 4097`, principal)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var group, permission string
		if e = rows.Scan(&group, &permission); e != nil {
			rows.Close()
			return out, e
		}
		out.Entries = append(out.Entries, EffectiveGrant{ID: "legacy_" + group + ":" + permission, PrincipalID: principal, Permission: canonicalRolePermission(permission), ScopeType: "global"})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.Query(ctx, `SELECT id,permission,scope_type,scope_id FROM config_scope_grants WHERE principal_id=? AND authority_epoch=? AND revoked=FALSE ORDER BY id LIMIT 4097`, principal, int64(h.Epoch))
	if e != nil {
		return out, e
	}
	for rows.Next() {
		g := EffectiveGrant{PrincipalID: principal}
		if e = rows.Scan(&g.ID, &g.Permission, &g.ScopeType, &g.ScopeID); e != nil {
			rows.Close()
			return out, e
		}
		g.Permission = canonicalRolePermission(g.Permission)
		out.Entries = append(out.Entries, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	bindings, e := ListRoleBindingsTx(ctx, tx, principal)
	if e != nil {
		return out, e
	}
	for _, b := range bindings {
		if b.AuthorityEpoch != h.Epoch || b.RevokedAt != nil || (b.ExpiresAt != nil && !b.ExpiresAt.After(h.RecordedAt)) {
			continue
		}
		denied, e := Strings(ctx, tx, `SELECT binding_id FROM role_binding_revocations WHERE binding_id=?`, b.ID)
		if e != nil {
			return out, e
		}
		if len(denied) > 0 {
			continue
		}
		definition, e := ReadRoleDefinitionDigestTx(ctx, tx, b.RoleDigest)
		if e != nil {
			return out, e
		}
		allowed := false
		for _, scope := range definition.AllowedScopes {
			if scope == b.ScopeType {
				allowed = true
			}
		}
		if !allowed {
			return EffectiveGrants{}, ErrUnavailable
		}
		for _, p := range definition.Permissions {
			out.Entries = append(out.Entries, EffectiveGrant{ID: b.ID, PrincipalID: principal, Permission: p, ScopeType: b.ScopeType, ScopeID: b.ScopeID, RoleDigest: b.RoleDigest, ExpiresAt: b.ExpiresAt})
		}
	}
	if len(out.Entries) > 4096 {
		return EffectiveGrants{}, ErrUnavailable
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Permission < b.Permission
	})
	global := map[string]bool{}
	for _, g := range out.Entries {
		if !validRoleScope(g.ScopeType, g.ScopeID) {
			return EffectiveGrants{}, ErrUnavailable
		}
		if g.ScopeType == "global" {
			global[g.Permission] = true
		} else {
			out.Scoped = append(out.Scoped, g)
		}
	}
	for p := range global {
		out.Global = append(out.Global, p)
	}
	sort.Strings(out.Global)
	return out, nil
}

func materializeRoleBindingRevocation(ctx context.Context, tx storage.IdentityTx, event securityjournal.Event) error {
	id := event.Request.Payload.GrantID
	if !strings.HasPrefix(id, "rbinding_") || !roleObjectID.MatchString(id) || event.Epoch == 0 || event.RecordedAt.IsZero() {
		return fmt.Errorf("%w: invalid role binding revocation", securityjournal.ErrInvalid)
	}
	if _, e := tx.Exec(ctx, `INSERT INTO role_binding_revocations(binding_id,authority_epoch,event_id,revoked_at) VALUES(?,?,?,?) ON CONFLICT(binding_id) DO NOTHING`, id, int64(event.Epoch), event.ID, event.RecordedAt); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE role_bindings SET revoked_at=?,revision=revision+1 WHERE binding_id=? AND revoked_at IS NULL`, event.RecordedAt, id)
	return e
}
