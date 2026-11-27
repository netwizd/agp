package identity

import (
	"context"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Service) RoleBindingService() *RoleBindingService { return s.roleBindings }

func (s *Service) resolveRoleScope(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, kind, id string) (RoleScopeSnapshot, error) {
	if !validRoleScope(kind, id) || h.Epoch == 0 || h.RecordedAt.IsZero() {
		return RoleScopeSnapshot{}, ErrLifecycleInvalid
	}
	{
		resolved, e := rolescope.Resolve(ctx, tx, h, kind, id)
		if e != nil {
			return RoleScopeSnapshot{}, e
		}
		out := RoleScopeSnapshot{ScopeType: resolved.ScopeType, ScopeID: resolved.ScopeID, Digest: resolved.Digest, Closure: []RoleScopeRef{}, Sources: []RoleScopeSourceVersion{}}
		for _, object := range resolved.Closure {
			out.Closure = append(out.Closure, RoleScopeRef{ScopeType: object.ScopeType, ScopeID: object.ScopeID})
		}
		for _, source := range resolved.Sources {
			out.Sources = append(out.Sources, RoleScopeSourceVersion{Kind: source.Kind, ID: source.ID, Revision: source.Revision, Digest: source.Digest})
		}
		return out, nil
	}
}

func (s *Service) requireRoleScopeCeiling(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string, permissions []string, target RoleScopeSnapshot) error {
	grants, e := securitystate.ReadEffectiveGrants(ctx, tx, h, principal)
	if e != nil {
		return e
	}
	var admin bool
	if e = securitystate.One(ctx, tx, `SELECT is_admin FROM users WHERE id=?`, []any{principal}, func(r storage.IdentityRows) error { return r.Scan(&admin) }); e != nil {
		return e
	}
	global := lifecyclePermissions(grants.Global)
	if admin {
		for _, permission := range authz.AllPermissions() {
			if permission != authz.PermConfigApprove {
				global = append(global, canonicalLifecyclePermission(permission))
			}
		}
		// The existing node service admits legacy administrators for these
		// operations. Approval still requires its own explicit global grant.
		global = lifecyclePermissions(append(global, "nodes.read", "nodes.enroll", "nodes.revoke"))
	}
	for _, permission := range permissions {
		permission = canonicalLifecyclePermission(permission)
		if lifecycleHas(global, permission) || permission == "config.read" && lifecycleHas(global, "config.edit") {
			continue
		}
		// A union of restricted scopes never authorizes a global assignment.
		if target.ScopeType == "global" {
			return storage.ErrPermissionDenied
		}
		covered := false
		for _, grant := range grants.Scoped {
			if !rolescope.CanContain(grant.ScopeType, target.ScopeType) {
				continue
			}
			if !lifecycleHas([]string{grant.Permission}, permission) && !(permission == "config.read" && grant.Permission == "config.edit") {
				continue
			}
			if grant.ScopeType == target.ScopeType && grant.ScopeID == target.ScopeID {
				covered = true
				break
			}
			scope, e := s.resolveRoleScope(ctx, tx, h, grant.ScopeType, grant.ScopeID)
			if e != nil {
				return e
			}
			for _, object := range scope.Closure {
				if object.ScopeType == target.ScopeType && object.ScopeID == target.ScopeID {
					covered = true
					break
				}
			}
			if covered {
				break
			}
		}
		if !covered {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}
