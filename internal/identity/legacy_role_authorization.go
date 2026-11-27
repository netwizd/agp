package identity

import (
	"context"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// Legacy metadata/restrictive mutations share the same complete delegation
// ceiling as the typed lifecycle. Passive target classification remains valid
// for blocked or below-floor principals; it never supplies actor authority.
func (s *Service) legacyIdentityTargetAuthorization(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor string, user domain.User, proposed []string) error {
	a, e := s.lifecycleSubject(ctx, tx, h, actor, "", false)
	if e != nil {
		return e
	}
	metadata, e := securitystate.ReadPrincipalGrantMetadata(ctx, tx, h, user.ID)
	if e != nil {
		return e
	}
	t := &lifecycleTarget{View: LifecycleUserView{ID: user.ID, Privileged: user.IsAdmin}, Permissions: identityGlobalPermissions(metadata.Global, user.IsAdmin), Grants: metadata.Entries}
	for _, grant := range metadata.Entries {
		if authz.IsPrivileged([]string{grant.Permission}) {
			t.View.Privileged = true
		}
	}
	if e = s.lifecycleTargetCeiling(ctx, tx, h, a, t); e != nil {
		return e
	}
	return s.requireRoleScopeCeiling(ctx, tx, h, actor, lifecyclePermissions(proposed), RoleScopeSnapshot{ScopeType: "global"})
}
