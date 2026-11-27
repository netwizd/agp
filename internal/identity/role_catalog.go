package identity

import (
	"context"
	"sort"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type RoleCatalogView struct {
	Items []securitystate.RoleDefinition `json:"items"`
}
type RoleBindingsView struct {
	Items      []securitystate.RoleBinding `json:"items"`
	NextCursor string                      `json:"nextCursor,omitempty"`
}
type RolePermissionView struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Dangerous   bool   `json:"dangerous"`
}
type RolePermissionsView struct {
	Items []RolePermissionView `json:"items"`
}

func (r *RoleBindingService) Catalog(ctx context.Context, a LifecycleActor) (out *RoleCatalogView, err error) {
	err = r.current(ctx, a, "users.read", false, false, func(c context.Context, tx storage.IdentityTx, _ securityjournal.Head, _ *lifecyclePrincipal) error {
		if e := securitystate.EnsureBuiltinRolesTx(c, tx); e != nil {
			return e
		}
		items, e := securitystate.ListRoleDefinitionsTx(c, tx)
		if e != nil {
			return e
		}
		out = &RoleCatalogView{Items: items}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r *RoleBindingService) Permissions(ctx context.Context, a LifecycleActor) (out *RolePermissionsView, err error) {
	err = r.current(ctx, a, "users.read", false, false, func(c context.Context, tx storage.IdentityTx, _ securityjournal.Head, _ *lifecyclePrincipal) error {
		if e := securitystate.EnsureBuiltinRolesTx(c, tx); e != nil {
			return e
		}
		roles, e := securitystate.ListRoleDefinitionsTx(c, tx)
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		items := []RolePermissionView{}
		for _, role := range roles {
			for _, permission := range role.Permissions {
				if seen[permission] {
					continue
				}
				seen[permission] = true
				items = append(items, RolePermissionView{ID: permission, Description: permissionDescription(permission), Dangerous: authz.IsPrivileged([]string{permission}) || permission == "nodes.enroll" || permission == "nodes.revoke"})
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		out = &RolePermissionsView{Items: items}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func permissionDescription(p string) string {
	descriptions := map[string]string{"config.read": "Просмотр конфигурации в разрешённой области.", "config.edit": "Изменение конфигурации в разрешённой области.", "config.approve": "Независимое согласование операций в разрешённой области.", "users.read": "Просмотр пользователей и назначений ролей.", "users.manage": "Управление обычными пользователями.", "users.privileged.manage": "Управление привилегированными пользователями и назначениями в пределах собственных прав.", "nodes.read": "Просмотр узлов в разрешённой области.", "nodes.enroll": "Приём узлов в разрешённой области.", "nodes.revoke": "Отзыв идентичности узлов в разрешённой области."}
	if v := descriptions[p]; v != "" {
		return v
	}
	return "Разрешение " + p + " в пределах назначенной области."
}
func (r *RoleBindingService) Bindings(ctx context.Context, a LifecycleActor, limit int, cursor string) (out *RoleBindingsView, err error) {
	if limit < 1 || limit > 200 || (cursor != "" && !configmodel.ValidID(cursor)) {
		return nil, ErrLifecycleInvalid
	}
	err = r.current(ctx, a, "users.read", false, false, func(c context.Context, tx storage.IdentityTx, _ securityjournal.Head, _ *lifecyclePrincipal) error {
		ids, e := securitystate.Strings(c, tx, `SELECT binding_id FROM role_bindings WHERE binding_id>? ORDER BY binding_id LIMIT ?`, cursor, limit+1)
		if e != nil {
			return e
		}
		out = &RoleBindingsView{Items: []securitystate.RoleBinding{}}
		if len(ids) > limit {
			ids = ids[:limit]
			out.NextCursor = ids[len(ids)-1]
		}
		for _, id := range ids {
			b, e := securitystate.ReadRoleBindingTx(c, tx, id)
			if e != nil {
				return e
			}
			out.Items = append(out.Items, b)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
