package securitystate

import (
	"slices"
	"testing"

	"github.com/netwizd/agp/internal/authz"
)

func TestRolloutRoleScopesDoNotPromoteResourceAuthority(t *testing.T) {
	permissions := map[string]bool{authz.PermRolloutsCreate: false, authz.PermRolloutsCancel: false, authz.PermRolloutsRollback: false}
	for _, role := range BuiltinRoleDefinitions() {
		if _, ok := permissions[role.Name]; !ok {
			continue
		}
		permissions[role.Name] = true
		if !slices.Equal(role.AllowedScopes, []string{"global", "node", "node_group", "site"}) || !slices.Equal(role.Permissions, []string{role.Name}) {
			t.Fatalf("rollout role grants unrelated or resource-wide execution: %+v", role)
		}
	}
	for permission, found := range permissions {
		if !found {
			t.Fatalf("missing explicit rollout role %s", permission)
		}
	}
}
