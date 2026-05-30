package authz

import "strings"

const (
	PermDashboardRead            = "dashboard.read"
	PermUsersRead                = "users.read"
	PermUsersManage              = "users.manage"
	PermGroupsRead               = "groups.read"
	PermGroupsManage             = "groups.manage"
	PermResourcesRead            = "resources.read"
	PermResourcesManage          = "resources.manage"
	PermResourcesDiagnostics     = "resources.diagnostics"
	PermNginxRecommendationsRead = "nginx.recommendations.read"
	PermSessionsRead             = "sessions.read"
	PermSessionsRevoke           = "sessions.revoke"
	PermAuditRead                = "audit.read"
)

func AllPermissions() []string {
	return []string{
		PermDashboardRead,
		PermUsersRead,
		PermUsersManage,
		PermGroupsRead,
		PermGroupsManage,
		PermResourcesRead,
		PermResourcesManage,
		PermResourcesDiagnostics,
		PermNginxRecommendationsRead,
		PermSessionsRead,
		PermSessionsRevoke,
		PermAuditRead,
	}
}

func HasPermission(permissions []string, required string) bool {
	for _, permission := range permissions {
		if permission == required || implies(permission, required) {
			return true
		}
	}
	return false
}

func implies(granted string, required string) bool {
	if !strings.HasSuffix(required, ".read") {
		return false
	}
	prefix := strings.TrimSuffix(required, ".read")
	return granted == prefix+".manage"
}
