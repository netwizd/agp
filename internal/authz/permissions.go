package authz

import "strings"

const (
	PermDashboardRead            = "dashboard.read"
	PermUsersRead                = "users.read"
	PermUsersManage              = "users.manage"
	PermUsersSuperAdminManage    = "users.superadmin.manage"
	PermGroupsRead               = "groups.read"
	PermGroupsManage             = "groups.manage"
	PermResourcesRead            = "resources.read"
	PermResourcesManage          = "resources.manage"
	PermResourcesDiagnostics     = "resources.diagnostics"
	PermNginxRecommendationsRead = "nginx.recommendations.read"
	PermDownloadsRead            = "downloads.read"
	PermDownloadsManage          = "downloads.manage"
	PermPortalSettingsRead       = "portal.settings.read"
	PermPortalSettingsManage     = "portal.settings.manage"
	PermSessionsRead             = "sessions.read"
	PermSessionsRevoke           = "sessions.revoke"
	PermAuditRead                = "audit.read"
	PermAuditExport              = "audit.export"
)

func AllPermissions() []string {
	return []string{
		PermDashboardRead,
		PermUsersRead,
		PermUsersManage,
		PermUsersSuperAdminManage,
		PermGroupsRead,
		PermGroupsManage,
		PermResourcesRead,
		PermResourcesManage,
		PermResourcesDiagnostics,
		PermNginxRecommendationsRead,
		PermDownloadsRead,
		PermDownloadsManage,
		PermPortalSettingsRead,
		PermPortalSettingsManage,
		PermSessionsRead,
		PermSessionsRevoke,
		PermAuditRead,
		PermAuditExport,
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
