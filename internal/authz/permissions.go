package authz

import "strings"

const (
	PermConfigRead               = "config.read"
	PermConfigEdit               = "config.edit"
	PermConfigApprove            = "config.approve"
	PermRolloutsCreate           = "rollouts.create"
	PermRolloutsCancel           = "rollouts.cancel"
	PermRolloutsRollback         = "rollouts.rollback"
	PermDashboardRead            = "dashboard.read"
	PermUsersRead                = "users.read"
	PermUsersManage              = "users.manage"
	PermUsersSuperAdminManage    = "users.superadmin.manage"
	PermUsersPrivilegedManage    = "users.privileged.manage"
	PermNodesRead                = "nodes.read"
	PermNodesEnroll              = "nodes.enroll"
	PermNodesRevoke              = "nodes.revoke"
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
		PermConfigRead, PermConfigEdit, PermConfigApprove,
		PermRolloutsCreate, PermRolloutsCancel, PermRolloutsRollback,
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
		PermNodesRead, PermNodesEnroll, PermNodesRevoke,
	}
}

// CanonicalPermission preserves the legacy persisted privilege identifier while
// allowing TARGET role grants to satisfy the same exact administrative checks.
func CanonicalPermission(permission string) string {
	if permission == PermUsersSuperAdminManage {
		return PermUsersPrivilegedManage
	}
	return permission
}
func HasPermission(permissions []string, required string) bool {
	required = CanonicalPermission(required)
	for _, permission := range permissions {
		permission = CanonicalPermission(permission)
		if permission == required || implies(permission, required) {
			return true
		}
	}
	return false
}

// CanDelegate checks effective permissions, including the legacy manage -> read
// implication. Holding a management permission never grants unrelated rights.
func CanDelegate(permissions, requested []string) bool {
	for _, permission := range requested {
		if !HasPermission(permissions, permission) {
			return false
		}
	}
	return true
}

// IsPrivileged identifies baseline permissions that can change identity, access,
// published content or settings, revoke sessions, or initiate network probes.
func IsPrivileged(permissions []string) bool {
	for _, permission := range permissions {
		permission = CanonicalPermission(permission)
		if strings.HasSuffix(permission, ".manage") || permission == PermSessionsRevoke || permission == PermResourcesDiagnostics || permission == "config.edit" || permission == "config.approve" || permission == PermNodesEnroll || permission == PermNodesRevoke || permission == PermRolloutsCreate || permission == PermRolloutsCancel || permission == PermRolloutsRollback {
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
