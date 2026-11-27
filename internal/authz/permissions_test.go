package authz

import "testing"

func TestHasPermission(t *testing.T) {
	if !HasPermission([]string{PermResourcesManage}, PermResourcesRead) {
		t.Fatal("expected manage permission to imply read permission")
	}
	if HasPermission([]string{PermResourcesRead}, PermResourcesManage) {
		t.Fatal("read permission must not imply manage permission")
	}
}

func TestDelegationCeiling(t *testing.T) {
	if !CanDelegate([]string{PermUsersManage}, []string{PermUsersRead}) {
		t.Fatal("effective manage permission must cover its read permission")
	}
	for _, requested := range [][]string{{PermUsersSuperAdminManage}, {PermGroupsManage}, {PermUsersManage, PermResourcesRead}} {
		if CanDelegate([]string{PermUsersManage}, requested) {
			t.Fatalf("unrelated or combined grants bypassed ceiling: %v", requested)
		}
	}
}

func TestPrivilegedPermissions(t *testing.T) {
	for _, permission := range []string{PermUsersManage, PermUsersSuperAdminManage, PermGroupsManage, PermResourcesManage, PermResourcesDiagnostics, PermSessionsRevoke, PermDownloadsManage, PermPortalSettingsManage} {
		if !IsPrivileged([]string{PermDashboardRead, permission}) {
			t.Fatalf("mutating baseline permission is not protected: %s", permission)
		}
	}
	if IsPrivileged([]string{PermDashboardRead, PermUsersRead, PermResourcesRead, PermAuditRead, PermAuditExport}) {
		t.Fatal("read/export rights should not be treated as mutation privileges")
	}
}

func TestPrivilegeAliasAndNodePermissions(t *testing.T) {
	for _, pair := range [][2]string{{PermUsersSuperAdminManage, PermUsersPrivilegedManage}, {PermUsersPrivilegedManage, PermUsersSuperAdminManage}} {
		if !HasPermission([]string{pair[0]}, pair[1]) || !CanDelegate([]string{pair[0]}, []string{pair[1]}) {
			t.Fatalf("explicit legacy alias failed %v", pair)
		}
	}
	if HasPermission([]string{PermUsersManage}, PermUsersPrivilegedManage) || HasPermission([]string{PermNodesRead}, PermNodesRevoke) {
		t.Fatal("unrelated privilege inferred")
	}
	for _, p := range []string{PermNodesEnroll, PermNodesRevoke, PermUsersPrivilegedManage} {
		if !IsPrivileged([]string{p}) {
			t.Fatalf("mutating permission not privileged %s", p)
		}
	}
	if IsPrivileged([]string{PermNodesRead}) {
		t.Fatal("read-only node grant became privileged")
	}
}

func TestRolloutPermissionsAreExplicitAndPrivileged(t *testing.T) {
	for _, permission := range []string{PermRolloutsCreate, PermRolloutsCancel, PermRolloutsRollback} {
		if !IsPrivileged([]string{permission}) {
			t.Fatalf("execution authority was treated as passive: %s", permission)
		}
		for _, grant := range []string{PermConfigRead, PermConfigEdit, PermConfigApprove, PermNodesEnroll, PermRolloutsCreate, PermRolloutsCancel, PermRolloutsRollback} {
			if HasPermission([]string{grant}, permission) != (grant == permission) {
				t.Fatalf("unrelated permission %s authorized %s", grant, permission)
			}
		}
	}
}
