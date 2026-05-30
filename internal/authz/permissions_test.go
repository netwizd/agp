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
