package catalog

import (
	"testing"

	rbacservice "github.com/openrealm/openiam/backend/internal/modules/rbac/service"
)

func roleByCode(t *testing.T, code string) Role {
	t.Helper()
	for _, r := range Roles {
		if r.Code == code {
			return r
		}
	}
	t.Fatalf("role %q not found in catalog", code)
	return Role{}
}

func TestSuperAdminHasWildcard(t *testing.T) {
	superAdmin := roleByCode(t, "super-admin")
	if !rbacservice.ContainsPermission(superAdmin.Permissions, "users:disable") ||
		!rbacservice.ContainsPermission(superAdmin.Permissions, "system:settings") {
		t.Fatal("super-admin wildcard must grant every permission")
	}
}

func TestAdminIsSeparatedFromPrivilegedPermissions(t *testing.T) {
	admin := roleByCode(t, "admin")
	for _, privileged := range PrivilegedPermissions {
		if rbacservice.ContainsPermission(admin.Permissions, privileged) {
			t.Fatalf("admin role must not contain privileged permission %q", privileged)
		}
	}

	for _, operational := range []string{"users:read", "users:create", "users:update", "sessions:revoke", "audit-logs:read"} {
		if !rbacservice.ContainsPermission(admin.Permissions, operational) {
			t.Fatalf("admin role should contain operational permission %q", operational)
		}
	}
}

func TestAllRolePermissionsExistInCatalog(t *testing.T) {
	codes := permissionCodes()
	for _, role := range Roles {
		for _, code := range role.Permissions {
			if code == WildcardPermission {
				continue
			}
			if !codes[code] {
				t.Fatalf("role %q references unknown permission %q", role.Code, code)
			}
		}
	}
}

func TestPrivilegedPermissionsExistInCatalog(t *testing.T) {
	codes := permissionCodes()
	for _, code := range PrivilegedPermissions {
		if !codes[code] {
			t.Fatalf("privileged permission %q missing from catalog", code)
		}
	}
}
