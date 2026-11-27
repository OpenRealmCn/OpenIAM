package router_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 域管理员不得通过角色分配、策略配置或操作超级管理员账号来提权，也不得跨域写入。
func TestDomainAdminCannotEscalatePrivileges(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	createW := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]interface{}{
		"username":    "da_user",
		"email":       "da@openrealm.local",
		"password":    "DaUser@123456",
		"domain_code": "openiam",
		"role_codes":  []string{"domain_admin"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, createW.Code, createW.Body.String())

	var daUser, adminUser models.User
	require.NoError(t, env.db.Where("username = ?", "da_user").First(&daUser).Error)
	require.NoError(t, env.db.Where("username = ?", "admin").First(&adminUser).Error)
	daToken, _ := loginAs(t, env.engine, "da_user", "DaUser@123456")

	// 1. 自我授予 super_admin 必须被拒绝
	w := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", daUser.ID), map[string]interface{}{
		"domain_code": "openiam",
		"role_codes":  []string{"super_admin"},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 2. 为任意角色添加通配符策略必须被拒绝
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
		"role": "viewer", "domain": "openiam", "resource": "*", "action": "*",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 3. 修改 super_admin 角色策略必须被拒绝
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
		"role": "super_admin", "domain": "openiam", "resource": "users", "action": "read",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 4. 重置或禁用超级管理员账号必须被拒绝
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", adminUser.ID), map[string]string{
		"new_password": "Hacked@123456",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", adminUser.ID), map[string]string{
		"status": "disabled",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 5. 域管理员不得修改全局系统设置
	w = doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{"security.allow_public_register": "true"},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 6. 跨域写入：在 billing 域创建角色必须被拒绝（仅拥有 openiam 域权限）
	domW := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{
		"code": "billing", "name": "Billing",
	}, adminToken)
	require.Equal(t, http.StatusCreated, domW.Code, domW.Body.String())
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "billing", "code": "x_role", "name": "X",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 7. 对照：为自己增量分配普通角色仍然允许
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", daUser.ID), map[string]interface{}{
		"domain_code": "openiam",
		"role_codes":  []string{"viewer"},
	}, daToken)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
