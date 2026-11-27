package router_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 修改密码后，此前签发的 Access Token 与 Refresh Token 必须全部失效，新登录签发的令牌可用。
func TestPasswordChangeRevokesExistingSessions(t *testing.T) {
	env := setupTestEnv(t, "")
	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "carol", "email": "carol@openrealm.local", "password": "Carol@123456",
	}, "")
	require.Equal(t, http.StatusCreated, regW.Code, regW.Body.String())
	access, refresh := loginAs(t, env.engine, "carol", "Carol@123456")

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
		"old_password": "Carol@123456", "new_password": "Carol@654321",
	}, access)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	assert.Equal(t, http.StatusUnauthorized, doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, access).Code)
	assert.Equal(t, http.StatusUnauthorized, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{"refresh_token": refresh}, "").Code)

	newAccess, _ := loginAs(t, env.engine, "carol", "Carol@654321")
	assert.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, newAccess).Code)
}

// 管理员重置他人密码后，目标用户的旧会话必须失效。
func TestAdminPasswordResetRevokesTargetSessions(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "dave", "email": "dave@openrealm.local", "password": "Dave@123456",
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	daveAccess, daveRefresh := loginAs(t, env.engine, "dave", "Dave@123456")

	var dave models.User
	require.NoError(t, env.db.Where("username = ?", "dave").First(&dave).Error)
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", dave.ID), map[string]string{
		"new_password": "Reset@123456",
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	assert.Equal(t, http.StatusUnauthorized, doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, daveAccess).Code)
	assert.Equal(t, http.StatusUnauthorized, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{"refresh_token": daveRefresh}, "").Code)
}

// 列表类接口必须按调用者所在域收敛，不能通过 domain 参数读取其他域的数据。
func TestListEndpointsAreScopedToCallerDomain(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{"code": "billing", "name": "Billing"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	roleW := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "billing", "code": "billing_ops", "name": "计费运维",
	}, adminToken)
	require.Equal(t, http.StatusCreated, roleW.Code, roleW.Body.String())
	var role models.Role
	require.NoError(t, env.db.Where("code = ?", "billing_ops").First(&role).Error)
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID), map[string]any{
		"policies": []map[string]string{
			{"resource": "roles", "action": "read"},
			{"resource": "users", "action": "read"},
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "bob", "email": "bob@openrealm.local", "password": "Bob@123456",
		"domain_code": "billing", "role_codes": []string{"billing_ops"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	bobToken, _ := loginAs(t, env.engine, "bob", "Bob@123456")
	hdr := map[string]string{"X-OpenIAM-Domain": "billing"}

	// 即使显式指定 domain=openiam，也只能看到 billing 域的角色
	w = doJSON(t, env.engine, http.MethodGet, "/api/v1/roles?domain=openiam", nil, bobToken, hdr)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"domain_code":"billing"`)
	assert.NotContains(t, w.Body.String(), `"domain_code":"openiam"`)

	// 域列表仅包含自己所属的域
	w = doJSON(t, env.engine, http.MethodGet, "/api/v1/domains", nil, bobToken, hdr)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"code":"billing"`)
	assert.NotContains(t, w.Body.String(), `"code":"openiam"`)

	// 用户列表不得泄露其他域的角色（如 super_admin）
	w = doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, bobToken, hdr)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "super_admin")

	// 域管理员不得在自己无权限的域查询他人权限，但可以查询自己
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "da2", "email": "da2@openrealm.local", "password": "Da2User@123456",
		"domain_code": "openiam", "role_codes": []string{"domain_admin"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	daToken, _ := loginAs(t, env.engine, "da2", "Da2User@123456")
	var adminUser, daUser models.User
	require.NoError(t, env.db.Where("username = ?", "admin").First(&adminUser).Error)
	require.NoError(t, env.db.Where("username = ?", "da2").First(&daUser).Error)

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies/check", map[string]any{
		"user_id": adminUser.ID, "domain": "billing", "resource": "users", "action": "read",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies/check", map[string]any{
		"user_id": daUser.ID, "domain": "billing", "resource": "users", "action": "read",
	}, daToken)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
