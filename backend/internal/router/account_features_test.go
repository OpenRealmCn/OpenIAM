package router_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 密码策略可配置：注册与管理员建号都按当前策略校验，站点信息同步返回策略供前端提示。
func TestPasswordPolicySetting(t *testing.T) {
	env := setupTestEnv(t, "")
	_, _, err := env.settingsSvc.UpdateBatch(map[string]string{
		settings.KeyPasswordMinLength:         "12",
		settings.KeyPasswordRequireComplexity: "true",
	}, 0)
	require.NoError(t, err)

	info := doJSON(t, env.engine, http.MethodGet, "/api/v1/site/info", nil, "")
	require.Equal(t, http.StatusOK, info.Code)
	assert.Contains(t, info.Body.String(), `"password_min_length":12`)
	assert.Contains(t, info.Body.String(), `"password_require_complexity":true`)

	short := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "pp_short", "email": "pp_short@openrealm.local", "password": "Short1Aa",
	}, "")
	require.Equal(t, http.StatusBadRequest, short.Code, short.Body.String())
	assert.Contains(t, short.Body.String(), "至少需要 12 位")

	weak := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "pp_weak", "email": "pp_weak@openrealm.local", "password": "alllowercase1234",
	}, "")
	require.Equal(t, http.StatusBadRequest, weak.Code, weak.Body.String())
	assert.Contains(t, weak.Body.String(), "大写字母")

	ok := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "pp_ok", "email": "pp_ok@openrealm.local", "password": "GoodPassword12",
	}, "")
	require.Equal(t, http.StatusCreated, ok.Code, ok.Body.String())

	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	adminWeak := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]interface{}{
		"username": "pp_admin_weak", "password": "Weak12345",
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, adminWeak.Code, adminWeak.Body.String())

	_, _, err = env.settingsSvc.UpdateBatch(map[string]string{settings.KeyPasswordMinLength: "4"}, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "密码最小长度")
}

// 管理员可以解除登录锁定、重置用户的两步验证；用户本人会收到安全提醒。
func TestAdminUnlockAndResetMFA(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	u := createScopedUser(t, env, adminToken, "lockee", "lockee@openrealm.local", "Lockee@123456", rbac.DefaultDomain, []string{"viewer"})

	var last int
	var body string
	for i := 0; i < 3; i++ {
		w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"username": "lockee", "password": "wrong-password",
		}, "")
		last, body = w.Code, w.Body.String()
	}
	require.Equal(t, http.StatusTooManyRequests, last, body)
	assert.Contains(t, body, "分钟后再试")
	assert.Equal(t, int64(1), countRows(t, env, &models.Notification{}, "user_id = ? AND title = ?", u.ID, "账号已被临时锁定"))

	locked := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "lockee", "password": "Lockee@123456",
	}, "")
	require.Equal(t, http.StatusTooManyRequests, locked.Code, locked.Body.String())

	unlock := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/unlock", u.ID), nil, adminToken)
	require.Equal(t, http.StatusOK, unlock.Code, unlock.Body.String())
	loginAs(t, env.engine, "lockee", "Lockee@123456")

	require.NoError(t, env.db.Create(&models.UserTOTP{UserID: u.ID, Secret: "sealed-test-secret", Enabled: true}).Error)

	noReauth := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-mfa", u.ID), nil, adminToken)
	require.Equal(t, http.StatusForbidden, noReauth.Code, noReauth.Body.String())
	assert.Contains(t, noReauth.Body.String(), "reauth_required")

	require.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/reauth",
		map[string]string{"password": testSeedAdminPassword}, adminToken).Code)
	reset := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-mfa", u.ID), nil, adminToken)
	require.Equal(t, http.StatusOK, reset.Code, reset.Body.String())
	assert.Equal(t, int64(0), countRows(t, env, &models.UserTOTP{}, "user_id = ?", u.ID))
	assert.Equal(t, int64(1), countRows(t, env, &models.Notification{}, "user_id = ? AND title = ?", u.ID, "两步验证已被管理员重置"))

	again := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-mfa", u.ID), nil, adminToken)
	require.Equal(t, http.StatusBadRequest, again.Code, again.Body.String())

	var admin models.User
	require.NoError(t, env.db.Where("username = ?", "admin").First(&admin).Error)
	self := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-mfa", admin.ID), nil, adminToken)
	require.Equal(t, http.StatusBadRequest, self.Code, self.Body.String())
}

// 修改密码后账号本人收到安全提醒。
func TestPasswordChangeSendsSecurityNotice(t *testing.T) {
	env := setupTestEnv(t, "")
	require.Equal(t, http.StatusCreated, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "notice", "email": "notice@openrealm.local", "password": "Notice@12345",
	}, "").Code)
	tok, _ := loginAs(t, env.engine, "notice", "Notice@12345")
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
		"old_password": "Notice@12345", "new_password": "Notice@67890",
	}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var u models.User
	require.NoError(t, env.db.Where("username = ?", "notice").First(&u).Error)
	assert.Equal(t, int64(1), countRows(t, env, &models.Notification{}, "user_id = ? AND title = ?", u.ID, "登录密码已修改"))
}

// super_admin 在平台域的 *,* 策略不能被删除，也不能被角色权限全量替换掉。
func TestSuperAdminWildcardPolicyProtected(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	w := doJSON(t, env.engine, http.MethodDelete, "/api/v1/policies", map[string]string{
		"role": rbac.SuperAdminRole, "domain": rbac.DefaultDomain, "resource": "*", "action": "*",
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	var role models.Role
	require.NoError(t, env.db.Where("domain_code = ? AND code = ?", rbac.DefaultDomain, rbac.SuperAdminRole).First(&role).Error)
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID), map[string]interface{}{
		"policies": []map[string]string{{"resource": "users", "action": "read"}},
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// 策略仍在，超管仍能正常访问控制台
	require.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, adminToken).Code)
}

// 非超管的概览只统计当前域，并且不返回平台级信息。
func TestDashboardScopedForDomainAdmin(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	createDomainAs(t, env, adminToken, "gamma")
	addPolicyAs(t, env, adminToken, "domain_admin", "gamma", "system", "read")
	createScopedUser(t, env, adminToken, "da_gamma", "da_gamma@openrealm.local", "DaGamma@123456", "gamma", []string{"domain_admin"})
	createScopedUser(t, env, adminToken, "u_gamma", "u_gamma@openrealm.local", "UGamma@123456", "gamma", []string{"viewer"})

	daToken, _ := loginAs(t, env.engine, "da_gamma", "DaGamma@123456")
	w := doJSON(t, env.engine, http.MethodGet, "/api/v1/system/dashboard", nil, daToken, map[string]string{"X-OpenIAM-Domain": "gamma"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"scope":"domain"`)
	assert.Contains(t, w.Body.String(), `"users":2`)
	assert.NotContains(t, w.Body.String(), `"domains"`)
	assert.NotContains(t, w.Body.String(), `"version"`)

	w = doJSON(t, env.engine, http.MethodGet, "/api/v1/system/dashboard", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"scope":"platform"`)
}

// 参数绑定失败时返回中文提示，不透出结构体名与校验标签。
func TestBindErrorsAreReadable(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "Field validation")
	assert.Contains(t, w.Body.String(), "请填写")
}
