package router_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/seed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 复审返工批（阿评 review d4aaf8c）：每条必须改各配一个能复现旧行为的回归。

// 必须改 1：域管理员不能给外域用户授本域角色来自行制造归属，再借归属改其全局账号。
func TestDomainAdminCannotManufactureForeignUserBinding(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	createDomainAs(t, env, adminToken, "alpha")
	createDomainAs(t, env, adminToken, "beta")
	for _, p := range [][2]string{
		{"users", "read"}, {"users", "write"},
		{"roles", "read"}, {"roles", "write"},
	} {
		addPolicyAs(t, env, adminToken, "domain_admin", "beta", p[0], p[1])
	}
	createScopedUser(t, env, adminToken, "da_beta_x", "da_beta_x@openrealm.local", "DaBeta@123456", "beta", []string{"domain_admin"})
	target := createScopedUser(t, env, adminToken, "ua_alpha_x", "ua_alpha_x@openrealm.local", "UaAlpha@123456", "alpha", []string{"viewer"})

	daToken, _ := loginAs(t, env.engine, "da_beta_x", "DaBeta@123456")

	// 在 beta 建一个空角色：这一步本身合法（不造成任何越权）
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "beta",
		"code":        "empty_role",
		"name":        "Empty Role",
	}, daToken, escDomainHeader("beta"))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// 给 alpha 用户授 beta 角色：越界，按「用户不存在」处理
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", target.ID), map[string]interface{}{
		"domain_code": "beta",
		"role_codes":  []string{"empty_role"},
	}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	assert.Empty(t, env.enforcer.GetRolesForUserInDomain(target.ID, "beta"), "绑定不得被写入")

	// 后续按 beta 域改该用户仍然 404：不能「先绑进来，再改别人」
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", target.ID),
		map[string]string{"status": "disabled"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var after models.User
	require.NoError(t, env.db.First(&after, target.ID).Error)
	assert.Equal(t, "active", after.Status)
	assert.Equal(t, "ua_alpha_x@openrealm.local", after.Email)
}

// 必须改 1（补）：共享身份（多域归属）的全局资料与状态只能由平台超管改。
func TestSharedUserGlobalFieldsAreSuperadminOnly(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	createDomainAs(t, env, adminToken, "alpha")
	createDomainAs(t, env, adminToken, "beta")
	for _, p := range [][2]string{
		{"users", "read"}, {"users", "write"},
		{"roles", "read"}, {"roles", "write"},
	} {
		addPolicyAs(t, env, adminToken, "domain_admin", "beta", p[0], p[1])
	}
	createScopedUser(t, env, adminToken, "da_beta_y", "da_beta_y@openrealm.local", "DaBeta@123456", "beta", []string{"domain_admin"})
	shared := createScopedUser(t, env, adminToken, "us_shared_y", "us_shared_y@openrealm.local", "UsShared@123456", "alpha", []string{"viewer"})

	// 超管把这个账号也加入 beta：合法的共享身份
	w := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", shared.ID), map[string]interface{}{
		"domain_code": "beta",
		"role_codes":  []string{"viewer"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	daToken, _ := loginAs(t, env.engine, "da_beta_y", "DaBeta@123456")

	// 改邮箱 -> 403
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", shared.ID),
		map[string]string{"email": "hijacked@openrealm.local"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 停用 -> 403
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", shared.ID),
		map[string]string{"status": "disabled"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	var after models.User
	require.NoError(t, env.db.First(&after, shared.ID).Error)
	assert.Equal(t, "us_shared_y@openrealm.local", after.Email)
	assert.Equal(t, "active", after.Status)

	// 超管仍然可以改
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", shared.ID),
		map[string]string{"display_name": "By Platform"}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// 必须改 2：原口令原样提交 / 换成历史默认口令 / 换弱口令，都不能解除强制改密。
func TestForcedChangeRejectsSameAndLegacyPassword(t *testing.T) {
	const newPassword = "ChangedAdmin@2026#Ok"
	env := newBootstrapEnv(t, testSeedAdminPassword)

	login := loginFull(t, env.engine, "admin", testSeedAdminPassword)
	require.True(t, login.MustChangePassword)

	// 受限会话可以读自己的身份（前端据此进入改密页），但业务接口一律 403。
	meW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, login.AccessToken)
	require.Equal(t, http.StatusOK, meW.Code, meW.Body.String())
	usersW := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, login.AccessToken)
	require.Equal(t, http.StatusForbidden, usersW.Code, usersW.Body.String())

	flag := func() bool {
		var u models.User
		require.NoError(t, env.db.Where("username = ?", "admin").First(&u).Error)
		return u.MustChangePassword
	}

	change := func(oldPwd, newPwd string) *httptest.ResponseRecorder {
		return doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"old_password": oldPwd,
			"new_password": newPwd,
		}, login.AccessToken)
	}

	// 1) 原口令原样提交
	w := change(testSeedAdminPassword, testSeedAdminPassword)
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.True(t, flag(), "失败后强制改密标记必须保持")

	// 2) 换成历史默认口令
	w = change(testSeedAdminPassword, "Admin@123456")
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.True(t, flag())

	// 3) 8 位弱口令（包装层只要求 8 位，强制改密沿用初始口令策略）
	w = change(testSeedAdminPassword, "Abc12345")
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.True(t, flag())

	// 4) 合格新口令：成功、标记清除、旧会话失效
	w = change(testSeedAdminPassword, newPassword)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.False(t, flag())

	oldLogin := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": testSeedAdminPassword,
	}, "", map[string]string{"X-Token-Delivery": "body"})
	assert.Equal(t, http.StatusUnauthorized, oldLogin.Code, oldLogin.Body.String())

	relogin := loginFull(t, env.engine, "admin", newPassword)
	assert.False(t, relogin.MustChangePassword)
	okW := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, relogin.AccessToken)
	assert.Equal(t, http.StatusOK, okW.Code, okW.Body.String())
}

// 必须改 4：旧库残留的平台策略必须在升级时清掉，否则内置角色分配不出去。
func TestSeedPurgesLegacyPlatformPolicies(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	createScopedUser(t, env, adminToken, "da_main", "da_main@openrealm.local", "DaMain@123456", rbac.DefaultDomain, []string{"domain_admin"})
	target := createScopedUser(t, env, adminToken, "um_main", "um_main@openrealm.local", "UmMain@123456", rbac.DefaultDomain, []string{"viewer"})

	// 模拟旧版本 seed 留下的平台级策略
	_, err := env.enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, rbac.ResourceSettings, "read")
	require.NoError(t, err)
	_, err = env.enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, rbac.ResourceDomains, "read")
	require.NoError(t, err)

	// 升级：再跑一次初始化
	cfg := config.Default()
	cfg.Seed.AdminPassword = testSeedAdminPassword
	require.NoError(t, seed.EnsureDefaults(env.db, env.enforcer, cfg.Seed, nil))

	rules, err := env.enforcer.GetPolicies(rbac.DefaultDomain, "domain_admin")
	require.NoError(t, err)
	for _, r := range rules {
		assert.False(t, rbac.IsPlatformPermission(r.Resource, r.Action),
			"内置角色仍残留平台策略: %s %s", r.Resource, r.Action)
	}

	// 域管理员现在能正常把内置 domain_admin 分配给本域用户（升级前会被残留策略卡成 403）
	daToken, _ := loginAs(t, env.engine, "da_main", "DaMain@123456")
	w := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", target.ID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{"domain_admin"},
	}, daToken, escDomainHeader(rbac.DefaultDomain))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, env.enforcer.GetRolesForUserInDomain(target.ID, rbac.DefaultDomain), "domain_admin")
}
