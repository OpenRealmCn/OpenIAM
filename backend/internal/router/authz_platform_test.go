package router_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 本文件覆盖模块 A（授权边界）的验收清单：
// 平台级权限只对超管生效、授予侧有可委派上限、全局设置只给超管。
// 所有断言都打到真实路由，读的是服务端状态（Casbin 策略 / 数据库 / 运行时快照）。

// createUserAs 用调用者 token 建用户（可选带角色），返回用户 ID。
func createUserAs(t *testing.T, env *testEnv, token, username, password, domain string, roleCodes []string) uint64 {
	t.Helper()
	body := map[string]interface{}{
		"username":    username,
		"email":       username + "@openrealm.local",
		"password":    password,
		"domain_code": domain,
	}
	if len(roleCodes) > 0 {
		body["role_codes"] = roleCodes
	}
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", body, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var user models.User
	require.NoError(t, env.db.Where("username = ?", username).First(&user).Error)
	return user.ID
}

// newDomainAdmin 建一个只持有 domain_admin 的域管理员，返回 ID 与访问令牌。
func newDomainAdmin(t *testing.T, env *testEnv, adminToken, username string) (uint64, string) {
	t.Helper()
	id := createUserAs(t, env, adminToken, username, "DaUser@123456", rbac.DefaultDomain, []string{"domain_admin"})
	token, _ := loginAs(t, env.engine, username, "DaUser@123456")
	require.NotEmpty(t, token)
	return id, token
}

// createRoleAs 在指定域建一个空角色并返回其数据库记录。
func createRoleAs(t *testing.T, env *testEnv, token, domain, code string) models.Role {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": domain,
		"code":        code,
		"name":        code,
	}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role models.Role
	require.NoError(t, env.db.Where("domain_code = ? AND code = ?", domain, code).First(&role).Error)
	return role
}

// setRolePermissions 调用角色权限全量替换接口。
func setRolePermissions(t *testing.T, env *testEnv, token string, roleID uint64, policies [][2]string) *httptest.ResponseRecorder {
	t.Helper()
	items := make([]map[string]string, 0, len(policies))
	for _, p := range policies {
		items = append(items, map[string]string{"resource": p[0], "action": p[1]})
	}
	return doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/permissions", roleID), map[string]interface{}{
		"policies": items,
	}, token)
}

// rolePolicies 读取角色当前在域内的 Casbin 策略，返回 "resource:action" 集合。
func rolePolicies(t *testing.T, env *testEnv, domain, code string) map[string]bool {
	t.Helper()
	rules, err := env.enforcer.GetPolicies(domain, code)
	require.NoError(t, err)
	out := make(map[string]bool, len(rules))
	for _, r := range rules {
		out[r.Resource+":"+r.Action] = true
	}
	return out
}

// settingsValues 读出全局设置表的全部键值，用于比对「配置没有被改动」。
func settingsValues(t *testing.T, env *testEnv) map[string]string {
	t.Helper()
	var rows []models.SystemSetting
	require.NoError(t, env.db.Find(&rows).Error)
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.SettingKey] = r.Value
	}
	return out
}

// 验收 1：域管理员新建含 settings:write / domains:write / 全局身份源管理权限的角色 → 403。
func TestDomainAdminCannotGrantPlatformPermissions(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	_, daToken := newDomainAdmin(t, env, adminToken, "p0a_da")

	role := createRoleAs(t, env, daToken, rbac.DefaultDomain, "escalate_role")

	// 角色权限全量写入：平台级资源一律 403
	for _, p := range [][2]string{
		{"settings", "write"},
		{"settings", "read"},
		{"domains", "write"},
		{"oauth_providers", "write"},
	} {
		w := setRolePermissions(t, env, daToken, role.ID, [][2]string{p})
		assert.Equal(t, http.StatusForbidden, w.Code, "resource=%s action=%s body=%s", p[0], p[1], w.Body.String())
	}
	// 一次都没写进去
	require.Empty(t, rolePolicies(t, env, rbac.DefaultDomain, role.Code))

	// 单条策略写入路径同样被拦
	for _, p := range [][2]string{
		{"settings", "write"},
		{"settings", "*"},
		{"*", "*"},
		{"oauth_providers", "write"},
	} {
		w := doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
			"role":     role.Code,
			"domain":   rbac.DefaultDomain,
			"resource": p[0],
			"action":   p[1],
		}, daToken)
		assert.Equal(t, http.StatusForbidden, w.Code, "resource=%s action=%s body=%s", p[0], p[1], w.Body.String())
	}
	require.Empty(t, rolePolicies(t, env, rbac.DefaultDomain, role.Code))

	// 权限点目录也不允许域管理员造平台级入口
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/permissions", map[string]string{
		"domain_code": rbac.DefaultDomain,
		"code":        "settings:tamper",
		"name":        "篡改全局设置",
		"resource":    "settings",
		"action":      "write",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 读取全局设置同样收窄到超管
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodGet, "/api/v1/system/settings", nil, daToken).Code)
}

// 验收 2：先建空角色→授自己→再往里加高权、改已授权角色加高权、引用 B 域角色、授已有高权角色，全部失败。
func TestDomainAdminCannotEscalateThroughRoleWorkflow(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	daID, daToken := newDomainAdmin(t, env, adminToken, "p0a_da2")

	// 先建空角色并授给自己
	selfRole := createRoleAs(t, env, daToken, rbac.DefaultDomain, "self_role")
	w := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", daID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{selfRole.Code},
	}, daToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// 再往里加平台级权限：失败
	w = setRolePermissions(t, env, daToken, selfRole.ID, [][2]string{{"settings", "write"}})
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = setRolePermissions(t, env, daToken, selfRole.ID, [][2]string{{"domains", "write"}})
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Empty(t, rolePolicies(t, env, rbac.DefaultDomain, selfRole.Code))

	// 业务上限内的权限照常可写（不是一刀切全禁）
	w = setRolePermissions(t, env, daToken, selfRole.ID, [][2]string{{"users", "write"}, {"audit_logs", "read"}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// 修改一个已授给自己的角色：合法项 + 平台级项混在一起时整体失败，且策略原地不动
	w = setRolePermissions(t, env, daToken, selfRole.ID, [][2]string{{"users", "read"}, {"settings", "write"}})
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Equal(t, map[string]bool{"users:write": true, "audit_logs:read": true},
		rolePolicies(t, env, rbac.DefaultDomain, selfRole.Code))

	// 引用其它域（billing）的角色
	domW := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{"code": "billing", "name": "Billing"}, adminToken)
	require.Equal(t, http.StatusCreated, domW.Code, domW.Body.String())
	createRoleAs(t, env, adminToken, "billing", "billing_ops")

	// 目标用户先由超管接入默认域：拿到一个基础角色才有域归属，
	// 域归属来自服务端角色绑定，不是请求头或请求体说了算。
	baseRole := createRoleAs(t, env, adminToken, rbac.DefaultDomain, "base_member")
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
		"role":     baseRole.Code,
		"domain":   rbac.DefaultDomain,
		"resource": "users",
		"action":   "read",
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	targetID := createUserAs(t, env, adminToken, "p0a_target", "Target@123456", rbac.DefaultDomain, []string{baseRole.Code})
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", targetID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{"billing_ops"},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 也不能借道 B 域自己去分配
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", targetID), map[string]interface{}{
		"domain_code": "billing",
		"role_codes":  []string{"billing_ops"},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 直接把一个已存在的高权角色授给用户
	highRole := createRoleAs(t, env, adminToken, rbac.DefaultDomain, "legacy_high")
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
		"role":     highRole.Code,
		"domain":   rbac.DefaultDomain,
		"resource": "settings",
		"action":   "write",
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", targetID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{highRole.Code},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 建号时夹带高权角色同样被拦
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]interface{}{
		"username":    "p0a_smuggled",
		"email":       "p0a_smuggled@openrealm.local",
		"password":    "Smuggle@123456",
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{highRole.Code},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 精确断言：被拒的越权分配一条都不能落库，目标用户仍只有接入时的基础角色。
	rolesAfter := env.enforcer.GetRolesForUserInDomain(targetID, rbac.DefaultDomain)
	assert.Equal(t, []string{baseRole.Code}, rolesAfter)
}

// 验收 3：域管理员给本域用户委派允许的业务权限 → 成功。
func TestDomainAdminCanDelegateBusinessPermissions(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	_, daToken := newDomainAdmin(t, env, adminToken, "p0a_da4")

	role := createRoleAs(t, env, daToken, rbac.DefaultDomain, "ops_role")
	w := setRolePermissions(t, env, daToken, role.ID, [][2]string{
		{"users", "read"},
		{"audit_logs", "read"},
		{"oauth_clients", "read"},
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// 成员由超管接入默认域时给一个空角色：只建立域归属，不带任何权限。
	memberRole := createRoleAs(t, env, adminToken, rbac.DefaultDomain, "member_base")
	memberID := createUserAs(t, env, adminToken, "p0a_member", "Member@123456", rbac.DefaultDomain, []string{memberRole.Code})
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", memberID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{role.Code},
	}, daToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	memberToken, _ := loginAs(t, env.engine, "p0a_member", "Member@123456")
	assert.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, memberToken).Code)
	assert.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet, "/api/v1/audit-logs", nil, memberToken).Code)
	assert.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet, "/api/v1/oauth-clients", nil, memberToken).Code)

	// 委派出去的是业务能力，平台能力仍不可达
	patch := map[string]interface{}{"settings": map[string]string{settings.KeySecurityAllowPublicRegister: "true"}}
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", patch, memberToken).Code)
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{"code": "x", "name": "X"}, memberToken).Code)
}

// 委派上限还要求「不超过调用者自身权限」。
func TestDelegationCannotExceedCallerOwnPermissions(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	_, daToken := newDomainAdmin(t, env, adminToken, "p0a_da5")

	role := createRoleAs(t, env, daToken, rbac.DefaultDomain, "ops_role_limit")

	// 收回 domain_admin 的 users:write，模拟「调用者自身没有这条权限」
	removed, err := env.enforcer.RemovePolicy("domain_admin", rbac.DefaultDomain, "users", "write")
	require.NoError(t, err)
	require.True(t, removed)

	w := setRolePermissions(t, env, daToken, role.ID, [][2]string{{"users", "write"}})
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// users:read 仍在，照常可委派
	w = setRolePermissions(t, env, daToken, role.ID, [][2]string{{"users", "read"}})
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// 验收 4：预置历史越权角色后，运行中与重启后都拿不到平台能力；含通配符的历史策略对非超管一律失效。
func TestPresetEscalatedPoliciesStayIneffective(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 直接往 Casbin 塞历史越权策略（等价于升级前遗留的脏数据）
	require.NoError(t, env.db.Create(&models.Role{
		DomainCode: rbac.DefaultDomain, Code: "legacy_escalated", Name: "历史越权角色",
	}).Error)
	for _, p := range [][2]string{
		{"settings", "write"},
		{"domains", "write"},
		{"oauth_providers", "write"},
		{"users", "read"},
	} {
		added, err := env.enforcer.AddPolicy("legacy_escalated", rbac.DefaultDomain, p[0], p[1])
		require.NoError(t, err)
		require.True(t, added)
	}
	legacyID := createUserAs(t, env, adminToken, "p0a_legacy", "Legacy@123456", rbac.DefaultDomain, []string{"legacy_escalated"})
	legacyToken, _ := loginAs(t, env.engine, "p0a_legacy", "Legacy@123456")

	patch := map[string]interface{}{"settings": map[string]string{settings.KeySecurityAllowPublicRegister: "true"}}
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", patch, legacyToken).Code)
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{"code": "legacy", "name": "L"}, legacyToken).Code)
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-providers", map[string]string{}, legacyToken).Code)
	// 同一角色的业务权限不受影响
	assert.Equal(t, http.StatusOK,
		doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, legacyToken).Code)

	// 「重启」：从库里重建 enforcer，结论不变
	restarted, err := rbac.NewEnforcer(env.db)
	require.NoError(t, err)
	allowed, err := restarted.Enforce(legacyID, rbac.DefaultDomain, "settings", "write")
	require.NoError(t, err)
	assert.False(t, allowed)
	allowed, err = restarted.Enforce(legacyID, rbac.DefaultDomain, "domains", "write")
	require.NoError(t, err)
	assert.False(t, allowed)
	allowed, err = restarted.Enforce(legacyID, rbac.DefaultDomain, "users", "read")
	require.NoError(t, err)
	assert.True(t, allowed)

	// 历史通配角色：只由通配策略带来的能力对非超管一律不生效（fail-closed）
	require.NoError(t, env.db.Create(&models.Role{
		DomainCode: rbac.DefaultDomain, Code: "legacy_wildcard", Name: "历史通配角色",
	}).Error)
	added, err := env.enforcer.AddPolicy("legacy_wildcard", rbac.DefaultDomain, "*", "*")
	require.NoError(t, err)
	require.True(t, added)
	wildID := createUserAs(t, env, adminToken, "p0a_wild", "Wildcard@123456", rbac.DefaultDomain, []string{"legacy_wildcard"})
	wildToken, _ := loginAs(t, env.engine, "p0a_wild", "Wildcard@123456")
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, wildToken).Code)
	allowed, err = env.enforcer.Enforce(wildID, rbac.DefaultDomain, "users", "read")
	require.NoError(t, err)
	assert.False(t, allowed)

	// 同一身份的精确业务授权不受影响：再授予 viewer（精确策略），通配策略依然不生效
	w := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", wildID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{"viewer"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, http.StatusOK,
		doJSON(t, env.engine, http.MethodGet, "/api/v1/my/oauth-clients", nil, wildToken).Code)
	assert.Equal(t, http.StatusForbidden,
		doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, wildToken).Code)
}

// 验收 5：普通权限变更造不出超管。
func TestPermissionChangesCannotCreateSuperAdmin(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	daID, daToken := newDomainAdmin(t, env, adminToken, "p0a_da6")

	// 不能建同名超管角色
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": rbac.DefaultDomain,
		"code":        rbac.SuperAdminRole,
		"name":        "伪造超管",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 不能把超管角色授给自己
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", daID), map[string]interface{}{
		"domain_code": rbac.DefaultDomain,
		"role_codes":  []string{rbac.SuperAdminRole},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 不能通过通配策略或给内置角色追加平台策略扩大权限
	for _, p := range [][2]string{{"*", "*"}, {"settings", "write"}, {"domains", "write"}} {
		w = doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
			"role":     "domain_admin",
			"domain":   rbac.DefaultDomain,
			"resource": p[0],
			"action":   p[1],
		}, daToken)
		assert.Equal(t, http.StatusForbidden, w.Code, "resource=%s body=%s", p[0], w.Body.String())
	}

	// 身份层面确认：现在不是、重启后也不是超管
	assert.False(t, env.enforcer.IsSuperAdmin(daID))
	restarted, err := rbac.NewEnforcer(env.db)
	require.NoError(t, err)
	assert.False(t, restarted.IsSuperAdmin(daID))

	meW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, daToken)
	require.Equal(t, http.StatusOK, meW.Code, meW.Body.String())
	var me struct {
		Data struct {
			Policies []rbac.PolicyRule `json:"policies"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(meW.Body.Bytes(), &me))
	for _, p := range me.Data.Policies {
		assert.NotEqual(t, "*", p.Resource, "域管理员不应持有通配策略")
		assert.NotEqual(t, "*", p.Action, "域管理员不应持有通配策略")
	}
}

// 验收 6：DA 即使被预置 settings:write 或伪造 X-OpenIAM-Domain，改全局设置仍 403，
// 且数据库配置与运行中的 CORS / 注册开关 / 限流 / TTL 都没变。
func TestGlobalSettingsOnlyForSuperAdmin(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	_, daToken := newDomainAdmin(t, env, adminToken, "p0a_da7")

	beforeSnapshot := env.settingsSvc.Snapshot()
	beforeValues := settingsValues(t, env)

	patch := map[string]interface{}{"settings": map[string]string{
		settings.KeySecurityAllowPublicRegister: "true",
		settings.KeyServerCORSAllowOrigins:      "https://evil.example",
		settings.KeyRateLimitEnabled:            "false",
		settings.KeyJWTAccessTokenTTLMin:        "9999",
	}}

	// 1) 普通域管理员：403
	w := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", patch, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	// 2) 伪造域头 / 查询参数：仍然 403
	for _, h := range []map[string]string{
		{"X-OpenIAM-Domain": rbac.DefaultDomain},
		{"X-OpenIAM-Domain": "billing"},
	} {
		w = doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", patch, daToken, h)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	}
	w = doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings?domain=billing", patch, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	// 3) 即使 domain_admin 被预置了 settings:write（历史脏数据），仍然 403
	added, err := env.enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, "settings", "write")
	require.NoError(t, err)
	require.True(t, added)
	w = doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", patch, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 4) 数据库与运行时快照都没有变化
	assert.Equal(t, beforeValues, settingsValues(t, env))
	afterSnapshot := env.settingsSvc.Snapshot()
	assert.Equal(t, beforeSnapshot.CORSAllowOrigins, afterSnapshot.CORSAllowOrigins)
	assert.Equal(t, beforeSnapshot.AllowPublicRegister, afterSnapshot.AllowPublicRegister)
	assert.Equal(t, beforeSnapshot.RateLimitEnabled, afterSnapshot.RateLimitEnabled)
	assert.Equal(t, beforeSnapshot.RateLimitGeneralRate, afterSnapshot.RateLimitGeneralRate)
	assert.Equal(t, beforeSnapshot.RateLimitAuthRate, afterSnapshot.RateLimitAuthRate)
	assert.Equal(t, beforeSnapshot.JWTAccessTTL, afterSnapshot.JWTAccessTTL)
	assert.Equal(t, beforeSnapshot.JWTRefreshTTL, afterSnapshot.JWTRefreshTTL)

	// 5) 对照：超管照常能改
	w = doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{settings.KeySecurityAllowPublicRegister: "false"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.False(t, env.settingsSvc.Snapshot().AllowPublicRegister)
}
