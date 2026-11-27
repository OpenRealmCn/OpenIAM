package router_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 域隔离第一批（模块 B）：对象归属判定与域生命周期收紧。
// 约定：请求头 X-OpenIAM-Domain 只表示"操作者本次在哪个域办事"，归属一律由服务端数据判定。

func escDomainHeader(domain string) map[string]string {
	return map[string]string{"X-OpenIAM-Domain": domain}
}

func createDomainAs(t *testing.T, env *testEnv, token, code string) models.Domain {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{
		"code": code,
		"name": code,
	}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var dom models.Domain
	require.NoError(t, env.db.Where("code = ?", code).First(&dom).Error)
	return dom
}

func addPolicyAs(t *testing.T, env *testEnv, token, role, domain, resource, action string) {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
		"role":     role,
		"domain":   domain,
		"resource": resource,
		"action":   action,
	}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func createScopedUser(t *testing.T, env *testEnv, token, username, email, password, domain string, roleCodes []string) models.User {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]interface{}{
		"username":    username,
		"email":       email,
		"password":    password,
		"domain_code": domain,
		"role_codes":  roleCodes,
	}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var user models.User
	require.NoError(t, env.db.Where("username = ?", username).First(&user).Error)
	return user
}

func countRows(t *testing.T, env *testEnv, model interface{}, query string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	require.NoError(t, env.db.Model(model).Where(query, args...).Count(&n).Error)
	return n
}

// 验收 1~4：域管理员不得跨域改 / 删 / 重置用户，也不能靠篡改请求头或请求体越权。
func TestDomainAdminCannotTouchUsersOutsideOwnDomain(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	createDomainAs(t, env, adminToken, "alpha")
	createDomainAs(t, env, adminToken, "beta")

	// beta 域管理员的授权（域内策略决定权限，与角色表是否存在同名行无关）
	for _, p := range [][2]string{
		{"users", "read"}, {"users", "write"},
		{"roles", "read"}, {"roles", "write"},
	} {
		addPolicyAs(t, env, adminToken, "domain_admin", "beta", p[0], p[1])
	}

	createScopedUser(t, env, adminToken, "da_beta", "da_beta@openrealm.local", "DaBeta@123456", "beta", []string{"domain_admin"})
	foreign := createScopedUser(t, env, adminToken, "ua_alpha", "ua_alpha@openrealm.local", "UaAlpha@123456", "alpha", []string{"viewer"})
	local := createScopedUser(t, env, adminToken, "ub_beta", "ub_beta@openrealm.local", "UbBeta@123456", "beta", []string{"viewer"})
	shared := createScopedUser(t, env, adminToken, "us_shared", "us_shared@openrealm.local", "UsShared@123456", "beta", []string{"viewer"})

	require.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodPost,
		fmt.Sprintf("/api/v1/users/%d/roles", shared.ID), map[string]interface{}{
			"domain_code": "alpha",
			"role_codes":  []string{"viewer"},
		}, adminToken).Code)

	var adminUser models.User
	require.NoError(t, env.db.Where("username = ?", "admin").First(&adminUser).Error)

	foreignToken, _ := loginAs(t, env.engine, "ua_alpha", "UaAlpha@123456")
	var foreignBefore models.User
	require.NoError(t, env.db.First(&foreignBefore, foreign.ID).Error)

	daToken, _ := loginAs(t, env.engine, "da_beta", "DaBeta@123456")

	// 1) 跨域改：404，与"用户不存在"同响应
	w := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", foreign.ID),
		map[string]string{"display_name": "hijacked"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// 2) 跨域删：删除的是全平台身份，非超管一律 403
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", foreign.ID),
		nil, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 3) 跨域重置密码：404
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", foreign.ID),
		map[string]string{"new_password": "Hijack@123456"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// 4) 攻击链回归：重置失败后拿新密码登录必须失败
	attackLogin := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "ua_alpha",
		"password": "Hijack@123456",
	}, "", map[string]string{"X-Token-Delivery": "body"})
	assert.Equal(t, http.StatusUnauthorized, attackLogin.Code, attackLogin.Body.String())

	// 5) 记录、密码、会话都没变
	loginAs(t, env.engine, "ua_alpha", "UaAlpha@123456")
	meW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, foreignToken)
	assert.Equal(t, http.StatusOK, meW.Code, meW.Body.String())

	var foreignAfter models.User
	require.NoError(t, env.db.First(&foreignAfter, foreign.ID).Error)
	assert.Equal(t, foreignBefore.PasswordHash, foreignAfter.PasswordHash)
	assert.Equal(t, foreignBefore.Email, foreignAfter.Email)
	assert.Equal(t, foreignBefore.DisplayName, foreignAfter.DisplayName)
	assert.Equal(t, foreignBefore.Status, foreignAfter.Status)
	assert.Equal(t, "ua_alpha@openrealm.local", foreignAfter.Email)

	// 6) 本域普通用户：允许改
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", local.ID),
		map[string]string{"display_name": "By Beta DA"}, daToken, escDomainHeader("beta"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var localAfter models.User
	require.NoError(t, env.db.First(&localAfter, local.ID).Error)
	assert.Equal(t, "By Beta DA", localAfter.DisplayName)

	// 7) 本域普通用户：允许重置密码
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", local.ID),
		map[string]string{"new_password": "BetaReset@123"}, daToken, escDomainHeader("beta"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	loginAs(t, env.engine, "ub_beta", "BetaReset@123")

	// 8) 跨域共享账号（beta + alpha）：密码只能由超管重置
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", shared.ID),
		map[string]string{"new_password": "Shared@123456"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 9) 超管目标：改状态与重置密码都拒绝
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", adminUser.ID),
		map[string]string{"status": "disabled"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", adminUser.ID),
		map[string]string{"new_password": "Hijack@123456"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 10) 请求体夹带身份边界字段：一律 400，且不产生任何改动
	for _, body := range []map[string]interface{}{
		{"status": "disabled", "domain_code": "alpha"},
		{"status": "disabled", "role_codes": []string{"domain_admin"}},
		{"status": "disabled", "is_super_admin": true},
		{"status": "disabled", "username": "root"},
	} {
		w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", local.ID), body, daToken, escDomainHeader("beta"))
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	var localFinal models.User
	require.NoError(t, env.db.First(&localFinal, local.ID).Error)
	assert.Equal(t, "active", localFinal.Status)
	assert.Equal(t, "ub_beta", localFinal.Username)

	// 11) 篡改请求头：声明 alpha 无权限 → 403
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", foreign.ID),
		map[string]string{"display_name": "hijacked"}, daToken, escDomainHeader("alpha"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 12) 缺失域头（落到默认域 openiam，域管理员在那里没有权限）→ 403
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", foreign.ID),
		map[string]string{"display_name": "hijacked"}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// 验收 5：域改 / 删为超管专属，域级 domains:write 不足以授权。
func TestDomainMutationsAreSuperAdminOnly(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	createDomainAs(t, env, adminToken, "beta")
	delta := createDomainAs(t, env, adminToken, "delta")

	for _, p := range [][2]string{
		{"users", "read"}, {"users", "write"},
		{"roles", "read"}, {"roles", "write"},
		{"domains", "read"}, {"domains", "write"},
	} {
		addPolicyAs(t, env, adminToken, "domain_admin", "beta", p[0], p[1])
	}
	createScopedUser(t, env, adminToken, "da_beta", "da_beta@openrealm.local", "DaBeta@123456", "beta", []string{"domain_admin"})
	daToken, _ := loginAs(t, env.engine, "da_beta", "DaBeta@123456")

	// 域管理员即便持有 domains:write，也不能改域
	w := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/domains/%d", delta.ID),
		map[string]string{"name": "renamed-by-da"}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var after models.Domain
	require.NoError(t, env.db.First(&after, delta.ID).Error)
	assert.Equal(t, "delta", after.Name)

	// 也不能删域
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", delta.ID),
		nil, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Equal(t, int64(1), countRows(t, env, &models.Domain{}, "code = ?", "delta"))

	// 超管按规则操作 → 成功
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/domains/%d", delta.ID),
		map[string]string{"name": "delta-2"}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var renamed models.Domain
	require.NoError(t, env.db.First(&renamed, delta.ID).Error)
	assert.Equal(t, "delta-2", renamed.Name)

	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", delta.ID), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, int64(0), countRows(t, env, &models.Domain{}, "code = ?", "delta"))

	// 域标识不可通过 body 修改
	epsilon := createDomainAs(t, env, adminToken, "epsilon")
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/domains/%d", epsilon.ID),
		map[string]string{"code": "epsilon2"}, adminToken)
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// 验收 6：有依赖的域删除返回 409，不产生部分删除。
func TestDomainDeleteBlocksOnDependencies(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	// 角色依赖
	gamma := createDomainAs(t, env, adminToken, "gamma")
	roleW := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "gamma", "code": "gamma_ops", "name": "Gamma Ops",
	}, adminToken)
	require.Equal(t, http.StatusCreated, roleW.Code, roleW.Body.String())

	w := doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", gamma.ID), nil, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Equal(t, int64(1), countRows(t, env, &models.Domain{}, "code = ?", "gamma"))
	assert.Equal(t, int64(1), countRows(t, env, &models.Role{}, "domain_code = ?", "gamma"))

	// 角色绑定依赖
	eta := createDomainAs(t, env, adminToken, "eta")
	u := createScopedUser(t, env, adminToken, "u_eta", "u_eta@openrealm.local", "UEta@123456", "openiam", []string{"viewer"})
	assignW := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", u.ID), map[string]interface{}{
		"domain_code": "eta", "role_codes": []string{"phantom"},
	}, adminToken)
	require.Equal(t, http.StatusOK, assignW.Code, assignW.Body.String())

	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", eta.ID), nil, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Equal(t, int64(1), countRows(t, env, &models.Domain{}, "code = ?", "eta"))

	// OAuth 客户端依赖
	zeta := createDomainAs(t, env, adminToken, "zeta")
	cliW := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-clients", map[string]interface{}{
		"name":            "Zeta App",
		"domain_code":     "zeta",
		"redirect_uris":   []string{"https://zeta.example.com/cb"},
		"grant_types":     []string{"authorization_code"},
		"scopes":          []string{"openid"},
		"require_pkce":    true,
		"is_confidential": true,
	}, adminToken)
	require.Equal(t, http.StatusCreated, cliW.Code, cliW.Body.String())

	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", zeta.ID), nil, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Equal(t, int64(1), countRows(t, env, &models.Domain{}, "code = ?", "zeta"))
}

// 验收 6+8：可清理的域删除后 Casbin 无残留（存储、运行时、重启后判定一致），重建同名域不继承旧权限。
func TestDomainDeleteCleansCasbinAndDoesNotResurrect(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	ghost := createDomainAs(t, env, adminToken, "ghost")
	addPolicyAs(t, env, adminToken, "phantom", "ghost", "users", "read")

	// 该域只有一条 p 策略，没有角色行 / 绑定 / 客户端 → 允许删除
	w := doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", ghost.ID), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	assert.Equal(t, int64(0), countRows(t, env, &models.Domain{}, "code = ?", "ghost"))
	assert.Equal(t, int64(0), countRows(t, env, &models.Role{}, "domain_code = ?", "ghost"))

	// 重启后判定：用同一份存储重新加载一个 enforcer，仍然没有任何该域策略
	reloaded, err := rbac.NewEnforcer(env.db)
	require.NoError(t, err)
	rules, rulesErr := reloaded.GetPolicies("ghost", "")
	require.NoError(t, rulesErr)
	assert.Empty(t, rules)

	// 重建同名域，并给用户授上同名角色：旧策略不得复活
	createDomainAs(t, env, adminToken, "ghost")
	u := createScopedUser(t, env, adminToken, "ghost_user", "ghost_user@openrealm.local", "GhostUser@123", "openiam", []string{"viewer"})
	assignW := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", u.ID), map[string]interface{}{
		"domain_code": "ghost", "role_codes": []string{"phantom"}, "replace": true,
	}, adminToken)
	require.Equal(t, http.StatusOK, assignW.Code, assignW.Body.String())

	ghostToken, _ := loginAs(t, env.engine, "ghost_user", "GhostUser@123")
	w = doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, ghostToken, escDomainHeader("ghost"))
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// 验收 7：注入策略清理失败 → 不报成功，域不能被删掉（不存在"域已删、授权仍生效"）。
func TestDomainDeleteFailsClosedWhenPolicyCleanupFails(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	kappa := createDomainAs(t, env, adminToken, "kappa")
	addPolicyAs(t, env, adminToken, "phantom", "kappa", "users", "read")

	// 让 casbin_rule 的删除永远失败，模拟"策略清理失败"
	require.NoError(t, env.db.Exec("CREATE TRIGGER casbin_rule_block_delete BEFORE DELETE ON casbin_rule BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;").Error)

	w := doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", kappa.ID), nil, adminToken)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())

	// 不报成功：域还在，策略也还在（fail-closed，不存在"域已删、授权仍生效"）
	assert.Equal(t, int64(1), countRows(t, env, &models.Domain{}, "code = ?", "kappa"))
	var policies int64
	require.NoError(t, env.db.Raw("SELECT COUNT(*) FROM casbin_rule WHERE ptype = ? AND v1 = ?", "p", "kappa").Row().Scan(&policies))
	assert.Equal(t, int64(1), policies)

	// 解除注入后可正常删除，且无残留
	require.NoError(t, env.db.Exec("DROP TRIGGER casbin_rule_block_delete").Error)
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", kappa.ID), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, env.db.Raw("SELECT COUNT(*) FROM casbin_rule WHERE ptype = ? AND v1 = ?", "p", "kappa").Row().Scan(&policies))
	assert.Equal(t, int64(0), policies)
}

// 验收 6（管理路径）：不能把最后一个可用超管停用、降权或删除；主域 openiam 不可停用/删除。
func TestManagementPathIsProtected(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", "Admin@123456")

	var admin models.User
	require.NoError(t, env.db.Where("username = ?", "admin").First(&admin).Error)

	w := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", admin.ID),
		map[string]string{"status": "disabled"}, adminToken)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	var stillActive models.User
	require.NoError(t, env.db.First(&stillActive, admin.ID).Error)
	assert.Equal(t, "active", stillActive.Status)

	// 替换 openiam 域角色摘掉 super_admin → 409
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", admin.ID), map[string]interface{}{
		"domain_code": "openiam", "role_codes": []string{"viewer"}, "replace": true,
	}, adminToken)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// 撤销 super_admin 角色 → 409
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d/roles/%s?domain=openiam", admin.ID, rbac.SuperAdminRole), nil, adminToken)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// 删除自己仍被拒
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", admin.ID), nil, adminToken)
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// 主域不可停用 / 删除
	var mainDomain models.Domain
	require.NoError(t, env.db.Where("code = ?", rbac.DefaultDomain).First(&mainDomain).Error)
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/domains/%d", mainDomain.ID),
		map[string]string{"status": "disabled"}, adminToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/domains/%d", mainDomain.ID), nil, adminToken)
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// 存在第二个超管后，停用原超管才被允许（放在最后：会吊销当前令牌）
	createScopedUser(t, env, adminToken, "admin2", "admin2@openrealm.local", "Admin2@123456", "openiam", []string{"super_admin"})
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", admin.ID),
		map[string]string{"status": "disabled"}, adminToken)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
