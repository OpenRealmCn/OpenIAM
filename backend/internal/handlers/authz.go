package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
)

// isSuperAdmin 判断用户是否拥有平台超级管理员身份；实现收敛到 rbac.Enforcer，
// 全平台只有一处推导逻辑（openiam 域下的固定角色常量 rbac.SuperAdminRole）。
func isSuperAdmin(enforcer *rbac.Enforcer, userID uint64) bool {
	return enforcer.IsSuperAdmin(userID)
}

// requireDomainPermission 校验当前用户在「目标域」（而非请求头声明的域）拥有指定权限，防止跨域越权。
func requireDomainPermission(c *gin.Context, enforcer *rbac.Enforcer, domain, resource, action string) bool {
	uid := CurrentUserID(c)
	if uid == 0 {
		Fail(c, http.StatusUnauthorized, "未认证用户")
		return false
	}
	if isSuperAdmin(enforcer, uid) {
		return true
	}
	domain = strings.TrimSpace(domain)
	if domain == "" || domain == "*" {
		Fail(c, http.StatusForbidden, "仅超级管理员可操作全局域")
		return false
	}
	allowed, err := enforcer.Enforce(uid, domain, resource, action)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "权限校验服务异常")
		return false
	}
	if !allowed {
		Fail(c, http.StatusForbidden, "权限不足: 缺少域 ["+domain+"] 下 "+resource+" ("+action+") 权限")
		return false
	}
	return true
}

// rejectSuperAdminGrant 非超级管理员不得授予 super_admin 角色；已拒绝并写出响应时返回 true。
func rejectSuperAdminGrant(c *gin.Context, enforcer *rbac.Enforcer, roleCodes []string) bool {
	if isSuperAdmin(enforcer, CurrentUserID(c)) {
		return false
	}
	for _, rc := range roleCodes {
		if strings.TrimSpace(rc) == rbac.SuperAdminRole {
			Fail(c, http.StatusForbidden, "仅超级管理员可授予超级管理员角色")
			return true
		}
	}
	return false
}

// protectSuperAdminTarget 非超级管理员不得修改、禁用、删除或重置超级管理员账号；已拒绝时返回 true。
func protectSuperAdminTarget(c *gin.Context, enforcer *rbac.Enforcer, targetID uint64) bool {
	if isSuperAdmin(enforcer, CurrentUserID(c)) {
		return false
	}
	if isSuperAdmin(enforcer, targetID) {
		Fail(c, http.StatusForbidden, "无权操作超级管理员账号")
		return true
	}
	return false
}

// validateDelegablePolicies 校验「非超管写入的最终生效权限集合」是否超界。
// 判定按最终生效的 (resource, action) 逐条进行，不看请求里有没有出现通配符：
//  1. 平台级权限（settings/domains/oauth_providers、任何通配形式）直接拒绝；
//  2. 必须落在代码内固定的可委派上限（rbac.IsDelegable）内；
//  3. 调用者自身在目标域必须拥有同一权限，禁止借委派放大自己的权力。
//
// 超管不受限（超管本身就是平台级权限的来源）。
func validateDelegablePolicies(c *gin.Context, enforcer *rbac.Enforcer, domain string, policies []rbac.Permission) bool {
	if enforcer.IsSuperAdmin(CurrentUserID(c)) {
		return true
	}
	domain = strings.TrimSpace(domain)
	if domain == "" || domain == "*" {
		Fail(c, http.StatusForbidden, "仅超级管理员可操作全局域")
		return false
	}
	uid := CurrentUserID(c)
	for _, p := range policies {
		res := strings.TrimSpace(p.Resource)
		act := strings.TrimSpace(p.Action)
		if rbac.IsPlatformPermission(res, act) {
			Fail(c, http.StatusForbidden, "仅超级管理员可授予平台级权限: "+res+" ("+act+")")
			return false
		}
		if !rbac.IsDelegable(res, act) {
			Fail(c, http.StatusForbidden, "该权限不在域管理员可委派上限内: "+res+" ("+act+")")
			return false
		}
		allowed, err := enforcer.Enforce(uid, domain, res, act)
		if err != nil {
			Fail(c, http.StatusInternalServerError, "权限校验服务异常")
			return false
		}
		if !allowed {
			Fail(c, http.StatusForbidden, "不可委派超出自身权限的能力: "+res+" ("+act+")")
			return false
		}
	}
	return true
}

// policiesToPermissions 把 Casbin 策略行转换成 (resource, action) 列表，用于委派上限校验。
func policiesToPermissions(rules []rbac.PolicyRule) []rbac.Permission {
	out := make([]rbac.Permission, 0, len(rules))
	for _, r := range rules {
		out = append(out, rbac.Permission{Resource: r.Resource, Action: r.Action})
	}
	return out
}

// validatePolicyScope 非超级管理员不得配置 super_admin 策略或含通配符的策略，防止自我提权。
func validatePolicyScope(c *gin.Context, enforcer *rbac.Enforcer, role, resource, action string) bool {
	if isSuperAdmin(enforcer, CurrentUserID(c)) {
		return true
	}
	if strings.TrimSpace(role) == rbac.SuperAdminRole ||
		strings.ContainsAny(resource, "*:") ||
		strings.TrimSpace(action) == "*" {
		Fail(c, http.StatusForbidden, "仅超级管理员可配置通配符或超级管理员策略")
		return false
	}
	return true
}

// requirePolicyWriteAccess 校验策略所属域的 permissions:write 权限，并限制策略范围。
func requirePolicyWriteAccess(c *gin.Context, enforcer *rbac.Enforcer, role, domain, resource, action string) bool {
	if !requireDomainPermission(c, enforcer, domain, "permissions", "write") {
		return false
	}
	return validatePolicyScope(c, enforcer, role, resource, action)
}

// scopedDomain 返回列表类接口应使用的域范围：超级管理员可用 domain 参数指定任意域或 "*"（全部）；
// 其他用户固定为已通过权限校验的请求域，忽略 domain 查询参数，防止跨域读取。
func scopedDomain(c *gin.Context, enforcer *rbac.Enforcer) (domain string, all bool) {
	if isSuperAdmin(enforcer, CurrentUserID(c)) {
		q := strings.TrimSpace(c.Query("domain"))
		if q == "" || q == "*" {
			return "", true
		}
		return q, false
	}
	return middleware.ResolveDomain(c), false
}

// visibleRoles 非超级管理员只能看到请求域内的角色映射，避免泄露其他域的授权信息。
func visibleRoles(c *gin.Context, enforcer *rbac.Enforcer, roles map[string][]string) map[string][]string {
	if isSuperAdmin(enforcer, CurrentUserID(c)) {
		return roles
	}
	dom := middleware.ResolveDomain(c)
	out := map[string][]string{}
	if v, ok := roles[dom]; ok {
		out[dom] = v
	}
	return out
}

// requireRoleMutation 校验目标角色所属域的 roles:write 权限；内置系统角色仅超级管理员可修改。
func requireRoleMutation(c *gin.Context, enforcer *rbac.Enforcer, role models.Role) bool {
	if !requireDomainPermission(c, enforcer, role.DomainCode, "roles", "write") {
		return false
	}
	if role.IsSystem && !isSuperAdmin(enforcer, CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅超级管理员可修改内置系统角色")
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// 对象归属判定（安全修复第一批 · 模块 B）
//
// 约定：
//   * 归属一律以服务端数据为准（Casbin 分组策略 user -> role -> domain）；
//   * 请求头 X-OpenIAM-Domain 只用来确定"操作者本次在哪个域办事"，不作为目标对象归属的依据；
//   * 越界目标统一用"用户不存在"（404）回应，与真正不存在的响应完全一致，避免跨域探测。
// ---------------------------------------------------------------------------

// userBindings 返回目标用户在全部域中的角色绑定（服务端权威查询）。
func userBindings(enforcer *rbac.Enforcer, userID uint64) (map[string][]string, error) {
	return enforcer.GetAllUserRoles(userID)
}

// bindingsOutsideDomain 返回目标用户在 domain 之外仍有角色绑定的域名（已排序，便于响应与审计）。
func bindingsOutsideDomain(bindings map[string][]string, domain string) []string {
	out := make([]string, 0, len(bindings))
	for d, roles := range bindings {
		if d == domain || len(roles) == 0 {
			continue
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// denyTargetUserNotFound 以"用户不存在"回应越界用户。
func denyTargetUserNotFound(c *gin.Context) {
	Fail(c, http.StatusNotFound, "用户不存在")
}

// requireTargetUserInDomain 判定目标用户是否落在操作者本次办理的域内。
// 超级管理员不受域归属限制；非超管遇到越界目标时已写出 404 并返回 false。
func requireTargetUserInDomain(c *gin.Context, enforcer *rbac.Enforcer, targetID uint64, domain string) (map[string][]string, bool) {
	bindings, err := userBindings(enforcer, targetID)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "查询用户归属失败")
		return nil, false
	}
	if isSuperAdmin(enforcer, CurrentUserID(c)) {
		return bindings, true
	}
	// 先确认操作者本人在该域确实有角色（请求头只能声明"在哪个域办事"，不能凭空赋予域身份）。
	if len(enforcer.GetRolesForUserInDomain(CurrentUserID(c), domain)) == 0 {
		Fail(c, http.StatusForbidden, "无权在该域操作")
		return bindings, false
	}
	if len(bindings[domain]) == 0 {
		denyTargetUserNotFound(c)
		return bindings, false
	}
	return bindings, true
}

// decodeStrictJSON 严格解析请求体：出现未声明字段（domain_code、role_codes、username、
// is_super_admin 等身份边界字段）直接拒绝，杜绝通过 body 夹带域迁移或提权参数。
func decodeStrictJSON(c *gin.Context, dst interface{}) bool {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if err == io.EOF {
			Fail(c, http.StatusBadRequest, "请求体不能为空")
			return false
		}
		Fail(c, http.StatusBadRequest, "参数错误: 请求包含不允许提交的字段")
		return false
	}
	return true
}
