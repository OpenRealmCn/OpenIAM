package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
)

// isSuperAdmin 判断用户是否拥有平台超级管理员角色。
func isSuperAdmin(enforcer *rbac.Enforcer, userID uint64) bool {
	if userID == 0 {
		return false
	}
	for _, r := range enforcer.GetRolesForUserInDomain(userID, rbac.DefaultDomain) {
		if r == rbac.SuperAdminRole {
			return true
		}
	}
	return false
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
