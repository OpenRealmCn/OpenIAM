package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/rbac"
)

// ResolveDomain 从 Header `X-OpenIAM-Domain`、Query `domain` 或路由参数提取目标域，默认为 `openiam`。
func ResolveDomain(c *gin.Context) string {
	dom := strings.TrimSpace(c.GetHeader("X-OpenIAM-Domain"))
	if dom == "" {
		dom = strings.TrimSpace(c.Query("domain"))
	}
	if dom == "" {
		dom = strings.TrimSpace(c.Param("domain"))
	}
	if dom == "" {
		dom = rbac.DefaultDomain
	}
	c.Set("domain", dom)
	return dom
}

// RequirePermission 返回基于 Casbin 多域 RBAC 的权限校验中间件。
func RequirePermission(enforcer *rbac.Enforcer, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		uidVal, ok := c.Get("user_id")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "未认证用户",
			})
			return
		}
		userID, ok := uidVal.(uint64)
		if !ok || userID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "无效的用户身份",
			})
			return
		}

		domain := ResolveDomain(c)
		allowed, err := enforcer.Enforce(userID, domain, resource, action)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"code":    500,
				"message": "权限校验服务异常: " + err.Error(),
			})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "权限不足: 缺少域 [" + domain + "] 下 " + resource + " (" + action + ") 权限",
			})
			return
		}
		c.Next()
	}
}
