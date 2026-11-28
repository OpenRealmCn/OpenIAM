package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

// AuthMiddleware 校验 Bearer JWT、检查 Redis 黑名单与用户状态，并将身份注入上下文。
func AuthMiddleware(jwtMgr *security.JWTManager, stateStore *security.StateStore, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "缺少有效的 Bearer 访问令牌",
			})
			return
		}
		tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		claims, err := jwtMgr.ParseAccessToken(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "访问令牌无效或已过期",
			})
			return
		}

		// 第三方 OAuth 应用令牌与无用户身份的令牌不得访问管理 API
		if claims.ClientID != "" || claims.UserID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "该令牌不可用于管理接口",
			})
			return
		}

		if stateStore != nil && claims.ID != "" {
			revoked, err := stateStore.IsAccessTokenRevoked(c.Request.Context(), claims.ID)
			if err != nil || revoked {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "访问令牌已被注销",
				})
				return
			}
		}

		if stateStore != nil {
			issuedMs := claims.IssuedAtMs
			if issuedMs == 0 && claims.IssuedAt != nil {
				issuedMs = claims.IssuedAt.UnixMilli()
			}
			revokedByUser, rErr := stateStore.IsIssuedBeforeRevocation(c.Request.Context(), claims.UserID, issuedMs)
			if rErr != nil || revokedByUser {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "会话已失效，请重新登录",
				})
				return
			}
		}

		if stateStore != nil && claims.SessionID != "" {
			sessRevoked, sErr := stateStore.IsSessionRevoked(c.Request.Context(), claims.SessionID)
			if sErr != nil || sessRevoked {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "当前设备会话已下线，请重新登录",
				})
				return
			}
		}

		if db != nil && claims.UserID > 0 {
			var user models.User
			if err := db.Select("id, username, status, must_change_password").First(&user, claims.UserID).Error; err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "用户不存在",
				})
				return
			}
			if user.Status != "active" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"code":    403,
					"message": "账号已被禁用",
				})
				return
			}
			// 强制改密状态：除修改密码与退出登录外，一律拒绝，避免受限账号拿到可用于业务的令牌。
			if user.MustChangePassword && !allowsPasswordChangeOnly(c.Request.Method, requestPath(c)) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"code":       403,
					"error":      "password_change_required",
					"message":    "当前账号处于强制改密状态，请先修改密码后再访问其他接口",
					"change_url": "/api/v1/auth/change-password",
				})
				return
			}
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("jti", claims.ID)
		c.Set("session_id", claims.SessionID)
		c.Set("claims", claims)
		c.Next()
	}
}

// passwordChangeAllowedRoutes 为强制改密状态下唯一允许访问的接口。
// 键为「方法 路径」。受限会话只能读自己的身份、改密与退出。
// 允许 GET /auth/me 是为了让控制台能识别 must_change_password 并进入改密页；
// 否则前端一刷新就拿不到身份、只能被踢回登录页，首次登录永远走不完初始化。
var passwordChangeAllowedRoutes = map[string]bool{
	"POST /api/v1/auth/change-password": true,
	"POST /api/v1/auth/logout":          true,
	"GET /api/v1/auth/me":               true,
}

// allowsPasswordChangeOnly 判断强制改密账号能否访问该请求。
func allowsPasswordChangeOnly(method, path string) bool {
	return passwordChangeAllowedRoutes[method+" "+path]
}

// requestPath 优先使用 Gin 注册路由的完整路径，避免尾斜杠等写法绕过白名单。
func requestPath(c *gin.Context) string {
	if fp := c.FullPath(); fp != "" {
		return fp
	}
	return c.Request.URL.Path
}
