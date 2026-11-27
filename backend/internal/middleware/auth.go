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

		if stateStore != nil && claims.ID != "" {
			revoked, err := stateStore.IsAccessTokenRevoked(c.Request.Context(), claims.ID)
			if err == nil && revoked {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "访问令牌已被注销",
				})
				return
			}
		}

		if db != nil && claims.UserID > 0 {
			var user models.User
			if err := db.Select("id, username, status").First(&user, claims.UserID).Error; err != nil {
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
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("jti", claims.ID)
		c.Set("claims", claims)
		c.Next()
	}
}
