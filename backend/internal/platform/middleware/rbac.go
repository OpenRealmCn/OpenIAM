package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/response"
	"go.uber.org/zap"
)

type PermissionChecker interface {
	HasPermission(ctx context.Context, userID uint64, code string) (bool, error)
}

func RequirePermission(checker PermissionChecker, log *zap.Logger, code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFrom(c)
		if !ok {
			response.Error(c, http.StatusUnauthorized, "AUTH_UNAUTHENTICATED", "Authentication is required")
			return
		}

		allowed, err := checker.HasPermission(c.Request.Context(), userID, code)
		if err != nil {
			if log != nil {
				log.Error("permission check failed",
					zap.Uint64("user_id", userID),
					zap.String("permission", code),
					zap.Error(err),
				)
			}
			response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed")
			return
		}

		if !allowed {
			response.Error(c, http.StatusForbidden, "RBAC_FORBIDDEN", "You do not have permission to perform this action")
			return
		}

		c.Next()
	}
}
