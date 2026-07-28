package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/response"
)

const csrfHeader = "X-CSRF-Token"

func RequireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		sess, ok := SessionFrom(c)
		if !ok {
			response.Error(c, http.StatusUnauthorized, "AUTH_UNAUTHENTICATED", "Authentication is required")
			return
		}

		expected := sess.CSRFToken()
		provided := c.GetHeader(csrfHeader)
		if expected == "" || provided == "" ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			response.Error(c, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing CSRF token")
			return
		}

		c.Next()
	}
}
