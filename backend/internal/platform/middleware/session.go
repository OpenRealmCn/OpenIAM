package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/response"
)

const (
	sessionContextKey = "auth.session"
	userIDContextKey  = "auth.user_id"
)

type Session interface {
	UserID() uint64
	PublicID() string
	CSRFToken() string
}

type SessionStore interface {
	Load(ctx context.Context, sessionID string) (Session, error)
}

func Authenticate(store SessionStore, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie(cookieName)
		if err != nil || sessionID == "" {
			response.Error(c, http.StatusUnauthorized, "AUTH_UNAUTHENTICATED", "Authentication is required")
			return
		}

		sess, err := store.Load(c.Request.Context(), sessionID)
		if err != nil || sess == nil {
			response.Error(c, http.StatusUnauthorized, "AUTH_UNAUTHENTICATED", "Authentication is required")
			return
		}

		c.Set(sessionContextKey, sess)
		c.Set(userIDContextKey, sess.UserID())
		c.Next()
	}
}

func SessionFrom(c *gin.Context) (Session, bool) {
	value, ok := c.Get(sessionContextKey)
	if !ok {
		return nil, false
	}
	sess, ok := value.(Session)
	return sess, ok
}

func UserIDFrom(c *gin.Context) (uint64, bool) {
	value, ok := c.Get(userIDContextKey)
	if !ok {
		return 0, false
	}
	id, ok := value.(uint64)
	return id, ok
}
