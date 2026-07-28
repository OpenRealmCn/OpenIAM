package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/modules/identity/service"
	"github.com/openrealm/openiam/backend/internal/modules/session"
	"github.com/openrealm/openiam/backend/internal/platform/middleware"
	"github.com/openrealm/openiam/backend/internal/platform/ratelimit"
	"github.com/openrealm/openiam/backend/internal/platform/response"
)

type PermissionLister interface {
	Permissions(ctx context.Context, userID uint64) ([]string, error)
}

type AuthHandler struct {
	auth       *service.AuthService
	sessions   *session.Manager
	perms      PermissionLister
	limiter    *ratelimit.Limiter
	cookieName string
}

func NewAuthHandler(
	auth *service.AuthService,
	sessions *session.Manager,
	perms PermissionLister,
	limiter *ratelimit.Limiter,
	cookieName string,
) *AuthHandler {
	return &AuthHandler{
		auth:       auth,
		sessions:   sessions,
		perms:      perms,
		limiter:    limiter,
		cookieName: cookieName,
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Login and password are required")
		return
	}

	// Throttle before touching credentials so brute-force attempts are cheap to
	// reject. Account lockout still applies per user; this adds an IP dimension
	// so distributed attempts against many accounts are also bounded.
	if h.limiter != nil {
		ctx := c.Request.Context()
		allowed, err := h.limiter.AllowLogin(ctx, c.ClientIP(), req.Login)
		if err != nil {
			response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to complete login")
			return
		}
		if !allowed {
			response.Error(c, http.StatusTooManyRequests, "RATE_LIMITED", "Too many login attempts, try again later")
			return
		}
	}

	sess, err := h.auth.Login(c.Request.Context(), req.Login, req.Password, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			response.Error(c, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "Invalid username or password")
			return
		}
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to complete login")
		return
	}

	user, err := h.auth.UserByID(c.Request.Context(), sess.UserID())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to load user")
		return
	}

	h.sessions.WriteCookie(c, sess.ID())
	response.Data(c, http.StatusOK, LoginResponse{
		User:      ToUserResponse(user),
		CSRFToken: sess.CSRFToken(),
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	sess, ok := middleware.SessionFrom(c)
	if !ok {
		response.Error(c, http.StatusUnauthorized, "AUTH_UNAUTHENTICATED", "Authentication is required")
		return
	}

	user, err := h.auth.UserByID(c.Request.Context(), sess.UserID())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to load user")
		return
	}

	permissions := []string{}
	if h.perms != nil {
		if codes, err := h.perms.Permissions(c.Request.Context(), sess.UserID()); err == nil {
			permissions = codes
		}
	}

	response.Data(c, http.StatusOK, MeResponse{
		User:        ToUserResponse(user),
		Permissions: permissions,
		CSRFToken:   sess.CSRFToken(),
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID, err := c.Cookie(h.cookieName)
	if err == nil && sessionID != "" {
		_ = h.auth.Logout(c.Request.Context(), sessionID)
	}
	h.sessions.ClearCookie(c)
	response.Data(c, http.StatusOK, gin.H{"revoked": true})
}
