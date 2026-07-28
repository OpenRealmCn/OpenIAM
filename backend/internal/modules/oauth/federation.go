package oauth

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/modules/oauth/feishu"
	"github.com/openrealm/openiam/backend/internal/modules/session"
	"github.com/openrealm/openiam/backend/internal/platform/crypto"
	"github.com/openrealm/openiam/backend/internal/platform/response"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type IdentityProvisioner interface {
	ProvisionFederated(ctx context.Context, email, displayName string) (userID uint64, publicID string, err error)
}

type FederationHandler struct {
	provider    feishu.Provider
	enabled     bool
	rdb         *redis.Client
	prefix      string
	identity    IdentityProvisioner
	sessions    *session.Manager
	frontendURL string
	log         *zap.Logger
}

func NewFederationHandler(
	provider feishu.Provider,
	enabled bool,
	rdb *redis.Client,
	keyPrefix string,
	identity IdentityProvisioner,
	sessions *session.Manager,
	frontendURL string,
	log *zap.Logger,
) *FederationHandler {
	return &FederationHandler{
		provider:    provider,
		enabled:     enabled,
		rdb:         rdb,
		prefix:      keyPrefix,
		identity:    identity,
		sessions:    sessions,
		frontendURL: frontendURL,
		log:         log,
	}
}

func (h *FederationHandler) stateKey(state string) string {
	return h.prefix + ":oauth:state:" + state
}

func (h *FederationHandler) FeishuLogin(c *gin.Context) {
	if !h.enabled {
		response.Error(c, http.StatusServiceUnavailable, "FEISHU_DISABLED", "Feishu login is not configured")
		return
	}

	state := crypto.Token(16)
	if err := h.rdb.Set(c.Request.Context(), h.stateKey(state), "1", 5*time.Minute).Err(); err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to start login")
		return
	}

	c.Redirect(http.StatusFound, h.provider.AuthorizeURL(state))
}

func (h *FederationHandler) FeishuCallback(c *gin.Context) {
	if !h.enabled {
		response.Error(c, http.StatusServiceUnavailable, "FEISHU_DISABLED", "Feishu login is not configured")
		return
	}

	state := c.Query("state")
	code := c.Query("code")
	if state == "" || code == "" {
		h.redirectToLogin(c, "missing_params")
		return
	}

	consumed, err := h.rdb.GetDel(c.Request.Context(), h.stateKey(state)).Result()
	if err != nil || consumed == "" {
		h.redirectToLogin(c, "invalid_state")
		return
	}

	info, err := h.provider.Exchange(c.Request.Context(), code)
	if err != nil {
		h.log.Warn("feishu token exchange failed", zap.Error(err))
		h.redirectToLogin(c, "exchange_failed")
		return
	}
	if info.Email == "" {
		h.redirectToLogin(c, "no_email")
		return
	}

	userID, publicID, err := h.identity.ProvisionFederated(c.Request.Context(), info.Email, info.Name)
	if err != nil {
		h.log.Error("provision federated user failed", zap.String("email", info.Email), zap.Error(err))
		h.redirectToLogin(c, "provision_failed")
		return
	}

	sess, err := h.sessions.Create(c.Request.Context(), userID, publicID)
	if err != nil {
		h.log.Error("create session failed", zap.Error(err))
		h.redirectToLogin(c, "session_failed")
		return
	}

	h.sessions.WriteCookie(c, sess.ID())
	c.Redirect(http.StatusFound, h.frontendURL+"/dashboard")
}

func (h *FederationHandler) redirectToLogin(c *gin.Context, reason string) {
	query := url.Values{}
	query.Set("error", reason)
	c.Redirect(http.StatusFound, h.frontendURL+"/login?"+query.Encode())
}
