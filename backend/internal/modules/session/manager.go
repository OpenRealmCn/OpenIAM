package session

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/crypto"
	"github.com/openrealm/openiam/backend/internal/platform/middleware"
	"github.com/redis/go-redis/v9"
)

var ErrNotFound = errors.New("session not found")

const (
	fieldUserID    = "user_id"
	fieldPublicID  = "public_id"
	fieldCSRF      = "csrf"
	fieldCreatedAt = "created_at"
)

type Manager struct {
	rdb    *redis.Client
	cfg    config.SessionConfig
	prefix string
}

func NewManager(rdb *redis.Client, cfg config.SessionConfig, keyPrefix string) *Manager {
	return &Manager{rdb: rdb, cfg: cfg, prefix: keyPrefix}
}

func (m *Manager) key(sessionID string) string {
	return m.prefix + ":session:" + sessionID
}

func (m *Manager) Create(ctx context.Context, userID uint64, publicID string) (*Data, error) {
	sessionID := crypto.Token(32)
	csrf := crypto.Token(32)
	now := time.Now().UTC()

	pipe := m.rdb.TxPipeline()
	pipe.HSet(ctx, m.key(sessionID), map[string]any{
		fieldUserID:    userID,
		fieldPublicID:  publicID,
		fieldCSRF:      csrf,
		fieldCreatedAt: now.Unix(),
	})
	pipe.Expire(ctx, m.key(sessionID), m.cfg.TTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}

	return NewData(sessionID, userID, publicID, csrf, now), nil
}

func (m *Manager) Load(ctx context.Context, sessionID string) (middleware.Session, error) {
	values, err := m.rdb.HGetAll(ctx, m.key(sessionID)).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrNotFound
	}

	userID, err := strconv.ParseUint(values[fieldUserID], 10, 64)
	if err != nil {
		return nil, ErrNotFound
	}
	createdUnix, _ := strconv.ParseInt(values[fieldCreatedAt], 10, 64)

	return NewData(
		sessionID,
		userID,
		values[fieldPublicID],
		values[fieldCSRF],
		time.Unix(createdUnix, 0).UTC(),
	), nil
}

func (m *Manager) Revoke(ctx context.Context, sessionID string) error {
	return m.rdb.Del(ctx, m.key(sessionID)).Err()
}

func (m *Manager) WriteCookie(c *gin.Context, sessionID string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(m.cfg.CookieName, sessionID, int(m.cfg.TTL.Seconds()), "/", "", m.cfg.CookieSecure, true)
}

func (m *Manager) ClearCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(m.cfg.CookieName, "", -1, "/", "", m.cfg.CookieSecure, true)
}
