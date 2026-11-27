package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	oauthmodels "github.com/go-oauth2/oauth2/v4/models"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// ClientRecord 实现 oauth2.ClientInfo 和 oauth2.ClientPasswordVerifier，
// 使得 go-oauth2 能直接使用 bcrypt 校验 client_secret 并读取多 RedirectURI 列表。
type ClientRecord struct {
	Model models.OAuthClient
}

func (c *ClientRecord) GetID() string {
	return c.Model.ClientID
}

func (c *ClientRecord) GetSecret() string {
	return c.Model.ClientSecretHash
}

func (c *ClientRecord) GetDomain() string {
	if len(c.Model.RedirectURIs) > 0 {
		return c.Model.RedirectURIs[0]
	}
	return ""
}

func (c *ClientRecord) IsPublic() bool {
	return !c.Model.IsConfidential
}

func (c *ClientRecord) GetUserID() string {
	return fmt.Sprintf("%d", c.Model.CreatedBy)
}

func (c *ClientRecord) VerifyPassword(secret string) bool {
	if !c.Model.IsConfidential {
		return true
	}
	return security.VerifyPassword(c.Model.ClientSecretHash, secret)
}

func (c *ClientRecord) AllowsRedirectURI(uri string) bool {
	for _, allowed := range c.Model.RedirectURIs {
		if strings.TrimSpace(allowed) == strings.TrimSpace(uri) {
			return true
		}
	}
	return false
}

func (c *ClientRecord) AllowsGrantType(gt string) bool {
	if len(c.Model.GrantTypes) == 0 {
		return true
	}
	for _, g := range c.Model.GrantTypes {
		if g == gt {
			return true
		}
	}
	return false
}

// MySQLClientStore 从 MySQL oauth_clients 表读取客户端配置。
type MySQLClientStore struct {
	db *gorm.DB
}

func NewMySQLClientStore(db *gorm.DB) *MySQLClientStore {
	return &MySQLClientStore{db: db}
}

func (s *MySQLClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var client models.OAuthClient
	if err := s.db.WithContext(ctx).Where("client_id = ? AND status = ?", id, "active").First(&client).Error; err != nil {
		return nil, fmt.Errorf("oauth client %q not found or inactive: %w", id, err)
	}
	return &ClientRecord{Model: client}, nil
}

// RedisTokenStore 基于 go-redis/v9 实现 oauth2.TokenStore。
type RedisTokenStore struct {
	rdb    *redis.Client
	prefix string
}

func NewRedisTokenStore(rdb *redis.Client, prefix string) *RedisTokenStore {
	if prefix == "" {
		prefix = "openiam:oauth2:"
	}
	return &RedisTokenStore{rdb: rdb, prefix: prefix}
}

func (s *RedisTokenStore) key(kind, val string) string {
	return s.prefix + kind + ":" + val
}

func (s *RedisTokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	payload, err := json.Marshal(info)
	if err != nil {
		return err
	}
	now := time.Now()
	pipe := s.rdb.TxPipeline()

	if code := info.GetCode(); code != "" {
		exp := info.GetCodeExpiresIn()
		if exp <= 0 {
			exp = 10 * time.Minute
		}
		pipe.Set(ctx, s.key("code", code), payload, exp)
	}
	if access := info.GetAccess(); access != "" {
		exp := info.GetAccessExpiresIn()
		if exp <= 0 {
			exp = time.Hour
		}
		if !info.GetAccessCreateAt().IsZero() {
			rem := info.GetAccessCreateAt().Add(exp).Sub(now)
			if rem > 0 {
				exp = rem
			}
		}
		pipe.Set(ctx, s.key("access", access), payload, exp)
	}
	if refresh := info.GetRefresh(); refresh != "" {
		exp := info.GetRefreshExpiresIn()
		if exp <= 0 {
			exp = 30 * 24 * time.Hour
		}
		if !info.GetRefreshCreateAt().IsZero() {
			rem := info.GetRefreshCreateAt().Add(exp).Sub(now)
			if rem > 0 {
				exp = rem
			}
		}
		pipe.Set(ctx, s.key("refresh", refresh), payload, exp)
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisTokenStore) RemoveByCode(ctx context.Context, code string) error {
	return s.rdb.Del(ctx, s.key("code", code)).Err()
}

func (s *RedisTokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return s.rdb.Del(ctx, s.key("access", access)).Err()
}

func (s *RedisTokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return s.rdb.Del(ctx, s.key("refresh", refresh)).Err()
}

func (s *RedisTokenStore) getByKey(ctx context.Context, k string) (oauth2.TokenInfo, error) {
	val, err := s.rdb.Get(ctx, k).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ti oauthmodels.Token
	if err := json.Unmarshal(val, &ti); err != nil {
		return nil, err
	}
	return &ti, nil
}

func (s *RedisTokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return s.getByKey(ctx, s.key("code", code))
}

func (s *RedisTokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return s.getByKey(ctx, s.key("access", access))
}

func (s *RedisTokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return s.getByKey(ctx, s.key("refresh", refresh))
}
