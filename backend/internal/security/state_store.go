package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrStateNotFound = errors.New("state not found or expired")
)

type OAuthPluginState struct {
	ProviderName string `json:"provider_name"`
	CodeVerifier string `json:"code_verifier"`
	RedirectTo   string `json:"redirect_to,omitempty"`
}

type RefreshTokenRecord struct {
	UserID   uint64 `json:"user_id"`
	Username string `json:"username"`
}

type OAuthConsentRequest struct {
	ID                  string   `json:"id"`
	ClientID            string   `json:"client_id"`
	ClientName          string   `json:"client_name"`
	DomainCode          string   `json:"domain_code"`
	RedirectURI         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	CreatedAt           int64    `json:"created_at"`
}

// StateStore 使用 Redis 管理临时安全状态：
// Refresh Token、JWT 黑名单、登录失败锁定、OAuth 联合登录 state、OAuth2 授权同意请求。
type StateStore struct {
	rdb    *redis.Client
	prefix string
}

func NewStateStore(rdb *redis.Client, prefix string) *StateStore {
	if prefix == "" {
		prefix = "openiam:"
	}
	return &StateStore{rdb: rdb, prefix: prefix}
}

func (s *StateStore) key(parts ...string) string {
	k := s.prefix
	for i, p := range parts {
		if i > 0 {
			k += ":"
		}
		k += p
	}
	return k
}

// SaveRefreshToken 保存 Refresh Token 会话记录。
func (s *StateStore) SaveRefreshToken(ctx context.Context, token string, rec RefreshTokenRecord, ttl time.Duration) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("refresh", token), string(b), ttl).Err()
}

// ConsumeRefreshToken 原子性取出并删除旧 Refresh Token，实现单次轮换防重放。
func (s *StateStore) ConsumeRefreshToken(ctx context.Context, token string) (*RefreshTokenRecord, error) {
	val, err := s.rdb.GetDel(ctx, s.key("refresh", token)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec RefreshTokenRecord
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *StateStore) DeleteRefreshToken(ctx context.Context, token string) error {
	return s.rdb.Del(ctx, s.key("refresh", token)).Err()
}

// RevokeAccessToken 将已注销或吊销的 Access Token JTI 加入黑名单。
func (s *StateStore) RevokeAccessToken(ctx context.Context, jti string, ttl time.Duration) error {
	if jti == "" || ttl <= 0 {
		return nil
	}
	return s.rdb.Set(ctx, s.key("blacklist", jti), "1", ttl).Err()
}

func (s *StateStore) IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	n, err := s.rdb.Exists(ctx, s.key("blacklist", jti)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RecordLoginFailure 增加账号失败次数并在达到阈值时锁定。
func (s *StateStore) RecordLoginFailure(ctx context.Context, username string, maxFailures int, lockoutTTL time.Duration) (count int64, locked bool, err error) {
	k := s.key("login_fail", username)
	count, err = s.rdb.Incr(ctx, k).Result()
	if err != nil {
		return 0, false, err
	}
	if count == 1 {
		_ = s.rdb.Expire(ctx, k, lockoutTTL).Err()
	}
	if maxFailures > 0 && int(count) >= maxFailures {
		_ = s.rdb.Set(ctx, s.key("login_lock", username), "1", lockoutTTL).Err()
		return count, true, nil
	}
	return count, false, nil
}

func (s *StateStore) IsLoginLocked(ctx context.Context, username string) (bool, time.Duration, error) {
	k := s.key("login_lock", username)
	ttl, err := s.rdb.TTL(ctx, k).Result()
	if err != nil {
		return false, 0, err
	}
	if ttl > 0 {
		return true, ttl, nil
	}
	return false, 0, nil
}

func (s *StateStore) ClearLoginFailures(ctx context.Context, username string) error {
	return s.rdb.Del(ctx, s.key("login_fail", username), s.key("login_lock", username)).Err()
}

// SaveOAuthPluginState 暂存外部 OAuth 联合登录 state 与 PKCE verifier。
func (s *StateStore) SaveOAuthPluginState(ctx context.Context, state string, data OAuthPluginState, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("oauth_plugin_state", state), string(b), ttl).Err()
}

func (s *StateStore) ConsumeOAuthPluginState(ctx context.Context, state string) (*OAuthPluginState, error) {
	val, err := s.rdb.GetDel(ctx, s.key("oauth_plugin_state", state)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	var data OAuthPluginState
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// SaveConsentRequest 暂存 OpenIAM OAuth2 授权同意页请求参数。
func (s *StateStore) SaveConsentRequest(ctx context.Context, req OAuthConsentRequest, ttl time.Duration) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("oauth_consent", req.ID), string(b), ttl).Err()
}

func (s *StateStore) GetConsentRequest(ctx context.Context, id string) (*OAuthConsentRequest, error) {
	val, err := s.rdb.Get(ctx, s.key("oauth_consent", id)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	var req OAuthConsentRequest
	if err := json.Unmarshal([]byte(val), &req); err != nil {
		return nil, fmt.Errorf("decode consent request: %w", err)
	}
	return &req, nil
}

func (s *StateStore) DeleteConsentRequest(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, s.key("oauth_consent", id)).Err()
}
