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
	BindUserID   uint64 `json:"bind_user_id,omitempty"`
	// 以下字段只在外呼绑定流程中写入：发起绑定的会话标识（Access Token JTI）、
	// 该会话的签发时刻、以及发起时用户「凭据有效起点」的快照。
	// 回调阶段必须逐项复核，否则攻击者可以先发起绑定，等受害者改密踢人后再完成绑定。
	BindSessionID     string `json:"bind_session_id,omitempty"`
	BindIssuedAtMs    int64  `json:"bind_issued_at_ms,omitempty"`
	BindTokensValidAt int64  `json:"bind_tokens_valid_at,omitempty"`
}

type RefreshTokenRecord struct {
	UserID   uint64 `json:"user_id"`
	Username string `json:"username"`
	IssuedAt int64  `json:"issued_at"`
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

// userRevocationTTL 为「用户令牌失效时间点」在 Redis 中的保留时长，需长于任何刷新令牌的有效期。
const userRevocationTTL = 366 * 24 * time.Hour

// RevokeUserTokens 记录当前时刻为该用户的令牌失效时间点：此前签发的所有 Access Token 与 Refresh Token 都将失效。
func (s *StateStore) RevokeUserTokens(ctx context.Context, userID uint64) error {
	return s.rdb.Set(ctx, s.key("user_revoked_after", fmt.Sprintf("%d", userID)), time.Now().UnixMilli(), userRevocationTTL).Err()
}

// IsIssuedBeforeRevocation 判断（毫秒时间戳表示的）签发时间是否早于或等于该用户的令牌失效时间点。
func (s *StateStore) IsIssuedBeforeRevocation(ctx context.Context, userID uint64, issuedAtMs int64) (bool, error) {
	after, err := s.rdb.Get(ctx, s.key("user_revoked_after", fmt.Sprintf("%d", userID))).Int64()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return issuedAtMs <= after, nil
}

// SaveRefreshToken 保存 Refresh Token 会话记录。
func (s *StateStore) SaveRefreshToken(ctx context.Context, token string, rec RefreshTokenRecord, ttl time.Duration) error {
	rec.IssuedAt = time.Now().UnixMilli()
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

// ConsumeConsentRequest 原子性取出并删除授权同意请求，防止同一请求被重放。
func (s *StateStore) ConsumeConsentRequest(ctx context.Context, id string) (*OAuthConsentRequest, error) {
	val, err := s.rdb.GetDel(ctx, s.key("oauth_consent", id)).Result()
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

// SavePasskeySession 暂存 WebAuthn 注册或登录的 Challenge 会话。
func (s *StateStore) SavePasskeySession(ctx context.Context, sessionID string, rawJSON []byte, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("passkey_session", sessionID), string(rawJSON), ttl).Err()
}

// ConsumePasskeySession 原子取出并删除 WebAuthn Challenge 会话，防止重放。
func (s *StateStore) ConsumePasskeySession(ctx context.Context, sessionID string) ([]byte, error) {
	val, err := s.rdb.GetDel(ctx, s.key("passkey_session", sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

// PasswordResetRecord 为一次性重置密码验证码记录；Email 为发码时的收件地址，
// 确认阶段必须与账号当前邮箱比对，邮箱换绑后旧验证码随之作废。
type PasswordResetRecord struct {
	UserID uint64 `json:"user_id"`
	Email  string `json:"email"`
	Code   string `json:"code"`
}

var (
	// ErrPasswordResetCodeMismatch 表示验证码不正确（本次校验已计入失败次数）。
	ErrPasswordResetCodeMismatch = errors.New("验证码不正确")
	// ErrPasswordResetTooManyAttempts 表示同一账号连续错误次数达到上限，验证码已被作废。
	ErrPasswordResetTooManyAttempts = errors.New("验证码错误次数过多，验证码已失效，请重新获取")
)

// ConsumePasswordResetCode 原子校验并一次性消费重置密码验证码。
// 这里不用「读 → 比对 → 删除」的原因：GETDEL 是单条原子命令，并发请求里只有一个能取到验证码，
// 另一个必然拿到空值，从根上消除重复使用的窗口；失败次数用 INCR 累计，达到上限立刻作废验证码。
// 任何一个 Redis 写操作失败都会返回错误，绝不吞掉——「删不掉」必须让整个流程失败。
func (s *StateStore) ConsumePasswordResetCode(ctx context.Context, email, code string, maxAttempts int) (*PasswordResetRecord, error) {
	codeKey := s.key("pwd_reset", email, "code")
	attemptKey := s.key("pwd_reset", email, "attempts")
	recordKey := s.key("pwd_reset", email)
	const attemptTTL = 10 * time.Minute

	attempts, err := s.rdb.Incr(ctx, attemptKey).Result()
	if err != nil {
		return nil, fmt.Errorf("统计验证码错误次数失败: %w", err)
	}
	if attempts == 1 {
		if err := s.rdb.PExpire(ctx, attemptKey, attemptTTL).Err(); err != nil {
			return nil, fmt.Errorf("设置验证码计数有效期失败: %w", err)
		}
	}
	if maxAttempts > 0 && attempts > int64(maxAttempts) {
		if err := s.rdb.Del(ctx, codeKey, recordKey, attemptKey).Err(); err != nil {
			return nil, fmt.Errorf("作废验证码失败: %w", err)
		}
		return nil, ErrPasswordResetTooManyAttempts
	}

	stored, err := s.rdb.GetDel(ctx, codeKey).Result()
	if errors.Is(err, redis.Nil) {
		// 验证码已被并发请求消费或已过期。
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("读取验证码失败: %w", err)
	}
	if stored != code {
		if maxAttempts > 0 && attempts >= int64(maxAttempts) {
			if err := s.rdb.Del(ctx, codeKey, recordKey, attemptKey).Err(); err != nil {
				return nil, fmt.Errorf("作废验证码失败: %w", err)
			}
			return nil, ErrPasswordResetTooManyAttempts
		}
		return nil, ErrPasswordResetCodeMismatch
	}

	if err := s.rdb.Del(ctx, attemptKey).Err(); err != nil {
		return nil, fmt.Errorf("清理验证码计数失败: %w", err)
	}
	val, err := s.rdb.Get(ctx, recordKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("读取验证码记录失败: %w", err)
	}
	var rec PasswordResetRecord
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, err
	}
	// 记录本身也立即删除：即使验证码键已被消费，也不能留下可复用的记录。
	if err := s.rdb.Del(ctx, recordKey).Err(); err != nil {
		return nil, fmt.Errorf("清理验证码记录失败: %w", err)
	}
	return &rec, nil
}

// SavePasswordResetCode 保存 6 位一次性重置密码验证码，同时重置该账号的失败计数。
func (s *StateStore) SavePasswordResetCode(ctx context.Context, email string, rec PasswordResetRecord, ttl time.Duration) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, s.key("pwd_reset", email), string(b), ttl).Err(); err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, s.key("pwd_reset", email, "code"), rec.Code, ttl).Err(); err != nil {
		return err
	}
	// 新验证码重新计数：不清零会让正常用户的历史错误次数继续累计。
	if err := s.rdb.Del(ctx, s.key("pwd_reset", email, "attempts")).Err(); err != nil {
		return err
	}
	return nil
}
