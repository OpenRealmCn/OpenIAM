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
}

type RefreshTokenRecord struct {
	UserID    uint64 `json:"user_id"`
	Username  string `json:"username"`
	SessionID string `json:"session_id,omitempty"`
	IssuedAt  int64  `json:"issued_at"`
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

type PasswordResetRecord struct {
	UserID uint64 `json:"user_id"`
	Email  string `json:"email"`
	Code   string `json:"code"`
}

// SavePasswordResetCode 保存 6 位一次性重置密码验证码。
func (s *StateStore) SavePasswordResetCode(ctx context.Context, email string, rec PasswordResetRecord, ttl time.Duration) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("pwd_reset", email), string(b), ttl).Err()
}

// ConsumePasswordResetCode 校验并原子消费重置密码验证码。
func (s *StateStore) ConsumePasswordResetCode(ctx context.Context, email, code string) (*PasswordResetRecord, error) {
	k := s.key("pwd_reset", email)
	val, err := s.rdb.Get(ctx, k).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec PasswordResetRecord
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, err
	}
	if rec.Code != code {
		fails, fErr := s.IncrFailure(ctx, "pwd_reset", email, 10*time.Minute)
		if fErr != nil || fails >= 5 {
			_ = s.rdb.Del(ctx, k).Err()
			_ = s.ClearFailures(ctx, "pwd_reset", email)
			return nil, errors.New("验证码错误次数过多，请重新获取")
		}
		return nil, errors.New("验证码不正确")
	}
	if n, dErr := s.rdb.Del(ctx, k).Result(); dErr != nil || n == 0 {
		return nil, ErrStateNotFound
	}
	_ = s.ClearFailures(ctx, "pwd_reset", email)
	return &rec, nil
}

// RevokeSession 在 Redis 标记指定会话 ID 已下线。
func (s *StateStore) RevokeSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	if sessionID == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return s.rdb.Set(ctx, s.key("session_revoked", sessionID), "1", ttl).Err()
}

// IsSessionRevoked 判断指定会话是否已被下线；Redis 不可用时 fail-closed 返回 true。
func (s *StateStore) IsSessionRevoked(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	n, err := s.rdb.Exists(ctx, s.key("session_revoked", sessionID)).Result()
	if err != nil {
		return true, err
	}
	return n > 0, nil
}

// IncrFailure 原子累加某个范围（如 mfa_token、mfa_user）的失败次数，首次失败时设置过期时间。
func (s *StateStore) IncrFailure(ctx context.Context, scope, id string, ttl time.Duration) (int64, error) {
	k := s.key("fail", scope, id)
	n, err := s.rdb.Incr(ctx, k).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		_ = s.rdb.Expire(ctx, k, ttl).Err()
	}
	return n, nil
}

// FailureCount 读取某个范围的当前失败次数；不存在时返回 0。
func (s *StateStore) FailureCount(ctx context.Context, scope, id string) (int64, error) {
	n, err := s.rdb.Get(ctx, s.key("fail", scope, id)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return n, err
}

// ClearFailures 清除某个范围的失败计数。
func (s *StateStore) ClearFailures(ctx context.Context, scope, id string) error {
	return s.rdb.Del(ctx, s.key("fail", scope, id)).Err()
}

// SaveMFAChallenge 暂存登录二步验证会话数据。
func (s *StateStore) SaveMFAChallenge(ctx context.Context, token string, rawJSON []byte, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("mfa_challenge", token), string(rawJSON), ttl).Err()
}

// GetMFAChallenge 查询登录二步验证会话（不消费）。
func (s *StateStore) GetMFAChallenge(ctx context.Context, token string) ([]byte, error) {
	val, err := s.rdb.Get(ctx, s.key("mfa_challenge", token)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

// ConsumeMFAChallenge 原子取出并销毁二步验证会话。
func (s *StateStore) ConsumeMFAChallenge(ctx context.Context, token string) ([]byte, error) {
	val, err := s.rdb.GetDel(ctx, s.key("mfa_challenge", token)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

type OTPRecord struct {
	Code     string `json:"code"`
	Channel  string `json:"channel"`
	UserID   uint64 `json:"user_id"`
	Failures int    `json:"failures"`
}

// SaveOTP 存储一次性短信/邮件验证码及接收冷却标记。
func (s *StateStore) SaveOTP(ctx context.Context, scopeKey string, rec OTPRecord, ttl time.Duration) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, s.key("otp_code", scopeKey), string(b), ttl).Err(); err != nil {
		return err
	}
	return s.ClearFailures(ctx, "otp", scopeKey)
}

// VerifyAndConsumeOTP 校验验证码，超过 maxAttempts 错误后立即作废防暴力破解。
func (s *StateStore) VerifyAndConsumeOTP(ctx context.Context, scopeKey, code string, maxAttempts int) (*OTPRecord, error) {
	k := s.key("otp_code", scopeKey)
	val, err := s.rdb.Get(ctx, k).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec OTPRecord
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, err
	}
	if rec.Code != code {
		if maxAttempts <= 0 {
			maxAttempts = 5
		}
		// 使用原子自增计数，避免「先读后写」被并发请求绕过错误次数限制
		fails, fErr := s.IncrFailure(ctx, "otp", scopeKey, 10*time.Minute)
		if fErr != nil || int(fails) >= maxAttempts {
			_ = s.rdb.Del(ctx, k).Err()
			_ = s.ClearFailures(ctx, "otp", scopeKey)
			return nil, errors.New("验证码错误次数过多，请重新获取")
		}
		return nil, errors.New("验证码不正确")
	}
	// 以 DEL 的返回值原子消费验证码，防止同一验证码被并发请求重复使用
	if n, dErr := s.rdb.Del(ctx, k).Result(); dErr != nil || n == 0 {
		return nil, ErrStateNotFound
	}
	_ = s.ClearFailures(ctx, "otp", scopeKey)
	return &rec, nil
}

// CheckAndIncrOTPRate 检查 OTP 目标冷却时间、目标小时上限与来源 IP 小时上限，通过则自增计数。
func (s *StateStore) CheckAndIncrOTPRate(ctx context.Context, target, ip string, cooldownSec, maxPerHourTarget, maxPerHourIP int) error {
	coolKey := s.key("otp_cool", target)
	if ok, ttl, err := func() (bool, time.Duration, error) {
		t, e := s.rdb.TTL(ctx, coolKey).Result()
		if e != nil {
			return false, 0, e
		}
		return t > 0, t, nil
	}(); err == nil && ok {
		return fmt.Errorf("发送过于频繁，请在 %d 秒后重试", int(ttl.Seconds())+1)
	}

	targetHourKey := s.key("otp_hour_target", target)
	if cnt, err := s.rdb.Get(ctx, targetHourKey).Int(); err == nil && maxPerHourTarget > 0 && cnt >= maxPerHourTarget {
		return fmt.Errorf("该接收地址每小时发送次数已达上限（%d 次）", maxPerHourTarget)
	}

	ipHourKey := s.key("otp_hour_ip", ip)
	if ip != "" {
		if cnt, err := s.rdb.Get(ctx, ipHourKey).Int(); err == nil && maxPerHourIP > 0 && cnt >= maxPerHourIP {
			return fmt.Errorf("当前网络请求验证码过于频繁，请稍后再试")
		}
	}

	if cooldownSec > 0 {
		_ = s.rdb.Set(ctx, coolKey, "1", time.Duration(cooldownSec)*time.Second).Err()
	}
	if n, err := s.rdb.Incr(ctx, targetHourKey).Result(); err == nil && n == 1 {
		_ = s.rdb.Expire(ctx, targetHourKey, time.Hour).Err()
	}
	if ip != "" {
		if n, err := s.rdb.Incr(ctx, ipHourKey).Result(); err == nil && n == 1 {
			_ = s.rdb.Expire(ctx, ipHourKey, time.Hour).Err()
		}
	}
	return nil
}

// IncrDailySMSCost 累加今日短信成本（单位：分）并返回累加后总额。
func (s *StateStore) IncrDailySMSCost(ctx context.Context, cents int64) (int64, error) {
	dayKey := s.key("sms_cost", time.Now().Format("2006-01-02"))
	total, err := s.rdb.IncrBy(ctx, dayKey, cents).Result()
	if err != nil {
		return 0, err
	}
	if total == cents {
		_ = s.rdb.Expire(ctx, dayKey, 48*time.Hour).Err()
	}
	return total, nil
}

// GetDailySMSCost 读取今日累计短信折算成本（单位：分）。
func (s *StateStore) GetDailySMSCost(ctx context.Context) int64 {
	dayKey := s.key("sms_cost", time.Now().Format("2006-01-02"))
	v, err := s.rdb.Get(ctx, dayKey).Int64()
	if err != nil {
		return 0
	}
	return v
}

// MarkSMSAlertSentToday 确保当日成本告警只向管理员推送一次，避免刷屏。
func (s *StateStore) MarkSMSAlertSentToday(ctx context.Context) bool {
	k := s.key("sms_alert_sent", time.Now().Format("2006-01-02"))
	ok, err := s.rdb.SetNX(ctx, k, "1", 48*time.Hour).Result()
	return err == nil && ok
}

// SaveCapChallenge 暂存本地 Cap PoW 挑战数据。
func (s *StateStore) SaveCapChallenge(ctx context.Context, token string, rawJSON []byte, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("cap_challenge", token), string(rawJSON), ttl).Err()
}

// ConsumeCapChallenge 原子取出并删除本地 Cap PoW 挑战，防止重放。
func (s *StateStore) ConsumeCapChallenge(ctx context.Context, token string) ([]byte, error) {
	val, err := s.rdb.GetDel(ctx, s.key("cap_challenge", token)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

// SaveCapVerifiedToken 保存本地 Cap PoW 核销通过后的一次性验证令牌。
func (s *StateStore) SaveCapVerifiedToken(ctx context.Context, token string, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("cap_verified", token), "1", ttl).Err()
}

// ConsumeCapVerifiedToken 原子验证并核销本地 Cap 人机验证令牌。
func (s *StateStore) ConsumeCapVerifiedToken(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	_, err := s.rdb.GetDel(ctx, s.key("cap_verified", token)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RecordIPFailure 记录来源 IP 的认证失败次数用于风险评分。
func (s *StateStore) RecordIPFailure(ctx context.Context, ip string, ttl time.Duration) (int64, error) {
	if ip == "" {
		return 0, nil
	}
	k := s.key("ip_fail", ip)
	n, err := s.rdb.Incr(ctx, k).Result()
	if err == nil && n == 1 {
		_ = s.rdb.Expire(ctx, k, ttl).Err()
	}
	return n, err
}

// GetIPFailureCount 获取来源 IP 近期认证失败次数。
func (s *StateStore) GetIPFailureCount(ctx context.Context, ip string) int64 {
	if ip == "" {
		return 0
	}
	n, err := s.rdb.Get(ctx, s.key("ip_fail", ip)).Int64()
	if err != nil {
		return 0
	}
	return n
}
