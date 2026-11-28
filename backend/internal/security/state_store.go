package security

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	// BrowserBinding 为发起浏览器所持 Cookie 随机值的摘要，回调时必须匹配，防止登录 CSRF 与绑定劫持。
	BrowserBinding string `json:"browser_binding,omitempty"`
}

// BrowserBindingDigest 计算联合登录浏览器绑定值的摘要。
func BrowserBindingDigest(v string) string {
	return tokenDigest(v)
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
	Nonce               string   `json:"nonce,omitempty"`
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

// ErrTooManyAttempts 表示一次性验证码的校验次数已用尽，验证码已作废。
var ErrTooManyAttempts = errors.New("验证码错误次数过多，请重新获取")

// ErrCodeMismatch 表示一次性验证码不正确。
var ErrCodeMismatch = errors.New("验证码不正确")

// ConsumePasswordResetCode 校验并原子消费重置密码验证码。
// 每次校验先原子占用一次尝试机会再比对，并发请求也无法突破 5 次上限。
func (s *StateStore) ConsumePasswordResetCode(ctx context.Context, email, code string) (*PasswordResetRecord, error) {
	const maxAttempts = 5
	k := s.key("pwd_reset", email)
	val, err := s.rdb.Get(ctx, k).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	attempts, aErr := s.IncrFailure(ctx, "pwd_reset", email, 10*time.Minute)
	if aErr != nil || attempts > maxAttempts {
		_ = s.rdb.Del(ctx, k).Err()
		_ = s.ClearFailures(ctx, "pwd_reset", email)
		return nil, ErrTooManyAttempts
	}
	var rec PasswordResetRecord
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, err
	}
	if !constantTimeEqual(rec.Code, code) {
		if attempts >= maxAttempts {
			_ = s.rdb.Del(ctx, k).Err()
			_ = s.ClearFailures(ctx, "pwd_reset", email)
			return nil, ErrTooManyAttempts
		}
		return nil, ErrCodeMismatch
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
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	// 先原子占用一次尝试机会再比对：并发请求即使同时读到验证码，也只有前 maxAttempts 个能进入比对
	attempts, aErr := s.IncrFailure(ctx, "otp", scopeKey, 10*time.Minute)
	if aErr != nil || int(attempts) > maxAttempts {
		_ = s.rdb.Del(ctx, k).Err()
		_ = s.ClearFailures(ctx, "otp", scopeKey)
		return nil, ErrTooManyAttempts
	}
	var rec OTPRecord
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, err
	}
	if !constantTimeEqual(rec.Code, code) {
		if int(attempts) >= maxAttempts {
			_ = s.rdb.Del(ctx, k).Err()
			_ = s.ClearFailures(ctx, "otp", scopeKey)
			return nil, ErrTooManyAttempts
		}
		return nil, ErrCodeMismatch
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

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// MarkRefreshUsed 记录已被轮换消费的 Refresh Token（仅存摘要）及其所属会话，用于识别令牌重放。
func (s *StateStore) MarkRefreshUsed(ctx context.Context, token, sessionID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	val := sessionID
	if val == "" {
		val = "-"
	}
	return s.rdb.Set(ctx, s.key("refresh_used", tokenDigest(token)), val, ttl).Err()
}

// RefreshReuse 判断给定 Refresh Token 是否属于已轮换消费过的令牌；found=true 表示发生了重放，返回其会话 ID（可能为空）。
func (s *StateStore) RefreshReuse(ctx context.Context, token string) (sessionID string, found bool, err error) {
	val, err := s.rdb.Get(ctx, s.key("refresh_used", tokenDigest(token))).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if val == "-" {
		val = ""
	}
	return val, true, nil
}

func reauthKeyPart(userID uint64, sessionID string) string {
	if sessionID == "" {
		sessionID = "nosid"
	}
	return fmt.Sprintf("%d:%s", userID, sessionID)
}

// MarkReauth 记录用户在当前会话内刚完成过一次身份再确认（输入密码或动态码）。
func (s *StateStore) MarkReauth(ctx context.Context, userID uint64, sessionID string, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("reauth", reauthKeyPart(userID, sessionID)), time.Now().UnixMilli(), ttl).Err()
}

// HasRecentReauth 判断用户在当前会话内是否于有效期内完成过身份再确认；Redis 异常时返回 false。
func (s *StateStore) HasRecentReauth(ctx context.Context, userID uint64, sessionID string) bool {
	n, err := s.rdb.Exists(ctx, s.key("reauth", reauthKeyPart(userID, sessionID))).Result()
	return err == nil && n > 0
}

// ClearReauth 清除身份再确认标记。
func (s *StateStore) ClearReauth(ctx context.Context, userID uint64, sessionID string) {
	_ = s.rdb.Del(ctx, s.key("reauth", reauthKeyPart(userID, sessionID))).Err()
}

// MarkTOTPStepUsed 标记某用户的某个 TOTP 时间步已被使用；返回 false 表示该动态码已用过（重放）。
func (s *StateStore) MarkTOTPStepUsed(ctx context.Context, userID uint64, step int64) (bool, error) {
	return s.rdb.SetNX(ctx, s.key("totp_used", fmt.Sprintf("%d:%d", userID, step)), "1", 3*time.Minute).Result()
}

// AcquireOnce 以 SET NX 抢占一次性处理权，用于防止同一授权码或刷新令牌被并发重复兑换。
func (s *StateStore) AcquireOnce(ctx context.Context, scope, id string, ttl time.Duration) (bool, error) {
	return s.rdb.SetNX(ctx, s.key("once", scope, tokenDigest(id)), "1", ttl).Result()
}

// SaveCodeNonce 记录授权码对应的 OIDC nonce，换取令牌时写入 ID Token，供客户端防重放校验。
func (s *StateStore) SaveCodeNonce(ctx context.Context, code, nonce string, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("oidc_nonce", tokenDigest(code)), nonce, ttl).Err()
}

// ConsumeCodeNonce 取出并删除授权码对应的 nonce；不存在时返回空串。
func (s *StateStore) ConsumeCodeNonce(ctx context.Context, code string) string {
	v, err := s.rdb.GetDel(ctx, s.key("oidc_nonce", tokenDigest(code))).Result()
	if err != nil {
		return ""
	}
	return v
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
