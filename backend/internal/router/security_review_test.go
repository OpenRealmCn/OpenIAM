package router_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func srRegister(t *testing.T, env *testEnv, username, password string) models.User {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": username, "email": username + "@openrealm.local", "password": password,
	}, "")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var u models.User
	require.NoError(t, env.db.Where("username = ?", username).First(&u).Error)
	return u
}

func srStore(env *testEnv) *security.StateStore {
	return security.NewStateStore(env.rdb, "openiam:")
}

// 公开 OTP 发送接口只允许登录场景，且账号不存在时不得真正发送（避免成为任意地址的验证码发送器）。
func TestPublicOTPSendIsLoginOnlyAndDoesNotRelayToUnknownTargets(t *testing.T) {
	env := setupTestEnv(t, "")

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene": "mfa", "channel": "email", "target": "x@openrealm.local",
	}, "")
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene": "login", "channel": "email", "target": "nobody@openrealm.local",
	}, "")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"sent":true`)
}

// 重置密码验证码连续输错 5 次后必须作废，之后即使提交正确验证码也不能使用。
func TestPasswordResetCodeIsInvalidatedAfterRepeatedFailures(t *testing.T) {
	env := setupTestEnv(t, "")
	u := srRegister(t, env, "resetuser", "Reset@123456")
	require.NoError(t, srStore(env).SavePasswordResetCode(context.Background(), u.Email, security.PasswordResetRecord{
		UserID: u.ID, Email: u.Email, Code: "123456",
	}, 10*time.Minute))

	confirm := func(code string) int {
		return doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/password-reset/confirm", map[string]string{
			"email": u.Email, "code": code, "new_password": "NewReset@123456",
		}, "").Code
	}
	// 前几次是「验证码不正确」的 400；触发来源 IP 限流后会变成 429，两者都属于拒绝。
	for i := 0; i < 5; i++ {
		code := confirm("000000")
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusTooManyRequests}, code)
	}
	assert.NotEqual(t, http.StatusOK, confirm("123456"), "错误次数超限后验证码必须作废")
}

// 已启用 TOTP 的账号不能仅凭邮箱验证码登录；停用 TOTP 后同样流程可以登录。
func TestOTPLoginIsRefusedWhenTOTPIsEnabled(t *testing.T) {
	env := setupTestEnv(t, "")
	u := srRegister(t, env, "otptotp", "Otp@123456789")
	ctx := context.Background()
	store := srStore(env)
	scope := "login:" + strings.ToLower(u.Email)

	row := models.UserTOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP", Enabled: true, RecoveryCodesJSON: "[]"}
	require.NoError(t, env.db.Create(&row).Error)
	require.NoError(t, store.SaveOTP(ctx, scope, security.OTPRecord{Code: "123456", Channel: "email", UserID: u.ID}, 10*time.Minute))
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/login", map[string]string{"target": u.Email, "code": "123456"}, "")
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	require.NoError(t, env.db.Delete(&row).Error)
	require.NoError(t, store.SaveOTP(ctx, scope, security.OTPRecord{Code: "123456", Channel: "email", UserID: u.ID}, 10*time.Minute))
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/login", map[string]string{"target": u.Email, "code": "123456"}, "")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// 同一个 mfa_token 连续输错 5 次后挑战被销毁，之后即使提交正确的动态码也必须失败。
func TestMFAAttemptsAreLimitedPerChallenge(t *testing.T) {
	env := setupTestEnv(t, "")
	u := srRegister(t, env, "mfauser", "Mfa@123456789")
	secret := "JBSWY3DPEHPK3PXP"
	require.NoError(t, env.db.Create(&models.UserTOTP{UserID: u.ID, Secret: secret, Enabled: true, RecoveryCodesJSON: "[]"}).Error)

	login := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "mfauser", "password": "Mfa@123456789"}, "")
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	var resp struct {
		Data struct {
			MFAToken string `json:"mfa_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.MFAToken)

	verify := func(code string) int {
		return doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{
			"mfa_token": resp.Data.MFAToken, "method": "totp", "code": code,
		}, "").Code
	}
	for i := 0; i < 5; i++ {
		assert.NotEqual(t, http.StatusOK, verify("000000"))
	}
	good, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	assert.NotEqual(t, http.StatusOK, verify(good), "挑战被销毁后正确动态码也不应通过")
}

// JIT 临时授权不得针对用户已持有的角色（否则到期回收会误删永久角色），有效期不得超过 30 天。
func TestJITRejectsExistingRoleAndOverlongDuration(t *testing.T) {
	env := setupTestEnv(t, "")
	admin, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	u := srRegister(t, env, "jituser", "Jit@123456789")

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/jit-grants", map[string]any{
		"user_id": u.ID, "domain_code": "openiam", "role_code": "viewer", "ttl_minutes": 60,
	}, admin)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/jit-grants", map[string]any{
		"user_id": u.ID, "domain_code": "openiam", "role_code": "auditor", "ttl_minutes": 60 * 24 * 60,
	}, admin)
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}
