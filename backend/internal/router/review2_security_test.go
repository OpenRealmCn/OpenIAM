package router_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rotatedAdminPassword = "SeedAdmin@2026#Rotated"

// 漏洞 1：改密后旧刷新令牌仍能换出新令牌。这里把 Redis 里的失效时间点删掉（模拟重启 / 淘汰），
// 只保留库里的「凭据有效起点」，旧刷新令牌依然必须被拒绝——这正是修复前会放行的路径。
func TestRefreshTokenIssuedBeforePasswordChangeIsRejectedWithoutRedisMarker(t *testing.T) {
	env := setupTestEnv(t, "")
	cfg := config.Default()
	adminUsername := cfg.Seed.AdminUsername

	access, oldRefresh := loginAs(t, env.engine, adminUsername, testSeedAdminPassword)

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
		"old_password": testSeedAdminPassword,
		"new_password": rotatedAdminPassword,
	}, access)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var dbUser models.User
	require.NoError(t, env.db.Where("username = ?", adminUsername).First(&dbUser).Error)
	require.NotNil(t, dbUser.TokensValidAfterMs, "改密必须写入凭据有效起点")

	require.NoError(t, env.rdb.Del(context.Background(),
		fmt.Sprintf("%suser_revoked_after:%d", cfg.Redis.KeyPrefix, dbUser.ID)).Err())

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": oldRefresh,
	}, "", map[string]string{"X-Token-Delivery": "body"})
	assert.Equal(t, http.StatusUnauthorized, w.Code, "改密前签发的刷新令牌必须被拒绝: "+w.Body.String())

	// 改密后重新登录拿到的刷新令牌必须仍然可用，否则等于把所有人踢出去。
	_, freshRefresh := loginAs(t, env.engine, adminUsername, rotatedAdminPassword)
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": freshRefresh,
	}, "", map[string]string{"X-Token-Delivery": "body"})
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// 漏洞 3 + 4：RP ID 与允许来源必须来自服务端配置，请求头里的 Origin 不能决定可信来源；
// 注册参数必须要求用户验证（PIN / 生物识别）。
func TestPasskeyRegistrationRequiresWhitelistedOriginAndUserVerification(t *testing.T) {
	env := setupTestEnv(t, "")
	access, _ := loginAs(t, env.engine, config.Default().Seed.AdminUsername, testSeedAdminPassword)

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/passkeys/register/begin", nil, access,
		map[string]string{"Origin": "http://localhost:5173"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"userVerification":"required"`,
		"注册参数必须强制用户验证")

	// 伪造来源：攻击者用自己的域名让用户注册通行密钥，必须被拒绝。
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/passkeys/register/begin", nil, access,
		map[string]string{"Origin": "https://evil.example"})
	assert.Equal(t, http.StatusBadRequest, w.Code, "不在白名单里的来源必须被拒绝: "+w.Body.String())

	// 没有任何 Origin 头也不能放行（旧实现会退化成 Host）。
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/passkeys/register/begin", nil, access)
	assert.Equal(t, http.StatusBadRequest, w.Code, "缺少 Origin 头必须拒绝: "+w.Body.String())
}

// 漏洞 6：验证码是发给旧邮箱的，账号邮箱换绑之后旧链接必须失效，否则前手仍能夺号。
func TestPasswordResetConfirmRejectsCodeIssuedForPreviousEmail(t *testing.T) {
	env := setupTestEnv(t, "")
	cfg := config.Default()

	hash, err := security.HashPassword("OriginalPwd@2026")
	require.NoError(t, err)
	user := models.User{
		Username:     "resetcase",
		Email:        "new@example.com",
		PasswordHash: hash,
		Status:       "active",
	}
	require.NoError(t, env.db.Create(&user).Error)

	store := security.NewStateStore(env.rdb, cfg.Redis.KeyPrefix)
	require.NoError(t, store.SavePasswordResetCode(context.Background(), strings.ToLower(user.Email), security.PasswordResetRecord{
		UserID: user.ID,
		Email:  "old@example.com",
		Code:   "123456",
	}, 10*time.Minute))

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/password-reset/confirm", map[string]string{
		"email":        "new@example.com",
		"code":         "123456",
		"new_password": "AnotherPwd@2026",
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	var after models.User
	require.NoError(t, env.db.First(&after, user.ID).Error)
	assert.Equal(t, hash, after.PasswordHash, "邮箱已换绑时，旧验证码不能改掉密码")
}
