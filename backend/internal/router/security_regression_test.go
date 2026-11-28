package router_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// readRegisterOTP 从 miniredis 读出某个注册目标的验证码。
func readRegisterOTP(t *testing.T, env *testEnv, target string) string {
	t.Helper()
	for _, k := range env.mr.Keys() {
		if strings.Contains(k, "register:"+target) {
			raw, err := env.mr.Get(k)
			require.NoError(t, err)
			var rec struct {
				Code string `json:"code"`
			}
			require.NoError(t, json.Unmarshal([]byte(raw), &rec))
			return rec.Code
		}
	}
	t.Fatalf("register OTP for %s not found", target)
	return ""
}

// either 模式下提交的每个联系方式都必须验证：不能用自己的手机号过验证、顺带写入他人邮箱。
func TestRegisterEitherModeVerifiesEverySubmittedContact(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	var smsInst models.PluginInstance
	require.NoError(t, env.db.Where("name = ?", "console-sms-default").First(&smsInst).Error)
	require.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/plugins/%d", smsInst.ID),
		map[string]any{"enabled": true}, adminToken).Code)
	w := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]any{
		"settings": map[string]string{
			"security.register_email_mode":  "optional",
			"security.register_phone_mode":  "optional",
			"security.register_verify_mode": "either",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	send := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene": "register", "channel": "sms", "target": "+86 138-0099-3344",
	}, "")
	require.Equal(t, http.StatusOK, send.Code, send.Body.String())
	code := readRegisterOTP(t, env, "+8613800993344")

	hijack := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "eitheruser",
		"phone":    "+8613800993344",
		"email":    "victim@openrealm.local",
		"password": "Either@1234",
		"sms_code": code,
	}, "")
	assert.Equal(t, http.StatusBadRequest, hijack.Code, hijack.Body.String())
	assert.Zero(t, countRows(t, env, &models.User{}, "email = ?", "victim@openrealm.local"))

	ok := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "eitheruser",
		"phone":    "+86 138 0099 3344",
		"password": "Either@1234",
		"sms_code": code,
	}, "")
	require.Equal(t, http.StatusCreated, ok.Code, ok.Body.String())
	var u models.User
	require.NoError(t, env.db.Where("username = ?", "eitheruser").First(&u).Error)
	assert.Equal(t, "+8613800993344", u.Phone, "phone must be stored normalized")
	assert.False(t, u.EmailVerified)
}

// 单域管理员不能列出或读取其它域的用户。
func TestDomainAdminUserListAndGetAreDomainScoped(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	createDomainAs(t, env, adminToken, "alpha")
	createDomainAs(t, env, adminToken, "beta")
	for _, p := range [][2]string{{"users", "read"}, {"users", "write"}, {"roles", "read"}, {"roles", "write"}} {
		addPolicyAs(t, env, adminToken, "domain_admin", "beta", p[0], p[1])
	}
	createScopedUser(t, env, adminToken, "list_da", "list_da@openrealm.local", "ListDa@123456", "beta", []string{"domain_admin"})
	foreign := createScopedUser(t, env, adminToken, "list_alpha", "list_alpha@openrealm.local", "ListAlpha@123456", "alpha", []string{"viewer"})
	local := createScopedUser(t, env, adminToken, "list_beta", "list_beta@openrealm.local", "ListBeta@123456", "beta", []string{"viewer"})
	daToken, _ := loginAs(t, env.engine, "list_da", "ListDa@123456")

	w := doJSON(t, env.engine, http.MethodGet, "/api/v1/users?size=100", nil, daToken, escDomainHeader("beta"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, `"username":"list_beta"`)
	assert.NotContains(t, body, `"username":"list_alpha"`)
	assert.NotContains(t, body, `"username":"admin"`)

	assert.Equal(t, http.StatusNotFound, doJSON(t, env.engine, http.MethodGet,
		fmt.Sprintf("/api/v1/users/%d", foreign.ID), nil, daToken, escDomainHeader("beta")).Code)
	assert.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet,
		fmt.Sprintf("/api/v1/users/%d", local.ID), nil, daToken, escDomainHeader("beta")).Code)

	// 在 beta 办事时不能把新用户建到 alpha
	cross := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]any{
		"username":    "cross_user",
		"password":    "CrossUser@123456",
		"domain_code": "alpha",
		"role_codes":  []string{"viewer"},
	}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, cross.Code, cross.Body.String())

	// JIT 同理：目标用户归属与授权域必须一致
	jit := doJSON(t, env.engine, http.MethodPost, "/api/v1/jit-grants", map[string]any{
		"user_id":     local.ID,
		"domain_code": "alpha",
		"role_code":   "viewer",
	}, daToken, escDomainHeader("beta"))
	assert.Equal(t, http.StatusForbidden, jit.Code, jit.Body.String())
}

// 配置数据加密密钥后，TOTP 密钥以密文落库，绑定与登录校验仍然可用。
func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	require.NoError(t, security.SetDataEncryptionKey(base64.StdEncoding.EncodeToString(key)))
	t.Cleanup(func() { _ = security.SetDataEncryptionKey("") })

	env := setupTestEnv(t, "")
	require.Equal(t, http.StatusCreated, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "encuser", "email": "encuser@openrealm.local", "password": "EncUser@1234",
	}, "").Code)
	tok, _ := loginAs(t, env.engine, "encuser", "EncUser@1234")
	require.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/reauth",
		map[string]string{"password": "EncUser@1234"}, tok).Code)

	setup := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/setup", nil, tok)
	require.Equal(t, http.StatusOK, setup.Code, setup.Body.String())
	var setupResp struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(setup.Body.Bytes(), &setupResp))

	var u models.User
	require.NoError(t, env.db.Where("username = ?", "encuser").First(&u).Error)
	var row models.UserTOTP
	require.NoError(t, env.db.Where("user_id = ?", u.ID).First(&row).Error)
	assert.True(t, security.IsSealed(row.Secret))
	assert.NotContains(t, row.Secret, setupResp.Data.Secret)

	code, err := totp.GenerateCode(setupResp.Data.Secret, time.Now())
	require.NoError(t, err)
	bind := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/verify-bind", map[string]string{"code": code}, tok)
	require.Equal(t, http.StatusOK, bind.Code, bind.Body.String())
}

// 全员公告的已读状态按用户独立记录。
func TestAnnouncementReadStateIsPerUser(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	createUserAs(t, env, adminToken, "reader_a", "ReaderA@123456", "default", []string{"viewer"})
	createUserAs(t, env, adminToken, "reader_b", "ReaderB@123456", "default", []string{"viewer"})
	tokA, _ := loginAs(t, env.engine, "reader_a", "ReaderA@123456")
	tokB, _ := loginAs(t, env.engine, "reader_b", "ReaderB@123456")

	created := doJSON(t, env.engine, http.MethodPost, "/api/v1/notifications/announcements", map[string]string{
		"title": "维护通知", "content": "今晚维护",
	}, adminToken)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var resp struct {
		Data models.Notification `json:"data"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &resp))

	unread := func(token string) int64 {
		w := doJSON(t, env.engine, http.MethodGet, "/api/v1/notifications/unread-count", nil, token)
		require.Equal(t, http.StatusOK, w.Code)
		var r struct {
			Data struct {
				ByType map[string]int64 `json:"by_type"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
		return r.Data.ByType["announcement"]
	}
	require.Equal(t, int64(1), unread(tokA))
	require.Equal(t, int64(1), unread(tokB))

	require.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodPost,
		fmt.Sprintf("/api/v1/notifications/%d/read", resp.Data.ID), nil, tokA).Code)
	assert.Equal(t, int64(0), unread(tokA))
	assert.Equal(t, int64(1), unread(tokB), "another user's read must not mark the announcement read for everyone")

	var shared models.Notification
	require.NoError(t, env.db.First(&shared, resp.Data.ID).Error)
	assert.False(t, shared.IsRead)
}
