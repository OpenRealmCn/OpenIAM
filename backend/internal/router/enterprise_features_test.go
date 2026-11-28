package router_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/jit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOTPBindMFALoginAndRecoveryCode(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 注册并登录普通用户 alice
	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "totpalice",
		"email":    "totpalice@openrealm.local",
		"password": "Alice@123456",
	}, "")
	require.Equal(t, http.StatusCreated, regW.Code)
	_ = adminToken
	aliceToken, _ := loginAs(t, env.engine, "totpalice", "Alice@123456")

	// 1. 生成 TOTP 密钥与 otpauth URI（启用验证器前需重新认证）
	noReauth := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/setup", nil, aliceToken)
	require.Equal(t, http.StatusForbidden, noReauth.Code)
	reauthW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/reauth", map[string]string{"password": "Alice@123456"}, aliceToken)
	require.Equal(t, http.StatusOK, reauthW.Code, reauthW.Body.String())
	setupW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/setup", nil, aliceToken)
	require.Equal(t, http.StatusOK, setupW.Code, setupW.Body.String())
	var setupResp struct {
		Data struct {
			Secret     string `json:"secret"`
			OtpAuthURI string `json:"otpauth_uri"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(setupW.Body.Bytes(), &setupResp))
	require.NotEmpty(t, setupResp.Data.Secret)

	// 2. 用合法 TOTP 动态码完成绑定并获取恢复码
	code, err := totp.GenerateCode(setupResp.Data.Secret, time.Now())
	require.NoError(t, err)
	bindW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/verify-bind", map[string]string{
		"code": code,
	}, aliceToken)
	require.Equal(t, http.StatusOK, bindW.Code, bindW.Body.String())
	var bindResp struct {
		Data struct {
			Enabled       bool     `json:"enabled"`
			RecoveryCodes []string `json:"recovery_codes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(bindW.Body.Bytes(), &bindResp))
	require.True(t, bindResp.Data.Enabled)
	require.Len(t, bindResp.Data.RecoveryCodes, 10)

	// 3. 登录必须触发 MFA 挑战
	loginW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "totpalice",
		"password": "Alice@123456",
	}, "")
	require.Equal(t, http.StatusOK, loginW.Code)
	var mfaResp struct {
		Data struct {
			MFARequired bool     `json:"mfa_required"`
			MFAToken    string   `json:"mfa_token"`
			Methods     []string `json:"methods"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginW.Body.Bytes(), &mfaResp))
	require.True(t, mfaResp.Data.MFARequired)
	require.NotEmpty(t, mfaResp.Data.MFAToken)
	assert.ElementsMatch(t, []string{"totp", "recovery_code"}, mfaResp.Data.Methods, "启用 TOTP 的账号不得提供邮件/短信替代方式")

	// 已启用 TOTP 时不能改用邮件验证码完成二步验证
	emailW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{
		"mfa_token": mfaResp.Data.MFAToken,
		"method":    "email_otp",
		"code":      "123456",
	}, "")
	assert.Equal(t, http.StatusBadRequest, emailW.Code)

	// 绑定时用过的动态码不能在同一时间窗内再次使用
	replayW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{
		"mfa_token": mfaResp.Data.MFAToken,
		"method":    "totp",
		"code":      code,
	}, "")
	assert.Equal(t, http.StatusUnauthorized, replayW.Code)

	// 4. 使用一次性恢复码通过 MFA，第二次再使用同一个恢复码应失败
	mfaW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{
		"mfa_token": mfaResp.Data.MFAToken,
		"method":    "recovery_code",
		"code":      bindResp.Data.RecoveryCodes[0],
	}, "")
	require.Equal(t, http.StatusOK, mfaW.Code, mfaW.Body.String())
	assert.Contains(t, mfaW.Body.String(), `"access_token"`)

	// 同一 mfa_token 只能换取一次会话
	againW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{
		"mfa_token": mfaResp.Data.MFAToken,
		"method":    "recovery_code",
		"code":      bindResp.Data.RecoveryCodes[1],
	}, "")
	assert.Equal(t, http.StatusBadRequest, againW.Code)

	// 解绑必须同时提供密码与第二因子，仅密码不足以关闭二步验证
	pwOnly := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/unbind", map[string]string{
		"password": "Alice@123456",
	}, aliceToken)
	assert.Equal(t, http.StatusBadRequest, pwOnly.Code)
	usedRecovery := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/unbind", map[string]string{
		"password": "Alice@123456",
		"code":     bindResp.Data.RecoveryCodes[0],
	}, aliceToken)
	assert.Equal(t, http.StatusBadRequest, usedRecovery.Code, "已使用的恢复码不能再次使用")
	unbindW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/totp/unbind", map[string]string{
		"password": "Alice@123456",
		"code":     bindResp.Data.RecoveryCodes[2],
	}, aliceToken)
	require.Equal(t, http.StatusOK, unbindW.Code, unbindW.Body.String())
}

func TestOTPRateLimitCostAlertAndDegradation(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 公开接口只会向已注册且手机号匹配的活跃账号真正发送验证码（未知地址一律返回统一响应），因此先创建带手机号的账号
	regOTP := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "otpsmsuser",
		"email":    "otpsmsuser@openrealm.local",
		"password": "OtpSms@123456",
	}, "")
	require.Equal(t, http.StatusCreated, regOTP.Code, regOTP.Body.String())
	require.NoError(t, env.db.Model(&models.User{}).Where("username = ?", "otpsmsuser").Update("phone", "+8613800001111").Error)

	// 调整 OTP 参数便于测试：冷却 60 秒、每小时最多 2 次、单条短信 60 分、日预算 50 分（立即触发告警）
	updW := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{
			"otp.cooldown_seconds":       "60",
			"otp.max_per_hour_target":    "2",
			"otp.sms_cost_cents":         "60",
			"otp.sms_daily_budget_cents": "50",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, updW.Code)

	// 启用内置 console-sms-default 插件
	var smsInst models.PluginInstance
	require.NoError(t, env.db.Where("name = ?", "console-sms-default").First(&smsInst).Error)
	enW := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/plugins/%d", smsInst.ID), map[string]interface{}{
		"enabled": true,
	}, adminToken)
	require.Equal(t, http.StatusOK, enW.Code)

	// 1. 首次发送短信 OTP 成功并触发管理员成本告警
	send1 := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene":   "login",
		"channel": "sms",
		"target":  "+8613800001111",
	}, "")
	require.Equal(t, http.StatusOK, send1.Code, send1.Body.String())

	// 检查管理员是否收到 system_notice 成本告警
	notifW := doJSON(t, env.engine, http.MethodGet, "/api/v1/notifications?category=system_notice", nil, adminToken)
	require.Equal(t, http.StatusOK, notifW.Code)
	assert.Contains(t, notifW.Body.String(), "短信日预算成本告警")

	// 2. 冷却期内第二次向同一手机号发送被频控拦截
	send2 := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene":   "login",
		"channel": "sms",
		"target":  "+8613800001111",
	}, "")
	assert.Equal(t, http.StatusTooManyRequests, send2.Code)
	assert.Contains(t, send2.Body.String(), "频繁")

	// 未注册的地址同样受冷却约束，响应与已注册地址一致，不能据此枚举手机号
	ghost1 := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene": "login", "channel": "sms", "target": "+8613899998888",
	}, "")
	require.Equal(t, http.StatusOK, ghost1.Code)
	ghost2 := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene": "login", "channel": "sms", "target": "+86 138-9999-8888",
	}, "")
	assert.Equal(t, http.StatusTooManyRequests, ghost2.Code, "手机号归一化后应命中同一频控键")
}

func TestRiskAdaptiveSessionsAndCapLocalPlugin(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 地理位置请求头默认不被采信（可被客户端伪造），此处通过系统设置模拟由前置网关注入并覆盖该头的部署环境
	setGeo := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{
			"risk.trust_geo_header": "true",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, setGeo.Code, setGeo.Body.String())

	listSet := doJSON(t, env.engine, http.MethodGet, "/api/v1/system/settings", nil, adminToken)
	require.Equal(t, http.StatusOK, listSet.Code)
	assert.Contains(t, listSet.Body.String(), "security.allow_private_upstream")
	assert.Contains(t, listSet.Body.String(), "risk.trust_geo_header")

	// 创建测试账号 rick，并先用设备 A 登录
	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "riskuser",
		"email":    "riskuser@openrealm.local",
		"password": "RiskUser@123",
	}, "")
	require.Equal(t, http.StatusCreated, regW.Code)

	loginA := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "riskuser",
		"password": "RiskUser@123",
	}, "", map[string]string{"X-Device-Fingerprint": "dev_A", "X-Geo-Location": "Beijing"})
	require.Equal(t, http.StatusOK, loginA.Code)
	var tokA struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginA.Body.Bytes(), &tokA))

	// 使用异地 + 新设备 B 登录：风险分 30 + 20 = 50 >= 30（medium），应生成风险事件并向用户发系统消息
	loginB := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "riskuser",
		"password": "RiskUser@123",
	}, "", map[string]string{"X-Device-Fingerprint": "dev_B", "X-Geo-Location": "Shanghai"})
	require.Equal(t, http.StatusOK, loginB.Code)

	riskW := doJSON(t, env.engine, http.MethodGet, "/api/v1/risk-events", nil, adminToken)
	require.Equal(t, http.StatusOK, riskW.Code)
	assert.Contains(t, riskW.Body.String(), "Shanghai")

	msgW := doJSON(t, env.engine, http.MethodGet, "/api/v1/notifications?category=system_message", nil, tokA.Data.AccessToken)
	require.Equal(t, http.StatusOK, msgW.Code)
	assert.Contains(t, msgW.Body.String(), "发现一次异常登录")

	// 查询在线会话，并单会话下线其中之一，验证该令牌立即失效
	sessW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/sessions", nil, tokA.Data.AccessToken)
	require.Equal(t, http.StatusOK, sessW.Code)
	var sessResp struct {
		Data []struct {
			SessionID string `json:"session_id"`
			IsCurrent bool   `json:"is_current"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(sessW.Body.Bytes(), &sessResp))
	require.GreaterOrEqual(t, len(sessResp.Data), 2)

	var currentSID string
	for _, s := range sessResp.Data {
		if s.IsCurrent {
			currentSID = s.SessionID
		}
	}
	require.NotEmpty(t, currentSID)
	kickW := doJSON(t, env.engine, http.MethodDelete, "/api/v1/auth/sessions/"+currentSID, nil, tokA.Data.AccessToken)
	require.Equal(t, http.StatusOK, kickW.Code)

	meAfterKick := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, tokA.Data.AccessToken)
	assert.Equal(t, http.StatusUnauthorized, meAfterKick.Code)

	// 测试 Cap.js 本地 PoW 插件：降低难度为 2 方便测试快速求解并启用登录保护
	var capInst models.PluginInstance
	require.NoError(t, env.db.Where("name = ?", "cap-default").First(&capInst).Error)
	capUpd := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/plugins/%d", capInst.ID), map[string]interface{}{
		"enabled": true,
		"config": map[string]string{
			"mode":            "local",
			"challenge_count": "4",
			"difficulty":      "2",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, capUpd.Code)
	setCap := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{"captcha.protect_login": "true"},
	}, adminToken)
	require.Equal(t, http.StatusOK, setCap.Code)

	// 无 captcha_token 登录被拒绝
	noCapW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "riskuser",
		"password": "RiskUser@123",
	}, "")
	assert.Equal(t, http.StatusBadRequest, noCapW.Code)

	// 拉取 challenge -> 求解 PoW -> redeem 拿到一次性 token -> 登录成功
	chW := doJSON(t, env.engine, http.MethodPost, "/api/v1/captcha/cap/challenge", map[string]any{}, "")
	require.Equal(t, http.StatusOK, chW.Code)
	var chResp struct {
		Challenge struct {
			C int    `json:"c"`
			S string `json:"s"`
			D int    `json:"d"`
		} `json:"challenge"`
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(chW.Body.Bytes(), &chResp))

	sols := make([]int64, chResp.Challenge.C)
	for i := 0; i < chResp.Challenge.C; i++ {
		var nonce int64
		for {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", chResp.Challenge.S, i, nonce)))
			if hex.EncodeToString(sum[:])[:chResp.Challenge.D] == "00" {
				sols[i] = nonce
				break
			}
			nonce++
		}
	}
	rdW := doJSON(t, env.engine, http.MethodPost, "/api/v1/captcha/cap/redeem", map[string]any{
		"token":     chResp.Token,
		"solutions": sols,
	}, "")
	require.Equal(t, http.StatusOK, rdW.Code, rdW.Body.String())
	var rdResp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rdW.Body.Bytes(), &rdResp))
	require.NotEmpty(t, rdResp.Token)

	okCapLogin := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username":      "riskuser",
		"password":      "RiskUser@123",
		"captcha_token": rdResp.Token,
	}, "")
	require.Equal(t, http.StatusOK, okCapLogin.Code, okCapLogin.Body.String())
}

func TestPermissionSimulatorJITNotificationsAndAdminTiers(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 1. 权限模拟器：模拟给 viewer 添加 orders:read，不污染线上 Casbin 策略
	var viewer models.User
	doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "simuser",
		"email":    "simuser@openrealm.local",
		"password": "SimUser@1234",
	}, "")
	require.NoError(t, env.db.Where("username = ?", "simuser").First(&viewer).Error)

	simW := doJSON(t, env.engine, http.MethodPost, "/api/v1/permissions/simulate", map[string]any{
		"user_id":  viewer.ID,
		"domain":   rbac.DefaultDomain,
		"resource": "orders",
		"action":   "read",
		"draft": map[string]any{
			"add_policies": []map[string]string{
				{"role": "viewer", "domain": rbac.DefaultDomain, "resource": "orders", "action": "read"},
			},
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, simW.Code, simW.Body.String())
	assert.Contains(t, simW.Body.String(), `"current":false`)
	assert.Contains(t, simW.Body.String(), `"simulated":true`)
	assert.Contains(t, simW.Body.String(), `"effect":"granted"`)

	realAllowed, _ := env.enforcer.Enforce(viewer.ID, rbac.DefaultDomain, "orders", "read")
	assert.False(t, realAllowed, "simulation must not mutate live Casbin policies")

	// 2. JIT 临时权限授予与到期自动回收
	jitW := doJSON(t, env.engine, http.MethodPost, "/api/v1/jit-grants", map[string]any{
		"user_id":     viewer.ID,
		"domain_code": rbac.DefaultDomain,
		"role_code":   "auditor",
		"reason":      "临时审计协助",
		"ttl_minutes": 30,
	}, adminToken)
	require.Equal(t, http.StatusCreated, jitW.Code, jitW.Body.String())
	var jitResp struct {
		Data models.TempRoleGrant `json:"data"`
	}
	require.NoError(t, json.Unmarshal(jitW.Body.Bytes(), &jitResp))
	assert.Equal(t, "active", jitResp.Data.Status)

	canAudit, _ := env.enforcer.Enforce(viewer.ID, rbac.DefaultDomain, "audit_logs", "read")
	assert.True(t, canAudit)

	// 模拟时间到期并运行一次 JIT 调度器，应自动撤销 auditor 角色
	require.NoError(t, env.db.Model(&models.TempRoleGrant{}).Where("id = ?", jitResp.Data.ID).
		Update("expires_at", time.Now().Add(-time.Minute)).Error)
	notifySvc := notify.NewService(env.db, nil, env.enforcer, nil)
	jitSvc := jit.NewService(env.db, env.enforcer, notifySvc, nil, nil)
	_, expired := jitSvc.ProcessDueGrants(t.Context())
	assert.Equal(t, 1, expired)

	canAuditAfter, _ := env.enforcer.Enforce(viewer.ID, rbac.DefaultDomain, "audit_logs", "read")
	assert.False(t, canAuditAfter)

	// 3. 管理员分级验证（platform_admin vs user）与模板/公告/退信接口
	adminMeW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, adminToken)
	require.Equal(t, http.StatusOK, adminMeW.Code)
	assert.Contains(t, adminMeW.Body.String(), `"admin_tier":"platform_admin"`)

	simToken, _ := loginAs(t, env.engine, "simuser", "SimUser@1234")
	userMeW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, simToken)
	require.Equal(t, http.StatusOK, userMeW.Code)
	assert.Contains(t, userMeW.Body.String(), `"admin_tier":"user"`)

	// 普通用户禁止访问平台插件与模板管理接口
	denyPluginW := doJSON(t, env.engine, http.MethodGet, "/api/v1/plugins", nil, simToken)
	assert.Equal(t, http.StatusForbidden, denyPluginW.Code)

	tplW := doJSON(t, env.engine, http.MethodGet, "/api/v1/notifications/templates", nil, adminToken)
	require.Equal(t, http.StatusOK, tplW.Code)
	assert.Contains(t, tplW.Body.String(), "otp_verify")
}

func TestClientIPSettingsPreviewAndHotReload(t *testing.T) {
	defer clientip.SetPolicy(clientip.MethodXForwardedFor, "", clientip.DefaultTrustedProxies)
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 注册普通用户并验证禁止访问真实 IP 预览接口
	doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "ipuser",
		"email":    "ipuser@openrealm.local",
		"password": "IpUser@12345",
	}, "")
	userToken, _ := loginAs(t, env.engine, "ipuser", "IpUser@12345")

	denyW := doJSON(t, env.engine, http.MethodPost, "/api/v1/system/settings/client-ip-preview", map[string]string{}, userToken)
	assert.Equal(t, http.StatusForbidden, denyW.Code)

	// 超管携带可信代理头预览全部 6 种方式
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/settings/client-ip-preview", strings.NewReader(`{"custom_header":"EO-Client-IP"}`))
	req.RemoteAddr = "127.0.0.1:45678"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	req.Header.Set("X-Real-IP", "203.0.113.11")
	req.Header.Set("CF-Connecting-IP", "203.0.113.55")
	req.Header.Set("EO-Client-IP", "114.114.114.114")

	w := httptest.NewRecorder()
	env.engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var previewResp struct {
		Data clientip.PreviewResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &previewResp))
	assert.True(t, previewResp.Data.TrustedProxyMatched)
	assert.Equal(t, "198.51.100.10", previewResp.Data.ActiveIP)
	assert.Len(t, previewResp.Data.Options, 6)

	byMethod := map[string]clientip.MethodPreview{}
	for _, opt := range previewResp.Data.Options {
		byMethod[opt.Method] = opt
	}
	assert.Equal(t, "127.0.0.1", byMethod[clientip.MethodRemoteAddr].ResolvedIP)
	assert.Equal(t, "203.0.113.55", byMethod[clientip.MethodCFConnectingIP].ResolvedIP)
	assert.Equal(t, "114.114.114.114", byMethod[clientip.MethodCustomHeader].ResolvedIP)
	assert.True(t, byMethod[clientip.MethodCustomHeader].IsPublic)

	// 热更新为 CF-Connecting-IP，并检查生效状态立即切换
	updW := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]any{
		"settings": map[string]string{
			"server.client_ip_method": "cf_connecting_ip",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, updW.Code, updW.Body.String())

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/system/settings/client-ip-preview", strings.NewReader(`{}`))
	req2.RemoteAddr = "127.0.0.1:45679"
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	req2.Header.Set("CF-Connecting-IP", "203.0.113.55")
	w2 := httptest.NewRecorder()
	env.engine.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	var previewResp2 struct {
		Data clientip.PreviewResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &previewResp2))
	assert.Equal(t, "cf_connecting_ip", previewResp2.Data.ActiveMethod)
	assert.Equal(t, "203.0.113.55", previewResp2.Data.ActiveIP)
}

func TestOAuthPKCEFalseUserEditAndRegisterOTPSettings(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 1. 公共客户端无法保管密钥，关闭 PKCE 必须被拒绝；危险协议的回调地址同样被拒绝
	publicNoPKCE := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-clients", map[string]any{
		"name":            "PublicNoPKCE",
		"domain_code":     rbac.DefaultDomain,
		"redirect_uris":   []string{"https://app.example.com/cb"},
		"require_pkce":    false,
		"is_confidential": false,
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, publicNoPKCE.Code, publicNoPKCE.Body.String())
	jsRedirect := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-clients", map[string]any{
		"name":          "JSRedirect",
		"domain_code":   rbac.DefaultDomain,
		"redirect_uris": []string{"javascript:alert(document.cookie)"},
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, jsRedirect.Code, jsRedirect.Body.String())

	// 机密客户端可以关闭 RequirePKCE：应真实落库为 false 且 /oauth2/authorize 不强制 code_challenge
	createW := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-clients", map[string]any{
		"name":            "NoPKCEApp",
		"domain_code":     rbac.DefaultDomain,
		"redirect_uris":   []string{"https://app.example.com/cb"},
		"scopes":          []string{"openid", "profile", "email"},
		"require_pkce":    false,
		"is_confidential": true,
	}, adminToken)
	require.Equal(t, http.StatusCreated, createW.Code, createW.Body.String())
	var createResp struct {
		Data struct {
			Client       models.OAuthClient `json:"client"`
			ClientSecret string             `json:"client_secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createW.Body.Bytes(), &createResp))
	assert.False(t, createResp.Data.Client.RequirePKCE, "require_pkce=false must be persisted")
	assert.True(t, createResp.Data.Client.IsConfidential)
	assert.NotEmpty(t, createResp.Data.ClientSecret)

	reqAuth := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=https://app.example.com/cb&scope=openid&state=s1",
			createResp.Data.Client.ClientID),
		nil)
	reqAuth.Header.Set("Accept", "application/json")
	wAuth := httptest.NewRecorder()
	env.engine.ServeHTTP(wAuth, reqAuth)
	require.Equal(t, http.StatusOK, wAuth.Code, wAuth.Body.String())

	// 管理员编辑应用切换 require_pkce=true，并在编辑为机密客户端时生成 secret
	updAppW := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/oauth-clients/%d", createResp.Data.Client.ID), map[string]any{
		"name":            "NoPKCEApp-Edited",
		"description":     "updated",
		"redirect_uris":   []string{"https://app.example.com/cb2"},
		"require_pkce":    true,
		"is_confidential": true,
		"status":          "active",
	}, adminToken)
	require.Equal(t, http.StatusOK, updAppW.Code, updAppW.Body.String())
	var updAppResp struct {
		Data struct {
			models.OAuthClient
			ClientSecret string `json:"client_secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(updAppW.Body.Bytes(), &updAppResp))
	assert.Equal(t, "NoPKCEApp-Edited", updAppResp.Data.Name)
	assert.True(t, updAppResp.Data.RequirePKCE)
	assert.True(t, updAppResp.Data.IsConfidential)

	// 编辑为公共客户端同时关闭 PKCE 必须被拒绝
	toPublic := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/oauth-clients/%d", createResp.Data.Client.ID), map[string]any{
		"require_pkce":    false,
		"is_confidential": false,
	}, adminToken)
	assert.Equal(t, http.StatusBadRequest, toPublic.Code, toPublic.Body.String())

	// 2. 普通用户创建与编辑自有应用（关闭 PKCE）
	doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "appowner",
		"email":    "appowner@openrealm.local",
		"password": "AppOwner@1234",
	}, "")
	ownerToken, _ := loginAs(t, env.engine, "appowner", "AppOwner@1234")

	myCreateW := doJSON(t, env.engine, http.MethodPost, "/api/v1/my/oauth-clients", map[string]any{
		"name":            "MyOwnApp",
		"domain_code":     rbac.DefaultDomain,
		"redirect_uris":   []string{"https://my.example.com/cb"},
		"grant_types":     []string{"authorization_code", "refresh_token"},
		"scopes":          []string{"openid", "profile"},
		"require_pkce":    false,
		"is_confidential": true,
	}, ownerToken)
	require.Equal(t, http.StatusCreated, myCreateW.Code, myCreateW.Body.String())
	var myCreateResp struct {
		Data struct {
			Client models.OAuthClient `json:"client"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(myCreateW.Body.Bytes(), &myCreateResp))
	assert.False(t, myCreateResp.Data.Client.RequirePKCE)

	myUpdW := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/my/oauth-clients/%d", myCreateResp.Data.Client.ID), map[string]any{
		"name":          "MyOwnAppV2",
		"redirect_uris": []string{"https://my.example.com/cb2"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
		"scopes":        []string{"openid", "email"},
		"require_pkce":  true,
	}, ownerToken)
	require.Equal(t, http.StatusOK, myUpdW.Code, myUpdW.Body.String())
	assert.Contains(t, myUpdW.Body.String(), `"name":"MyOwnAppV2"`)
	assert.Contains(t, myUpdW.Body.String(), `"require_pkce":true`)

	// 3. 管理员编辑用户资料（邮箱/手机号/显示名/头像/状态）并校重
	var owner models.User
	require.NoError(t, env.db.Where("username = ?", "appowner").First(&owner).Error)
	editUserW := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", owner.ID), map[string]any{
		"display_name": "应用创建者",
		"email":        "appowner_new@openrealm.local",
		"phone":        "+8613800138999",
		"avatar_url":   "/logo.png",
		"status":       "active",
	}, adminToken)
	require.Equal(t, http.StatusOK, editUserW.Code, editUserW.Body.String())
	assert.Contains(t, editUserW.Body.String(), `"phone":"+8613800138999"`)
	assert.Contains(t, editUserW.Body.String(), `"email":"appowner_new@openrealm.local"`)

	// 4. 后台关闭注册邮箱、开启手机号选填：连续注册 2 个无邮箱账号不应触发邮箱唯一约束冲突
	setNoEmailW := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]any{
		"settings": map[string]string{
			"security.register_email_mode":  "disabled",
			"security.register_phone_mode":  "optional",
			"security.register_verify_mode": "none",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, setNoEmailW.Code, setNoEmailW.Body.String())

	r1 := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "noemail1",
		"phone":    "+8613800008001",
		"password": "NoEmail@1234",
	}, "")
	require.Equal(t, http.StatusCreated, r1.Code, r1.Body.String())

	r2 := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "noemail2",
		"password": "NoEmail@1234",
	}, "")
	require.Equal(t, http.StatusCreated, r2.Code, r2.Body.String())

	// 5. 启用内置短信插件并开启注册短信验证码校验：不带验证码被拒；发送注册 OTP 后携带正确验证码注册成功
	var smsInst models.PluginInstance
	require.NoError(t, env.db.Where("name = ?", "console-sms-default").First(&smsInst).Error)
	enSMS := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/plugins/%d", smsInst.ID), map[string]any{
		"enabled": true,
	}, adminToken)
	require.Equal(t, http.StatusOK, enSMS.Code)

	setSMSRegW := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]any{
		"settings": map[string]string{
			"security.register_email_mode":  "disabled",
			"security.register_phone_mode":  "required",
			"security.register_verify_mode": "sms",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, setSMSRegW.Code, setSMSRegW.Body.String())

	failReg := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "smsreguser",
		"phone":    "+8613800991122",
		"password": "SmsReg@1234",
	}, "")
	assert.Equal(t, http.StatusBadRequest, failReg.Code)

	sendW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{
		"scene":   "register",
		"channel": "sms",
		"target":  "+8613800991122",
	}, "")
	require.Equal(t, http.StatusOK, sendW.Code, sendW.Body.String())

	// 从 miniredis 中读取保存的注册验证码
	var otpCode string
	for _, k := range env.mr.Keys() {
		if strings.Contains(k, "register:+8613800991122") {
			raw, gErr := env.mr.Get(k)
			require.NoError(t, gErr)
			var rec struct {
				Code string `json:"code"`
			}
			require.NoError(t, json.Unmarshal([]byte(raw), &rec))
			otpCode = rec.Code
			break
		}
	}
	require.NotEmpty(t, otpCode, "expected register SMS OTP in Redis")

	okReg := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "smsreguser",
		"phone":    "+8613800991122",
		"password": "SmsReg@1234",
		"sms_code": otpCode,
	}, "")
	require.Equal(t, http.StatusCreated, okReg.Code, okReg.Body.String())
}
