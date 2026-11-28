package router_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/oauthserver"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/router"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/seed"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/openrealm/openiam/internal/version"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testSeedAdminPassword 为测试环境初始管理员口令：必须满足初始化口令策略，且不能是历史默认口令。
const testSeedAdminPassword = "SeedAdmin@2026#Str0ng"

type testEnv struct {
	engine      *gin.Engine
	db          *gorm.DB
	rdb         *redis.Client
	mr          *miniredis.Miniredis
	enforcer    *rbac.Enforcer
	settingsSvc *settings.Service
}

func setupTestEnv(t *testing.T, authRate string) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := config.Default()
	cfg.Server.Mode = "release"
	cfg.Seed.AdminPassword = testSeedAdminPassword

	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)

	updates := map[string]string{
		settings.KeySecurityMaxLoginFailures: "3",
		settings.KeySecurityLockoutMinutes:   "5",
	}
	if authRate != "" {
		updates[settings.KeyRateLimitEnabled] = "true"
		updates[settings.KeyRateLimitGeneralRate] = "500-M"
		updates[settings.KeyRateLimitAuthRate] = authRate
	} else {
		updates[settings.KeyRateLimitEnabled] = "false"
	}
	_, _, err = settingsSvc.UpdateBatch(updates, 0)
	require.NoError(t, err)

	snap := settingsSvc.Snapshot()
	jwtMgr, err := security.NewJWTManager(snap.JWTIssuer, "", snap.JWTAccessTTL)
	require.NoError(t, err)
	stateStore := security.NewStateStore(rdb, cfg.Redis.KeyPrefix)
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	require.NoError(t, seed.EnsureDefaults(db, enforcer, cfg.Seed, stateStore))
	// 常规用例关注管理 API 行为，这里直接解除初始管理员的强制改密标记；
	// 强制改密流程本身在 bootstrap_password_test.go 中单独覆盖。
	require.NoError(t, db.Model(&models.User{}).Where("username = ?", cfg.Seed.AdminUsername).
		Update("must_change_password", false).Error)

	auditSvc := audit.NewService(db, zap.NewNop())
	pluginSvc := oauthplugin.NewService(
		db,
		oauthplugin.NewDefaultRegistry(),
		stateStore,
		jwtMgr,
		enforcer,
		auditSvc,
		settingsSvc,
	)
	oauthSrv := oauthserver.NewServer(db, rdb, stateStore, jwtMgr, auditSvc, settingsSvc)

	engine, err := router.Setup(router.Dependencies{
		Config:      cfg,
		DB:          db,
		Redis:       rdb,
		Logger:      zap.NewNop(),
		JWTManager:  jwtMgr,
		StateStore:  stateStore,
		Enforcer:    enforcer,
		AuditSvc:    auditSvc,
		SettingsSvc: settingsSvc,
		PluginSvc:   pluginSvc,
		OAuthSrv:    oauthSrv,
	})
	require.NoError(t, err)

	return &testEnv{engine: engine, db: db, rdb: rdb, mr: mr, enforcer: enforcer, settingsSvc: settingsSvc}
}

func doJSON(t *testing.T, engine *gin.Engine, method, path string, body interface{}, token string, headers ...map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:12345"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, hMap := range headers {
		for k, v := range hMap {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func loginAs(t *testing.T, engine *gin.Engine, username, password string) (access, refresh string) {
	w := doJSON(t, engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, "", map[string]string{"X-Token-Delivery": "body"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Data.AccessToken, resp.Data.RefreshToken
}

func TestAuthLifecycleAndLockout(t *testing.T) {
	env := setupTestEnv(t, "")

	// 1. 注册普通用户
	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username":     "alice",
		"email":        "alice@openrealm.local",
		"password":     "Alice@123456",
		"display_name": "Alice",
	}, "")
	require.Equal(t, http.StatusCreated, regW.Code)

	// 2. 登录、Token 刷新轮换与注销黑名单
	access, refresh := loginAs(t, env.engine, "alice", "Alice@123456")
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	meW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, access)
	require.Equal(t, http.StatusOK, meW.Code)

	refW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refresh,
	}, "", map[string]string{"X-Token-Delivery": "body"})
	require.Equal(t, http.StatusOK, refW.Code)
	var refResp struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(refW.Body.Bytes(), &refResp))
	assert.NotEqual(t, refresh, refResp.Data.RefreshToken)

	// 旧 refresh token 不能重复使用
	reuseW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refresh,
	}, "")
	assert.Equal(t, http.StatusUnauthorized, reuseW.Code)

	// 登出后旧 access token 被 Redis 黑名单拦截
	outW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/logout", map[string]string{
		"refresh_token": refResp.Data.RefreshToken,
	}, refResp.Data.AccessToken)
	require.Equal(t, http.StatusOK, outW.Code)

	blockedW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, refResp.Data.AccessToken)
	assert.Equal(t, http.StatusUnauthorized, blockedW.Code)

	// 3. 连续失败登录触发账号锁定
	for i := 0; i < 3; i++ {
		w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"username": "alice",
			"password": "wrong_password",
		}, "")
		if i < 2 {
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, w.Code)
		}
	}
}

func TestIPRateLimiting(t *testing.T) {
	env := setupTestEnv(t, "3-M")

	for i := 0; i < 3; i++ {
		w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"username": "nobody",
			"password": "bad",
		}, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}

	// 第 4 次请求超出 3-M 限制，应返回 429
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "nobody",
		"password": "bad",
	}, "")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestMultiDomainRBACAndAuditLogs(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 1. 创建一个新业务域 billing
	domW := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{
		"code": "billing",
		"name": "OpenRealm 计费域",
	}, adminToken)
	require.Equal(t, http.StatusCreated, domW.Code)

	// 2. 在 billing 域创建角色 billing_ops 并绑定权限策略
	roleW := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "billing",
		"code":        "billing_ops",
		"name":        "计费运维",
	}, adminToken)
	require.Equal(t, http.StatusCreated, roleW.Code)
	var roleResp struct {
		Data models.Role `json:"data"`
	}
	require.NoError(t, json.Unmarshal(roleW.Body.Bytes(), &roleResp))

	setPermW := doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/permissions", roleResp.Data.ID), map[string]interface{}{
		"policies": []map[string]string{
			{"resource": "users", "action": "read"},
			{"resource": "roles", "action": "read"},
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, setPermW.Code)

	// 3. 创建普通用户 bob
	bobW := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", map[string]interface{}{
		"username":    "bob",
		"email":       "bob@openrealm.local",
		"password":    "Bob@123456",
		"domain_code": "billing",
		"role_codes":  []string{"billing_ops"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, bobW.Code)

	bobToken, _ := loginAs(t, env.engine, "bob", "Bob@123456")

	// 4. 验证域隔离：bob 在 billing 域有 users:read，在 openiam 域没有 users:read，且没有 roles:write
	allowW := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, bobToken, map[string]string{"X-OpenIAM-Domain": "billing"})
	assert.Equal(t, http.StatusOK, allowW.Code)

	denyDomainW := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, bobToken, map[string]string{"X-OpenIAM-Domain": "openiam"})
	assert.Equal(t, http.StatusForbidden, denyDomainW.Code)

	denyWriteW := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "billing",
		"code":        "evil",
		"name":        "Evil",
	}, bobToken, map[string]string{"X-OpenIAM-Domain": "billing"})
	assert.Equal(t, http.StatusForbidden, denyWriteW.Code)

	// 5. 为 bob 追加分配角色，然后查询审计日志确认登录 + 角色 + 权限管理操作全部被审计
	var bobUser models.User
	require.NoError(t, env.db.Where("username = ?", "bob").First(&bobUser).Error)
	assignW := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/roles", bobUser.ID), map[string]interface{}{
		"domain_code": "billing",
		"role_codes":  []string{"billing_ops"},
		"replace":     true,
	}, adminToken)
	require.Equal(t, http.StatusOK, assignW.Code)

	auditW := doJSON(t, env.engine, http.MethodGet, "/api/v1/audit-logs?page_size=100", nil, adminToken)
	require.Equal(t, http.StatusOK, auditW.Code)
	var auditResp struct {
		Data struct {
			Items []models.AuditLog `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(auditW.Body.Bytes(), &auditResp))

	actions := make(map[string]models.AuditLog)
	for _, item := range auditResp.Data.Items {
		actions[item.Action] = item
	}
	assert.Contains(t, actions, "auth.login")
	assert.Contains(t, actions, "domain.create")
	assert.Contains(t, actions, "rbac.role.create")
	assert.Contains(t, actions, "rbac.role_permission.set")
	assert.Contains(t, actions, "rbac.user_role.assign")
	assert.NotNil(t, actions["rbac.role_permission.set"].AfterState)
	assert.NotNil(t, actions["rbac.user_role.assign"].BeforeState)
}

func TestOpenIAMOAuth2ServerFullFlow(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 1. 检查 OIDC Discovery & JWKS
	discW := doJSON(t, env.engine, http.MethodGet, "/.well-known/openid-configuration", nil, "")
	require.Equal(t, http.StatusOK, discW.Code)
	assert.Contains(t, discW.Body.String(), "/oauth2/authorize")

	jwksW := doJSON(t, env.engine, http.MethodGet, "/.well-known/jwks.json", nil, "")
	require.Equal(t, http.StatusOK, jwksW.Code)
	assert.Contains(t, jwksW.Body.String(), `"alg":"RS256"`)

	// 2. 创建一个接入手册应用
	cliW := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-clients", map[string]interface{}{
		"name":            "OpenRealm Portal",
		"domain_code":     "openiam",
		"redirect_uris":   []string{"http://localhost:3000/cb"},
		"grant_types":     []string{"authorization_code", "refresh_token", "client_credentials"},
		"scopes":          []string{"openid", "profile", "email"},
		"require_pkce":    true,
		"is_confidential": true,
	}, adminToken)
	require.Equal(t, http.StatusCreated, cliW.Code, cliW.Body.String())

	var cliResp struct {
		Data struct {
			Client       models.OAuthClient `json:"client"`
			ClientSecret string             `json:"client_secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(cliW.Body.Bytes(), &cliResp))
	clientID := cliResp.Data.Client.ClientID
	clientSecret := cliResp.Data.ClientSecret
	require.NotEmpty(t, clientID)
	require.NotEmpty(t, clientSecret)

	// 3. 发起 PKCE 授权请求
	verifier := "test_pkce_verifier_secret_string_1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := fmt.Sprintf("/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=xyz&code_challenge=%s&code_challenge_method=S256",
		url.QueryEscape(clientID),
		url.QueryEscape("http://localhost:3000/cb"),
		url.QueryEscape("openid profile email"),
		url.QueryEscape(challenge),
	)
	authReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	authReq.Header.Set("Accept", "application/json")
	authW := httptest.NewRecorder()
	env.engine.ServeHTTP(authW, authReq)
	require.Equal(t, http.StatusOK, authW.Code, authW.Body.String())

	var authInitResp struct {
		Data struct {
			RequestID string `json:"request_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(authW.Body.Bytes(), &authInitResp))

	// 4. 用户在同意页批准授权
	approveW := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth2/consent/"+authInitResp.Data.RequestID, map[string]bool{
		"approved": true,
	}, adminToken)
	require.Equal(t, http.StatusOK, approveW.Code, approveW.Body.String())
	var approveResp struct {
		Data struct {
			Code        string `json:"code"`
			RedirectURI string `json:"redirect_uri"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(approveW.Body.Bytes(), &approveResp))
	require.NotEmpty(t, approveResp.Data.Code)

	// 5. 用 authorization_code + code_verifier 换取 Access Token + ID Token
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", approveResp.Data.Code)
	form.Set("redirect_uri", "http://localhost:3000/cb")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW := httptest.NewRecorder()
	env.engine.ServeHTTP(tokW, tokReq)
	require.Equal(t, http.StatusOK, tokW.Code, tokW.Body.String())

	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(tokW.Body.Bytes(), &tokResp))
	require.NotEmpty(t, tokResp.AccessToken)
	require.NotEmpty(t, tokResp.IDToken)

	// 6. 请求 /oauth2/userinfo & /oauth2/introspect & /oauth2/revoke
	uiReq := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	uiW := httptest.NewRecorder()
	env.engine.ServeHTTP(uiW, uiReq)
	require.Equal(t, http.StatusOK, uiW.Code, uiW.Body.String())
	assert.Contains(t, uiW.Body.String(), `"preferred_username":"admin"`)

	basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))}
	introW := doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", map[string]string{
		"token": tokResp.AccessToken,
	}, "", basic)
	require.Equal(t, http.StatusOK, introW.Code)
	assert.Contains(t, introW.Body.String(), `"active":true`)

	revW := doJSON(t, env.engine, http.MethodPost, "/oauth2/revoke", map[string]string{
		"token": tokResp.AccessToken,
	}, "", basic)
	require.Equal(t, http.StatusOK, revW.Code)

	introAfterW := doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", map[string]string{
		"token": tokResp.AccessToken,
	}, "", basic)
	assert.Contains(t, introAfterW.Body.String(), `"active":false`)
}

func TestSystemSettingsDatabasePersistenceAndHotReload(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 1. 管理员读取数据库中的系统设置列表
	listW := doJSON(t, env.engine, http.MethodGet, "/api/v1/system/settings", nil, adminToken)
	require.Equal(t, http.StatusOK, listW.Code)
	assert.Contains(t, listW.Body.String(), settings.KeySecurityAllowPublicRegister)
	assert.Contains(t, listW.Body.String(), settings.KeyOAuthServerIssuer)

	// 2. 在线修改配置：关闭公开注册 + 修改 OIDC Issuer + 开启限流
	updW := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{
			settings.KeySecurityAllowPublicRegister: "false",
			settings.KeyOAuthServerIssuer:           "https://iam.openrealm.io",
			settings.KeyRateLimitEnabled:            "true",
			settings.KeyRateLimitAuthRate:           "2-M",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, updW.Code, updW.Body.String())

	// 3. 验证公开注册接口立即受控关闭（热生效）
	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "blocked_user",
		"email":    "blocked@openrealm.local",
		"password": "Password@123",
	}, "")
	assert.Equal(t, http.StatusForbidden, regW.Code)

	// 4. 验证 OIDC Discovery 立即反映新的 Issuer
	discW := doJSON(t, env.engine, http.MethodGet, "/.well-known/openid-configuration", nil, "")
	require.Equal(t, http.StatusOK, discW.Code)
	assert.Contains(t, discW.Body.String(), `"issuer":"https://iam.openrealm.io"`)

	// 5. 验证数据库持久化记录 & 审计日志写入 system.settings.update
	var saved models.SystemSetting
	require.NoError(t, env.db.Where("setting_key = ?", settings.KeyOAuthServerIssuer).First(&saved).Error)
	assert.Equal(t, "https://iam.openrealm.io", saved.Value)

	var auditRow models.AuditLog
	require.NoError(t, env.db.Where("action = ?", "system.settings.update").Order("id DESC").First(&auditRow).Error)
	assert.Equal(t, "system_setting", auditRow.ResourceType)
	assert.NotNil(t, auditRow.BeforeState)
	assert.NotNil(t, auditRow.AfterState)
}

func TestOrdinaryUserSelfServiceOAuthClientAndAuthCode(t *testing.T) {
	env := setupTestEnv(t, "")

	// 1. 注册并登录普通用户（默认拥有 viewer 角色 -> oauth_clients:create_own & oauth_clients:authorize）
	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "devuser",
		"email":    "devuser@openrealm.local",
		"password": "DevUser@123",
	}, "")
	require.Equal(t, http.StatusCreated, regW.Code)
	userToken, _ := loginAs(t, env.engine, "devuser", "DevUser@123")

	// 2. 普通用户创建自己的 OAuth 应用
	createW := doJSON(t, env.engine, http.MethodPost, "/api/v1/my/oauth-clients", map[string]interface{}{
		"name":            "My Personal App",
		"domain_code":     "openiam",
		"redirect_uris":   []string{"https://myapp.example.com/callback"},
		"grant_types":     []string{"authorization_code", "refresh_token"},
		"scopes":          []string{"openid", "profile", "email"},
		"require_pkce":    false,
		"is_confidential": true,
	}, userToken)
	require.Equal(t, http.StatusCreated, createW.Code, createW.Body.String())

	var createResp struct {
		Data struct {
			Client       models.OAuthClient `json:"client"`
			ClientSecret string             `json:"client_secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createW.Body.Bytes(), &createResp))
	require.NotEmpty(t, createResp.Data.Client.ClientID)
	require.NotEmpty(t, createResp.Data.ClientSecret)

	// 3. 普通用户查看自己的应用列表
	listW := doJSON(t, env.engine, http.MethodGet, "/api/v1/my/oauth-clients", nil, userToken)
	require.Equal(t, http.StatusOK, listW.Code)
	assert.Contains(t, listW.Body.String(), createResp.Data.Client.ClientID)

	// 4. 普通用户为该应用生成一次性授权码 (Code)
	codeW := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth2/codes", map[string]interface{}{
		"client_id":    createResp.Data.Client.ClientID,
		"redirect_uri": "https://myapp.example.com/callback",
		"scopes":       []string{"openid", "profile", "email"},
	}, userToken)
	require.Equal(t, http.StatusCreated, codeW.Code, codeW.Body.String())

	var codeResp struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(codeW.Body.Bytes(), &codeResp))
	require.NotEmpty(t, codeResp.Data.Code)

	// 5. 使用该授权码调用标准 /oauth2/token 换取 Access Token 和 ID Token
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", codeResp.Data.Code)
	form.Set("redirect_uri", "https://myapp.example.com/callback")
	form.Set("client_id", createResp.Data.Client.ClientID)
	form.Set("client_secret", createResp.Data.ClientSecret)

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW := httptest.NewRecorder()
	env.engine.ServeHTTP(tokW, tokReq)
	require.Equal(t, http.StatusOK, tokW.Code, tokW.Body.String())
	assert.Contains(t, tokW.Body.String(), `"access_token"`)
	assert.Contains(t, tokW.Body.String(), `"id_token"`)
}

func TestProfilePasskeySiteAndSMTPSettings(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	// 1. 公开站点信息接口
	siteW := doJSON(t, env.engine, http.MethodGet, "/api/v1/site/info", nil, "")
	require.Equal(t, http.StatusOK, siteW.Code)
	assert.Contains(t, siteW.Body.String(), `"/logo.png"`)

	// 2. 管理员更新站点公告与 SMTP 密码，验证脱敏与公开接口实时更新
	updW := doJSON(t, env.engine, http.MethodPut, "/api/v1/system/settings", map[string]interface{}{
		"settings": map[string]string{
			"site.name":                 "OpenIAM Prod",
			"site.announcement_enabled": "true",
			"site.announcement_title":   "系统维护通知",
			"site.announcement_content": "今晚 23:00 进行例行升级",
			"smtp.password":             "SuperSecretSMTPPass!",
		},
	}, adminToken)
	require.Equal(t, http.StatusOK, updW.Code, updW.Body.String())
	// 响应与列表均不得回传 SMTP 密码明文
	assert.NotContains(t, updW.Body.String(), "SuperSecretSMTPPass!")

	listSetW := doJSON(t, env.engine, http.MethodGet, "/api/v1/system/settings", nil, adminToken)
	require.Equal(t, http.StatusOK, listSetW.Code)
	assert.NotContains(t, listSetW.Body.String(), "SuperSecretSMTPPass!")

	siteAfterW := doJSON(t, env.engine, http.MethodGet, "/api/v1/site/info", nil, "")
	require.Equal(t, http.StatusOK, siteAfterW.Code)
	assert.Contains(t, siteAfterW.Body.String(), "OpenIAM Prod")
	assert.Contains(t, siteAfterW.Body.String(), "系统维护通知")

	// 3. SMTP 未启用时发送测试邮件应返回 502 并给出明确错误
	testMailW := doJSON(t, env.engine, http.MethodPost, "/api/v1/system/settings/test-smtp", map[string]string{
		"to": "ops@example.com",
	}, adminToken)
	assert.Equal(t, http.StatusBadGateway, testMailW.Code)

	// 4. 区分管理员与普通用户的 is_admin 标记
	adminMeW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, adminToken)
	require.Equal(t, http.StatusOK, adminMeW.Code)
	assert.Contains(t, adminMeW.Body.String(), `"is_admin":true`)

	regW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "member1",
		"email":    "member1@openrealm.local",
		"password": "Member@12345",
	}, "")
	require.Equal(t, http.StatusCreated, regW.Code)
	memberToken, _ := loginAs(t, env.engine, "member1", "Member@12345")

	memberMeW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, memberToken)
	require.Equal(t, http.StatusOK, memberMeW.Code)
	assert.Contains(t, memberMeW.Body.String(), `"is_admin":false`)
	assert.Contains(t, memberMeW.Body.String(), `"has_password":true`)

	// 5. 个人资料更新与头像后缀/站内路径限制
	badAvatarW := doJSON(t, env.engine, http.MethodPut, "/api/v1/auth/me", map[string]string{
		"display_name": "普通成员",
		"avatar_url":   "javascript:alert(1)",
	}, memberToken)
	assert.Equal(t, http.StatusBadRequest, badAvatarW.Code)

	// 非管理员禁止使用站内路径
	relAvatarW := doJSON(t, env.engine, http.MethodPut, "/api/v1/auth/me", map[string]string{
		"display_name": "普通成员",
		"avatar_url":   "/logo.png",
	}, memberToken)
	assert.Equal(t, http.StatusBadRequest, relAvatarW.Code)

	// 仅允许 .png / .ico / .jpg 后缀
	badExtW := doJSON(t, env.engine, http.MethodPut, "/api/v1/auth/me", map[string]string{
		"display_name": "普通成员",
		"avatar_url":   "https://cdn.example.com/avatar.svg",
	}, memberToken)
	assert.Equal(t, http.StatusBadRequest, badExtW.Code)

	okProfileW := doJSON(t, env.engine, http.MethodPut, "/api/v1/auth/me", map[string]string{
		"display_name": "普通成员A",
		"avatar_url":   "https://cdn.example.com/avatar.png",
	}, memberToken)
	require.Equal(t, http.StatusOK, okProfileW.Code, okProfileW.Body.String())
	assert.Contains(t, okProfileW.Body.String(), "普通成员A")

	// 管理员允许使用合法扩展名的站内路径，但禁止非图片站内路径（如 /index.html）
	adminBadRelW := doJSON(t, env.engine, http.MethodPut, "/api/v1/auth/me", map[string]string{
		"display_name": "管理员",
		"avatar_url":   "/index.html",
	}, adminToken)
	assert.Equal(t, http.StatusBadRequest, adminBadRelW.Code)

	adminOkRelW := doJSON(t, env.engine, http.MethodPut, "/api/v1/auth/me", map[string]string{
		"display_name": "超级管理员",
		"avatar_url":   "/logo.png",
	}, adminToken)
	require.Equal(t, http.StatusOK, adminOkRelW.Code, adminOkRelW.Body.String())

	// 6. 通行密钥列表与注册 Challenge 生成
	pkListW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/passkeys", nil, memberToken)
	require.Equal(t, http.StatusOK, pkListW.Code)

	// 通行密钥的允许来源改由服务端配置决定，浏览器一定会带 Origin 头，这里按默认白名单的 Origin 发起。
	pkBeginW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/passkeys/register/begin", nil, memberToken,
		map[string]string{"Origin": "http://localhost:5173"})
	require.Equal(t, http.StatusOK, pkBeginW.Code, pkBeginW.Body.String())
	assert.Contains(t, pkBeginW.Body.String(), `"session_id"`)
	assert.Contains(t, pkBeginW.Body.String(), `"challenge"`)
}
