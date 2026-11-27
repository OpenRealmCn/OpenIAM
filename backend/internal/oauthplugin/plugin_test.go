package oauthplugin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/openrealm/openiam/internal/version"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultRegistryContainsAllPlugins(t *testing.T) {
	reg := oauthplugin.NewDefaultRegistry()
	metas := reg.ListMetadata()
	types := make(map[string]bool)
	for _, m := range metas {
		types[m.Type] = true
	}
	assert.True(t, types["generic_oidc"])
	assert.True(t, types["github"])
	assert.True(t, types["google"])
	assert.True(t, types["feishu"])
	assert.True(t, types["wecom"])
}

func TestFederatedLoginFlowWithMockGitHubAndFeishu(t *testing.T) {
	// Mock GitHub & Feishu OAuth endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/github/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "gho_mock_token",
			"token_type":   "bearer",
		})
	})
	mux.HandleFunc("/github/api/user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         98765,
			"login":      "octocat_openrealm",
			"name":       "Octo Cat",
			"avatar_url": "https://example.com/avatar.png",
		})
	})
	mux.HandleFunc("/github/api/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"email": "octo@openrealm.local", "primary": true, "verified": true},
		})
	})
	mux.HandleFunc("/feishu/open-apis/auth/v3/app_access_token/internal", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":             0,
			"app_access_token": "fs_app_tok",
		})
	})
	mux.HandleFunc("/feishu/open-apis/authen/v1/oidc/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"data": map[string]interface{}{"access_token": "fs_user_tok"},
		})
	})
	mux.HandleFunc("/feishu/open-apis/authen/v1/user_info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"data": map[string]interface{}{
				"open_id":          "ou_123456",
				"union_id":         "on_999999",
				"name":             "张三",
				"enterprise_email": "zhangsan@openrealm.local",
			},
		})
	})
	mockSrv := httptest.NewServer(mux)
	defer mockSrv.Close()

	db, err := gormOpenMemory()
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	jwtMgr, err := security.NewJWTManager("http://localhost:8080", "", 30*time.Minute)
	require.NoError(t, err)
	stateStore := security.NewStateStore(rdb, "test:")
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	auditSvc := audit.NewService(db, zap.NewNop())
	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)

	svc := oauthplugin.NewService(
		db,
		oauthplugin.NewDefaultRegistry(),
		stateStore,
		jwtMgr,
		enforcer,
		auditSvc,
		settingsSvc,
	)

	require.NoError(t, db.Create(&models.OAuthProvider{
		Name:         "github_mock",
		PluginType:   "github",
		DisplayName:  "GitHub",
		ClientID:     "gh_cli",
		ClientSecret: "gh_sec",
		AutoRegister: true,
		Enabled:      true,
		ExtraConfig: models.JSONMap{
			"auth_url":     mockSrv.URL + "/github/authorize",
			"token_url":    mockSrv.URL + "/github/token",
			"api_base_url": mockSrv.URL + "/github/api",
		},
	}).Error)

	require.NoError(t, db.Create(&models.OAuthProvider{
		Name:         "feishu_mock",
		PluginType:   "feishu",
		DisplayName:  "飞书",
		ClientID:     "fs_app",
		ClientSecret: "fs_sec",
		AutoRegister: true,
		Enabled:      true,
		ExtraConfig: models.JSONMap{
			"auth_base_url": mockSrv.URL + "/feishu",
			"api_base_url":  mockSrv.URL + "/feishu",
		},
	}).Error)

	// 1. 测试 GitHub 联合登录发起与回调自动建号
	authURL, state, err := svc.StartLogin(context.Background(), "github_mock", "")
	require.NoError(t, err)
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, state, parsed.Query().Get("state"))

	res, err := svc.HandleCallback(context.Background(), "github_mock", "mock_code", state, "", "127.0.0.1", "go-test")
	require.NoError(t, err)
	assert.True(t, res.IsNewUser)
	assert.Equal(t, "octocat_openrealm", res.User.Username)
	assert.Equal(t, "octo@openrealm.local", res.User.Email)
	assert.NotEmpty(t, res.AccessToken)

	// 2. 测试飞书联合登录发起与回调自动建号
	fsURL, fsState, err := svc.StartLogin(context.Background(), "feishu_mock", "")
	require.NoError(t, err)
	assert.Contains(t, fsURL, "/open-apis/authen/v1/authorize")

	fsRes, err := svc.HandleCallback(context.Background(), "feishu_mock", "fs_code", fsState, "", "127.0.0.1", "go-test")
	require.NoError(t, err)
	assert.True(t, fsRes.IsNewUser)
	assert.Equal(t, "zhangsan@openrealm.local", fsRes.User.Email)
	assert.Equal(t, "张三", fsRes.User.DisplayName)
}
