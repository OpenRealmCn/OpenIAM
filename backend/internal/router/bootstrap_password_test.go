package router_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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

// 本文件覆盖模块 C：初始管理员凭据、强制改密状态与存量库升级。

type bootstrapRuntime struct {
	rdb        *redis.Client
	stateStore *security.StateStore
}

func newBootstrapRuntime(t *testing.T) bootstrapRuntime {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return bootstrapRuntime{rdb: rdb, stateStore: security.NewStateStore(rdb, "openiam:")}
}

func newBootstrapDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))
	return db
}

type bootstrapEnv struct {
	engine     *gin.Engine
	db         *gorm.DB
	stateStore *security.StateStore
}

// setupBootstrapRouter 在给定数据库上执行 seed 并装配完整路由，供初始凭据与强制改密用例复用。
func setupBootstrapRouter(t *testing.T, db *gorm.DB, rt bootstrapRuntime, seedCfg config.SeedConfig) *bootstrapEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)
	_, _, err = settingsSvc.UpdateBatch(map[string]string{
		settings.KeyRateLimitEnabled:         "false",
		settings.KeySecurityMaxLoginFailures: "10",
	}, 0)
	require.NoError(t, err)

	snap := settingsSvc.Snapshot()
	jwtMgr, err := security.NewJWTManager(snap.JWTIssuer, "", snap.JWTAccessTTL)
	require.NoError(t, err)
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	require.NoError(t, seed.EnsureDefaults(db, enforcer, seedCfg, rt.stateStore))

	auditSvc := audit.NewService(db, zap.NewNop())
	pluginSvc := oauthplugin.NewService(
		db,
		oauthplugin.NewDefaultRegistry(),
		rt.stateStore,
		jwtMgr,
		enforcer,
		auditSvc,
		settingsSvc,
	)
	oauthSrv := oauthserver.NewServer(db, rt.rdb, rt.stateStore, jwtMgr, auditSvc, settingsSvc)

	cfg := config.Default()
	cfg.Server.Mode = "release"
	engine, err := router.Setup(router.Dependencies{
		Config:      cfg,
		DB:          db,
		Redis:       rt.rdb,
		Logger:      zap.NewNop(),
		JWTManager:  jwtMgr,
		StateStore:  rt.stateStore,
		Enforcer:    enforcer,
		AuditSvc:    auditSvc,
		SettingsSvc: settingsSvc,
		PluginSvc:   pluginSvc,
		OAuthSrv:    oauthSrv,
	})
	require.NoError(t, err)

	return &bootstrapEnv{engine: engine, db: db, stateStore: rt.stateStore}
}

func newBootstrapEnv(t *testing.T, adminPassword string) *bootstrapEnv {
	t.Helper()
	db := newBootstrapDB(t)
	rt := newBootstrapRuntime(t)
	return setupBootstrapRouter(t, db, rt, config.SeedConfig{
		Enabled:       true,
		AdminUsername: "admin",
		AdminEmail:    "admin@openrealm.local",
		AdminPassword: adminPassword,
	})
}

type loginResult struct {
	AccessToken        string
	RefreshToken       string
	MustChangePassword bool
}

func loginFull(t *testing.T, engine *gin.Engine, username, password string) loginResult {
	t.Helper()
	w := doJSON(t, engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, "", map[string]string{"X-Token-Delivery": "body"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			AccessToken        string `json:"access_token"`
			RefreshToken       string `json:"refresh_token"`
			MustChangePassword bool   `json:"must_change_password"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return loginResult{
		AccessToken:        resp.Data.AccessToken,
		RefreshToken:       resp.Data.RefreshToken,
		MustChangePassword: resp.Data.MustChangePassword,
	}
}

// 验收 1：空库 + 未配置初始口令 / 仍为已知默认值 / 不满足策略 => 初始化失败，且不建号、错误信息不含口令。
func TestBootstrapSeedRequiresExplicitStrongPassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{"未配置初始口令", ""},
		{"仍使用历史默认口令", "Admin@123456"},
		{"长度不足十二位", "Abc12345678"},
		{"缺少数字", "OnlyLettersHere"},
		{"缺少大写字母", "lowercase12345"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newBootstrapDB(t)
			enforcer, err := rbac.NewEnforcer(db)
			require.NoError(t, err)

			seedErr := seed.EnsureDefaults(db, enforcer, config.SeedConfig{
				Enabled:       true,
				AdminUsername: "admin",
				AdminEmail:    "admin@openrealm.local",
				AdminPassword: tc.password,
			}, nil)
			require.Error(t, seedErr)
			if tc.password != "" {
				assert.NotContains(t, seedErr.Error(), tc.password, "错误信息不得包含口令明文")
			}

			var count int64
			require.NoError(t, db.Model(&models.User{}).Where("username = ?", "admin").Count(&count).Error)
			assert.Zero(t, count, "初始化失败时不得创建管理员账号")
		})
	}
}

// 合格口令可以完成初始化，初始管理员带强制改密标记。
func TestBootstrapSeedCreatesFlaggedAdmin(t *testing.T) {
	db := newBootstrapDB(t)
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	require.NoError(t, seed.EnsureDefaults(db, enforcer, config.SeedConfig{
		Enabled:       true,
		AdminUsername: "admin",
		AdminEmail:    "admin@openrealm.local",
		AdminPassword: testSeedAdminPassword,
	}, nil))

	var admin models.User
	require.NoError(t, db.Where("username = ?", "admin").First(&admin).Error)
	assert.True(t, admin.MustChangePassword)
	assert.True(t, security.VerifyPassword(admin.PasswordHash, testSeedAdminPassword))
}

// 验收 2 + 3：强制改密状态下只能改密/退出；管理 API、OAuth 授权、refresh 全部失败；
// 改密后旧口令、旧会话失效，新口令可正常登录并访问业务接口。
func TestMustChangePasswordGateAndRecovery(t *testing.T) {
	const newPassword = "ChangedAdmin@2026#Ok"
	env := newBootstrapEnv(t, testSeedAdminPassword)

	var admin models.User
	require.NoError(t, env.db.Where("username = ?", "admin").First(&admin).Error)
	require.True(t, admin.MustChangePassword)

	login := loginFull(t, env.engine, "admin", testSeedAdminPassword)
	require.NotEmpty(t, login.AccessToken)
	assert.True(t, login.MustChangePassword)
	assert.Empty(t, login.RefreshToken, "强制改密状态不得下发 Refresh Token")

	// 管理 API 拒绝，并给出明确错误码
	denied := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, login.AccessToken)
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
	assert.Contains(t, denied.Body.String(), "password_change_required")

	// GET /auth/me 是唯一放行的读接口：控制台要靠它识别强制改密状态并跳到改密页。
	// 它只回调用者自己的资料，标记照样返回，不会泄露别人的数据。
	meW := doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, login.AccessToken)
	require.Equal(t, http.StatusOK, meW.Code, meW.Body.String())
	assert.Contains(t, meW.Body.String(), "\"must_change_password\":true")

	// OAuth 授权码申请拒绝
	codeW := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth2/codes", map[string]interface{}{
		"client_id":    "any-client",
		"redirect_uri": "http://localhost:3000/cb",
	}, login.AccessToken)
	assert.Equal(t, http.StatusForbidden, codeW.Code, codeW.Body.String())

	// 存量 refresh 会话在强制改密状态下不能续期
	ctx := context.Background()
	require.NoError(t, env.stateStore.SaveRefreshToken(ctx, "preexisting-refresh",
		security.RefreshTokenRecord{UserID: admin.ID, Username: admin.Username}, time.Hour))
	refW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "preexisting-refresh",
	}, "")
	require.Equal(t, http.StatusForbidden, refW.Code, refW.Body.String())
	assert.Contains(t, refW.Body.String(), "password_change_required")

	// 再准备一条改密前签发的会话，用于验证改密后的吊销
	require.NoError(t, env.stateStore.SaveRefreshToken(ctx, "before-change-refresh",
		security.RefreshTokenRecord{UserID: admin.ID, Username: admin.Username}, time.Hour))

	// 改密：只允许用受限令牌调用 /auth/change-password
	chW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
		"old_password": testSeedAdminPassword,
		"new_password": newPassword,
	}, login.AccessToken)
	require.Equal(t, http.StatusOK, chW.Code, chW.Body.String())

	// 旧 Access Token 已被吊销
	assert.Equal(t, http.StatusUnauthorized, doJSON(t, env.engine, http.MethodGet, "/api/v1/auth/me", nil, login.AccessToken).Code)
	// 改密前的 refresh 会话已失效
	oldRefW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "before-change-refresh",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, oldRefW.Code)
	// 旧口令不能登录
	assert.Equal(t, http.StatusUnauthorized, doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": testSeedAdminPassword,
	}, "").Code)

	// 新口令登录：不再被拦，能拿到正常 Refresh Token 并访问管理 API
	relogin := loginFull(t, env.engine, "admin", newPassword)
	assert.False(t, relogin.MustChangePassword)
	require.NotEmpty(t, relogin.RefreshToken)
	assert.Equal(t, http.StatusOK, doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, relogin.AccessToken).Code)

	// 标记已清除
	var updated models.User
	require.NoError(t, env.db.Where("username = ?", "admin").First(&updated).Error)
	assert.False(t, updated.MustChangePassword)
}

// 验收 4：用仍保留默认口令的旧库启动 => 标记强制改密、吊销旧会话，且默认口令只能进入改密流程。
func TestLegacyAdminUsingDefaultPasswordIsForcedToChange(t *testing.T) {
	rt := newBootstrapRuntime(t)
	db := newBootstrapDB(t)

	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	// 先只初始化域/角色/权限，模拟升级前的存量库
	require.NoError(t, seed.EnsureDefaults(db, enforcer, config.SeedConfig{
		Enabled:       false,
		AdminUsername: "admin",
	}, nil))

	legacyHash, err := security.HashPassword("Admin@123456")
	require.NoError(t, err)
	legacy := models.User{
		Username:     "admin",
		Email:        "admin@openrealm.local",
		DisplayName:  "超级管理员",
		PasswordHash: legacyHash,
		Status:       "active",
	}
	require.NoError(t, db.Create(&legacy).Error)

	ctx := context.Background()
	require.NoError(t, rt.stateStore.SaveRefreshToken(ctx, "legacy-session",
		security.RefreshTokenRecord{UserID: legacy.ID, Username: legacy.Username}, time.Hour))
	issuedAt := time.Now().UnixMilli()

	// 启动时会再次执行 seed：账号已存在 => 不重建、不改写密码，只做存量升级
	env := setupBootstrapRouter(t, db, rt, config.SeedConfig{
		Enabled:       true,
		AdminUsername: "admin",
		AdminEmail:    "admin@openrealm.local",
	})

	var updated models.User
	require.NoError(t, db.Where("username = ?", "admin").First(&updated).Error)
	assert.True(t, updated.MustChangePassword, "仍使用历史默认口令的管理员必须被标记强制改密")
	assert.True(t, security.VerifyPassword(updated.PasswordHash, "Admin@123456"), "存量口令不应被改写")

	revoked, err := rt.stateStore.IsIssuedBeforeRevocation(ctx, updated.ID, issuedAt)
	require.NoError(t, err)
	assert.True(t, revoked, "存量管理员的旧会话必须被吊销")

	// 默认口令仍可通过密码校验，但只能进入改密流程
	login := loginFull(t, env.engine, "admin", "Admin@123456")
	assert.True(t, login.MustChangePassword)
	assert.Empty(t, login.RefreshToken)
	blockedW := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", nil, login.AccessToken)
	require.Equal(t, http.StatusForbidden, blockedW.Code)
	assert.Contains(t, blockedW.Body.String(), "password_change_required")

	// 旧 refresh 会话不可用
	refW := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "legacy-session",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, refW.Code)
}

// 验收 5：已改密管理员的旧库 + 重复初始化 => 密码不被覆盖、不重复建号、不重新打标记。
func TestSeedIsIdempotentAndKeepsChangedPassword(t *testing.T) {
	const changedPassword = "ChangedAdmin@2026#Ok"
	db := newBootstrapDB(t)
	rt := newBootstrapRuntime(t)
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)

	cfg := config.SeedConfig{
		Enabled:       true,
		AdminUsername: "admin",
		AdminEmail:    "admin@openrealm.local",
		AdminPassword: testSeedAdminPassword,
	}
	require.NoError(t, seed.EnsureDefaults(db, enforcer, cfg, rt.stateStore))

	newHash, err := security.HashPassword(changedPassword)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.User{}).Where("username = ?", "admin").Updates(map[string]interface{}{
		"password_hash":        newHash,
		"must_change_password": false,
	}).Error)

	// 重复初始化，即使又给了另一个口令也不得覆盖
	cfg.AdminPassword = "AnotherAdmin@2026#Ok"
	require.NoError(t, seed.EnsureDefaults(db, enforcer, cfg, rt.stateStore))

	var admin models.User
	require.NoError(t, db.Where("username = ?", "admin").First(&admin).Error)
	assert.False(t, admin.MustChangePassword)
	assert.True(t, security.VerifyPassword(admin.PasswordHash, changedPassword))
	assert.False(t, security.VerifyPassword(admin.PasswordHash, "AnotherAdmin@2026#Ok"))

	var count int64
	require.NoError(t, db.Model(&models.User{}).Where("username = ?", "admin").Count(&count).Error)
	assert.EqualValues(t, 1, count, "重复初始化不得重复建号")
}
