package oauthserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	oauthmodels "github.com/go-oauth2/oauth2/v4/models"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/openrealm/openiam/internal/version"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 必须改 5：真实入库的 OAuth access token（走 manager.LoadAccessToken 分支）也必须
// 在账号被标记强制改密后内省为 inactive；旧实现只检查了 JWT 回退分支。
func TestIntrospectHidesTokenOfForcedChangeUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)
	snap := settingsSvc.Snapshot()
	jwtMgr, err := security.NewJWTManager(snap.JWTIssuer, "", snap.JWTAccessTTL)
	require.NoError(t, err)
	stateStore := security.NewStateStore(rdb, "openiam:")
	auditSvc := audit.NewService(db, zap.NewNop())

	srv := NewServer(db, rdb, stateStore, jwtMgr, auditSvc, settingsSvc)

	secretHash, err := security.HashPassword("client-secret-value")
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.OAuthClient{
		ClientID:         "client-a",
		ClientSecretHash: secretHash,
		Name:             "client-a",
		RedirectURIs:     models.StringSlice{"https://app.example/cb"},
		GrantTypes:       models.StringSlice{"authorization_code"},
		Scopes:           models.StringSlice{"openid"},
		IsConfidential:   true,
		Status:           "active",
	}).Error)

	user := models.User{Username: "forced_introspect", Email: "forced_introspect@openrealm.local", PasswordHash: "x", Status: "active"}
	require.NoError(t, db.Create(&user).Error)

	ti := oauthmodels.NewToken()
	ti.SetAccess("access-forced-1")
	ti.SetClientID("client-a")
	ti.SetUserID(fmt.Sprintf("%d", user.ID))
	ti.SetAccessCreateAt(time.Now())
	ti.SetAccessExpiresIn(time.Hour)
	require.NoError(t, srv.tokenStore.Create(context.Background(), ti))

	introspect := func() string {
		r := gin.New()
		r.POST("/oauth2/introspect", srv.Introspect)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader("token="+url.QueryEscape("access-forced-1")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("client-a", "client-secret-value")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		return w.Body.String()
	}

	// 对照：正常账号 active:true —— 证明确实走了 token store 分支
	require.Contains(t, introspect(), `"active":true`)

	require.NoError(t, db.Model(&models.User{}).Where("id = ?", user.ID).
		Update("must_change_password", true).Error)
	require.Contains(t, introspect(), `"active":false`)

	// 标记清除后恢复 active:true
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", user.ID).
		Update("must_change_password", false).Error)
	require.Contains(t, introspect(), `"active":true`)

	// 账号被删除：按不可用处理
	require.NoError(t, db.Delete(&models.User{}, user.ID).Error)
	require.Contains(t, introspect(), `"active":false`)
}

// 必须改（复审 485cf582）：JWT 回退分支必须和令牌存储分支共用同一套主体判定。
// 旧实现在这里自己查库，查询失败或账号已删除时不置 revoked，仍然返回 active:true，
// 与令牌存储分支的 fail-closed 结论相反。本用例专门盯这条回退路径。
func TestIntrospectJWTBranchFailsClosedOnSubjectState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)
	snap := settingsSvc.Snapshot()
	jwtMgr, err := security.NewJWTManager(snap.JWTIssuer, "", snap.JWTAccessTTL)
	require.NoError(t, err)
	stateStore := security.NewStateStore(rdb, "openiam:")
	auditSvc := audit.NewService(db, zap.NewNop())

	srv := NewServer(db, rdb, stateStore, jwtMgr, auditSvc, settingsSvc)

	secretHash, err := security.HashPassword("client-secret-value")
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.OAuthClient{
		ClientID:         "client-a",
		ClientSecretHash: secretHash,
		Name:             "client-a",
		RedirectURIs:     models.StringSlice{"https://app.example/cb"},
		GrantTypes:       models.StringSlice{"authorization_code"},
		Scopes:           models.StringSlice{"openid"},
		IsConfidential:   true,
		Status:           "active",
	}).Error)

	user := models.User{Username: "jwt_introspect", Email: "jwt_introspect@openrealm.local", PasswordHash: "x", Status: "active"}
	require.NoError(t, db.Create(&user).Error)

	// 只签发 JWT、不入 token store —— 强制内省走 JWT 回退分支。
	jwtStr, _, _, err := jwtMgr.GenerateAccessToken(user.ID, user.Username, user.Email, "openid", "client-a", time.Hour)
	require.NoError(t, err)

	introspect := func(token string) string {
		r := gin.New()
		r.POST("/oauth2/introspect", srv.Introspect)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader("token="+url.QueryEscape(token)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("client-a", "client-secret-value")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		return w.Body.String()
	}

	// 对照：正常账号 active:true
	require.Contains(t, introspect(jwtStr), `"active":true`)

	// 标记强制改密 → inactive
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", user.ID).
		Update("must_change_password", true).Error)
	require.Contains(t, introspect(jwtStr), `"active":false`)

	require.NoError(t, db.Model(&models.User{}).Where("id = ?", user.ID).
		Update("must_change_password", false).Error)
	require.Contains(t, introspect(jwtStr), `"active":true`)

	// 账号被删除 → 仍须 inactive（旧实现在这里会给出 active:true）
	require.NoError(t, db.Delete(&models.User{}, user.ID).Error)
	require.Contains(t, introspect(jwtStr), `"active":false`)

	// 用户查询本身失败（表被删）→ 同样必须 fail-closed
	require.NoError(t, db.Migrator().DropTable(&models.User{}))
	require.Contains(t, introspect(jwtStr), `"active":false`)
}
