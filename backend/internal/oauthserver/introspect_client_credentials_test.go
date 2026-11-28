package oauthserver

import (
	"context"
	"encoding/json"
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

// 必须改（复审 e511d44）：客户端凭据（client_credentials）令牌不属于任何用户账号，
// 不能被账号态判定拦下 —— 否则合法的机器对机器令牌会一律内省为 inactive。
// 这条漏洞有两条入口：令牌存储分支拿到空用户主体，JWT 回退分支拿到签发器写死的
// sub="0"；两种都被 subjectRequiresPasswordChange 当成「账号不存在」处理。
// 本用例走真实令牌端点签发客户端凭据令牌，两条分支都要覆盖到。
func TestIntrospectClientCredentialsTokenStaysActive(t *testing.T) {
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

	secretHash, err := security.HashPassword("svc-secret-value")
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.OAuthClient{
		ClientID:         "svc-a",
		ClientSecretHash: secretHash,
		Name:             "svc-a",
		RedirectURIs:     models.StringSlice{"https://svc.example/cb"},
		GrantTypes:       models.StringSlice{"client_credentials"},
		Scopes:           models.StringSlice{"api"},
		IsConfidential:   true,
		Status:           "active",
	}).Error)

	// 1. 真实令牌端点签发客户端凭据令牌
	tokenRouter := gin.New()
	tokenRouter.POST("/oauth2/token", srv.Token)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc-a", "svc-secret-value")
	w := httptest.NewRecorder()
	tokenRouter.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var issued struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))
	require.NotEmpty(t, issued.AccessToken)

	introspect := func(token string) string {
		r := gin.New()
		r.POST("/oauth2/introspect", srv.Introspect)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader("token="+url.QueryEscape(token)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("svc-a", "svc-secret-value")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return rec.Body.String()
	}

	// 2. 令牌存储分支：机器对机器令牌没有用户主体，必须仍然 active，且不被算到某个用户名下
	body := introspect(issued.AccessToken)
	require.Contains(t, body, `"active":true`)
	require.Contains(t, body, `"sub":""`)

	// 3. JWT 回退分支：把令牌从存储里移除，强制走签名校验路径，结论必须一致
	require.NoError(t, srv.tokenStore.RemoveByAccess(context.Background(), issued.AccessToken))
	require.Contains(t, introspect(issued.AccessToken), `"active":true`)

	// 4. 对照组：真实用户令牌在强制改密时仍必须 inactive，
	//    确认上面的放行只针对「没有用户主体」的令牌，而不是把账号态判定关掉。
	user := models.User{
		Username:           "cc_sanity_user",
		Email:              "cc_sanity@openrealm.local",
		PasswordHash:       "x",
		Status:             "active",
		MustChangePassword: true,
	}
	require.NoError(t, db.Create(&user).Error)
	userJWT, _, _, err := jwtMgr.GenerateAccessToken(user.ID, user.Username, user.Email, "openid", "svc-a", time.Hour)
	require.NoError(t, err)
	require.Contains(t, introspect(userJWT), `"active":false`)
}
