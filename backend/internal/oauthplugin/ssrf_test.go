package oauthplugin_test

import (
	"context"
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

func TestExtraConfigRejectsUnsafeUpstreamURLs(t *testing.T) {
	oauthplugin.SetAllowPrivateUpstream(false)
	t.Cleanup(func() { oauthplugin.SetAllowPrivateUpstream(true) })

	bad := []map[string]any{
		{"token_url": "http://169.254.169.254/latest/meta-data"},
		{"token_url": "https://127.0.0.1/token"},
		{"auth_url": "https://localhost/authorize"},
		{"api_base_url": "https://10.0.0.5"},
		{"issuer_url": "https://user:pw@idp.example.com"},
		{"userinfo_url": "file:///etc/passwd"},
		{"auth_url": 123},
	}
	for _, cfg := range bad {
		assert.Error(t, oauthplugin.ValidateExtraConfig(cfg), "%v", cfg)
	}
	assert.NoError(t, oauthplugin.ValidateExtraConfig(map[string]any{
		"issuer_url": "https://idp.example.com",
		"token_url":  "https://idp.example.com/token",
	}))
	assert.NoError(t, oauthplugin.ValidateExtraConfig(nil))
}

func TestStartLoginRejectsForeignRedirectURI(t *testing.T) {
	db, err := gormOpenMemory()
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	jwtMgr, err := security.NewJWTManager("http://localhost:8080", "", 30*time.Minute)
	require.NoError(t, err)
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)

	svc := oauthplugin.NewService(
		db,
		oauthplugin.NewDefaultRegistry(),
		security.NewStateStore(rdb, "test:"),
		jwtMgr,
		enforcer,
		audit.NewService(db, zap.NewNop()),
		settingsSvc,
	)
	require.NoError(t, db.Create(&models.OAuthProvider{
		Name:         "gh_redirect",
		PluginType:   "github",
		DisplayName:  "GitHub",
		ClientID:     "cid",
		ClientSecret: "sec",
		AutoRegister: true,
		Enabled:      true,
	}).Error)

	_, _, err = svc.StartLogin(context.Background(), "gh_redirect", "https://evil.example.com/oauth/callback/gh_redirect")
	assert.Error(t, err)

	_, _, err = svc.StartLogin(context.Background(), "gh_redirect", "http://localhost:5173/oauth/callback/gh_redirect")
	assert.NoError(t, err)
}
