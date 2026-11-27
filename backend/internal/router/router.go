package router

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/handlers"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/oauthserver"
	"github.com/openrealm/openiam/internal/ratelimit"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Dependencies struct {
	Config     *config.Config
	DB         *gorm.DB
	Redis      *redis.Client
	Logger     *zap.Logger
	JWTManager *security.JWTManager
	StateStore *security.StateStore
	Enforcer   *rbac.Enforcer
	AuditSvc   *audit.Service
	PluginSvc  *oauthplugin.Service
	OAuthSrv   *oauthserver.Server
}

func Setup(deps Dependencies) (*gin.Engine, error) {
	if deps.Config.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.ZapLogger(deps.Logger))
	r.Use(middleware.CORS(deps.Config.Server.CORSAllowOrigins))

	if deps.Config.RateLimit.Enabled {
		generalLimiter, err := ratelimit.NewIPRateLimiter(deps.Redis, deps.Config.RateLimit.GeneralRate, deps.Config.Redis.KeyPrefix+"rl:general")
		if err != nil {
			return nil, err
		}
		r.Use(generalLimiter)
	}

	var authRateLimiter gin.HandlerFunc
	if deps.Config.RateLimit.Enabled {
		var err error
		authRateLimiter, err = ratelimit.NewIPRateLimiter(deps.Redis, deps.Config.RateLimit.AuthRate, deps.Config.Redis.KeyPrefix+"rl:auth")
		if err != nil {
			return nil, err
		}
	} else {
		authRateLimiter = func(c *gin.Context) { c.Next() }
	}

	refreshTTL := time.Duration(deps.Config.JWT.RefreshTokenTTLHours) * time.Hour

	authH := handlers.NewAuthHandler(
		deps.DB,
		deps.JWTManager,
		deps.StateStore,
		deps.Enforcer,
		deps.AuditSvc,
		deps.PluginSvc,
		deps.Config.Security,
		refreshTTL,
	)
	userH := handlers.NewUserHandler(deps.DB, deps.Enforcer, deps.AuditSvc)
	domainH := handlers.NewDomainHandler(deps.DB, deps.AuditSvc)
	roleH := handlers.NewRoleHandler(deps.DB, deps.Enforcer, deps.AuditSvc)
	permH := handlers.NewPermissionHandler(deps.DB, deps.Enforcer, deps.AuditSvc)
	oauthClientH := handlers.NewOAuthClientHandler(deps.DB, deps.AuditSvc)
	oauthProviderH := handlers.NewOAuthProviderHandler(deps.DB, deps.PluginSvc.Registry(), deps.AuditSvc)
	auditH := handlers.NewAuditHandler(deps.DB)
	systemH := handlers.NewSystemHandler(deps.DB, deps.Redis)

	// OIDC Discovery & JWKS
	r.GET("/.well-known/openid-configuration", deps.OAuthSrv.Discovery)
	r.GET("/.well-known/jwks.json", deps.OAuthSrv.JWKS)

	// OpenIAM OAuth2 授权服务端标准端点
	oauth2Group := r.Group("/oauth2")
	{
		oauth2Group.GET("/authorize", deps.OAuthSrv.Authorize)
		oauth2Group.POST("/token", authRateLimiter, deps.OAuthSrv.Token)
		oauth2Group.GET("/userinfo", deps.OAuthSrv.UserInfo)
		oauth2Group.POST("/revoke", deps.OAuthSrv.Revoke)
		oauth2Group.POST("/introspect", deps.OAuthSrv.Introspect)
	}

	api := r.Group("/api/v1")
	{
		api.GET("/health", systemH.Health)

		// 公开认证与联合登录端点（受严格 IP 速率限制保护）
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/login", authRateLimiter, authH.Login)
			authGroup.POST("/register", authRateLimiter, authH.Register)
			authGroup.POST("/refresh", authRateLimiter, authH.Refresh)
			authGroup.GET("/oauth/providers", authH.ListPublicProviders)
			authGroup.GET("/oauth/:provider/authorize", authRateLimiter, authH.OAuthAuthorize)
			authGroup.GET("/oauth/:provider/callback", authRateLimiter, authH.OAuthCallback)
			authGroup.POST("/oauth/:provider/callback", authRateLimiter, authH.OAuthCallback)
		}

		// 需要认证的路由
		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(deps.JWTManager, deps.StateStore, deps.DB))
		{
			protected.POST("/auth/logout", authH.Logout)
			protected.GET("/auth/me", authH.Me)
			protected.POST("/auth/change-password", authH.ChangePassword)

			// OAuth2 授权同意页审批接口
			protected.GET("/oauth2/consent/:id", deps.OAuthSrv.GetConsentRequest)
			protected.POST("/oauth2/consent/:id", deps.OAuthSrv.SubmitConsentDecision)

			// 系统与版本状态
			protected.GET("/system/version", middleware.RequirePermission(deps.Enforcer, "system", "read"), systemH.VersionInfo)
			protected.GET("/system/dashboard", middleware.RequirePermission(deps.Enforcer, "system", "read"), systemH.Dashboard)

			// 域管理
			protected.GET("/domains", domainH.List)
			protected.POST("/domains", middleware.RequirePermission(deps.Enforcer, "domains", "write"), domainH.Create)
			protected.PUT("/domains/:id", middleware.RequirePermission(deps.Enforcer, "domains", "write"), domainH.Update)
			protected.DELETE("/domains/:id", middleware.RequirePermission(deps.Enforcer, "domains", "write"), domainH.Delete)

			// 用户管理与域角色分配
			protected.GET("/users", middleware.RequirePermission(deps.Enforcer, "users", "read"), userH.List)
			protected.GET("/users/:id", middleware.RequirePermission(deps.Enforcer, "users", "read"), userH.Get)
			protected.POST("/users", middleware.RequirePermission(deps.Enforcer, "users", "write"), userH.Create)
			protected.PUT("/users/:id", middleware.RequirePermission(deps.Enforcer, "users", "write"), userH.Update)
			protected.DELETE("/users/:id", middleware.RequirePermission(deps.Enforcer, "users", "write"), userH.Delete)
			protected.POST("/users/:id/reset-password", middleware.RequirePermission(deps.Enforcer, "users", "write"), userH.ResetPassword)
			protected.GET("/users/:id/roles", middleware.RequirePermission(deps.Enforcer, "roles", "read"), userH.GetRoles)
			protected.POST("/users/:id/roles", middleware.RequirePermission(deps.Enforcer, "roles", "write"), userH.AssignRoles)
			protected.DELETE("/users/:id/roles/:roleCode", middleware.RequirePermission(deps.Enforcer, "roles", "write"), userH.RevokeRole)

			// 角色管理与权限策略绑定
			protected.GET("/roles", middleware.RequirePermission(deps.Enforcer, "roles", "read"), roleH.List)
			protected.POST("/roles", middleware.RequirePermission(deps.Enforcer, "roles", "write"), roleH.Create)
			protected.PUT("/roles/:id", middleware.RequirePermission(deps.Enforcer, "roles", "write"), roleH.Update)
			protected.DELETE("/roles/:id", middleware.RequirePermission(deps.Enforcer, "roles", "write"), roleH.Delete)
			protected.GET("/roles/:id/permissions", middleware.RequirePermission(deps.Enforcer, "roles", "read"), roleH.GetPermissions)
			protected.PUT("/roles/:id/permissions", middleware.RequirePermission(deps.Enforcer, "roles", "write"), roleH.SetPermissions)

			// 权限点目录与 Casbin 策略管理
			protected.GET("/permissions", middleware.RequirePermission(deps.Enforcer, "permissions", "read"), permH.List)
			protected.POST("/permissions", middleware.RequirePermission(deps.Enforcer, "permissions", "write"), permH.Create)
			protected.PUT("/permissions/:id", middleware.RequirePermission(deps.Enforcer, "permissions", "write"), permH.Update)
			protected.DELETE("/permissions/:id", middleware.RequirePermission(deps.Enforcer, "permissions", "write"), permH.Delete)
			protected.GET("/policies", middleware.RequirePermission(deps.Enforcer, "permissions", "read"), permH.ListPolicies)
			protected.POST("/policies", middleware.RequirePermission(deps.Enforcer, "permissions", "write"), permH.AddPolicy)
			protected.DELETE("/policies", middleware.RequirePermission(deps.Enforcer, "permissions", "write"), permH.RemovePolicy)
			protected.POST("/policies/check", middleware.RequirePermission(deps.Enforcer, "permissions", "read"), permH.CheckPolicy)

			// OpenIAM OAuth2 应用管理
			protected.GET("/oauth-clients", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "read"), oauthClientH.List)
			protected.POST("/oauth-clients", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.Create)
			protected.PUT("/oauth-clients/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.Update)
			protected.POST("/oauth-clients/:id/rotate-secret", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.RotateSecret)
			protected.DELETE("/oauth-clients/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.Delete)

			// 外部 OAuth 联合登录插件管理
			protected.GET("/oauth-providers/plugins", middleware.RequirePermission(deps.Enforcer, "oauth_providers", "read"), oauthProviderH.ListPlugins)
			protected.GET("/oauth-providers", middleware.RequirePermission(deps.Enforcer, "oauth_providers", "read"), oauthProviderH.List)
			protected.POST("/oauth-providers", middleware.RequirePermission(deps.Enforcer, "oauth_providers", "write"), oauthProviderH.Create)
			protected.PUT("/oauth-providers/:id", middleware.RequirePermission(deps.Enforcer, "oauth_providers", "write"), oauthProviderH.Update)
			protected.DELETE("/oauth-providers/:id", middleware.RequirePermission(deps.Enforcer, "oauth_providers", "write"), oauthProviderH.Delete)

			// 审计日志查询与统计
			protected.GET("/audit-logs", middleware.RequirePermission(deps.Enforcer, "audit_logs", "read"), auditH.List)
			protected.GET("/audit-logs/stats", middleware.RequirePermission(deps.Enforcer, "audit_logs", "read"), auditH.Stats)
		}
	}

	return r, nil
}
