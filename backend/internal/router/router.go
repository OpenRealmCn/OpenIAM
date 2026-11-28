package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/handlers"
	"github.com/openrealm/openiam/internal/jit"
	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/oauthserver"
	"github.com/openrealm/openiam/internal/otp"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/ratelimit"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/risk"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Dependencies struct {
	Config      *config.BootstrapConfig
	DB          *gorm.DB
	Redis       *redis.Client
	Logger      *zap.Logger
	JWTManager  *security.JWTManager
	StateStore  *security.StateStore
	Enforcer    *rbac.Enforcer
	AuditSvc    *audit.Service
	SettingsSvc *settings.Service
	MailerSvc   *mailer.Service
	PluginSvc   *oauthplugin.Service
	OAuthSrv    *oauthserver.Server
	PluginMgr   *plugins.Manager
	NotifySvc   *notify.Service
	OTPSvc      *otp.Service
	RiskEngine  *risk.Engine
	JITSvc      *jit.Service
}

func Setup(deps Dependencies) (*gin.Engine, error) {
	if deps.Config.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	snap := deps.SettingsSvc.Snapshot()

	generalLimiter, err := ratelimit.NewDynamicIPRateLimiter(
		deps.Redis,
		deps.Config.Redis.KeyPrefix+"rl:general",
		snap.RateLimitEnabled,
		snap.RateLimitGeneralRate,
	)
	if err != nil {
		return nil, err
	}

	authLimiter, err := ratelimit.NewDynamicIPRateLimiter(
		deps.Redis,
		deps.Config.Redis.KeyPrefix+"rl:auth",
		snap.RateLimitEnabled,
		snap.RateLimitAuthRate,
	)
	if err != nil {
		return nil, err
	}

	// 注册系统设置变更热更新钩子
	deps.SettingsSvc.RegisterOnChange(func(s settings.RuntimeSettings) {
		deps.JWTManager.UpdateSettings(s.JWTIssuer, s.JWTAccessTTL)
		deps.OAuthSrv.ApplySettings(s)
		oauthplugin.SetAllowPrivateUpstream(s.AllowPrivateUpstream)
		plugins.SetAllowPrivateUpstream(s.AllowPrivateUpstream)
		trusted := s.TrustedProxies
		if len(trusted) == 0 && deps.Config != nil {
			trusted = deps.Config.Server.TrustedProxies
		}
		clientip.SetPolicy(s.ClientIPMethod, s.ClientIPCustomHeader, trusted)
		if err := generalLimiter.Update(s.RateLimitEnabled, s.RateLimitGeneralRate); err != nil && deps.Logger != nil {
			deps.Logger.Warn("failed to update general rate limiter", zap.Error(err))
		}
		if err := authLimiter.Update(s.RateLimitEnabled, s.RateLimitAuthRate); err != nil && deps.Logger != nil {
			deps.Logger.Warn("failed to update auth rate limiter", zap.Error(err))
		}
	})

	r := gin.New()
	r.Use(gin.Recovery())
	if err := r.SetTrustedProxies(deps.Config.Server.TrustedProxies); err != nil {
		return nil, err
	}
	// 限制请求体最大为 1 MiB，防止超大请求耗尽内存
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
		c.Next()
	})
	r.Use(middleware.ZapLogger(deps.Logger))
	r.Use(middleware.DynamicCORS(func() []string {
		return deps.SettingsSvc.Snapshot().CORSAllowOrigins
	}))
	r.Use(generalLimiter.Middleware())

	authRateMiddleware := authLimiter.Middleware()

	mailSvc := deps.MailerSvc
	if mailSvc == nil {
		mailSvc = mailer.NewService(deps.SettingsSvc)
	}
	pluginMgr := deps.PluginMgr
	if pluginMgr == nil {
		pluginMgr = plugins.NewManager(deps.DB, deps.StateStore, deps.SettingsSvc)
		_ = pluginMgr.EnsureDefaults()
	}
	notifySvc := deps.NotifySvc
	if notifySvc == nil {
		notifySvc = notify.NewService(deps.DB, mailSvc, deps.Enforcer, pluginMgr)
		_ = notifySvc.EnsureDefaultTemplates()
	}
	otpSvc := deps.OTPSvc
	if otpSvc == nil {
		otpSvc = otp.NewService(deps.DB, deps.StateStore, deps.SettingsSvc, mailSvc, notifySvc, pluginMgr)
	}
	riskEngine := deps.RiskEngine
	if riskEngine == nil {
		riskEngine = risk.NewEngine(deps.DB, deps.StateStore, deps.SettingsSvc, notifySvc, deps.AuditSvc)
	}
	jitSvc := deps.JITSvc
	if jitSvc == nil {
		jitSvc = jit.NewService(deps.DB, deps.Enforcer, notifySvc, deps.AuditSvc, deps.Logger)
	}

	authH := handlers.NewAuthHandler(
		deps.DB,
		deps.JWTManager,
		deps.StateStore,
		deps.Enforcer,
		deps.AuditSvc,
		deps.PluginSvc,
		deps.SettingsSvc,
		handlers.WithEnterpriseAuthDeps(pluginMgr, riskEngine, otpSvc, notifySvc),
	)
	userH := handlers.NewUserHandler(deps.DB, deps.Enforcer, deps.AuditSvc, deps.StateStore)
	domainH := handlers.NewDomainHandler(deps.DB, deps.AuditSvc, deps.Enforcer)
	roleH := handlers.NewRoleHandler(deps.DB, deps.Enforcer, deps.AuditSvc)
	permH := handlers.NewPermissionHandler(deps.DB, deps.Enforcer, deps.AuditSvc)
	oauthClientH := handlers.NewOAuthClientHandler(deps.DB, deps.AuditSvc, deps.Enforcer)
	oauthProviderH := handlers.NewOAuthProviderHandler(deps.DB, deps.PluginSvc.Registry(), deps.AuditSvc)
	auditH := handlers.NewAuditHandler(deps.DB, deps.Enforcer)
	systemH := handlers.NewSystemHandler(deps.DB, deps.Redis)
	settingsH := handlers.NewSettingsHandler(deps.SettingsSvc, deps.Enforcer, mailSvc, deps.AuditSvc)
	passkeyH := handlers.NewPasskeyHandler(deps.DB, deps.JWTManager, deps.StateStore, deps.Enforcer, deps.AuditSvc, deps.SettingsSvc)
	totpH := handlers.NewTOTPHandler(deps.DB, deps.SettingsSvc, deps.AuditSvc)
	otpH := handlers.NewOTPHandler(deps.DB, otpSvc)
	riskH := handlers.NewRiskHandler(deps.DB, deps.Enforcer)
	sessionH := handlers.NewSessionHandler(deps.DB, deps.StateStore, deps.Enforcer, deps.AuditSvc, deps.SettingsSvc)
	notifyH := handlers.NewNotificationHandler(deps.DB, notifySvc, deps.Enforcer, deps.AuditSvc)
	jitH := handlers.NewJITHandler(deps.DB, deps.Enforcer, jitSvc, notifySvc, deps.AuditSvc)
	pluginH := handlers.NewPluginHandler(pluginMgr, deps.AuditSvc)

	// OIDC Discovery & JWKS
	r.GET("/.well-known/openid-configuration", deps.OAuthSrv.Discovery)
	r.GET("/.well-known/jwks.json", deps.OAuthSrv.JWKS)

	// OpenIAM OAuth2 授权服务端标准端点
	oauth2Group := r.Group("/oauth2")
	{
		oauth2Group.GET("/authorize", deps.OAuthSrv.Authorize)
		oauth2Group.POST("/token", authRateMiddleware, deps.OAuthSrv.Token)
		oauth2Group.GET("/userinfo", deps.OAuthSrv.UserInfo)
		oauth2Group.POST("/revoke", deps.OAuthSrv.Revoke)
		oauth2Group.POST("/introspect", deps.OAuthSrv.Introspect)
	}

	api := r.Group("/api/v1")
	{
		api.GET("/health", systemH.Health)
		api.GET("/site/info", settingsH.PublicSiteInfo)
		api.GET("/captcha/config", pluginH.GetCaptchaConfig)
		api.POST("/captcha/cap/challenge", authRateMiddleware, pluginH.CreateCapChallenge)
		api.POST("/captcha/cap/redeem", authRateMiddleware, pluginH.RedeemCapChallenge)

		// 公开认证与联合登录端点（受严格 IP 速率限制保护）
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/login", authRateMiddleware, authH.Login)
			authGroup.POST("/register", authRateMiddleware, authH.Register)
			authGroup.POST("/refresh", authRateMiddleware, authH.Refresh)
			authGroup.POST("/otp/send", authRateMiddleware, otpH.Send)
			authGroup.POST("/otp/login", authRateMiddleware, authH.OTPLogin)
			authGroup.POST("/mfa/send-code", authRateMiddleware, authH.SendMFACode)
			authGroup.POST("/mfa/verify", authRateMiddleware, authH.VerifyMFA)
			authGroup.POST("/password-reset/request", authRateMiddleware, authH.RequestPasswordReset(mailSvc))
			authGroup.POST("/password-reset/confirm", authRateMiddleware, authH.ConfirmPasswordReset)
			authGroup.POST("/passkeys/login/begin", authRateMiddleware, passkeyH.BeginPasskeyLogin)
			authGroup.POST("/passkeys/login/finish", authRateMiddleware, passkeyH.FinishPasskeyLogin)
			authGroup.GET("/oauth/providers", authH.ListPublicProviders)
			authGroup.GET("/oauth/:provider/authorize", authRateMiddleware, authH.OAuthAuthorize)
			authGroup.GET("/oauth/:provider/callback", authRateMiddleware, authH.OAuthCallback)
			authGroup.POST("/oauth/:provider/callback", authRateMiddleware, authH.OAuthCallback)
		}

		// 需要认证的路由
		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(deps.JWTManager, deps.StateStore, deps.DB))
		{
			protected.POST("/auth/logout", authH.Logout)
			protected.GET("/auth/me", authH.Me)
			protected.PUT("/auth/me", authH.UpdateProfile)
			protected.POST("/auth/change-password", authH.ChangePassword)
			protected.GET("/auth/me/identities", authH.ListMyIdentities)
			protected.POST("/auth/me/identities/:provider/link", authH.StartBindIdentity)
			protected.DELETE("/auth/me/identities/:id", authH.UnbindIdentity)
			protected.GET("/auth/passkeys", passkeyH.ListPasskeys)
			protected.POST("/auth/passkeys/register/begin", passkeyH.BeginRegisterPasskey)
			protected.POST("/auth/passkeys/register/finish", passkeyH.FinishRegisterPasskey)
			protected.DELETE("/auth/passkeys/:id", passkeyH.DeletePasskey)
			protected.GET("/auth/totp/status", totpH.Status)
			protected.POST("/auth/totp/setup", totpH.Setup)
			protected.POST("/auth/totp/verify-bind", totpH.VerifyBind)
			protected.POST("/auth/totp/unbind", totpH.Unbind)
			protected.POST("/auth/totp/recovery-codes/regenerate", totpH.RegenerateRecoveryCodes)
			protected.GET("/auth/sessions", sessionH.ListMySessions)
			protected.DELETE("/auth/sessions/:sid", sessionH.RevokeMySession)
			protected.POST("/auth/sessions/revoke-all", sessionH.RevokeAllMySessions)
			protected.GET("/auth/risk-events", riskH.ListMy)

			// 站内通知中心（系统消息 / 系统公告 / 系统通知）
			protected.GET("/notifications", notifyH.List)
			protected.GET("/notifications/unread-count", notifyH.UnreadCount)
			protected.POST("/notifications/:id/read", notifyH.MarkRead)
			protected.POST("/notifications/read-all", notifyH.MarkAllRead)
			protected.POST("/notifications/announcements", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.CreateAnnouncement)
			protected.DELETE("/notifications/announcements/:id", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.DeleteAnnouncement)
			protected.GET("/notifications/templates", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.ListTemplates)
			protected.POST("/notifications/templates", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.CreateTemplate)
			protected.PUT("/notifications/templates/:id", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.UpdateTemplate)
			protected.DELETE("/notifications/templates/:id", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.DeleteTemplate)
			protected.POST("/notifications/templates/preview", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.PreviewTemplate)
			protected.GET("/notifications/deliveries", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.ListDeliveries)
			protected.POST("/notifications/deliveries/:id/bounce", middleware.RequireSuperAdmin(deps.Enforcer), notifyH.MarkBounced)

			// OAuth2 授权同意页审批与一次性授权码生成（普通用户默认具备 oauth_clients:authorize 权限）
			protected.GET("/oauth2/consent/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "authorize"), deps.OAuthSrv.GetConsentRequest)
			protected.POST("/oauth2/consent/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "authorize"), deps.OAuthSrv.SubmitConsentDecision)
			protected.POST("/oauth2/codes", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "authorize"), deps.OAuthSrv.CreateAuthorizationCode)

			// 个人 OAuth 应用自助管理（普通用户默认具备 oauth_clients:create_own 权限）
			protected.GET("/my/oauth-clients", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "create_own"), oauthClientH.ListMine)
			protected.POST("/my/oauth-clients", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "create_own"), oauthClientH.CreateMine)
			protected.PUT("/my/oauth-clients/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "create_own"), oauthClientH.UpdateMine)
			protected.POST("/my/oauth-clients/:id/rotate-secret", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "create_own"), oauthClientH.RotateSecretMine)
			protected.DELETE("/my/oauth-clients/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "create_own"), oauthClientH.DeleteMine)

			// 系统、版本与动态设置管理
			protected.GET("/system/version", middleware.RequirePermission(deps.Enforcer, "system", "read"), systemH.VersionInfo)
			protected.GET("/system/dashboard", middleware.RequirePermission(deps.Enforcer, "system", "read"), systemH.Dashboard)
			protected.GET("/system/settings", middleware.RequirePermission(deps.Enforcer, "settings", "read"), settingsH.List)
			// 全局设置属于平台级能力：更新与 SMTP 测试接口显式限定为超管专属（handler 内还有第二次判定）；
			// 读取接口走 Casbin 的 settings:read，同样被 rbac 的平台级闸门限制为仅超管生效。
			protected.PUT("/system/settings", middleware.RequireSuperAdmin(deps.Enforcer), settingsH.Update)
			protected.POST("/system/settings/test-smtp", middleware.RequireSuperAdmin(deps.Enforcer), settingsH.TestSMTP)
			protected.POST("/system/settings/client-ip-preview", middleware.RequireSuperAdmin(deps.Enforcer), settingsH.PreviewClientIP)

			// 域管理（domains 是平台级资源，rbac 闸门保证非超管即使被授予 domains:* 也不生效）
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
			protected.POST("/permissions/simulate", middleware.RequirePermission(deps.Enforcer, "permissions", "read"), permH.SimulatePolicy)

			// JIT 临时权限与到期自动回收
			protected.GET("/jit-grants", middleware.RequirePermission(deps.Enforcer, "roles", "read"), jitH.List)
			protected.POST("/jit-grants", middleware.RequirePermission(deps.Enforcer, "roles", "write"), jitH.Create)
			protected.POST("/jit-grants/:id/revoke", middleware.RequirePermission(deps.Enforcer, "roles", "write"), jitH.Revoke)

			// 会话与设备管理中心
			protected.GET("/sessions", middleware.RequirePermission(deps.Enforcer, "users", "read"), sessionH.ListAllSessions)
			protected.DELETE("/sessions/:sid", middleware.RequirePermission(deps.Enforcer, "users", "write"), sessionH.AdminRevokeSession)
			protected.POST("/users/:id/sessions/revoke-all", middleware.RequirePermission(deps.Enforcer, "users", "write"), sessionH.AdminRevokeUserSessions)

			// 风险自适应事件与 OTP 渠道监控
			protected.GET("/risk-events", middleware.RequirePermission(deps.Enforcer, "audit_logs", "read"), riskH.List)
			protected.GET("/system/otp/stats", middleware.RequireSuperAdmin(deps.Enforcer), otpH.Stats)

			// 统一插件管理（人机验证 Cap / 短信通道 / 通知 / 风控）
			protected.GET("/plugins/drivers", middleware.RequireSuperAdmin(deps.Enforcer), pluginH.ListDrivers)
			protected.GET("/plugins", middleware.RequireSuperAdmin(deps.Enforcer), pluginH.ListInstances)
			protected.POST("/plugins", middleware.RequireSuperAdmin(deps.Enforcer), pluginH.CreateInstance)
			protected.PUT("/plugins/:id", middleware.RequireSuperAdmin(deps.Enforcer), pluginH.UpdateInstance)
			protected.POST("/plugins/:id/test", middleware.RequireSuperAdmin(deps.Enforcer), pluginH.TestInstance)

			// OpenIAM OAuth2 应用管理
			protected.GET("/oauth-clients", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "read"), oauthClientH.List)
			protected.POST("/oauth-clients", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.Create)
			protected.PUT("/oauth-clients/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.Update)
			protected.POST("/oauth-clients/:id/rotate-secret", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.RotateSecret)
			protected.DELETE("/oauth-clients/:id", middleware.RequirePermission(deps.Enforcer, "oauth_clients", "write"), oauthClientH.Delete)

			// 外部 OAuth 联合登录插件管理（oauth_providers 是全局身份源，属平台级资源）
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
