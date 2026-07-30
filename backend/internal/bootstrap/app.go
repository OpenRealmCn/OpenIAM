package bootstrap

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/modules/audit"
	identityrepo "github.com/openrealm/openiam/backend/internal/modules/identity/repository"
	identityservice "github.com/openrealm/openiam/backend/internal/modules/identity/service"
	identityhttp "github.com/openrealm/openiam/backend/internal/modules/identity/transport/http"
	"github.com/openrealm/openiam/backend/internal/modules/oauth"
	"github.com/openrealm/openiam/backend/internal/modules/oauth/feishu"
	rbacrepo "github.com/openrealm/openiam/backend/internal/modules/rbac/repository"
	rbacservice "github.com/openrealm/openiam/backend/internal/modules/rbac/service"
	rbachttp "github.com/openrealm/openiam/backend/internal/modules/rbac/transport/http"
	"github.com/openrealm/openiam/backend/internal/modules/session"
	"github.com/openrealm/openiam/backend/internal/modules/system"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/mailer"
	"github.com/openrealm/openiam/backend/internal/platform/middleware"
	"github.com/openrealm/openiam/backend/internal/platform/ratelimit"
	"github.com/openrealm/openiam/backend/internal/platform/response"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type App struct {
	Router *gin.Engine
}

func New(router *gin.Engine, cfg config.Config, db *gorm.DB, cache *redis.Client, log *zap.Logger) *App {
	registerHealthRoutes(router, db, cache)

	sessions := session.NewManager(cache, cfg.Session, cfg.Redis.KeyPrefix)
	limiter := ratelimit.New(cache, cfg.Redis.KeyPrefix)

	auditSvc := audit.NewService(db)

	mail := mailer.New(cfg.SMTP, log)
	notifier := identityservice.NewEmailNotifier(mail, cfg.SMTP.FromName, log)

	userRepo := identityrepo.New(db)
	authSvc := identityservice.NewAuthService(userRepo, sessions, cfg.Security, auditSvc)
	userSvc := identityservice.NewUserService(userRepo, cfg.Security, notifier)

	rbacRepo := rbacrepo.New(db)
	checker := rbacservice.NewChecker(rbacRepo, cache, cfg.Redis.KeyPrefix)
	roleSvc := rbacservice.NewRoleService(rbacRepo, checker, auditSvc)
	grantSvc := rbacservice.NewGrantService(rbacRepo, checker, auditSvc)

	authHandler := identityhttp.NewAuthHandler(authSvc, sessions, checker, limiter, cfg.Session.CookieName)
	userHandler := identityhttp.NewUserHandler(userSvc, checker)
	rbacHandler := rbachttp.NewHandler(roleSvc, grantSvc, userRepo)
	mailHandler := system.NewMailHandler(mail)

	feishuProvider := feishu.NewHTTPProvider(feishu.Config{
		AppID:       cfg.Feishu.AppID,
		AppSecret:   cfg.Feishu.AppSecret,
		RedirectURI: cfg.Feishu.RedirectURI,
		BaseURL:     cfg.Feishu.BaseURL,
	}, nil)
	federationHandler := oauth.NewFederationHandler(
		feishuProvider,
		cfg.Feishu.Enabled(),
		cache,
		cfg.Redis.KeyPrefix,
		authSvc,
		sessions,
		cfg.Feishu.FrontendURL,
		log,
	)

	api := router.Group("/api/v1")

	authGroup := api.Group("/auth")
	authGroup.POST("/login", authHandler.Login)
	authGroup.GET("/feishu", federationHandler.FeishuLogin)
	authGroup.GET("/feishu/callback", federationHandler.FeishuCallback)
	authGroup.GET("/providers", func(c *gin.Context) {
		response.Data(c, http.StatusOK, gin.H{
			"feishu": cfg.Feishu.Enabled(),
		})
	})

	protected := api.Group("", middleware.Authenticate(sessions, cfg.Session.CookieName))
	protected.GET("/auth/me", authHandler.Me)
	protected.POST("/auth/logout", middleware.RequireCSRF(), authHandler.Logout)

	protected.GET("/users", middleware.RequirePermission(checker, log, "users:read"), userHandler.List)
	protected.POST("/users", middleware.RequireCSRF(), middleware.RequirePermission(checker, log, "users:create"), userHandler.Create)
	protected.GET("/users/:id", middleware.RequirePermission(checker, log, "users:read"), userHandler.Get)
	protected.PATCH("/users/:id", middleware.RequireCSRF(), middleware.RequirePermission(checker, log, "users:update"), userHandler.Update)
	protected.GET("/users/:id/roles", middleware.RequirePermission(checker, log, "roles:read"), rbacHandler.GetUserRoles)
	protected.PUT("/users/:id/roles", middleware.RequireCSRF(), middleware.RequirePermission(checker, log, "roles:assign"), rbacHandler.ReplaceUserRoles)

	protected.GET("/roles", middleware.RequirePermission(checker, log, "roles:read"), rbacHandler.ListRoles)
	protected.POST("/roles", middleware.RequireCSRF(), middleware.RequirePermission(checker, log, "roles:create"), rbacHandler.CreateRole)
	protected.GET("/roles/:code", middleware.RequirePermission(checker, log, "roles:read"), rbacHandler.GetRole)
	protected.PUT("/roles/:code/permissions", middleware.RequireCSRF(), middleware.RequirePermission(checker, log, "roles:update"), rbacHandler.ReplaceRolePermissions)
	protected.DELETE("/roles/:code", middleware.RequireCSRF(), middleware.RequirePermission(checker, log, "roles:delete"), rbacHandler.DeleteRole)

	protected.GET("/permissions", middleware.RequirePermission(checker, log, "permissions:read"), rbacHandler.ListPermissions)

	protected.POST("/system/mail/test",
		middleware.RequireCSRF(),
		middleware.RequirePermission(checker, log, "system:mail-test"),
		mailHandler.SendTest,
	)

	log.Info("api routes registered",
		zap.String("cookie", cfg.Session.CookieName),
		zap.Duration("session_ttl", cfg.Session.TTL),
		zap.Bool("smtp_enabled", cfg.SMTP.Enabled()),
		zap.Bool("feishu_enabled", cfg.Feishu.Enabled()),
	)

	return &App{Router: router}
}

func registerHealthRoutes(router *gin.Engine, db *gorm.DB, cache *redis.Client) {
	router.GET("/health/live", func(c *gin.Context) {
		response.Data(c, http.StatusOK, gin.H{"status": "ok"})
	})

	router.GET("/health/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		sqlDB, err := db.DB()
		if err != nil || sqlDB.PingContext(ctx) != nil {
			response.Error(c, http.StatusServiceUnavailable, "DEPENDENCY_MYSQL_UNAVAILABLE", "MySQL is unavailable")
			return
		}
		if err := cache.Ping(ctx).Err(); err != nil {
			response.Error(c, http.StatusServiceUnavailable, "DEPENDENCY_REDIS_UNAVAILABLE", "Redis is unavailable")
			return
		}

		response.Data(c, http.StatusOK, gin.H{"status": "ready"})
	})
}
