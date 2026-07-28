package bootstrap

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/modules"
	"github.com/openrealm/openiam/backend/internal/modules/audit"
	"github.com/openrealm/openiam/backend/internal/modules/identity"
	"github.com/openrealm/openiam/backend/internal/modules/oauth"
	"github.com/openrealm/openiam/backend/internal/modules/rbac"
	"github.com/openrealm/openiam/backend/internal/modules/session"
	"github.com/openrealm/openiam/backend/internal/platform/config"
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

	api := router.Group("/api/v1")
	loadedModules := []modules.Module{
		identity.New(db),
		rbac.New(db, cache),
		session.New(cache, cfg.Session),
		oauth.New(db, cache),
		audit.New(db),
	}

	for _, module := range loadedModules {
		module.RegisterRoutes(api)
		log.Info("module registered", zap.String("module", module.Name()))
	}

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
