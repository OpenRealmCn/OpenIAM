package session

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/response"
	"github.com/redis/go-redis/v9"
)

type Module struct {
	cache  *redis.Client
	config config.SessionConfig
}

func New(cache *redis.Client, cfg config.SessionConfig) *Module {
	return &Module{cache: cache, config: cfg}
}

func (m *Module) Name() string { return "session" }

func (m *Module) RegisterRoutes(api *gin.RouterGroup) {
	group := api.Group("/session")
	group.GET("/capabilities", func(c *gin.Context) {
		response.Data(c, http.StatusOK, gin.H{
			"module":   m.Name(),
			"features": []string{"opaque-cookie", "rotation", "revocation"},
		})
	})
}
