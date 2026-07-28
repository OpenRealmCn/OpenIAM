package oauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/response"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type Module struct {
	db    *gorm.DB
	cache *redis.Client
}

func New(db *gorm.DB, cache *redis.Client) *Module {
	return &Module{db: db, cache: cache}
}

func (m *Module) Name() string { return "oauth" }

func (m *Module) RegisterRoutes(api *gin.RouterGroup) {
	group := api.Group("/oauth")
	group.GET("/capabilities", func(c *gin.Context) {
		response.Data(c, http.StatusOK, gin.H{
			"module": m.Name(),
			"planned": []string{
				"authorization-code",
				"pkce-s256",
				"openid-connect",
				"refresh-token-rotation",
			},
		})
	})
}
