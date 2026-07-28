package identity

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/response"
	"gorm.io/gorm"
)

type Module struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Module {
	return &Module{db: db}
}

func (m *Module) Name() string { return "identity" }

func (m *Module) RegisterRoutes(api *gin.RouterGroup) {
	group := api.Group("/identity")
	group.GET("/capabilities", func(c *gin.Context) {
		response.Data(c, http.StatusOK, gin.H{
			"module":   m.Name(),
			"features": []string{"users", "credentials", "account-status"},
		})
	})
}
