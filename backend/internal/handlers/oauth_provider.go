package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

type OAuthProviderHandler struct {
	db       *gorm.DB
	registry *oauthplugin.Registry
	auditSvc *audit.Service
}

func NewOAuthProviderHandler(db *gorm.DB, registry *oauthplugin.Registry, auditSvc *audit.Service) *OAuthProviderHandler {
	return &OAuthProviderHandler{db: db, registry: registry, auditSvc: auditSvc}
}

// ListPlugins 返回所有已注册的联合登录插件及其动态配置表单结构。
func (h *OAuthProviderHandler) ListPlugins(c *gin.Context) {
	OK(c, h.registry.ListMetadata())
}

type providerView struct {
	models.OAuthProvider
	HasClientSecret bool `json:"has_client_secret"`
}

func (h *OAuthProviderHandler) List(c *gin.Context) {
	var providers []models.OAuthProvider
	if err := h.db.Order("id ASC").Find(&providers).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询联合登录配置失败")
		return
	}
	res := make([]providerView, 0, len(providers))
	for _, p := range providers {
		res = append(res, providerView{
			OAuthProvider:   p,
			HasClientSecret: p.ClientSecret != "",
		})
	}
	OK(c, res)
}

type upsertProviderReq struct {
	Name         string                 `json:"name" binding:"required"`
	PluginType   string                 `json:"plugin_type" binding:"required"`
	DisplayName  string                 `json:"display_name" binding:"required"`
	ClientID     string                 `json:"client_id" binding:"required"`
	ClientSecret string                 `json:"client_secret"`
	Scopes       string                 `json:"scopes"`
	ExtraConfig  map[string]interface{} `json:"extra_config"`
	AutoRegister *bool                  `json:"auto_register"`
	Enabled      *bool                  `json:"enabled"`
}

func (h *OAuthProviderHandler) Create(c *gin.Context) {
	var req upsertProviderReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, bindError(err))
		return
	}
	if _, ok := h.registry.Get(req.PluginType); !ok {
		Fail(c, http.StatusBadRequest, "未知的插件类型: "+req.PluginType)
		return
	}
	if err := oauthplugin.ValidateExtraConfig(req.ExtraConfig); err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	var dup int64
	h.db.Model(&models.OAuthProvider{}).Where("name = ?", name).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "联合登录配置标识已存在")
		return
	}

	autoReg := true
	if req.AutoRegister != nil {
		autoReg = *req.AutoRegister
	}
	enabled := false
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	sealedSecret, err := security.SealField(req.ClientSecret)
	if err != nil {
		failInternal(c, "加密 client secret 失败", err)
		return
	}
	p := models.OAuthProvider{
		Name:         name,
		PluginType:   req.PluginType,
		DisplayName:  strings.TrimSpace(req.DisplayName),
		ClientID:     strings.TrimSpace(req.ClientID),
		ClientSecret: sealedSecret,
		Scopes:       strings.TrimSpace(req.Scopes),
		ExtraConfig:  models.JSONMap(req.ExtraConfig),
		AutoRegister: autoReg,
		Enabled:      enabled,
	}
	if err := h.db.Create(&p).Error; err != nil {
		failWrite(c, err, "同名联合登录配置已存在", "创建联合登录配置失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "oauth_provider.create",
		ResourceType: "oauth_provider",
		ResourceID:   p.Name,
		After:        p,
		Status:       "success",
	})
	Created(c, providerView{OAuthProvider: p, HasClientSecret: p.ClientSecret != ""})
}

func (h *OAuthProviderHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的配置 ID")
		return
	}
	var p models.OAuthProvider
	if err := h.db.First(&p, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "联合登录配置不存在")
		return
	}
	before := p

	var req upsertProviderReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, bindError(err))
		return
	}
	if _, ok := h.registry.Get(req.PluginType); !ok {
		Fail(c, http.StatusBadRequest, "未知的插件类型: "+req.PluginType)
		return
	}

	if err := oauthplugin.ValidateExtraConfig(req.ExtraConfig); err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	p.PluginType = req.PluginType
	p.DisplayName = strings.TrimSpace(req.DisplayName)
	p.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientSecret != "" {
		sealedSecret, sErr := security.SealField(req.ClientSecret)
		if sErr != nil {
			failInternal(c, "加密 client secret 失败", sErr)
			return
		}
		p.ClientSecret = sealedSecret
	}
	p.Scopes = strings.TrimSpace(req.Scopes)
	if req.ExtraConfig != nil {
		p.ExtraConfig = models.JSONMap(req.ExtraConfig)
	}
	if req.AutoRegister != nil {
		p.AutoRegister = *req.AutoRegister
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}

	if err := h.db.Save(&p).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新联合登录配置失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "oauth_provider.update",
		ResourceType: "oauth_provider",
		ResourceID:   p.Name,
		Before:       before,
		After:        p,
		Status:       "success",
	})
	OK(c, providerView{OAuthProvider: p, HasClientSecret: p.ClientSecret != ""})
}

func (h *OAuthProviderHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的配置 ID")
		return
	}
	var p models.OAuthProvider
	if err := h.db.First(&p, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "联合登录配置不存在")
		return
	}
	if err := h.db.Delete(&p).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除联合登录配置失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "oauth_provider.delete",
		ResourceType: "oauth_provider",
		ResourceID:   p.Name,
		Before:       p,
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true})
}
