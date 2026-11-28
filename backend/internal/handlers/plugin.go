package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/rbac"
)

type PluginHandler struct {
	mgr      *plugins.Manager
	auditSvc *audit.Service
}

func NewPluginHandler(mgr *plugins.Manager, auditSvc *audit.Service) *PluginHandler {
	return &PluginHandler{mgr: mgr, auditSvc: auditSvc}
}

// GetCaptchaConfig 公开返回前端人机验证所需的插槽配置。
func (h *PluginHandler) GetCaptchaConfig(c *gin.Context) {
	OK(c, h.mgr.GetCaptchaPublicConfig())
}

// CreateCapChallenge 公开生成 Cap PoW 本地挑战包（与 trycap.dev 协议兼容）。
func (h *PluginHandler) CreateCapChallenge(c *gin.Context) {
	bundle, err := h.mgr.CreateCapChallenge(c.Request.Context())
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusOK, bundle)
}

type capRedeemReq struct {
	Token     string  `json:"token" binding:"required"`
	Solutions []int64 `json:"solutions" binding:"required"`
}

// RedeemCapChallenge 公开核销客户端提交的 Cap PoW 解答，返回一次性验证令牌。
func (h *PluginHandler) RedeemCapChallenge(c *gin.Context) {
	var req capRedeemReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "提交参数格式无效")
		return
	}
	tok, exp, err := h.mgr.RedeemCapChallenge(c.Request.Context(), req.Token, req.Solutions)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"token":   tok,
		"expires": exp,
	})
}

func (h *PluginHandler) ListDrivers(c *gin.Context) {
	OK(c, h.mgr.ListDrivers(strings.TrimSpace(c.Query("slot"))))
}

func (h *PluginHandler) ListInstances(c *gin.Context) {
	items, err := h.mgr.ListInstances(strings.TrimSpace(c.Query("slot")))
	if err != nil {
		Fail(c, http.StatusInternalServerError, "查询插件实例失败")
		return
	}
	OK(c, items)
}

type createPluginReq struct {
	Name        string         `json:"name" binding:"required"`
	Slot        string         `json:"slot"`
	PluginType  string         `json:"plugin_type" binding:"required"`
	DisplayName string         `json:"display_name" binding:"required"`
	Config      models.JSONMap `json:"config"`
	Enabled     bool           `json:"enabled"`
	Priority    int            `json:"priority"`
}

func (h *PluginHandler) CreateInstance(c *gin.Context) {
	var req createPluginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, bindError(err))
		return
	}
	if req.Priority == 0 {
		req.Priority = 100
	}
	inst := models.PluginInstance{
		Name:         strings.TrimSpace(req.Name),
		Slot:         strings.TrimSpace(req.Slot),
		PluginType:   strings.TrimSpace(req.PluginType),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		Config:       req.Config,
		Enabled:      req.Enabled,
		Priority:     req.Priority,
		HealthStatus: "unknown",
	}
	if err := h.mgr.CreateInstance(&inst); err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "plugin.create",
		ResourceType: "plugin_instance",
		ResourceID:   inst.Name,
		After:        h.mgr.SanitizeInstance(inst),
		Status:       "success",
	})
	Created(c, h.mgr.SanitizeInstance(inst))
}

type updatePluginReq struct {
	DisplayName string         `json:"display_name"`
	Config      models.JSONMap `json:"config"`
	Enabled     *bool          `json:"enabled"`
	Priority    *int           `json:"priority"`
}

func (h *PluginHandler) UpdateInstance(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的插件 ID")
		return
	}
	var req updatePluginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	updated, err := h.mgr.UpdateInstance(id, req.DisplayName, req.Config, req.Enabled, req.Priority)
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "plugin.update",
		ResourceType: "plugin_instance",
		ResourceID:   updated.Name,
		After:        updated,
		Status:       "success",
	})
	OK(c, updated)
}

func (h *PluginHandler) TestInstance(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的插件 ID")
		return
	}
	status, err := h.mgr.TestInstance(c.Request.Context(), id)
	if err != nil {
		Fail(c, http.StatusBadGateway, fmt.Sprintf("插件健康检查失败 (%s): %s", status, err.Error()))
		return
	}
	OK(c, gin.H{"status": status})
}
