package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/settings"
)

type SettingsHandler struct {
	svc      *settings.Service
	auditSvc *audit.Service
}

func NewSettingsHandler(svc *settings.Service, auditSvc *audit.Service) *SettingsHandler {
	return &SettingsHandler{svc: svc, auditSvc: auditSvc}
}

func (h *SettingsHandler) List(c *gin.Context) {
	items, err := h.svc.ListAll()
	if err != nil {
		Fail(c, http.StatusInternalServerError, "查询系统设置失败: "+err.Error())
		return
	}
	OK(c, items)
}

type updateSettingsReq struct {
	Settings map[string]string `json:"settings" binding:"required"`
}

func (h *SettingsHandler) Update(c *gin.Context) {
	var req updateSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数格式错误: "+err.Error())
		return
	}

	before, after, err := h.svc.UpdateBatch(req.Settings, CurrentUserID(c))
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}

	if len(after) > 0 {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "system.settings.update",
			ResourceType: "system_setting",
			ResourceID:   "global",
			Before:       before,
			After:        after,
			Status:       "success",
		})
	}

	items, _ := h.svc.ListAll()
	OK(c, items)
}
