package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

type DomainHandler struct {
	enforcer *rbac.Enforcer
	db       *gorm.DB
	auditSvc *audit.Service
}

func NewDomainHandler(db *gorm.DB, auditSvc *audit.Service, enforcer *rbac.Enforcer) *DomainHandler {
	return &DomainHandler{db: db, auditSvc: auditSvc, enforcer: enforcer}
}

func (h *DomainHandler) List(c *gin.Context) {
	var domains []models.Domain
	q := h.db.Order("id ASC")
	if uid := CurrentUserID(c); !isSuperAdmin(h.enforcer, uid) {
		// 非超级管理员只能看到自己持有角色的域
		roles, _ := h.enforcer.GetAllUserRoles(uid)
		codes := make([]string, 0, len(roles))
		for code := range roles {
			codes = append(codes, code)
		}
		if len(codes) == 0 {
			OK(c, []models.Domain{})
			return
		}
		q = q.Where("code IN ?", codes)
	}
	if err := q.Find(&domains).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询域列表失败")
		return
	}
	OK(c, domains)
}

type createDomainReq struct {
	Code        string `json:"code" binding:"required,min=2,max=64"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

func (h *DomainHandler) Create(c *gin.Context) {
	var req createDomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	code := strings.TrimSpace(req.Code)
	var dup int64
	h.db.Model(&models.Domain{}).Where("code = ?", code).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "域标识已存在")
		return
	}

	status := req.Status
	if status == "" {
		status = "active"
	}
	dom := models.Domain{
		Code:        code,
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		Status:      status,
	}
	if err := h.db.Create(&dom).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "创建域失败: "+err.Error())
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   dom.Code,
		Action:       "domain.create",
		ResourceType: "domain",
		ResourceID:   dom.Code,
		After:        dom,
		Status:       "success",
	})
	Created(c, dom)
}

type updateDomainReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

func (h *DomainHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的域 ID")
		return
	}
	var dom models.Domain
	if err := h.db.First(&dom, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "域不存在")
		return
	}
	before := dom

	var req updateDomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	if req.Name != "" {
		dom.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		dom.Description = strings.TrimSpace(req.Description)
	}
	if req.Status != "" {
		dom.Status = req.Status
	}

	if err := h.db.Save(&dom).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新域失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   dom.Code,
		Action:       "domain.update",
		ResourceType: "domain",
		ResourceID:   dom.Code,
		Before:       before,
		After:        dom,
		Status:       "success",
	})
	OK(c, dom)
}

func (h *DomainHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的域 ID")
		return
	}
	var dom models.Domain
	if err := h.db.First(&dom, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "域不存在")
		return
	}
	if dom.Code == rbac.DefaultDomain {
		Fail(c, http.StatusBadRequest, "默认系统域 openiam 不可删除")
		return
	}
	if err := h.db.Delete(&dom).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除域失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   dom.Code,
		Action:       "domain.delete",
		ResourceType: "domain",
		ResourceID:   dom.Code,
		Before:       dom,
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true})
}
