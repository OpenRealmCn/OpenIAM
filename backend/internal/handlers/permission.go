package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

type PermissionHandler struct {
	db       *gorm.DB
	enforcer *rbac.Enforcer
	auditSvc *audit.Service
}

func NewPermissionHandler(db *gorm.DB, enforcer *rbac.Enforcer, auditSvc *audit.Service) *PermissionHandler {
	return &PermissionHandler{db: db, enforcer: enforcer, auditSvc: auditSvc}
}

func (h *PermissionHandler) List(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	q := h.db.Model(&models.Permission{})
	if domain != "" && domain != "*" {
		q = q.Where("domain_code = ?", domain)
	}
	var perms []models.Permission
	if err := q.Order("domain_code ASC, id ASC").Find(&perms).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询权限点失败")
		return
	}
	OK(c, perms)
}

type createPermissionReq struct {
	DomainCode  string `json:"domain_code"`
	Code        string `json:"code" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Resource    string `json:"resource" binding:"required"`
	Action      string `json:"action" binding:"required"`
	Description string `json:"description"`
}

func (h *PermissionHandler) Create(c *gin.Context) {
	var req createPermissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	domain := strings.TrimSpace(req.DomainCode)
	if domain == "" {
		domain = middleware.ResolveDomain(c)
	}

	var dup int64
	h.db.Model(&models.Permission{}).Where("domain_code = ? AND code = ?", domain, req.Code).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "该域下权限编码已存在")
		return
	}

	perm := models.Permission{
		DomainCode:  domain,
		Code:        strings.TrimSpace(req.Code),
		Name:        strings.TrimSpace(req.Name),
		Resource:    strings.TrimSpace(req.Resource),
		Action:      strings.TrimSpace(req.Action),
		Description: strings.TrimSpace(req.Description),
	}
	if err := h.db.Create(&perm).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "创建权限点失败: "+err.Error())
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   domain,
		Action:       "rbac.permission.create",
		ResourceType: "permission",
		ResourceID:   fmt.Sprintf("%s:%s", domain, perm.Code),
		After:        perm,
		Status:       "success",
	})
	Created(c, perm)
}

type updatePermissionReq struct {
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

func (h *PermissionHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的权限点 ID")
		return
	}
	var perm models.Permission
	if err := h.db.First(&perm, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "权限点不存在")
		return
	}
	before := perm

	var req updatePermissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	if req.Name != "" {
		perm.Name = strings.TrimSpace(req.Name)
	}
	if req.Resource != "" {
		perm.Resource = strings.TrimSpace(req.Resource)
	}
	if req.Action != "" {
		perm.Action = strings.TrimSpace(req.Action)
	}
	if req.Description != "" {
		perm.Description = strings.TrimSpace(req.Description)
	}
	if err := h.db.Save(&perm).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新权限点失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   perm.DomainCode,
		Action:       "rbac.permission.update",
		ResourceType: "permission",
		ResourceID:   fmt.Sprintf("%s:%s", perm.DomainCode, perm.Code),
		Before:       before,
		After:        perm,
		Status:       "success",
	})
	OK(c, perm)
}

func (h *PermissionHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的权限点 ID")
		return
	}
	var perm models.Permission
	if err := h.db.First(&perm, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "权限点不存在")
		return
	}
	if err := h.db.Delete(&perm).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除权限点失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   perm.DomainCode,
		Action:       "rbac.permission.delete",
		ResourceType: "permission",
		ResourceID:   fmt.Sprintf("%s:%s", perm.DomainCode, perm.Code),
		Before:       perm,
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true})
}

func (h *PermissionHandler) ListPolicies(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	role := strings.TrimSpace(c.Query("role"))
	rules, err := h.enforcer.GetPolicies(domain, role)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "查询 Casbin 策略失败")
		return
	}
	OK(c, rules)
}

type policyReq struct {
	Role     string `json:"role" binding:"required"`
	Domain   string `json:"domain" binding:"required"`
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

func (h *PermissionHandler) AddPolicy(c *gin.Context) {
	var req policyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "策略参数无效: "+err.Error())
		return
	}
	added, err := h.enforcer.AddPolicy(req.Role, req.Domain, req.Resource, req.Action)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "添加策略失败: "+err.Error())
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   req.Domain,
		Action:       "rbac.policy.add",
		ResourceType: "casbin_policy",
		ResourceID:   fmt.Sprintf("%s:%s:%s:%s", req.Role, req.Domain, req.Resource, req.Action),
		After:        req,
		Status:       "success",
	})
	OK(c, gin.H{"added": added, "policy": req})
}

func (h *PermissionHandler) RemovePolicy(c *gin.Context) {
	var req policyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "策略参数无效: "+err.Error())
		return
	}
	removed, err := h.enforcer.RemovePolicy(req.Role, req.Domain, req.Resource, req.Action)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "删除策略失败: "+err.Error())
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   req.Domain,
		Action:       "rbac.policy.remove",
		ResourceType: "casbin_policy",
		ResourceID:   fmt.Sprintf("%s:%s:%s:%s", req.Role, req.Domain, req.Resource, req.Action),
		Before:       req,
		Status:       "success",
	})
	OK(c, gin.H{"removed": removed})
}

type checkPolicyReq struct {
	UserID   uint64 `json:"user_id" binding:"required"`
	Domain   string `json:"domain" binding:"required"`
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

// CheckPolicy 提供实时权限仿真校验接口，同时供 OpenRealm 业务微服务或控制台测试调用。
func (h *PermissionHandler) CheckPolicy(c *gin.Context) {
	var req checkPolicyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数无效: "+err.Error())
		return
	}
	allowed, err := h.enforcer.Enforce(req.UserID, req.Domain, req.Resource, req.Action)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "校验失败: "+err.Error())
		return
	}
	roles := h.enforcer.GetRolesForUserInDomain(req.UserID, req.Domain)
	OK(c, gin.H{
		"allowed": allowed,
		"roles":   roles,
	})
}
