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
	domain, all := scopedDomain(c, h.enforcer)
	q := h.db.Model(&models.Permission{})
	if !all {
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

	if !requireDomainPermission(c, h.enforcer, domain, "permissions", "write") {
		return
	}
	// 平台级权限点只在平台超管手里维护，避免域内权限体系里出现全局能力的入口。
	if !h.enforcer.IsSuperAdmin(CurrentUserID(c)) &&
		rbac.IsPlatformPermission(strings.TrimSpace(req.Resource), strings.TrimSpace(req.Action)) {
		Fail(c, http.StatusForbidden, "平台级权限点仅超级管理员可维护")
		return
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
	if !requireDomainPermission(c, h.enforcer, perm.DomainCode, "permissions", "write") {
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
	// 按合并后的最终 resource/action 判定：不允许把域内权限点改造成平台级能力。
	if !h.enforcer.IsSuperAdmin(CurrentUserID(c)) && rbac.IsPlatformPermission(perm.Resource, perm.Action) {
		Fail(c, http.StatusForbidden, "平台级权限点仅超级管理员可维护")
		return
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
	if !requireDomainPermission(c, h.enforcer, perm.DomainCode, "permissions", "write") {
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
	domain, all := scopedDomain(c, h.enforcer)
	if all {
		domain = ""
	}
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
	req.Role = strings.TrimSpace(req.Role)
	req.Domain = strings.TrimSpace(req.Domain)
	req.Resource = strings.TrimSpace(req.Resource)
	req.Action = strings.TrimSpace(req.Action)
	if !requirePolicyWriteAccess(c, h.enforcer, req.Role, req.Domain, req.Resource, req.Action, true) {
		return
	}
	// 策略写入同样受「可委派上限 ∩ 调用者自身权限」约束，并且在写入前确认角色属于该域，
	// 否则可以给 B 域角色或幽灵角色挂权限，等角色被引用时一次性放大。
	if !validateDelegablePolicies(c, h.enforcer, req.Domain, []rbac.Permission{{Resource: req.Resource, Action: req.Action}}) {
		return
	}
	if !h.requireRoleInDomain(c, req.Role, req.Domain) {
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
	req.Role = strings.TrimSpace(req.Role)
	req.Domain = strings.TrimSpace(req.Domain)
	req.Resource = strings.TrimSpace(req.Resource)
	req.Action = strings.TrimSpace(req.Action)
	if !requirePolicyWriteAccess(c, h.enforcer, req.Role, req.Domain, req.Resource, req.Action, false) {
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

// requireRoleInDomain 校验策略目标角色确实存在于该域；超管不受限。
// 用于阻断「引用其它域的角色」「为不存在的角色预先挂权限」两类写入。
func (h *PermissionHandler) requireRoleInDomain(c *gin.Context, role, domain string) bool {
	if h.enforcer.IsSuperAdmin(CurrentUserID(c)) {
		return true
	}
	var count int64
	if err := h.db.Model(&models.Role{}).Where("domain_code = ? AND code = ?", domain, role).Count(&count).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询角色失败")
		return false
	}
	if count == 0 {
		Fail(c, http.StatusForbidden, "角色 ["+role+"] 不存在于域 ["+domain+"]，禁止跨域引用角色")
		return false
	}
	return true
}

// CheckPolicy 提供实时权限仿真校验接口，同时供 OpenRealm 业务微服务或控制台测试调用。
func (h *PermissionHandler) CheckPolicy(c *gin.Context) {
	var req checkPolicyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数无效: "+err.Error())
		return
	}
	// 查询他人权限需要在目标域拥有 permissions:read；查询自身权限不受限
	if req.UserID != CurrentUserID(c) && !requireDomainPermission(c, h.enforcer, req.Domain, "permissions", "read") {
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
