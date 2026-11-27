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

type RoleHandler struct {
	db       *gorm.DB
	enforcer *rbac.Enforcer
	auditSvc *audit.Service
}

func NewRoleHandler(db *gorm.DB, enforcer *rbac.Enforcer, auditSvc *audit.Service) *RoleHandler {
	return &RoleHandler{db: db, enforcer: enforcer, auditSvc: auditSvc}
}

type roleDetail struct {
	models.Role
	Permissions []rbac.PolicyRule `json:"permissions"`
	MemberCount int               `json:"member_count"`
}

func (h *RoleHandler) List(c *gin.Context) {
	domain, all := scopedDomain(c, h.enforcer)
	q := h.db.Model(&models.Role{})
	if !all {
		q = q.Where("domain_code = ?", domain)
	}
	var roles []models.Role
	if err := q.Order("domain_code ASC, id ASC").Find(&roles).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询角色列表失败")
		return
	}

	details := make([]roleDetail, 0, len(roles))
	for _, r := range roles {
		perms, _ := h.enforcer.GetPolicies(r.DomainCode, r.Code)
		members, _ := h.enforcer.GetUsersForRoleInDomain(r.Code, r.DomainCode)
		details = append(details, roleDetail{
			Role:        r,
			Permissions: perms,
			MemberCount: len(members),
		})
	}
	OK(c, details)
}

type createRoleReq struct {
	DomainCode  string `json:"domain_code"`
	Code        string `json:"code" binding:"required,min=2,max=64"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

func (h *RoleHandler) Create(c *gin.Context) {
	var req createRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	domain := strings.TrimSpace(req.DomainCode)
	if domain == "" {
		domain = middleware.ResolveDomain(c)
	}
	code := strings.TrimSpace(req.Code)
	if !requireDomainPermission(c, h.enforcer, domain, "roles", "write") {
		return
	}
	// 超管角色标识是平台保留常量，非超管不得创建同名角色（防止伪造超管身份的数据）。
	if code == rbac.SuperAdminRole && !isSuperAdmin(h.enforcer, CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅超级管理员可创建超级管理员角色")
		return
	}

	var dup int64
	h.db.Model(&models.Role{}).Where("domain_code = ? AND code = ?", domain, code).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "该域下角色标识已存在")
		return
	}

	role := models.Role{
		DomainCode:  domain,
		Code:        code,
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		IsSystem:    false,
	}
	if err := h.db.Create(&role).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "创建角色失败: "+err.Error())
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   domain,
		Action:       "rbac.role.create",
		ResourceType: "role",
		ResourceID:   fmt.Sprintf("%s:%s", domain, role.Code),
		After:        role,
		Status:       "success",
	})
	Created(c, role)
}

type updateRoleReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *RoleHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的角色 ID")
		return
	}
	var role models.Role
	if err := h.db.First(&role, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "角色不存在")
		return
	}
	if !requireRoleMutation(c, h.enforcer, role) {
		return
	}
	before := role

	var req updateRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	if req.Name != "" {
		role.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		role.Description = strings.TrimSpace(req.Description)
	}
	if err := h.db.Save(&role).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新角色失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   role.DomainCode,
		Action:       "rbac.role.update",
		ResourceType: "role",
		ResourceID:   fmt.Sprintf("%s:%s", role.DomainCode, role.Code),
		Before:       before,
		After:        role,
		Status:       "success",
	})
	OK(c, role)
}

func (h *RoleHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的角色 ID")
		return
	}
	var role models.Role
	if err := h.db.First(&role, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "角色不存在")
		return
	}
	if role.IsSystem {
		Fail(c, http.StatusBadRequest, "内置系统角色不可删除")
		return
	}

	if !requireRoleMutation(c, h.enforcer, role) {
		return
	}

	beforePolicies, _ := h.enforcer.GetPolicies(role.DomainCode, role.Code)
	beforeMembers, _ := h.enforcer.GetUsersForRoleInDomain(role.Code, role.DomainCode)

	if err := h.db.Delete(&role).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除角色失败")
		return
	}
	_, _ = h.enforcer.RemovePoliciesForRoleInDomain(role.Code, role.DomainCode)
	_, _ = h.enforcer.RemoveGroupingForRoleInDomain(role.Code, role.DomainCode)

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   role.DomainCode,
		Action:       "rbac.role.delete",
		ResourceType: "role",
		ResourceID:   fmt.Sprintf("%s:%s", role.DomainCode, role.Code),
		Before: map[string]interface{}{
			"role":       role,
			"policies":   beforePolicies,
			"member_ids": beforeMembers,
		},
		Status: "success",
	})
	OK(c, gin.H{"deleted": true})
}

func (h *RoleHandler) GetPermissions(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的角色 ID")
		return
	}
	var role models.Role
	if err := h.db.First(&role, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "角色不存在")
		return
	}
	if !requireDomainPermission(c, h.enforcer, role.DomainCode, "roles", "read") {
		return
	}
	policies, err := h.enforcer.GetPolicies(role.DomainCode, role.Code)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "获取角色权限失败")
		return
	}
	OK(c, policies)
}

type rolePolicyItem struct {
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

type setRolePermissionsReq struct {
	Policies []rolePolicyItem `json:"policies" binding:"required"`
}

// SetPermissions 全量更新指定角色的 Casbin 权限策略并记录变更前后审计快照。
func (h *RoleHandler) SetPermissions(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的角色 ID")
		return
	}
	var role models.Role
	if err := h.db.First(&role, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "角色不存在")
		return
	}
	var req setRolePermissionsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}

	if !requireRoleMutation(c, h.enforcer, role) {
		return
	}
	requested := make([]rbac.Permission, 0, len(req.Policies))
	for _, p := range req.Policies {
		res := strings.TrimSpace(p.Resource)
		act := strings.TrimSpace(p.Action)
		if !validatePolicyScope(c, h.enforcer, role.Code, res, act) {
			return
		}
		requested = append(requested, rbac.Permission{Resource: res, Action: act})
	}
	// 全量替换后的最终生效权限集合必须落在调用者自身权限与可委派上限之内，
	// 否则「先建空角色→授给自己→再加高权」就能绕过授予侧。
	if !validateDelegablePolicies(c, h.enforcer, role.DomainCode, requested) {
		return
	}

	beforePolicies, _ := h.enforcer.GetPolicies(role.DomainCode, role.Code)
	_, _ = h.enforcer.RemovePoliciesForRoleInDomain(role.Code, role.DomainCode)
	for _, p := range req.Policies {
		_, _ = h.enforcer.AddPolicy(role.Code, role.DomainCode, strings.TrimSpace(p.Resource), strings.TrimSpace(p.Action))
	}
	afterPolicies, _ := h.enforcer.GetPolicies(role.DomainCode, role.Code)

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   role.DomainCode,
		Action:       "rbac.role_permission.set",
		ResourceType: "role_policy",
		ResourceID:   fmt.Sprintf("%s:%s", role.DomainCode, role.Code),
		Before:       map[string]interface{}{"role": role.Code, "domain": role.DomainCode, "policies": beforePolicies},
		After:        map[string]interface{}{"role": role.Code, "domain": role.DomainCode, "policies": afterPolicies},
		Status:       "success",
	})

	OK(c, afterPolicies)
}
