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
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

type UserHandler struct {
	stateStore *security.StateStore
	db         *gorm.DB
	enforcer   *rbac.Enforcer
	auditSvc   *audit.Service
}

func NewUserHandler(db *gorm.DB, enforcer *rbac.Enforcer, auditSvc *audit.Service, stateStore *security.StateStore) *UserHandler {
	return &UserHandler{db: db, enforcer: enforcer, auditSvc: auditSvc, stateStore: stateStore}
}

type userWithRoles struct {
	models.User
	Roles map[string][]string `json:"roles"`
}

func (h *UserHandler) List(c *gin.Context) {
	page, size, offset := ParsePagination(c)
	keyword := strings.TrimSpace(c.Query("keyword"))
	status := strings.TrimSpace(c.Query("status"))

	q := h.db.Model(&models.User{})
	if keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("username LIKE ? OR email LIKE ? OR display_name LIKE ?", like, like, like)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var total int64
	q.Count(&total)

	var users []models.User
	if err := q.Order("id DESC").Limit(size).Offset(offset).Find(&users).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询用户失败")
		return
	}

	items := make([]userWithRoles, 0, len(users))
	for _, u := range users {
		roles, _ := h.enforcer.GetAllUserRoles(u.ID)
		roles = visibleRoles(c, h.enforcer, roles)
		items = append(items, userWithRoles{User: u, Roles: roles})
	}

	OK(c, PagedResult{Items: items, Total: total, Page: page, Size: size})
}

func (h *UserHandler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	var user models.User
	if err := h.db.First(&user, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	roles, _ := h.enforcer.GetAllUserRoles(user.ID)
	roles = visibleRoles(c, h.enforcer, roles)
	OK(c, userWithRoles{User: user, Roles: roles})
}

type createUserReq struct {
	Username    string   `json:"username" binding:"required,min=3,max=64,excludes=@"`
	Email       string   `json:"email" binding:"required,email"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password" binding:"required,min=8,max=72"`
	Status      string   `json:"status"`
	DomainCode  string   `json:"domain_code"`
	RoleCodes   []string `json:"role_codes"`
}

func (h *UserHandler) Create(c *gin.Context) {
	var req createUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}

	roleDomain := strings.TrimSpace(req.DomainCode)
	if roleDomain == "" {
		roleDomain = middleware.ResolveDomain(c)
	}
	if len(req.RoleCodes) > 0 {
		if !requireDomainPermission(c, h.enforcer, roleDomain, "roles", "write") {
			return
		}
		if rejectSuperAdminGrant(c, h.enforcer, req.RoleCodes) {
			return
		}
		// 建号时夹带角色同样是一次授予，必须过可委派上限检查。
		if !h.requireAssignableRoles(c, roleDomain, req.RoleCodes) {
			return
		}
	}
	if req.Status != "" && req.Status != "active" && req.Status != "disabled" {
		Fail(c, http.StatusBadRequest, "无效的用户状态")
		return
	}

	var dup int64
	h.db.Model(&models.User{}).Where("username = ? OR email = ?", req.Username, req.Email).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "用户名或邮箱已存在")
		return
	}

	hash, err := security.HashPassword(req.Password)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "密码加密失败")
		return
	}
	status := req.Status
	if status == "" {
		status = "active"
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = req.Username
	}

	user := models.User{
		Username:     strings.TrimSpace(req.Username),
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  displayName,
		PasswordHash: hash,
		Status:       status,
	}
	if err := h.db.Create(&user).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "创建用户失败")
		return
	}

	domain := req.DomainCode
	if domain == "" {
		domain = middleware.ResolveDomain(c)
	}
	for _, rc := range req.RoleCodes {
		_, _ = h.enforcer.AddRoleForUserInDomain(user.ID, rc, domain)
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   domain,
		Action:       "user.create",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		After: map[string]interface{}{
			"user":       user,
			"role_codes": req.RoleCodes,
		},
		Status: "success",
	})

	roles, _ := h.enforcer.GetAllUserRoles(user.ID)
	Created(c, userWithRoles{User: user, Roles: roles})
}

type updateUserReq struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
	Status      string `json:"status"`
}

func (h *UserHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	var user models.User
	if err := h.db.First(&user, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, id) {
		return
	}
	before := user

	var req updateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}

	if req.Email != "" {
		user.Email = strings.TrimSpace(req.Email)
	}
	if req.DisplayName != "" {
		user.DisplayName = strings.TrimSpace(req.DisplayName)
	}
	if req.AvatarURL != "" {
		user.AvatarURL = strings.TrimSpace(req.AvatarURL)
	}
	if req.Status != "" {
		if req.Status != "active" && req.Status != "disabled" {
			Fail(c, http.StatusBadRequest, "无效的用户状态")
			return
		}
		user.Status = req.Status
	}

	if err := h.db.Save(&user).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新用户失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		Action:       "user.update",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Before:       before,
		After:        user,
		Status:       "success",
	})
	if before.Status == "active" && user.Status != "active" {
		_ = h.stateStore.RevokeUserTokens(c.Request.Context(), user.ID)
	}
	OK(c, user)
}

func (h *UserHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	if id == CurrentUserID(c) {
		Fail(c, http.StatusBadRequest, "不能删除当前登录账号")
		return
	}
	var user models.User
	if err := h.db.First(&user, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}

	if protectSuperAdminTarget(c, h.enforcer, id) {
		return
	}
	if err := h.db.Delete(&user).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除用户失败")
		return
	}
	_, _ = h.enforcer.RemoveGroupingForUser(id)
	_ = h.db.Where("user_id = ?", id).Delete(&models.UserIdentity{}).Error

	h.auditSvc.RecordFromContext(c, audit.Entry{
		Action:       "user.delete",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", id),
		Before:       user,
		Status:       "success",
	})
	_ = h.stateStore.RevokeUserTokens(c.Request.Context(), id)
	OK(c, gin.H{"deleted": true})
}

type resetPasswordReq struct {
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

func (h *UserHandler) ResetPassword(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "新密码需为 8~72 位")
		return
	}
	var user models.User
	if err := h.db.First(&user, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, id) {
		return
	}
	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "加密失败")
		return
	}
	if err := h.db.Model(&user).Update("password_hash", hash).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "重置密码失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		Action:       "user.reset_password",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		After:        map[string]interface{}{"username": user.Username},
		Status:       "success",
	})
	if err := h.stateStore.RevokeUserTokens(c.Request.Context(), user.ID); err != nil {
		Fail(c, http.StatusInternalServerError, "密码已重置，但撤销旧会话失败，请重试")
		return
	}
	OK(c, gin.H{"reset": true})
}

func (h *UserHandler) GetRoles(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	domain := strings.TrimSpace(c.Query("domain"))
	if domain != "" {
		if domain != middleware.ResolveDomain(c) && !isSuperAdmin(h.enforcer, CurrentUserID(c)) {
			Fail(c, http.StatusForbidden, "无权查看其他域的角色")
			return
		}
		roles := h.enforcer.GetRolesForUserInDomain(id, domain)
		OK(c, gin.H{"domain": domain, "roles": roles})
		return
	}
	all, err := h.enforcer.GetAllUserRoles(id)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "查询角色失败")
		return
	}
	OK(c, visibleRoles(c, h.enforcer, all))
}

type assignRolesReq struct {
	DomainCode string   `json:"domain_code" binding:"required"`
	RoleCodes  []string `json:"role_codes" binding:"required"`
	Replace    bool     `json:"replace"` // true 时替换该域下原有角色；false 时增量添加
}

// requireAssignableRoles 校验把 roleCodes 授予目标域用户后不会造成越权：
//  1. 角色必须真实存在于目标域（禁止引用其它域的角色，也禁止挂不存在的角色）；
//  2. 角色在该域的最终生效权限集合必须落在调用者可委派上限与自身权限内
//     —— 直接授予一个已存在的高权角色同样会被拦下。
//
// 超管不受限。注意这里看的是角色「当前」的最终权限，而不是角色名或角色是否内置。
func (h *UserHandler) requireAssignableRoles(c *gin.Context, domain string, roleCodes []string) bool {
	if h.enforcer.IsSuperAdmin(CurrentUserID(c)) {
		return true
	}
	seen := make(map[string]struct{}, len(roleCodes))
	for _, rc := range roleCodes {
		code := strings.TrimSpace(rc)
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}

		var role models.Role
		if err := h.db.Where("domain_code = ? AND code = ?", domain, code).First(&role).Error; err != nil {
			Fail(c, http.StatusForbidden, "角色 ["+code+"] 不存在于域 ["+domain+"]，禁止跨域引用角色")
			return false
		}
		rules, err := h.enforcer.GetPolicies(domain, code)
		if err != nil {
			Fail(c, http.StatusInternalServerError, "查询角色权限失败")
			return false
		}
		if !validateDelegablePolicies(c, h.enforcer, domain, policiesToPermissions(rules)) {
			return false
		}
	}
	return true
}

// AssignRoles 为用户在指定域分配或替换角色，并记录完整前后审计快照。
func (h *UserHandler) AssignRoles(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	var user models.User
	if err := h.db.First(&user, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}

	var req assignRolesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}

	req.DomainCode = strings.TrimSpace(req.DomainCode)
	if !requireDomainPermission(c, h.enforcer, req.DomainCode, "roles", "write") {
		return
	}
	if rejectSuperAdminGrant(c, h.enforcer, req.RoleCodes) {
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, id) {
		return
	}
	if !h.requireAssignableRoles(c, req.DomainCode, req.RoleCodes) {
		return
	}

	beforeRoles := h.enforcer.GetRolesForUserInDomain(id, req.DomainCode)

	if req.Replace {
		for _, oldRole := range beforeRoles {
			_, _ = h.enforcer.DeleteRoleForUserInDomain(id, oldRole, req.DomainCode)
		}
	}
	for _, rc := range req.RoleCodes {
		if strings.TrimSpace(rc) != "" {
			_, _ = h.enforcer.AddRoleForUserInDomain(id, strings.TrimSpace(rc), req.DomainCode)
		}
	}

	afterRoles := h.enforcer.GetRolesForUserInDomain(id, req.DomainCode)

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   req.DomainCode,
		Action:       "rbac.user_role.assign",
		ResourceType: "user_role",
		ResourceID:   fmt.Sprintf("%d:%s", id, req.DomainCode),
		Before:       map[string]interface{}{"user_id": id, "username": user.Username, "domain": req.DomainCode, "roles": beforeRoles},
		After:        map[string]interface{}{"user_id": id, "username": user.Username, "domain": req.DomainCode, "roles": afterRoles},
		Status:       "success",
	})

	OK(c, gin.H{
		"user_id": id,
		"domain":  req.DomainCode,
		"roles":   afterRoles,
	})
}

func (h *UserHandler) RevokeRole(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	roleCode := c.Param("roleCode")
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" {
		domain = middleware.ResolveDomain(c)
	}

	if !requireDomainPermission(c, h.enforcer, domain, "roles", "write") {
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, id) {
		return
	}

	beforeRoles := h.enforcer.GetRolesForUserInDomain(id, domain)
	_, err = h.enforcer.DeleteRoleForUserInDomain(id, roleCode, domain)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "移除角色失败")
		return
	}
	afterRoles := h.enforcer.GetRolesForUserInDomain(id, domain)

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   domain,
		Action:       "rbac.user_role.revoke",
		ResourceType: "user_role",
		ResourceID:   fmt.Sprintf("%d:%s:%s", id, domain, roleCode),
		Before:       map[string]interface{}{"user_id": id, "domain": domain, "roles": beforeRoles},
		After:        map[string]interface{}{"user_id": id, "domain": domain, "roles": afterRoles},
		Status:       "success",
	})

	OK(c, gin.H{"roles": afterRoles})
}
