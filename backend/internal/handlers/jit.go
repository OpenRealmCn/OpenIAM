package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/jit"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

type JITHandler struct {
	db        *gorm.DB
	enforcer  *rbac.Enforcer
	jitSvc    *jit.Service
	notifySvc *notify.Service
	auditSvc  *audit.Service
}

func NewJITHandler(db *gorm.DB, enforcer *rbac.Enforcer, jitSvc *jit.Service, notifySvc *notify.Service, auditSvc *audit.Service) *JITHandler {
	return &JITHandler{db: db, enforcer: enforcer, jitSvc: jitSvc, notifySvc: notifySvc, auditSvc: auditSvc}
}

type jitGrantView struct {
	models.TempRoleGrant
	Username string `json:"username"`
}

func (h *JITHandler) List(c *gin.Context) {
	domain, all := scopedDomain(c, h.enforcer)
	q := h.db.Model(&models.TempRoleGrant{})
	if !all {
		q = q.Where("domain_code = ?", domain)
	} else if d := strings.TrimSpace(c.Query("domain")); d != "" {
		q = q.Where("domain_code = ?", d)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		q = q.Where("status = ?", status)
	}
	var rows []models.TempRoleGrant
	if err := q.Order("id DESC").Limit(200).Find(&rows).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询临时权限记录失败")
		return
	}
	uidSet := make([]uint64, 0, len(rows))
	seen := make(map[uint64]bool)
	for _, r := range rows {
		if !seen[r.UserID] {
			seen[r.UserID] = true
			uidSet = append(uidSet, r.UserID)
		}
	}
	nameMap := make(map[uint64]string)
	if len(uidSet) > 0 {
		var users []models.User
		_ = h.db.Select("id, username").Where("id IN ?", uidSet).Find(&users).Error
		for _, u := range users {
			nameMap[u.ID] = u.Username
		}
	}
	out := make([]jitGrantView, 0, len(rows))
	for _, r := range rows {
		out = append(out, jitGrantView{
			TempRoleGrant: r,
			Username:      nameMap[r.UserID],
		})
	}
	OK(c, out)
}

type createJITReq struct {
	UserID     uint64 `json:"user_id" binding:"required"`
	DomainCode string `json:"domain_code"`
	RoleCode   string `json:"role_code" binding:"required"`
	Reason     string `json:"reason"`
	StartsAt   string `json:"starts_at"`
	ExpiresAt  string `json:"expires_at"`
	TTLMinutes int    `json:"ttl_minutes"`
}

func (h *JITHandler) Create(c *gin.Context) {
	var req createJITReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	domain := strings.TrimSpace(req.DomainCode)
	if domain == "" {
		domain = middleware.ResolveDomain(c)
	}
	roleCode := strings.TrimSpace(req.RoleCode)

	if !requireDomainPermission(c, h.enforcer, domain, "roles", "write") {
		return
	}
	if rejectSuperAdminGrant(c, h.enforcer, []string{roleCode}) ||
		protectSuperAdminTarget(c, h.enforcer, req.UserID) ||
		!requireTargetInDomain(c, h.enforcer, req.UserID) {
		return
	}

	var targetUser models.User
	if err := h.db.First(&targetUser, req.UserID).Error; err != nil {
		Fail(c, http.StatusNotFound, "目标用户不存在")
		return
	}
	var role models.Role
	if err := h.db.Where("domain_code = ? AND code = ?", domain, roleCode).First(&role).Error; err != nil {
		Fail(c, http.StatusBadRequest, "目标域下不存在该角色")
		return
	}
	// 目标用户已持有该角色时拒绝临时授权，否则到期回收会把用户原有的永久角色一并删除
	for _, held := range h.enforcer.GetRolesForUserInDomain(req.UserID, domain) {
		if held == roleCode {
			Fail(c, http.StatusConflict, "目标用户已持有该角色，无需临时授权")
			return
		}
	}

	// 非超管仅可临时授予策略全部在自身权限与可委派上限内的角色
	rules, _ := h.enforcer.GetPolicies(domain, roleCode)
	if !validateDelegablePolicies(c, h.enforcer, domain, policiesToPermissions(rules)) {
		return
	}

	now := time.Now()
	startsAt := now
	if strings.TrimSpace(req.StartsAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.StartsAt))
		if err != nil {
			Fail(c, http.StatusBadRequest, "生效时间格式无效（需 RFC3339 格式）")
			return
		}
		startsAt = parsed
	}

	var expiresAt time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			Fail(c, http.StatusBadRequest, "到期时间格式无效（需 RFC3339 格式）")
			return
		}
		expiresAt = parsed
	} else if req.TTLMinutes > 0 {
		expiresAt = startsAt.Add(time.Duration(req.TTLMinutes) * time.Minute)
	} else {
		expiresAt = startsAt.Add(2 * time.Hour)
	}

	if !expiresAt.After(startsAt) || !expiresAt.After(now) {
		Fail(c, http.StatusBadRequest, "到期时间必须晚于生效时间及当前时间")
		return
	}
	if expiresAt.Sub(startsAt) > 30*24*time.Hour || startsAt.After(now.Add(30*24*time.Hour)) {
		Fail(c, http.StatusBadRequest, "临时授权有效期不得超过 30 天，且生效时间不得晚于 30 天后")
		return
	}

	status := "pending"
	var activatedAt *time.Time
	if !startsAt.After(now) {
		if _, err := h.enforcer.AddRoleForUserInDomain(req.UserID, roleCode, domain); err != nil {
			Fail(c, http.StatusInternalServerError, "激活临时角色失败")
			return
		}
		status = "active"
		activatedAt = &now
	}

	grant := models.TempRoleGrant{
		UserID:      req.UserID,
		DomainCode:  domain,
		RoleCode:    roleCode,
		Reason:      strings.TrimSpace(req.Reason),
		GrantedBy:   CurrentUserID(c),
		StartsAt:    startsAt,
		ExpiresAt:   expiresAt,
		Status:      status,
		ActivatedAt: activatedAt,
	}
	if err := h.db.Create(&grant).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "创建临时权限记录失败")
		return
	}

	if h.notifySvc != nil {
		_, _ = h.notifySvc.SendInApp(c.Request.Context(), grant.UserID, notify.CategorySystemMessage, "info",
			"获得临时权限授权",
			fmt.Sprintf("管理员已为您授予域 %s 下角色「%s」（状态：%s），将于 %s 自动回收。原因：%s",
				domain, roleCode, status, expiresAt.Format("2006-01-02 15:04"), grant.Reason),
			models.JSONMap{"grant_id": grant.ID, "domain": domain, "role": roleCode},
			CurrentUserID(c), nil)
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   domain,
		Action:       "rbac.jit.create",
		ResourceType: "temp_role_grant",
		ResourceID:   fmt.Sprintf("%d", grant.ID),
		After:        grant,
		Status:       "success",
	})
	Created(c, grant)
}

func (h *JITHandler) Revoke(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的授权 ID")
		return
	}
	var grant models.TempRoleGrant
	if err := h.db.First(&grant, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "临时权限记录不存在")
		return
	}
	if !requireDomainPermission(c, h.enforcer, grant.DomainCode, "roles", "write") {
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, grant.UserID) {
		return
	}
	if grant.Status != "active" && grant.Status != "pending" {
		Fail(c, http.StatusBadRequest, "该记录已处于结束状态")
		return
	}
	wasActive := grant.Status == "active"
	now := time.Now()
	actorID := CurrentUserID(c)
	_ = h.db.Model(&grant).Updates(map[string]interface{}{
		"status":     "revoked",
		"revoked_at": &now,
		"revoked_by": actorID,
	}).Error

	if wasActive {
		var otherActive int64
		h.db.Model(&models.TempRoleGrant{}).
			Where("user_id = ? AND domain_code = ? AND role_code = ? AND status = ? AND id <> ?",
				grant.UserID, grant.DomainCode, grant.RoleCode, "active", grant.ID).
			Count(&otherActive)
		if otherActive == 0 {
			_, _ = h.enforcer.DeleteRoleForUserInDomain(grant.UserID, grant.RoleCode, grant.DomainCode)
		}
	}
	if h.notifySvc != nil {
		_, _ = h.notifySvc.SendInApp(c.Request.Context(), grant.UserID, notify.CategorySystemMessage, "info",
			"临时权限已提前撤销",
			fmt.Sprintf("您在域 %s 下的临时角色「%s」已被管理员提前撤销。", grant.DomainCode, grant.RoleCode),
			models.JSONMap{"grant_id": grant.ID, "domain": grant.DomainCode, "role": grant.RoleCode},
			actorID, nil)
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   grant.DomainCode,
		Action:       "rbac.jit.revoke",
		ResourceType: "temp_role_grant",
		ResourceID:   fmt.Sprintf("%d", grant.ID),
		Before:       grant,
		Status:       "success",
	})
	OK(c, gin.H{"revoked": true})
}
