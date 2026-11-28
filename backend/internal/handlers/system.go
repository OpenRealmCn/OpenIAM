package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/version"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type SystemHandler struct {
	db       *gorm.DB
	rdb      *redis.Client
	enforcer *rbac.Enforcer
}

func NewSystemHandler(db *gorm.DB, rdb *redis.Client) *SystemHandler {
	return &SystemHandler{db: db, rdb: rdb}
}

func (h *SystemHandler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	dbOK := false
	if sqlDB, err := h.db.DB(); err == nil {
		if err := sqlDB.PingContext(ctx); err == nil {
			dbOK = true
		}
	}
	redisOK := false
	if h.rdb != nil {
		if err := h.rdb.Ping(ctx).Err(); err == nil {
			redisOK = true
		}
	}

	status := http.StatusOK
	if !dbOK || !redisOK {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{
		"code": 0,
		"data": gin.H{
			"status": map[bool]string{true: "healthy", false: "degraded"}[dbOK && redisOK],
			"mysql":  dbOK,
			"redis":  redisOK,
		},
	})
}

func (h *SystemHandler) VersionInfo(c *gin.Context) {
	status, err := version.GetVersionStatus(h.db)
	if err != nil {
		failInternal(c, "版本检查失败", err)
		return
	}
	var history []models.SystemVersionHistory
	h.db.Order("id DESC").Limit(30).Find(&history)

	OK(c, gin.H{
		"status":  status,
		"history": history,
	})
}

// SetEnforcer 注入权限引擎，用于按操作者身份决定概览统计范围。
func (h *SystemHandler) SetEnforcer(e *rbac.Enforcer) {
	h.enforcer = e
}

// Dashboard 返回控制台概览统计。超管看全平台；其他管理员只看当前办理域，
// 且不返回域数量、身份源和版本等平台级信息。
func (h *SystemHandler) Dashboard(c *gin.Context) {
	if h.enforcer != nil && !h.enforcer.IsSuperAdmin(CurrentUserID(c)) {
		dom := middleware.ResolveDomain(c)
		var roleCount, permCount, oauthClientCount, auditCount int64
		h.db.Model(&models.Role{}).Where("domain_code = ?", dom).Count(&roleCount)
		h.db.Model(&models.Permission{}).Where("domain_code = ?", dom).Count(&permCount)
		h.db.Model(&models.OAuthClient{}).Where("domain_code = ?", dom).Count(&oauthClientCount)
		h.db.Model(&models.AuditLog{}).Where("domain_code = ?", dom).Count(&auditCount)
		OK(c, gin.H{
			"scope":  "domain",
			"domain": dom,
			"counts": gin.H{
				"users":         len(domainUserIDs(h.enforcer, dom)),
				"roles":         roleCount,
				"permissions":   permCount,
				"oauth_clients": oauthClientCount,
				"audit_logs":    auditCount,
			},
		})
		return
	}

	var userCount, domainCount, roleCount, permCount, oauthClientCount, providerCount, auditCount int64
	h.db.Model(&models.User{}).Count(&userCount)
	h.db.Model(&models.Domain{}).Count(&domainCount)
	h.db.Model(&models.Role{}).Count(&roleCount)
	h.db.Model(&models.Permission{}).Count(&permCount)
	h.db.Model(&models.OAuthClient{}).Count(&oauthClientCount)
	h.db.Model(&models.OAuthProvider{}).Where("enabled = ?", true).Count(&providerCount)
	h.db.Model(&models.AuditLog{}).Count(&auditCount)

	verStatus, _ := version.GetVersionStatus(h.db)

	OK(c, gin.H{
		"scope": "platform",
		"counts": gin.H{
			"users":            userCount,
			"domains":          domainCount,
			"roles":            roleCount,
			"permissions":      permCount,
			"oauth_clients":    oauthClientCount,
			"active_providers": providerCount,
			"audit_logs":       auditCount,
		},
		"version": verStatus,
	})
}
