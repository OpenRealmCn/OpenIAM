package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/version"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type SystemHandler struct {
	db  *gorm.DB
	rdb *redis.Client
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
			"status":      map[bool]string{true: "healthy", false: "degraded"}[dbOK && redisOK],
			"mysql":       dbOK,
			"redis":       redisOK,
			"app_version": version.AppVersion,
		},
	})
}

func (h *SystemHandler) VersionInfo(c *gin.Context) {
	status, err := version.GetVersionStatus(h.db)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "版本检查失败: "+err.Error())
		return
	}
	var history []models.SystemVersionHistory
	h.db.Order("id DESC").Limit(30).Find(&history)

	OK(c, gin.H{
		"status":  status,
		"history": history,
	})
}

func (h *SystemHandler) Dashboard(c *gin.Context) {
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
