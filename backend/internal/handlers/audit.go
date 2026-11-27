package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

type AuditHandler struct {
	db       *gorm.DB
	enforcer *rbac.Enforcer
}

func NewAuditHandler(db *gorm.DB, enforcer *rbac.Enforcer) *AuditHandler {
	return &AuditHandler{db: db, enforcer: enforcer}
}

func (h *AuditHandler) List(c *gin.Context) {
	page, size, offset := ParsePagination(c)

	q := h.db.Model(&models.AuditLog{})
	if actor := strings.TrimSpace(c.Query("actor")); actor != "" {
		q = q.Where("actor_username LIKE ?", "%"+actor+"%")
	}
	if action := strings.TrimSpace(c.Query("action")); action != "" {
		q = q.Where("action LIKE ?", "%"+action+"%")
	}
	if resType := strings.TrimSpace(c.Query("resource_type")); resType != "" {
		q = q.Where("resource_type = ?", resType)
	}
	// 非超级管理员只能查看请求域内的审计日志
	if domain, all := scopedDomain(c, h.enforcer); !all {
		q = q.Where("domain_code = ?", domain)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		q = q.Where("status = ?", status)
	}
	if startStr := strings.TrimSpace(c.Query("start_time")); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			q = q.Where("created_at >= ?", t)
		}
	}
	if endStr := strings.TrimSpace(c.Query("end_time")); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			q = q.Where("created_at <= ?", t)
		}
	}

	var total int64
	q.Count(&total)

	var logs []models.AuditLog
	if err := q.Order("id DESC").Limit(size).Offset(offset).Find(&logs).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询审计日志失败")
		return
	}
	OK(c, PagedResult{Items: logs, Total: total, Page: page, Size: size})
}

type dayBucket struct {
	Date      string `json:"date"`
	AuthCount int    `json:"auth_count"`
	RBACCount int    `json:"rbac_count"`
	FailCount int    `json:"fail_count"`
}

// Stats 使用数据库聚合计数统计近 7 天趋势，不再把记录整体读入内存；非超级管理员仅统计请求域。
func (h *AuditHandler) Stats(c *gin.Context) {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	domain, all := scopedDomain(c, h.enforcer)

	base := func() *gorm.DB {
		q := h.db.Model(&models.AuditLog{})
		if !all {
			q = q.Where("domain_code = ?", domain)
		}
		return q
	}

	buckets := make([]dayBucket, 7)
	for i := 0; i < 7; i++ {
		start := today.AddDate(0, 0, i-6)
		end := start.AddDate(0, 0, 1)
		day := func() *gorm.DB {
			return base().Where("created_at >= ? AND created_at < ?", start, end)
		}
		b := dayBucket{Date: start.Format("2006-01-02")}
		var n int64
		day().Where("(action LIKE ? OR action LIKE ?)", "auth.%", "oauth2.%").Count(&n)
		b.AuthCount = int(n)
		day().Where("action LIKE ?", "rbac.%").Count(&n)
		b.RBACCount = int(n)
		day().Where("status <> ?", "success").Count(&n)
		b.FailCount = int(n)
		buckets[i] = b
	}

	var totalCount int64
	base().Count(&totalCount)

	OK(c, gin.H{
		"total":    totalCount,
		"daily_7d": buckets,
	})
}
