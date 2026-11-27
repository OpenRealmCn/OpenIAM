package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/models"
	"gorm.io/gorm"
)

type AuditHandler struct {
	db *gorm.DB
}

func NewAuditHandler(db *gorm.DB) *AuditHandler {
	return &AuditHandler{db: db}
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
	if domain := strings.TrimSpace(c.Query("domain")); domain != "" && domain != "*" {
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

func (h *AuditHandler) Stats(c *gin.Context) {
	now := time.Now()
	since := now.AddDate(0, 0, -6).Truncate(24 * time.Hour)

	var recent []models.AuditLog
	h.db.Select("id, action, resource_type, status, created_at").Where("created_at >= ?", since).Find(&recent)

	type dayBucket struct {
		Date      string `json:"date"`
		AuthCount int    `json:"auth_count"`
		RBACCount int    `json:"rbac_count"`
		FailCount int    `json:"fail_count"`
	}
	buckets := make([]dayBucket, 7)
	idxMap := make(map[string]int, 7)
	for i := 0; i < 7; i++ {
		d := since.AddDate(0, 0, i).Format("2006-01-02")
		buckets[i] = dayBucket{Date: d}
		idxMap[d] = i
	}

	for _, item := range recent {
		d := item.CreatedAt.Format("2006-01-02")
		idx, ok := idxMap[d]
		if !ok {
			continue
		}
		if item.Status != "success" {
			buckets[idx].FailCount++
		}
		if strings.HasPrefix(item.Action, "auth.") || strings.HasPrefix(item.Action, "oauth2.") {
			buckets[idx].AuthCount++
		}
		if strings.HasPrefix(item.Action, "rbac.") {
			buckets[idx].RBACCount++
		}
	}

	var totalCount int64
	h.db.Model(&models.AuditLog{}).Count(&totalCount)

	OK(c, gin.H{
		"total":      totalCount,
		"daily_7d":   buckets,
	})
}
