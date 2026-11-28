package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

type NotificationHandler struct {
	db       *gorm.DB
	svc      *notify.Service
	enforcer *rbac.Enforcer
	auditSvc *audit.Service
}

func NewNotificationHandler(db *gorm.DB, svc *notify.Service, enforcer *rbac.Enforcer, auditSvc *audit.Service) *NotificationHandler {
	return &NotificationHandler{db: db, svc: svc, enforcer: enforcer, auditSvc: auditSvc}
}

func (h *NotificationHandler) userCanSeeSystemNotice(uid uint64) bool {
	if h.enforcer == nil {
		return false
	}
	if h.enforcer.IsSuperAdmin(uid) {
		return true
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(uid)
	for _, list := range rolesMap {
		for _, r := range list {
			if r != "viewer" {
				return true
			}
		}
	}
	return false
}

// List 返回当前用户的系统消息、系统公告及管理员系统通知。
func (h *NotificationHandler) List(c *gin.Context) {
	uid := CurrentUserID(c)
	category := strings.TrimSpace(c.Query("category"))
	unreadOnly := c.Query("unread_only") == "true"

	q := h.db.Model(&models.Notification{})
	if !h.userCanSeeSystemNotice(uid) {
		q = q.Where("(user_id = ? OR (category = ? AND user_id = 0))", uid, notify.CategoryAnnouncement)
	} else {
		q = q.Where("(user_id = ? OR (category = ? AND user_id = 0))", uid, notify.CategoryAnnouncement)
	}
	if category != "" {
		q = q.Where("category = ?", category)
	}
	if unreadOnly {
		q = q.Where("is_read = ?", false)
	}
	q = q.Where("(expires_at IS NULL OR expires_at > ?)", time.Now())

	var items []models.Notification
	if err := q.Order("id DESC").Limit(100).Find(&items).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询通知列表失败")
		return
	}
	OK(c, items)
}

// UnreadCount 返回按系统消息/系统公告/系统通知分类统计的未读数量。
func (h *NotificationHandler) UnreadCount(c *gin.Context) {
	uid := CurrentUserID(c)
	type row struct {
		Category string
		Total    int64
	}
	var rows []row
	_ = h.db.Model(&models.Notification{}).
		Select("category, count(*) as total").
		Where("(user_id = ? OR (category = ? AND user_id = 0)) AND is_read = ? AND (expires_at IS NULL OR expires_at > ?)",
			uid, notify.CategoryAnnouncement, false, time.Now()).
		Group("category").
		Scan(&rows).Error

	counts := map[string]int64{
		notify.CategorySystemMessage: 0,
		notify.CategoryAnnouncement:  0,
		notify.CategorySystemNotice:  0,
	}
	var total int64
	for _, r := range rows {
		counts[r.Category] = r.Total
		total += r.Total
	}
	OK(c, gin.H{
		"total":   total,
		"by_type": counts,
	})
}

func (h *NotificationHandler) MarkRead(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的通知 ID")
		return
	}
	uid := CurrentUserID(c)
	now := time.Now()
	res := h.db.Model(&models.Notification{}).
		Where("id = ? AND (user_id = ? OR (category = ? AND user_id = 0))", id, uid, notify.CategoryAnnouncement).
		Updates(map[string]interface{}{"is_read": true, "read_at": &now})
	if res.Error != nil {
		Fail(c, http.StatusInternalServerError, "更新已读状态失败")
		return
	}
	OK(c, gin.H{"updated": res.RowsAffected})
}

func (h *NotificationHandler) MarkAllRead(c *gin.Context) {
	uid := CurrentUserID(c)
	category := strings.TrimSpace(c.Query("category"))
	now := time.Now()
	q := h.db.Model(&models.Notification{}).Where("user_id = ? AND is_read = ?", uid, false)
	if category != "" {
		q = q.Where("category = ?", category)
	}
	_ = q.Updates(map[string]interface{}{"is_read": true, "read_at": &now}).Error
	OK(c, gin.H{"ok": true})
}

type announcementReq struct {
	Title     string `json:"title" binding:"required,max=255"`
	Content   string `json:"content" binding:"required"`
	Level     string `json:"level"`
	ExpiresAt string `json:"expires_at"`
}

// CreateAnnouncement 发布全员系统公告（平台超管专属）。
func (h *NotificationHandler) CreateAnnouncement(c *gin.Context) {
	var req announcementReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	var exp *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			Fail(c, http.StatusBadRequest, "过期时间格式无效（需 RFC3339 格式）")
			return
		}
		exp = &t
	}
	level := req.Level
	if level != "info" && level != "warning" && level != "security" && level != "error" {
		level = "info"
	}
	row, err := h.svc.SendInApp(c.Request.Context(), 0, notify.CategoryAnnouncement, level, req.Title, req.Content, nil, CurrentUserID(c), exp)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "发布公告失败")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "notification.announcement.create",
		ResourceType: "notification",
		ResourceID:   fmt.Sprintf("%d", row.ID),
		After:        row,
		Status:       "success",
	})
	Created(c, row)
}

func (h *NotificationHandler) DeleteAnnouncement(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的公告 ID")
		return
	}
	res := h.db.Where("id = ? AND category = ?", id, notify.CategoryAnnouncement).Delete(&models.Notification{})
	if res.Error != nil {
		Fail(c, http.StatusInternalServerError, "删除公告失败")
		return
	}
	if res.RowsAffected == 0 {
		Fail(c, http.StatusNotFound, "公告不存在")
		return
	}
	OK(c, gin.H{"deleted": true})
}

func (h *NotificationHandler) ListTemplates(c *gin.Context) {
	var items []models.NotificationTemplate
	if err := h.db.Order("id ASC").Find(&items).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询模板失败")
		return
	}
	OK(c, items)
}

type templateReq struct {
	Code      string   `json:"code"`
	Name      string   `json:"name" binding:"required"`
	Channel   string   `json:"channel" binding:"required"`
	Subject   string   `json:"subject"`
	Body      string   `json:"body" binding:"required"`
	Variables []string `json:"variables"`
	Enabled   bool     `json:"enabled"`
}

func (h *NotificationHandler) CreateTemplate(c *gin.Context) {
	var req templateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		Fail(c, http.StatusBadRequest, "模板编码不能为空")
		return
	}
	tpl := models.NotificationTemplate{
		Code:      strings.TrimSpace(req.Code),
		Name:      strings.TrimSpace(req.Name),
		Channel:   strings.TrimSpace(req.Channel),
		Subject:   req.Subject,
		Body:      req.Body,
		Variables: models.StringSlice(req.Variables),
		Enabled:   req.Enabled,
		UpdatedBy: CurrentUserID(c),
	}
	if err := h.db.Create(&tpl).Error; err != nil {
		Fail(c, http.StatusConflict, "创建模板失败（编码可能已存在）")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "notification.template.create",
		ResourceType: "notification_template",
		ResourceID:   tpl.Code,
		After:        tpl,
		Status:       "success",
	})
	Created(c, tpl)
}

func (h *NotificationHandler) UpdateTemplate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的模板 ID")
		return
	}
	var tpl models.NotificationTemplate
	if err := h.db.First(&tpl, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "模板不存在")
		return
	}
	var req templateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	tpl.Name = strings.TrimSpace(req.Name)
	tpl.Channel = strings.TrimSpace(req.Channel)
	tpl.Subject = req.Subject
	tpl.Body = req.Body
	if req.Variables != nil {
		tpl.Variables = models.StringSlice(req.Variables)
	}
	tpl.Enabled = req.Enabled
	tpl.UpdatedBy = CurrentUserID(c)
	if err := h.db.Save(&tpl).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新模板失败")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "notification.template.update",
		ResourceType: "notification_template",
		ResourceID:   tpl.Code,
		After:        tpl,
		Status:       "success",
	})
	OK(c, tpl)
}

func (h *NotificationHandler) DeleteTemplate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的模板 ID")
		return
	}
	if err := h.db.Delete(&models.NotificationTemplate{}, id).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除模板失败")
		return
	}
	OK(c, gin.H{"deleted": true})
}

type previewTemplateReq struct {
	Subject string            `json:"subject"`
	Body    string            `json:"body" binding:"required"`
	Vars    map[string]string `json:"vars"`
}

func (h *NotificationHandler) PreviewTemplate(c *gin.Context) {
	var req previewTemplateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	OK(c, gin.H{
		"subject": notify.RenderText(req.Subject, req.Vars, false),
		"body":    notify.RenderText(req.Body, req.Vars, false),
	})
}

func (h *NotificationHandler) ListDeliveries(c *gin.Context) {
	channel := strings.TrimSpace(c.Query("channel"))
	status := strings.TrimSpace(c.Query("status"))
	recipient := strings.TrimSpace(c.Query("recipient"))

	q := h.db.Model(&models.NotificationDelivery{})
	if channel != "" {
		q = q.Where("channel = ?", channel)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if recipient != "" {
		q = q.Where("recipient LIKE ?", "%"+recipient+"%")
	}
	var items []models.NotificationDelivery
	if err := q.Order("id DESC").Limit(200).Find(&items).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询发送记录失败")
		return
	}
	OK(c, items)
}

type bounceReq struct {
	Reason string `json:"reason"`
}

// MarkBounced 标记发送记录发生退信，同步生成系统通知并累计退信阻断计数。
func (h *NotificationHandler) MarkBounced(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的记录 ID")
		return
	}
	var req bounceReq
	_ = c.ShouldBindJSON(&req)
	updated, err := h.svc.MarkBounced(c.Request.Context(), id, req.Reason)
	if err != nil {
		Fail(c, http.StatusNotFound, "发送记录不存在")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "notification.delivery.bounce",
		ResourceType: "notification_delivery",
		ResourceID:   fmt.Sprintf("%d", id),
		After:        updated,
		Status:       "success",
	})
	OK(c, updated)
}
