package handlers

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/settings"
)

type SettingsHandler struct {
	svc      *settings.Service
	enforcer *rbac.Enforcer
	mailSvc  *mailer.Service
	auditSvc *audit.Service
}

func NewSettingsHandler(svc *settings.Service, enforcer *rbac.Enforcer, mailSvc *mailer.Service, auditSvc *audit.Service) *SettingsHandler {
	return &SettingsHandler{svc: svc, enforcer: enforcer, mailSvc: mailSvc, auditSvc: auditSvc}
}

// PublicSiteInfo 公开返回站点名称、图标、首页公告等非敏感品牌与运维配置。
func (h *SettingsHandler) PublicSiteInfo(c *gin.Context) {
	snap := h.svc.Snapshot()
	OK(c, gin.H{
		"name":                  snap.SiteName,
		"subtitle":              snap.SiteSubtitle,
		"logo_url":              snap.SiteLogoURL,
		"favicon_url":           snap.SiteFaviconURL,
		"announcement_enabled":  snap.SiteAnnouncementEnabled,
		"announcement_title":    snap.SiteAnnouncementTitle,
		"announcement_content":  snap.SiteAnnouncementContent,
		"announcement_type":     snap.SiteAnnouncementType,
		"footer_text":           snap.SiteFooterText,
		"allow_public_register": snap.AllowPublicRegister,
		"register_email_mode":   snap.RegisterEmailMode,
		"register_phone_mode":   snap.RegisterPhoneMode,
		"register_verify_mode":  snap.RegisterVerifyMode,
		"smtp_enabled":          snap.SMTPEnabled,
	})
}

func (h *SettingsHandler) List(c *gin.Context) {
	items, err := h.svc.ListAll()
	if err != nil {
		Fail(c, http.StatusInternalServerError, "查询系统设置失败: "+err.Error())
		return
	}
	OK(c, items)
}

type updateSettingsReq struct {
	Settings map[string]string `json:"settings" binding:"required"`
}

func (h *SettingsHandler) Update(c *gin.Context) {
	// 双保险：路由层已限制为超管专属，这里再做一次服务端判定，
	// 即使路由或中间件被改错，全局配置也不会落到非超管手里。
	if !h.enforcer.IsSuperAdmin(CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅平台超级管理员可修改全局系统设置")
		return
	}

	var req updateSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数格式错误: "+err.Error())
		return
	}

	before, after, err := h.svc.UpdateBatch(req.Settings, CurrentUserID(c))
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}

	if len(after) > 0 {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "system.settings.update",
			ResourceType: "system_setting",
			ResourceID:   "global",
			Before:       before,
			After:        after,
			Status:       "success",
		})
	}

	items, _ := h.svc.ListAll()
	OK(c, items)
}

type testSMTPReq struct {
	To string `json:"to" binding:"required,email"`
}

// TestSMTP 使用当前数据库中保存的 SMTP 配置发送一封测试邮件。
func (h *SettingsHandler) TestSMTP(c *gin.Context) {
	if !h.enforcer.IsSuperAdmin(CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅平台超级管理员可测试全局邮件服务")
		return
	}
	var req testSMTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入有效的测试收件人邮箱")
		return
	}
	if h.mailSvc == nil {
		Fail(c, http.StatusInternalServerError, "邮件服务未初始化")
		return
	}
	if err := h.mailSvc.SendTestEmail(c.Request.Context(), req.To); err != nil {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "system.smtp.test",
			ResourceType: "system_setting",
			ResourceID:   "smtp",
			After:        map[string]interface{}{"to": req.To},
			Status:       "failed",
			ErrorMessage: err.Error(),
		})
		Fail(c, http.StatusBadGateway, "测试邮件发送失败: "+err.Error())
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "system.smtp.test",
		ResourceType: "system_setting",
		ResourceID:   "smtp",
		After:        map[string]interface{}{"to": req.To},
		Status:       "success",
	})
	OK(c, gin.H{"sent": true})
}

type previewClientIPReq struct {
	CustomHeader   string `json:"custom_header"`
	TrustedProxies string `json:"trusted_proxies"`
}

// PreviewClientIP 试算并预览当前请求在全部真实 IP 获取方式下的解析结果，辅助管理员核对部署环境。
func (h *SettingsHandler) PreviewClientIP(c *gin.Context) {
	if !h.enforcer.IsSuperAdmin(CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅平台超级管理员可预览客户端 IP 识别结果")
		return
	}
	var req previewClientIPReq
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		Fail(c, http.StatusBadRequest, "预览参数格式无效")
		return
	}
	customHeader := strings.TrimSpace(req.CustomHeader)
	if err := clientip.ValidateCustomHeader(customHeader); err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	var draftTrusted []string
	if strings.TrimSpace(req.TrustedProxies) != "" {
		for _, part := range strings.Split(req.TrustedProxies, ",") {
			t := strings.TrimSpace(part)
			if t == "" {
				continue
			}
			if err := clientip.ValidateTrustedProxyEntry(t); err != nil {
				Fail(c, http.StatusBadRequest, err.Error())
				return
			}
			draftTrusted = append(draftTrusted, t)
		}
	}

	snap := h.svc.Snapshot()
	res := clientip.Preview(
		c.Request,
		snap.ClientIPMethod,
		snap.ClientIPCustomHeader,
		snap.TrustedProxies,
		customHeader,
		draftTrusted,
	)
	OK(c, res)
}
