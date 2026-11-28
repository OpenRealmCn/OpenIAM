package handlers

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
)

type updateProfileReq struct {
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

func isValidAvatarURL(raw string) bool {
	if raw == "" {
		return true
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// UpdateProfile 允许当前登录用户更新显示名称与头像 URL。
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	var req updateProfileReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数格式错误")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	avatarURL := strings.TrimSpace(req.AvatarURL)
	if len(displayName) > 128 {
		Fail(c, http.StatusBadRequest, "显示名称不能超过 128 个字符")
		return
	}
	if len(avatarURL) > 512 || !isValidAvatarURL(avatarURL) {
		Fail(c, http.StatusBadRequest, "头像地址必须是站内路径或有效的 http(s) 地址")
		return
	}

	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	before := map[string]interface{}{
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarURL,
	}

	if displayName != "" {
		user.DisplayName = displayName
	}
	user.AvatarURL = avatarURL
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarURL,
	}).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新个人资料失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.profile.update",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Before:       before,
		After: map[string]interface{}{
			"display_name": user.DisplayName,
			"avatar_url":   user.AvatarURL,
		},
		Status: "success",
	})
	OK(c, user)
}

// ListMyIdentities 列出当前用户已绑定的外部 OAuth 身份。
func (h *AuthHandler) ListMyIdentities(c *gin.Context) {
	uid := CurrentUserID(c)
	var list []models.UserIdentity
	if err := h.db.Where("user_id = ?", uid).Order("id ASC").Find(&list).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询绑定账号失败")
		return
	}
	OK(c, list)
}

// StartBindIdentity 生成当前用户绑定外部 OAuth 身份的授权跳转 URL。
func (h *AuthHandler) StartBindIdentity(c *gin.Context) {
	providerName := c.Param("provider")
	redirectOverride := c.Query("redirect_uri")
	authURL, state, err := h.pluginSvc.StartBind(c.Request.Context(), providerName, redirectOverride, CurrentUserID(c))
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	OK(c, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

// UnbindIdentity 解绑当前用户的某个外部 OAuth 账号（防止未设密码且仅剩最后一个身份时锁死账号）。
func (h *AuthHandler) UnbindIdentity(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的绑定 ID")
		return
	}
	uid := CurrentUserID(c)

	var identity models.UserIdentity
	if err := h.db.Where("id = ? AND user_id = ?", id, uid).First(&identity).Error; err != nil {
		Fail(c, http.StatusNotFound, "未找到该绑定记录")
		return
	}

	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}

	if user.PasswordHash == "" {
		var otherCount int64
		h.db.Model(&models.UserIdentity{}).Where("user_id = ? AND id <> ?", uid, id).Count(&otherCount)
		var passkeyCount int64
		h.db.Model(&models.UserPasskey{}).Where("user_id = ?", uid).Count(&passkeyCount)
		if otherCount == 0 && passkeyCount == 0 {
			Fail(c, http.StatusBadRequest, "请先设置登录密码或绑定通行密钥后再解绑最后一个第三方账号")
			return
		}
	}

	if err := h.db.Delete(&identity).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "解绑失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.oauth_unbind",
		ResourceType: "user_identity",
		ResourceID:   fmt.Sprintf("%s:%s", identity.ProviderName, identity.ExternalUserID),
		Before: map[string]interface{}{
			"provider":          identity.ProviderName,
			"external_username": identity.ExternalUsername,
		},
		Status: "success",
	})
	OK(c, gin.H{"unbound": true})
}

type passwordResetRequestBody struct {
	Email string `json:"email" binding:"required,email"`
}

// RequestPasswordReset 发送 6 位一次性密码重置验证码到用户邮箱（对未注册邮箱返回统一提示以防枚举）。
func (h *AuthHandler) RequestPasswordReset(mailSvc *mailer.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req passwordResetRequestBody
		if err := c.ShouldBindJSON(&req); err != nil {
			Fail(c, http.StatusBadRequest, "请输入有效的邮箱地址")
			return
		}
		if !h.settingsSvc.Snapshot().SMTPEnabled {
			Fail(c, http.StatusServiceUnavailable, "系统尚未启用邮件服务，请联系管理员重置密码")
			return
		}

		email := strings.ToLower(strings.TrimSpace(req.Email))
		var user models.User
		if err := h.db.Where("LOWER(email) = ? AND status = ?", email, "active").First(&user).Error; err != nil {
			// 统一返回成功提示，防止邮箱枚举
			OK(c, gin.H{"sent": true, "message": "如果该邮箱已注册，我们已向其发送了重置密码验证码"})
			return
		}

		code := generateSixDigitCode()
		const ttlMinutes = 10
		if err := h.stateStore.SavePasswordResetCode(c.Request.Context(), email, security.PasswordResetRecord{
			UserID: user.ID,
			Email:  email,
			Code:   code,
		}, ttlMinutes*time.Minute); err != nil {
			Fail(c, http.StatusInternalServerError, "生成验证码失败")
			return
		}

		if err := mailSvc.SendPasswordResetCode(c.Request.Context(), user.Email, user.Username, code, ttlMinutes); err != nil {
			Fail(c, http.StatusBadGateway, "邮件发送失败: "+err.Error())
			return
		}

		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorID:       user.ID,
			ActorUsername: user.Username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.password_reset.request",
			ResourceType:  "user",
			ResourceID:    fmt.Sprintf("%d", user.ID),
			Status:        "success",
		})
		OK(c, gin.H{"sent": true, "message": "如果该邮箱已注册，我们已向其发送了重置密码验证码"})
	}
}

type passwordResetConfirmBody struct {
	Email       string `json:"email" binding:"required,email"`
	Code        string `json:"code" binding:"required,len=6"`
	NewPassword string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

// ConfirmPasswordReset 校验 6 位邮箱验证码并重置密码，同时吊销所有旧会话。
func (h *AuthHandler) ConfirmPasswordReset(c *gin.Context) {
	var req passwordResetConfirmBody
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数无效：请填写邮箱、6 位验证码及 8~72 位新密码")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	rec, err := h.stateStore.ConsumePasswordResetCode(c.Request.Context(), email, strings.TrimSpace(req.Code))
	if err != nil {
		Fail(c, http.StatusBadRequest, "验证码无效或已过期")
		return
	}

	var user models.User
	if err := h.db.First(&user, rec.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusBadRequest, "账号不存在或已被禁用")
		return
	}

	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "密码加密失败")
		return
	}
	if err := h.db.Model(&user).Update("password_hash", hash).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新密码失败")
		return
	}
	_ = h.stateStore.RevokeUserTokens(c.Request.Context(), user.ID)

	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.password_reset.confirm",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		Status:        "success",
	})
	OK(c, gin.H{"reset": true})
}

func generateSixDigitCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "000000"
	}
	return fmt.Sprintf("%06d", n.Int64())
}
