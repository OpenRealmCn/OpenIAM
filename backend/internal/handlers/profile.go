package handlers

import (
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/otp"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
)

type updateProfileReq struct {
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
	Phone       string `json:"phone"`
	// PhoneCode 是发送到新手机号的验证码；仅在手机号发生变化且新号码非空时需要。
	PhoneCode string `json:"phone_code"`
}

func hasAllowedAvatarExt(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".png", ".ico", ".jpg":
		return true
	default:
		return false
	}
}

func validateAvatarURL(raw string, isAdmin bool) string {
	if raw == "" {
		return ""
	}
	if len(raw) > 512 {
		return "头像地址长度不能超过 512 个字符"
	}
	if strings.HasPrefix(raw, "/") {
		if !isAdmin {
			return "非管理员禁止使用站内路径，请填写以 .png、.ico 或 .jpg 结尾的外部图片链接"
		}
		if strings.HasPrefix(raw, "//") {
			return "头像地址格式无效"
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "" || u.Host != "" || strings.Contains(u.Path, "..") {
			return "头像站内路径格式无效"
		}
		if !hasAllowedAvatarExt(u.Path) {
			return "头像仅支持 .png、.ico、.jpg 格式的图片地址"
		}
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "头像地址必须是有效的 http(s) 图片链接"
	}
	if !hasAllowedAvatarExt(u.Path) {
		return "头像仅支持 .png、.ico、.jpg 格式的图片地址"
	}
	return ""
}

func (h *AuthHandler) isAdminUser(uid uint64) bool {
	if h.enforcer.IsSuperAdmin(uid) {
		return true
	}
	rolesMap, err := h.enforcer.GetAllUserRoles(uid)
	if err != nil {
		return false
	}
	for _, roleList := range rolesMap {
		for _, r := range roleList {
			if r == "super_admin" || r == "domain_admin" {
				return true
			}
		}
	}
	return false
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
	phone := normalizePhone(req.Phone)
	if utf8.RuneCountInString(displayName) > 64 {
		Fail(c, http.StatusBadRequest, "显示名称不能超过 64 个字")
		return
	}
	if len(phone) > 32 {
		Fail(c, http.StatusBadRequest, "手机号格式无效")
		return
	}
	uid := CurrentUserID(c)
	if phone != "" {
		if !phonePattern.MatchString(phone) {
			Fail(c, http.StatusBadRequest, "手机号格式无效（可含前导 +，6~20 位数字）")
			return
		}
		var phoneCount int64
		h.db.Model(&models.User{}).Where("phone = ? AND id <> ?", phone, uid).Count(&phoneCount)
		if phoneCount > 0 {
			Fail(c, http.StatusConflict, "该手机号已被其他账号使用")
			return
		}
	}
	if errMsg := validateAvatarURL(avatarURL, h.isAdminUser(uid)); errMsg != "" {
		Fail(c, http.StatusBadRequest, errMsg)
		return
	}
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	// 手机号可用于验证码登录与二步验证，变更等同于更换登录凭据：需近期重新认证，且新号码必须验证持有
	if phone != user.Phone {
		if !requireReauth(c, h.db, h.stateStore) {
			return
		}
		if phone != "" {
			if h.otpSvc == nil {
				Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
				return
			}
			rec, vErr := h.otpSvc.VerifyCode(c.Request.Context(), "bind_phone", phone, req.PhoneCode)
			if vErr != nil || rec.UserID != uid {
				Fail(c, http.StatusBadRequest, "新手机号验证码不正确或已过期")
				return
			}
		}
	}
	before := map[string]interface{}{
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarURL,
		"phone":        user.Phone,
	}

	if displayName != "" {
		user.DisplayName = displayName
	}
	user.AvatarURL = avatarURL
	user.Phone = phone
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarURL,
		"phone":        user.Phone,
	}).Error; err != nil {
		if isUniqueViolation(err) {
			Fail(c, http.StatusConflict, "该手机号已被其他账号使用")
			return
		}
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
			"phone":        user.Phone,
		},
		Status: "success",
	})
	if before["phone"] != user.Phone {
		what := "你的账号已解除手机号绑定，之后将无法再用手机号接收验证码。"
		if user.Phone != "" {
			what = fmt.Sprintf("你的账号绑定的手机号已更换为 %s。", maskPhone(user.Phone))
		}
		notifySecurity(c, h.notifySvc, user.ID, "手机号已变更", what)
	}
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

type sendPhoneBindCodeReq struct {
	Phone string `json:"phone" binding:"required"`
}

// SendPhoneBindCode 向待绑定的新手机号发送验证码，用于证明用户确实持有该号码。
func (h *AuthHandler) SendPhoneBindCode(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
		return
	}
	var req sendPhoneBindCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入手机号")
		return
	}
	if !requireReauth(c, h.db, h.stateStore) {
		return
	}
	phone := normalizePhone(req.Phone)
	if !phonePattern.MatchString(phone) {
		Fail(c, http.StatusBadRequest, "手机号格式无效（可含前导 +，6~20 位数字）")
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if phone == user.Phone {
		Fail(c, http.StatusBadRequest, "新手机号与当前绑定的号码相同")
		return
	}
	var dup int64
	h.db.Model(&models.User{}).Where("phone = ? AND id <> ?", phone, uid).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "该手机号已被其他账号使用")
		return
	}
	res, err := h.otpSvc.SendCode(c.Request.Context(), otp.SendRequest{
		Scene:      "bind_phone",
		Channel:    "sms",
		Target:     phone,
		User:       &user,
		ClientIP:   clientip.FromGin(c),
		NoFallback: true,
	})
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	OK(c, res)
}

// StartBindIdentity 生成当前用户绑定外部 OAuth 身份的授权跳转 URL。
// 绑定后该外部账号可直接登录本账号，因此与新增登录凭据同等对待，要求近期重新认证。
func (h *AuthHandler) StartBindIdentity(c *gin.Context) {
	if !requireReauth(c, h.db, h.stateStore) {
		return
	}
	providerName := c.Param("provider")
	redirectOverride := c.Query("redirect_uri")
	binding, err := issueOAuthBindingCookie(c)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "初始化绑定流程失败")
		return
	}
	authURL, state, err := h.pluginSvc.StartBind(c.Request.Context(), providerName, redirectOverride, binding, CurrentUserID(c))
	if err != nil {
		Fail(c, http.StatusBadRequest, federatedErrorMessage(err, "发起绑定失败"))
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
	notifySecurity(c, h.notifySvc, uid, "已解绑第三方账号", fmt.Sprintf("你的账号已解除与 %s 账号的绑定，之后无法再用它登录。", identity.ProviderName))
	OK(c, gin.H{"unbound": true})
}

func validEmailAddress(email string) bool {
	if email == "" || len(email) > 254 || !usableEmail(email) {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && strings.EqualFold(addr.Address, email)
}

type sendEmailChangeCodeReq struct {
	Email string `json:"email" binding:"required"`
}

// SendEmailChangeCode 向新邮箱发送验证码。邮箱可用于找回密码与接收验证码，更换前需近期重新认证。
func (h *AuthHandler) SendEmailChangeCode(c *gin.Context) {
	if h.otpSvc == nil || !h.settingsSvc.Snapshot().SMTPEnabled {
		Fail(c, http.StatusServiceUnavailable, "系统未开启邮件服务，暂时无法更换邮箱，请联系管理员")
		return
	}
	var req sendEmailChangeCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入新邮箱")
		return
	}
	if !requireReauth(c, h.db, h.stateStore) {
		return
	}
	email := normalizeEmail(req.Email)
	if !validEmailAddress(email) {
		Fail(c, http.StatusBadRequest, "邮箱格式无效")
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if strings.EqualFold(email, user.Email) {
		Fail(c, http.StatusBadRequest, "新邮箱与当前邮箱相同")
		return
	}
	var dup int64
	h.db.Model(&models.User{}).Where("email <> '' AND LOWER(email) = ? AND id <> ?", email, uid).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "该邮箱已被其他账号使用")
		return
	}
	res, err := h.otpSvc.SendCode(c.Request.Context(), otp.SendRequest{
		Scene:      "bind_email",
		Channel:    "email",
		Target:     email,
		User:       &user,
		ClientIP:   clientip.FromGin(c),
		NoFallback: true,
	})
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	OK(c, res)
}

type changeEmailReq struct {
	Email string `json:"email" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// ChangeEmail 校验新邮箱验证码后更换邮箱，并把新邮箱标记为已验证。旧邮箱会收到一封变更提醒。
func (h *AuthHandler) ChangeEmail(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
		return
	}
	var req changeEmailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请填写新邮箱和验证码")
		return
	}
	if !requireReauth(c, h.db, h.stateStore) {
		return
	}
	email := normalizeEmail(req.Email)
	uid := CurrentUserID(c)
	rec, vErr := h.otpSvc.VerifyCode(c.Request.Context(), "bind_email", email, strings.TrimSpace(req.Code))
	if vErr != nil || rec.UserID != uid {
		Fail(c, http.StatusBadRequest, "验证码不正确或已过期")
		return
	}
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	oldEmail := user.Email
	// 先通知再改库：提醒邮件发往旧邮箱，邮箱被他人改掉时原主人能收到。
	notifySecurity(c, h.notifySvc, uid, "邮箱已变更", fmt.Sprintf("你的账号绑定的邮箱已更换为 %s。", maskEmail(email)))
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"email":          email,
		"email_verified": true,
	}).Error; err != nil {
		if isUniqueViolation(err) {
			Fail(c, http.StatusConflict, "该邮箱已被其他账号使用")
			return
		}
		Fail(c, http.StatusInternalServerError, "更换邮箱失败，请稍后重试")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.email.change",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", uid),
		Before:       map[string]interface{}{"email": oldEmail},
		After:        map[string]interface{}{"email": email},
		Status:       "success",
	})
	user.Email = email
	user.EmailVerified = true
	OK(c, user)
}

type passwordResetRequestBody struct {
	Email        string `json:"email" binding:"required,email"`
	CaptchaToken string `json:"captcha_token"`
}

// RequestPasswordReset 发送 6 位一次性密码重置验证码到用户邮箱。
// 无论邮箱是否注册、是否被限频、投递是否成功，响应都完全一致，失败原因只写入审计，防止邮箱枚举。
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
		if h.pluginMgr != nil {
			if cErr := h.pluginMgr.VerifyCaptchaForScene(c.Request.Context(), "reset_password", req.CaptchaToken); cErr != nil {
				Fail(c, http.StatusBadRequest, cErr.Error())
				return
			}
		}
		generic := gin.H{"sent": true, "message": "如果该邮箱已注册，我们已向其发送了重置密码验证码"}

		email := normalizeEmail(req.Email)
		// 按邮箱与来源 IP 限频（对存在与不存在的邮箱一视同仁），防止被用来轰炸邮箱或枚举账号
		if rlErr := h.stateStore.CheckAndIncrOTPRate(c.Request.Context(), "pwd_reset:"+email, clientip.FromGin(c), 60, 5, 20); rlErr != nil {
			OK(c, generic)
			return
		}
		var user models.User
		if err := h.db.Where("LOWER(email) = ? AND status = ?", email, "active").First(&user).Error; err != nil {
			OK(c, generic)
			return
		}
		fail := func(reason string) {
			h.auditSvc.RecordFromContext(c, audit.Entry{
				ActorID:       user.ID,
				ActorUsername: user.Username,
				DomainCode:    rbac.DefaultDomain,
				Action:        "auth.password_reset.request",
				ResourceType:  "user",
				ResourceID:    fmt.Sprintf("%d", user.ID),
				Status:        "failed",
				ErrorMessage:  reason,
			})
			OK(c, generic)
		}

		code, err := otp.GenerateCode()
		if err != nil {
			fail("generate code: " + err.Error())
			return
		}
		const ttlMinutes = 10
		if err := h.stateStore.SavePasswordResetCode(c.Request.Context(), email, security.PasswordResetRecord{
			UserID: user.ID,
			Email:  email,
			Code:   code,
		}, ttlMinutes*time.Minute); err != nil {
			fail("save reset code: " + err.Error())
			return
		}

		if err := mailSvc.SendPasswordResetCode(c.Request.Context(), user.Email, user.Username, code, ttlMinutes); err != nil {
			fail("send mail: " + err.Error())
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
		OK(c, generic)
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
		Fail(c, http.StatusBadRequest, "请填写邮箱、6 位验证码和至少 8 位的新密码")
		return
	}
	// 先校验密码策略再消耗验证码，避免密码不合格时验证码被白白用掉。
	if !h.checkPasswordPolicy(c, req.NewPassword) {
		return
	}
	email := normalizeEmail(req.Email)
	rec, err := h.stateStore.ConsumePasswordResetCode(c.Request.Context(), email, strings.TrimSpace(req.Code))
	if err != nil {
		Fail(c, http.StatusBadRequest, otpFailureMessage(err, "验证码无效或已过期"))
		return
	}

	var user models.User
	if err := h.db.First(&user, rec.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusBadRequest, "账号不存在或已被禁用")
		return
	}

	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "重置密码失败，请稍后重试")
		return
	}
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"password_hash":        hash,
		"must_change_password": false,
	}).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新密码失败")
		return
	}
	now := time.Now()
	_ = h.db.Model(&models.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error
	if rvErr := h.stateStore.RevokeUserTokens(c.Request.Context(), user.ID); rvErr != nil {
		Fail(c, http.StatusInternalServerError, "密码已重置，但撤销旧会话失败，请重试")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.password_reset.confirm",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		Status:        "success",
	})
	notifySecurity(c, h.notifySvc, user.ID, "登录密码已重置", "你的账号通过邮箱验证码重置了登录密码，所有设备上的登录状态均已失效。")
	OK(c, gin.H{"reset": true})
}
