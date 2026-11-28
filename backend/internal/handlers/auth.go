package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/otp"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/risk"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db          *gorm.DB
	jwtMgr      *security.JWTManager
	stateStore  *security.StateStore
	enforcer    *rbac.Enforcer
	auditSvc    *audit.Service
	pluginSvc   *oauthplugin.Service
	settingsSvc *settings.Service
	pluginMgr   *plugins.Manager
	riskEngine  *risk.Engine
	otpSvc      *otp.Service
	notifySvc   *notify.Service
}

func NewAuthHandler(
	db *gorm.DB,
	jwtMgr *security.JWTManager,
	stateStore *security.StateStore,
	enforcer *rbac.Enforcer,
	auditSvc *audit.Service,
	pluginSvc *oauthplugin.Service,
	settingsSvc *settings.Service,
	opts ...func(*AuthHandler),
) *AuthHandler {
	h := &AuthHandler{
		db:          db,
		jwtMgr:      jwtMgr,
		stateStore:  stateStore,
		enforcer:    enforcer,
		auditSvc:    auditSvc,
		pluginSvc:   pluginSvc,
		settingsSvc: settingsSvc,
	}
	for _, fn := range opts {
		if fn != nil {
			fn(h)
		}
	}
	return h
}

func WithEnterpriseAuthDeps(pluginMgr *plugins.Manager, riskEngine *risk.Engine, otpSvc *otp.Service, notifySvc *notify.Service) func(*AuthHandler) {
	return func(h *AuthHandler) {
		h.pluginMgr = pluginMgr
		h.riskEngine = riskEngine
		h.otpSvc = otpSvc
		h.notifySvc = notifySvc
	}
}

type loginReq struct {
	Username     string `json:"username" binding:"required"`
	Password     string `json:"password" binding:"required"`
	CaptchaToken string `json:"captcha_token"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入用户名和密码")
		return
	}
	if h.pluginMgr != nil {
		if cErr := h.pluginMgr.VerifyCaptchaForScene(c.Request.Context(), "login", req.CaptchaToken); cErr != nil {
			Fail(c, http.StatusBadRequest, cErr.Error())
			return
		}
	}
	username := strings.TrimSpace(req.Username)
	ctx := c.Request.Context()

	locked, ttl, lockErr := h.stateStore.IsLoginLocked(ctx, username)
	if lockErr != nil {
		Fail(c, http.StatusServiceUnavailable, "认证服务暂不可用，请稍后再试")
		return
	}
	if locked {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorUsername: username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    username,
			Status:        "failed",
			ErrorMessage:  "account locked due to repeated login failures",
		})
		Fail(c, http.StatusTooManyRequests, lockedMessage(ttl))
		return
	}

	snap := h.settingsSvc.Snapshot()

	var user models.User
	if err := h.db.Where("username = ? OR (email <> '' AND LOWER(email) = ?)", username, strings.ToLower(username)).First(&user).Error; err != nil {
		burnPasswordCheck(req.Password)
		_, locked, _ := h.stateStore.RecordLoginFailure(ctx, username, snap.MaxLoginFailures, time.Duration(snap.LockoutMinutes)*time.Minute)
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorUsername: username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    username,
			Status:        "failed",
			ErrorMessage:  "user not found",
		})
		if locked {
			Fail(c, http.StatusTooManyRequests, lockedMessage(time.Duration(snap.LockoutMinutes)*time.Minute))
			return
		}
		Fail(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	// 以规范用户名检查锁定状态，防止通过邮箱登录绕过按用户名的失败计数
	if locked, ttl, err := h.stateStore.IsLoginLocked(ctx, user.Username); err != nil {
		Fail(c, http.StatusServiceUnavailable, "认证服务暂不可用，请稍后再试")
		return
	} else if locked {
		Fail(c, http.StatusTooManyRequests, lockedMessage(ttl))
		return
	}

	if user.Status != "active" {
		burnPasswordCheck(req.Password)
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorID:       user.ID,
			ActorUsername: user.Username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    fmt.Sprintf("%d", user.ID),
			Status:        "failed",
			ErrorMessage:  "user disabled",
		})
		Fail(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	if !security.VerifyPassword(user.PasswordHash, req.Password) {
		count, locked, _ := h.stateStore.RecordLoginFailure(ctx, user.Username, snap.MaxLoginFailures, time.Duration(snap.LockoutMinutes)*time.Minute)
		_, _ = h.stateStore.RecordIPFailure(ctx, clientip.FromGin(c), time.Hour)
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorID:       user.ID,
			ActorUsername: user.Username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    fmt.Sprintf("%d", user.ID),
			After:         map[string]interface{}{"failure_count": count, "locked": locked},
			Status:        "failed",
			ErrorMessage:  "invalid password",
		})
		if locked {
			if int(count) == snap.MaxLoginFailures {
				notifySecurity(c, h.notifySvc, user.ID, "账号已被临时锁定",
					fmt.Sprintf("你的账号连续 %d 次密码输入错误，已被临时锁定 %d 分钟。如果不是你本人在尝试登录，建议尽快修改密码并开启两步验证。", count, snap.LockoutMinutes))
			}
			Fail(c, http.StatusTooManyRequests, lockedMessage(time.Duration(snap.LockoutMinutes)*time.Minute))
			return
		}
		Fail(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	_ = h.stateStore.ClearLoginFailures(ctx, username)
	_ = h.stateStore.ClearLoginFailures(ctx, user.Username)

	// 风控与二步验证先于强制改密判定：否则仅凭初始口令即可拿到改密令牌并改掉密码，绕过风控阻断与 TOTP。
	li := h.issuer()
	if li.gate(c, user, gateOptions{Channel: "password", RequireTOTP: true, AllowRiskChallenge: true}, nil) {
		return
	}
	li.finish(c, user, "auth.login", nil, nil)
}

type registerReq struct {
	Username     string `json:"username" binding:"required,min=3,max=64,excludes=@"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Password     string `json:"password" binding:"required,min=8,maxbytes=72"`
	DisplayName  string `json:"display_name"`
	EmailCode    string `json:"email_code"`
	SMSCode      string `json:"sms_code"`
	CaptchaToken string `json:"captcha_token"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	snap := h.settingsSvc.Snapshot()
	if !snap.AllowPublicRegister {
		Fail(c, http.StatusForbidden, "系统管理员已关闭自助注册功能")
		return
	}
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "注册参数无效：用户名 3~64 位且不含 @，密码至少 8 位")
		return
	}
	if h.pluginMgr != nil {
		if cErr := h.pluginMgr.VerifyCaptchaForScene(c.Request.Context(), "register", req.CaptchaToken); cErr != nil {
			Fail(c, http.StatusBadRequest, cErr.Error())
			return
		}
	}

	verifyMode := snap.RegisterVerifyMode
	if verifyMode == "" {
		verifyMode = "none"
	}
	emailRequired := snap.RegisterEmailMode == "required" || verifyMode == "email" || verifyMode == "both"
	phoneRequired := snap.RegisterPhoneMode == "required" || verifyMode == "sms" || verifyMode == "both"
	emailEnabled := snap.RegisterEmailMode != "disabled" || verifyMode == "email" || verifyMode == "both" || verifyMode == "either"
	phoneEnabled := snap.RegisterPhoneMode != "disabled" || verifyMode == "sms" || verifyMode == "both" || verifyMode == "either"

	username := strings.TrimSpace(req.Username)
	email := normalizeEmail(req.Email)
	phone := normalizePhone(req.Phone)

	if !emailEnabled {
		email = ""
	} else {
		if emailRequired && email == "" {
			Fail(c, http.StatusBadRequest, "请填写邮箱地址")
			return
		}
		if email != "" {
			if addr, err := mail.ParseAddress(email); err != nil || !strings.EqualFold(addr.Address, email) {
				Fail(c, http.StatusBadRequest, "邮箱格式无效")
				return
			}
		}
	}

	if !phoneEnabled {
		phone = ""
	} else {
		if phoneRequired && phone == "" {
			Fail(c, http.StatusBadRequest, "请填写手机号")
			return
		}
		if phone != "" && !phonePattern.MatchString(phone) {
			Fail(c, http.StatusBadRequest, "手机号格式无效，需为 6~20 位数字（可带国际区号前缀 +）")
			return
		}
	}

	if verifyMode == "either" && email == "" && phone == "" {
		Fail(c, http.StatusBadRequest, "请至少填写邮箱或手机号完成验证码校验")
		return
	}
	// 在消耗验证码之前校验密码，避免密码不合格时验证码作废、用户被迫重新获取。
	if !h.checkPasswordPolicy(c, req.Password) {
		return
	}

	var count int64
	h.db.Model(&models.User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		Fail(c, http.StatusConflict, "用户名已被占用")
		return
	}

	// 当前验证模式下可验证的渠道，只要提交了就必须带上有效验证码；
	// 否则「either」模式下可以用自己的邮箱过验证、顺带把他人手机号写进账号。
	emailVerifiable := verifyMode == "email" || verifyMode == "both" || verifyMode == "either"
	phoneVerifiable := verifyMode == "sms" || verifyMode == "both" || verifyMode == "either"
	emailVerified := false
	if verifyMode != "none" {
		if h.otpSvc == nil {
			Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
			return
		}
		if verifyMode == "email" && email == "" {
			Fail(c, http.StatusBadRequest, "请填写邮箱地址")
			return
		}
		if verifyMode == "sms" && phone == "" {
			Fail(c, http.StatusBadRequest, "请填写手机号")
			return
		}
		ctx := c.Request.Context()
		if email != "" && emailVerifiable {
			if strings.TrimSpace(req.EmailCode) == "" {
				Fail(c, http.StatusBadRequest, "请填写邮箱验证码")
				return
			}
			if _, vErr := h.otpSvc.VerifyCode(ctx, "register", email, req.EmailCode); vErr != nil {
				Fail(c, http.StatusBadRequest, otpFailureMessage(vErr, "邮箱验证码无效或已过期"))
				return
			}
			emailVerified = true
		}
		if phone != "" && phoneVerifiable {
			if strings.TrimSpace(req.SMSCode) == "" {
				Fail(c, http.StatusBadRequest, "请填写手机短信验证码")
				return
			}
			if _, vErr := h.otpSvc.VerifyCode(ctx, "register", phone, req.SMSCode); vErr != nil {
				Fail(c, http.StatusBadRequest, otpFailureMessage(vErr, "短信验证码无效或已过期"))
				return
			}
		}
	}

	// 唯一性放在验证码之后：未持有验证码时无法借注册接口探测邮箱/手机号是否已注册。
	if email != "" {
		h.db.Model(&models.User{}).Where("email <> '' AND LOWER(email) = ?", email).Count(&count)
		if count > 0 {
			Fail(c, http.StatusConflict, "邮箱已被占用")
			return
		}
	}
	if phone != "" {
		h.db.Model(&models.User{}).Where("phone <> '' AND phone = ?", phone).Count(&count)
		if count > 0 {
			Fail(c, http.StatusConflict, "手机号已被占用")
			return
		}
	}

	hash, err := security.HashPassword(req.Password)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "注册失败，请稍后重试")
		return
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = username
	}
	user := models.User{
		Username:      username,
		Email:         email,
		EmailVerified: emailVerified,
		Phone:         phone,
		DisplayName:   displayName,
		PasswordHash:  hash,
		Status:        "active",
	}
	if err := h.db.Create(&user).Error; err != nil {
		if isUniqueViolation(err) {
			Fail(c, http.StatusConflict, "用户名、邮箱或手机号已被占用")
			return
		}
		Fail(c, http.StatusInternalServerError, "创建用户失败")
		return
	}
	_, _ = h.enforcer.AddRoleForUserInDomain(user.ID, "viewer", rbac.DefaultDomain)

	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.register",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		After:         user,
		Status:        "success",
	})

	Created(c, user)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshReq
	_ = c.ShouldBindJSON(&req)
	token := readRefreshToken(c, req.RefreshToken)
	if token == "" {
		Fail(c, http.StatusBadRequest, "缺少 refresh_token")
		return
	}
	ctx := c.Request.Context()
	refreshTTL := h.settingsSvc.Snapshot().JWTRefreshTTL
	rec, err := h.stateStore.ConsumeRefreshToken(ctx, token)
	if err != nil {
		// 已轮换消费过的令牌再次出现，说明令牌被窃取并重放：下线整个会话，合法用户与攻击者都需重新登录
		if sid, reused, _ := h.stateStore.RefreshReuse(ctx, token); reused {
			if sid != "" {
				now := time.Now()
				_ = h.db.Model(&models.UserSession{}).Where("session_id = ?", sid).Update("revoked_at", &now).Error
				_ = h.stateStore.RevokeSession(ctx, sid, refreshTTL)
			}
			h.auditSvc.RecordFromContext(c, audit.Entry{
				DomainCode:   rbac.DefaultDomain,
				Action:       "auth.refresh_reuse",
				ResourceType: "user_session",
				ResourceID:   sid,
				Status:       "failed",
				ErrorMessage: "rotated refresh token replayed; session revoked",
			})
		}
		Fail(c, http.StatusUnauthorized, "Refresh Token 无效或已过期")
		return
	}
	_ = h.stateStore.MarkRefreshUsed(ctx, token, rec.SessionID, refreshTTL)

	var user models.User
	if revoked, rErr := h.stateStore.IsIssuedBeforeRevocation(ctx, rec.UserID, rec.IssuedAt); rErr != nil || revoked {
		Fail(c, http.StatusUnauthorized, "Refresh Token 无效或已过期")
		return
	}
	if err := h.db.First(&user, rec.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "用户不存在或已被禁用")
		return
	}
	if user.MustChangePassword {
		// 强制改密期间不允许续期会话，必须重新登录并先完成改密。
		c.JSON(http.StatusForbidden, gin.H{
			"code":    403,
			"error":   "password_change_required",
			"message": "当前账号处于强制改密状态，请重新登录并先修改密码",
		})
		return
	}

	if rec.SessionID != "" {
		if rev, rErr := h.stateStore.IsSessionRevoked(ctx, rec.SessionID); rErr != nil || rev {
			Fail(c, http.StatusUnauthorized, "该设备会话已下线，请重新登录")
			return
		}
		// Redis 中的下线标记有过期时间，数据库中的 revoked_at 是持久依据
		var revokedCount int64
		if dbErr := h.db.Model(&models.UserSession{}).
			Where("session_id = ? AND revoked_at IS NOT NULL", rec.SessionID).
			Count(&revokedCount).Error; dbErr != nil || revokedCount > 0 {
			Fail(c, http.StatusUnauthorized, "该设备会话已下线，请重新登录")
			return
		}
	}

	accessToken, _, _, err := h.jwtMgr.GenerateAccessTokenWithSession(user.ID, user.Username, user.Email, "openid profile email", "", rec.SessionID)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发令牌失败")
		return
	}
	newRefresh := uuid.NewString()
	if err := h.stateStore.SaveRefreshToken(ctx, newRefresh, security.RefreshTokenRecord{
		UserID:    user.ID,
		Username:  user.Username,
		SessionID: rec.SessionID,
	}, refreshTTL); err != nil {
		Fail(c, http.StatusInternalServerError, "刷新会话失败")
		return
	}
	if rec.SessionID != "" {
		now := time.Now()
		// 同步延长会话到期时间：下线标记的保留时长按 expires_at 计算，不延长会导致标记先于刷新令牌过期
		_ = h.db.Model(&models.UserSession{}).Where("session_id = ?", rec.SessionID).Updates(map[string]interface{}{
			"refresh_token_hash": hashRefreshToken(newRefresh),
			"last_active_at":     now,
			"ip_address":         clientip.FromGin(c),
			"expires_at":         now.Add(refreshTTL),
		}).Error
	}

	OK(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": h.deliverRefresh(c, newRefresh, refreshTTL),
		"expires_in":    int64(h.jwtMgr.AccessTTL().Seconds()),
	})
}

type logoutReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req logoutReq
	if ck := readRefreshToken(c, ""); ck != "" {
		_ = h.stateStore.DeleteRefreshToken(c.Request.Context(), ck)
	}
	clearRefreshCookie(c)
	_ = c.ShouldBindJSON(&req)

	ctx := c.Request.Context()
	if req.RefreshToken != "" {
		_ = h.stateStore.DeleteRefreshToken(ctx, req.RefreshToken)
	}
	if claimsVal, ok := c.Get("claims"); ok {
		if claims, ok2 := claimsVal.(*security.AccessClaims); ok2 && claims.ExpiresAt != nil {
			_ = h.stateStore.RevokeAccessToken(ctx, claims.ID, time.Until(claims.ExpiresAt.Time))
		}
	}
	if sid := c.GetString("session_id"); sid != "" {
		now := time.Now()
		_ = h.db.Model(&models.UserSession{}).Where("session_id = ?", sid).Update("revoked_at", &now).Error
		_ = h.stateStore.RevokeSession(ctx, sid, h.settingsSvc.Snapshot().JWTRefreshTTL)
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.logout",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", CurrentUserID(c)),
		Status:       "success",
	})
	OK(c, gin.H{"logged_out": true})
}

func (h *AuthHandler) Me(c *gin.Context) {
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(uid)
	domain := c.GetHeader("X-OpenIAM-Domain")
	if domain == "" {
		domain = rbac.DefaultDomain
	}
	policies := []rbac.PolicyRule{}
	for _, rc := range rolesMap[domain] {
		if p, pErr := h.enforcer.GetPolicies(domain, rc); pErr == nil {
			policies = append(policies, p...)
		}
	}
	var identities []models.UserIdentity
	h.db.Where("user_id = ?", uid).Find(&identities)
	var passkeyCount int64
	h.db.Model(&models.UserPasskey{}).Where("user_id = ?", uid).Count(&passkeyCount)

	var totpRow models.UserTOTP
	totpEnabled := h.db.Where("user_id = ? AND enabled = ?", uid, true).First(&totpRow).Error == nil

	unreadNotifs := CountUnreadNotifications(h.db, uid)

	capabilities := computeCapabilities(h.enforcer, uid, domain)
	adminTier, isAdmin := resolveAdminTier(h.enforcer, uid, rolesMap, capabilities)

	OK(c, gin.H{
		"user":                 user,
		"roles":                rolesMap,
		"identities":           identities,
		"policies":             policies,
		"has_password":         user.PasswordHash != "",
		"passkey_count":        passkeyCount,
		"totp_enabled":         totpEnabled,
		"is_admin":             isAdmin,
		"admin_tier":           adminTier,
		"capabilities":         capabilities,
		"session_id":           c.GetString("session_id"),
		"unread_notifications": unreadNotifs,
	})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数无效: 新密码需为 8~72 位")
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if user.PasswordHash != "" {
		// 先计数后校验：被盗的 Access Token 不能被用来无限次猜测原密码
		if !factorAttempt(c, h.stateStore, "change_password", uid, reauthMaxFailures, reauthFailureWindow) {
			return
		}
		if req.OldPassword == "" || !security.VerifyPassword(user.PasswordHash, req.OldPassword) {
			h.auditSvc.RecordFromContext(c, audit.Entry{
				DomainCode:   rbac.DefaultDomain,
				Action:       "auth.change_password",
				ResourceType: "user",
				ResourceID:   fmt.Sprintf("%d", user.ID),
				Status:       "failed",
				ErrorMessage: "invalid old password",
			})
			Fail(c, http.StatusBadRequest, "原密码不正确")
			return
		}
		clearFactorAttempts(c, h.stateStore, "change_password", uid)
	} else if !requireReauth(c, h.db, h.stateStore) {
		// 首次设置密码等同新增登录凭据；若账号已有 TOTP，需先用动态码再确认身份
		return
	}
	// 新口令不得与当前口令相同：否则强制改密账号可以把已知的默认口令原样提交一次，
	// 标记被清掉、默认口令继续可用，等于绕过整套初始凭据修复。
	if security.VerifyPassword(user.PasswordHash, req.NewPassword) {
		Fail(c, http.StatusBadRequest, "新密码不能与当前密码相同")
		return
	}
	// 强制改密（初始管理员）沿用初始口令策略，避免用 8 位弱口令替代初始强口令。
	if user.MustChangePassword {
		if vErr := security.ValidateInitialPassword(req.NewPassword); vErr != nil {
			Fail(c, http.StatusBadRequest, "新密码不符合要求："+strings.ReplaceAll(vErr.Error(), "口令", "密码"))
			return
		}
	} else if !h.checkPasswordPolicy(c, req.NewPassword) {
		return
	}
	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "修改密码失败，请稍后重试")
		return
	}
	hadPassword := user.PasswordHash != ""
	// 改密成功即清除强制改密标记，并在下方吊销该用户此前签发的所有会话。
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"password_hash":        hash,
		"must_change_password": false,
	}).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "修改密码失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.change_password",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Status:       "success",
	})
	now := time.Now()
	_ = h.db.Model(&models.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error
	if err := h.stateStore.RevokeUserTokens(c.Request.Context(), user.ID); err != nil {
		Fail(c, http.StatusInternalServerError, "密码已修改，但撤销旧会话失败，请重新登录后重试")
		return
	}
	title, what := "登录密码已修改", "你的账号登录密码已修改，所有设备上的登录状态均已失效，需要用新密码重新登录。"
	if !hadPassword {
		title, what = "已设置登录密码", "你的账号设置了登录密码，之后可以用用户名和密码登录。"
	}
	notifySecurity(c, h.notifySvc, user.ID, title, what)
	OK(c, gin.H{"changed": true, "relogin_required": true})
}

// lockedMessage 生成账号锁定提示，剩余时间按分钟向上取整，避免出现"请 873 秒后重试"这类难读的数字。
func lockedMessage(remaining time.Duration) string {
	minutes := int((remaining + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return fmt.Sprintf("密码错误次数过多，账号已临时锁定，请 %d 分钟后再试，或联系管理员解锁", minutes)
}

// ListPublicProviders 公开返回已启用的外部 OAuth 联合登录列表，供登录页渲染按钮。
func (h *AuthHandler) ListPublicProviders(c *gin.Context) {
	var providers []models.OAuthProvider
	h.db.Where("enabled = ?", true).Order("id ASC").Find(&providers)

	type item struct {
		Name        string `json:"name"`
		PluginType  string `json:"plugin_type"`
		DisplayName string `json:"display_name"`
	}
	res := make([]item, 0, len(providers))
	for _, p := range providers {
		res = append(res, item{
			Name:        p.Name,
			PluginType:  p.PluginType,
			DisplayName: p.DisplayName,
		})
	}
	OK(c, res)
}

func (h *AuthHandler) OAuthAuthorize(c *gin.Context) {
	providerName := c.Param("provider")
	redirectOverride := c.Query("redirect_uri")
	binding, err := issueOAuthBindingCookie(c)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "初始化联合登录失败")
		return
	}
	authURL, state, err := h.pluginSvc.StartLogin(c.Request.Context(), providerName, redirectOverride, binding)
	if err != nil {
		Fail(c, http.StatusBadRequest, federatedErrorMessage(err, "发起联合登录失败"))
		return
	}
	OK(c, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

type oauthCallbackReq struct {
	Code        string `json:"code" binding:"required"`
	State       string `json:"state" binding:"required"`
	RedirectURI string `json:"redirect_uri"`
}

func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	providerName := c.Param("provider")
	var req oauthCallbackReq
	if c.Request.Method == http.MethodGet {
		req.Code = c.Query("code")
		req.State = c.Query("state")
		req.RedirectURI = c.Query("redirect_uri")
		if req.Code == "" || req.State == "" {
			Fail(c, http.StatusBadRequest, "缺少 code 或 state 参数")
			return
		}
	} else {
		if err := c.ShouldBindJSON(&req); err != nil {
			Fail(c, http.StatusBadRequest, "回调参数无效")
			return
		}
	}

	binding := readOAuthBindingCookie(c)
	clearOAuthBindingCookie(c)
	result, err := h.pluginSvc.HandleCallback(
		c.Request.Context(),
		providerName,
		req.Code,
		req.State,
		req.RedirectURI,
		binding,
		clientip.FromGin(c),
		c.Request.UserAgent(),
	)
	if err != nil {
		Fail(c, http.StatusBadRequest, federatedErrorMessage(err, "联合登录失败，请稍后重试"))
		return
	}
	// 绑定流程只建立关联，不签发新的登录会话：发起绑定的浏览器本就处于登录状态
	if result.Bound {
		OK(c, gin.H{"bound": true, "provider": providerName})
		return
	}

	extra := gin.H{"is_new_user": result.IsNewUser}
	li := h.issuer()
	if li.gate(c, result.User, gateOptions{Channel: "federated", RequireTOTP: true, AllowRiskChallenge: true}, extra) {
		return
	}
	li.finish(c, result.User, "auth.oauth_login", map[string]interface{}{
		"provider":    providerName,
		"is_new_user": result.IsNewUser,
	}, extra)
}

// federatedErrorMessage 只向客户端返回联合登录插件明确标记为可公开的错误文本，其余错误统一使用兜底提示，
// 避免把上游响应体、带密钥的请求地址或数据库错误透传给未认证的调用方。
func federatedErrorMessage(err error, fallback string) string {
	var pub *oauthplugin.PublicError
	if errors.As(err, &pub) {
		return pub.Error()
	}
	return fallback
}

type sendMFACodeReq struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Channel  string `json:"channel" binding:"required"` // sms | email
}

// SendMFACode 在二步验证阶段向当前用户的绑定手机或邮箱发送一次性验证码。
func (h *AuthHandler) SendMFACode(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
		return
	}
	var req sendMFACodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	raw, err := h.stateStore.GetMFAChallenge(c.Request.Context(), req.MFAToken)
	if err != nil {
		Fail(c, http.StatusBadRequest, "二步验证会话已过期，请重新登录")
		return
	}
	var ch mfaChallengeState
	if err := json.Unmarshal(raw, &ch); err != nil {
		Fail(c, http.StatusBadRequest, "验证会话无效")
		return
	}
	method := ""
	switch strings.ToLower(strings.TrimSpace(req.Channel)) {
	case "email":
		method = "email_otp"
	case "sms":
		method = "sms_otp"
	}
	if method == "" || !slices.Contains(ch.Methods, method) {
		Fail(c, http.StatusBadRequest, "当前二步验证不支持该验证码通道")
		return
	}
	var user models.User
	if err := h.db.First(&user, ch.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "用户不存在或已禁用")
		return
	}
	res, err := h.otpSvc.SendCode(c.Request.Context(), otp.SendRequest{
		Scene:    "mfa",
		Channel:  req.Channel,
		User:     &user,
		ClientIP: clientip.FromGin(c),
	})
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	OK(c, res)
}

type verifyMFAReq struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Method   string `json:"method" binding:"required"` // totp | recovery_code | email_otp | sms_otp
	Code     string `json:"code" binding:"required"`
}

// VerifyMFA 校验二步验证因子（TOTP / 恢复码 / 邮件或短信验证码）并正式签发会话令牌。
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	var req verifyMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数格式错误")
		return
	}
	ctx := c.Request.Context()
	raw, err := h.stateStore.GetMFAChallenge(ctx, req.MFAToken)
	if err != nil {
		Fail(c, http.StatusBadRequest, "二步验证会话已过期，请重新登录")
		return
	}
	var ch mfaChallengeState
	if err := json.Unmarshal(raw, &ch); err != nil {
		Fail(c, http.StatusBadRequest, "验证会话无效")
		return
	}
	// 只接受挑战下发时允许的方式：已启用 TOTP 的账号不能改用邮件或短信验证码
	if !slices.Contains(ch.Methods, req.Method) {
		Fail(c, http.StatusBadRequest, "不支持的二次验证方式")
		return
	}
	var user models.User
	if err := h.db.First(&user, ch.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "账号不可用")
		return
	}

	tokenFails, userFails, ok := h.mfaAttempt(c, req.MFAToken, user.ID)
	if !ok {
		return
	}

	code := strings.TrimSpace(req.Code)
	verified := false
	switch req.Method {
	case "totp":
		var row models.UserTOTP
		if h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&row).Error == nil {
			verified = verifyTOTPFactor(ctx, h.stateStore, user.ID, row.Secret, code)
		}
	case "recovery_code":
		var row models.UserTOTP
		if h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&row).Error == nil {
			verified = consumeRecoveryCode(h.db, row, code)
		}
	case "email_otp":
		if h.otpSvc != nil && user.Email != "" {
			_, vErr := h.otpSvc.VerifyCode(ctx, "mfa", user.Email, code)
			verified = vErr == nil
		}
	case "sms_otp":
		if h.otpSvc != nil && user.Phone != "" {
			_, vErr := h.otpSvc.VerifyCode(ctx, "mfa", user.Phone, code)
			verified = vErr == nil
		}
	}
	if !verified {
		h.mfaFailed(c, req.MFAToken, user.ID, tokenFails, userFails, "验证码不正确或已过期")
		return
	}

	// 以原子消费结果作为唯一放行依据：并发提交同一有效验证码时只有一个请求能拿到会话
	if _, err := h.stateStore.ConsumeMFAChallenge(ctx, req.MFAToken); err != nil {
		Fail(c, http.StatusBadRequest, "二步验证会话已失效，请重新登录")
		return
	}
	_ = h.stateStore.ClearFailures(ctx, "mfa_user", fmt.Sprintf("%d", user.ID))
	_ = h.stateStore.ClearFailures(ctx, "mfa_token", req.MFAToken)
	h.issuer().finish(c, user, "auth.mfa_verify", map[string]interface{}{
		"method":  req.Method,
		"channel": ch.Channel,
	}, ch.Extra)
}

type otpLoginReq struct {
	Target       string `json:"target" binding:"required"`
	Code         string `json:"code" binding:"required"`
	CaptchaToken string `json:"captcha_token"`
}

// OTPLogin 使用一次性邮箱或短信验证码无密码登录。
func (h *AuthHandler) OTPLogin(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
		return
	}
	var req otpLoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请填写手机号或邮箱以及验证码")
		return
	}
	// 人机验证在发码环节（otp 场景）完成：验证码只会发到账号本人的邮箱或手机，
	// 且每个验证码的尝试次数有上限，提交环节再要求一次会让同一页面出现两道验证。
	target := normalizeContactTarget(req.Target)
	rec, err := h.otpSvc.VerifyCode(c.Request.Context(), "login", target, req.Code)
	if err != nil {
		Fail(c, http.StatusUnauthorized, otpFailureMessage(err, "验证码不正确或已过期"))
		return
	}
	var user models.User
	if rec.UserID == 0 || h.db.First(&user, rec.UserID).Error != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "验证码不正确或已过期")
		return
	}
	// 已启用 TOTP 的账号不允许仅凭邮箱或短信验证码登录，否则等于绕过二步验证
	var otpUserTOTP models.UserTOTP
	if h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&otpUserTOTP).Error == nil {
		Fail(c, http.StatusForbidden, "该账号已启用二步验证，请使用账号密码登录并完成二步验证")
		return
	}
	li := h.issuer()
	if li.gate(c, user, gateOptions{Channel: "otp"}, nil) {
		return
	}
	li.finish(c, user, "auth.otp_login", map[string]interface{}{"channel": rec.Channel}, nil)
}

func computeCapabilities(enforcer *rbac.Enforcer, uid uint64, domain string) []string {
	if enforcer == nil || uid == 0 {
		return nil
	}
	checks := [][2]string{
		{"users", "read"}, {"users", "write"},
		{"roles", "read"}, {"roles", "write"},
		{"permissions", "read"}, {"permissions", "write"},
		{"domains", "read"}, {"domains", "write"},
		{"oauth_clients", "read"}, {"oauth_clients", "write"},
		{"oauth_clients", "create_own"}, {"oauth_clients", "authorize"},
		{"oauth_providers", "read"}, {"oauth_providers", "write"},
		{"audit_logs", "read"}, {"system", "read"},
		{"settings", "read"}, {"settings", "write"},
	}
	isSuper := enforcer.IsSuperAdmin(uid)
	caps := make([]string, 0, len(checks)+6)
	for _, p := range checks {
		if ok, _ := enforcer.Enforce(uid, domain, p[0], p[1]); ok {
			caps = append(caps, p[0]+":"+p[1])
		}
	}
	if isSuper {
		caps = append(caps, "plugins:read", "plugins:write", "notifications:write", "sessions:read", "sessions:write", "jit:read", "jit:write", "risk:read")
	} else {
		capSet := make(map[string]bool, len(caps))
		for _, c := range caps {
			capSet[c] = true
		}
		if capSet["users:read"] || capSet["users:write"] {
			caps = append(caps, "sessions:read")
		}
		if capSet["users:write"] {
			caps = append(caps, "sessions:write")
		}
		if capSet["roles:read"] || capSet["roles:write"] {
			caps = append(caps, "jit:read")
		}
		if capSet["roles:write"] {
			caps = append(caps, "jit:write")
		}
		if capSet["audit_logs:read"] {
			caps = append(caps, "risk:read")
		}
	}
	return caps
}

func resolveAdminTier(enforcer *rbac.Enforcer, uid uint64, rolesMap map[string][]string, caps []string) (tier string, isAdmin bool) {
	if enforcer != nil && enforcer.IsSuperAdmin(uid) {
		return "platform_admin", true
	}
	hasDomainWrite := false
	hasReadAdmin := false
	for _, c := range caps {
		switch c {
		case "users:write", "roles:write", "permissions:write", "oauth_clients:write":
			hasDomainWrite = true
		case "users:read", "roles:read", "permissions:read", "audit_logs:read", "system:read", "oauth_clients:read":
			hasReadAdmin = true
		}
	}
	if !hasDomainWrite {
		for _, rList := range rolesMap {
			for _, rc := range rList {
				if rc == "domain_admin" {
					hasDomainWrite = true
				} else if rc == "auditor" {
					hasReadAdmin = true
				}
			}
		}
	}
	if hasDomainWrite {
		return "domain_admin", true
	}
	if hasReadAdmin {
		return "auditor", true
	}
	return "user", false
}

func maskEmail(e string) string {
	parts := strings.Split(e, "@")
	if len(parts) != 2 || len(parts[0]) == 0 {
		return e
	}
	name := parts[0]
	if len(name) <= 2 {
		return name[:1] + "***@" + parts[1]
	}
	return name[:2] + "***@" + parts[1]
}

func maskPhone(p string) string {
	if len(p) < 7 {
		return p
	}
	return p[:3] + "****" + p[len(p)-4:]
}
