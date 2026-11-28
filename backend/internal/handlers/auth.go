package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	"github.com/openrealm/openiam/internal/totp"
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

	if locked, ttl, err := h.stateStore.IsLoginLocked(ctx, username); err == nil && locked {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorUsername: username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    username,
			Status:        "failed",
			ErrorMessage:  "account locked due to repeated login failures",
		})
		Fail(c, http.StatusTooManyRequests, fmt.Sprintf("连续登录失败次数过多，账号已锁定，请 %d 秒后重试", int(ttl.Seconds())))
		return
	}

	snap := h.settingsSvc.Snapshot()

	var user models.User
	if err := h.db.Where("username = ? OR email = ?", username, username).First(&user).Error; err != nil {
		_, locked, _ := h.stateStore.RecordLoginFailure(ctx, username, snap.MaxLoginFailures, time.Duration(snap.LockoutMinutes)*time.Minute)
		msg := "用户名或密码错误"
		if locked {
			msg = "连续登录失败次数过多，账号已被临时锁定"
		}
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorUsername: username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    username,
			Status:        "failed",
			ErrorMessage:  "user not found",
		})
		Fail(c, http.StatusUnauthorized, msg)
		return
	}

	// 以规范用户名检查锁定状态，防止通过邮箱登录绕过按用户名的失败计数
	if locked, ttl, err := h.stateStore.IsLoginLocked(ctx, user.Username); err == nil && locked {
		Fail(c, http.StatusTooManyRequests, fmt.Sprintf("连续登录失败次数过多，账号已锁定，请 %d 秒后重试", int(ttl.Seconds())))
		return
	}

	if user.Status != "active" {
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
			Fail(c, http.StatusTooManyRequests, "连续登录失败次数过多，账号已被临时锁定")
			return
		}
		Fail(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	_ = h.stateStore.ClearLoginFailures(ctx, username)
	_ = h.stateStore.ClearLoginFailures(ctx, user.Username)
	now := time.Now()
	_ = h.db.Model(&user).Updates(map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": clientip.FromGin(c),
	}).Error

	// 强制改密状态：只签发短期受限令牌，不下发 Refresh Token；
	// 该令牌仅能用于修改密码与退出登录，其余接口由 AuthMiddleware 统一返回 403 password_change_required。
	if user.MustChangePassword {
		accessToken, _, _, err := h.jwtMgr.GenerateAccessToken(
			user.ID, user.Username, user.Email,
			security.ScopePasswordChange, "", security.PasswordChangeTokenTTL,
		)
		if err != nil {
			Fail(c, http.StatusInternalServerError, "签发令牌失败")
			return
		}
		clearRefreshCookie(c)
		h.auditSvc.RecordFromContext(c, audit.Entry{
			ActorID:       user.ID,
			ActorUsername: user.Username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "auth.login",
			ResourceType:  "user",
			ResourceID:    fmt.Sprintf("%d", user.ID),
			After:         map[string]interface{}{"must_change_password": true},
			Status:        "success",
		})
		OK(c, gin.H{
			"access_token":         accessToken,
			"expires_in":           int64(security.PasswordChangeTokenTTL.Seconds()),
			"must_change_password": true,
			"user":                 user,
		})
		return
	}

	// 风险自适应评估与 TOTP 多因素挑战检查
	var riskEval *risk.Evaluation
	if h.riskEngine != nil {
		riskEval = h.riskEngine.EvaluateLogin(
			ctx,
			user,
			clientip.FromGin(c),
			truncateStr(c.GetHeader("User-Agent"), 512),
			headerFingerprint(c),
			headerGeo(c, h.settingsSvc),
			now,
		)
		if riskEval.Action == "block" {
			Fail(c, http.StatusForbidden, "当前登录环境存在高风险，已被系统安全策略阻断")
			return
		}
	}

	var userTOTP models.UserTOTP
	totpEnabled := h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&userTOTP).Error == nil
	needMFA := totpEnabled || (riskEval != nil && riskEval.Action == "challenge_mfa")
	if needMFA {
		methods := make([]string, 0, 4)
		if totpEnabled {
			methods = append(methods, "totp", "recovery_code")
		}
		if user.Email != "" && snap.SMTPEnabled {
			methods = append(methods, "email_otp")
		}
		if user.Phone != "" {
			methods = append(methods, "sms_otp")
		}
		if len(methods) > 0 {
			mfaToken := "mfa_" + uuid.NewString()
			riskLevel := "low"
			var riskReasons []string
			if riskEval != nil {
				riskLevel = riskEval.Level
				riskReasons = riskEval.Reasons
			}
			payload, _ := json.Marshal(mfaChallengeState{
				UserID:      user.ID,
				Methods:     methods,
				RiskLevel:   riskLevel,
				RiskReasons: riskReasons,
			})
			if err := h.stateStore.SaveMFAChallenge(ctx, mfaToken, payload, 5*time.Minute); err != nil {
				Fail(c, http.StatusInternalServerError, "创建二次验证会话失败")
				return
			}
			OK(c, gin.H{
				"mfa_required": true,
				"mfa_token":    mfaToken,
				"methods":      methods,
				"risk_level":   riskLevel,
				"risk_reasons": riskReasons,
				"email_hint":   maskEmail(user.Email),
				"phone_hint":   maskPhone(user.Phone),
			})
			return
		}
	}

	accessToken, refreshToken, _, expiresIn, err := createSessionAndTokens(c, h.db, h.jwtMgr, h.stateStore, h.settingsSvc, user)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发令牌与保存会话失败")
		return
	}

	rolesMap, _ := h.enforcer.GetAllUserRoles(user.ID)
	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.login",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		Status:        "success",
	})

	OK(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": h.deliverRefresh(c, refreshToken, snap.JWTRefreshTTL),
		"expires_in":    expiresIn,
		"user":          user,
		"roles":         rolesMap,
	})
}

type registerReq struct {
	Username     string `json:"username" binding:"required,min=3,max=64,excludes=@"`
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required,min=8,maxbytes=72"`
	DisplayName  string `json:"display_name"`
	CaptchaToken string `json:"captcha_token"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	if !h.settingsSvc.Snapshot().AllowPublicRegister {
		Fail(c, http.StatusForbidden, "系统管理员已关闭自助注册功能")
		return
	}
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "注册参数无效: "+err.Error())
		return
	}
	if h.pluginMgr != nil {
		if cErr := h.pluginMgr.VerifyCaptchaForScene(c.Request.Context(), "register", req.CaptchaToken); cErr != nil {
			Fail(c, http.StatusBadRequest, cErr.Error())
			return
		}
	}

	var count int64
	h.db.Model(&models.User{}).Where("username = ? OR email = ?", req.Username, req.Email).Count(&count)
	if count > 0 {
		Fail(c, http.StatusConflict, "用户名或邮箱已被占用")
		return
	}

	hash, err := security.HashPassword(req.Password)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "密码加密失败")
		return
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = req.Username
	}
	user := models.User{
		Username:     strings.TrimSpace(req.Username),
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  displayName,
		PasswordHash: hash,
		Status:       "active",
	}
	if err := h.db.Create(&user).Error; err != nil {
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
	rec, err := h.stateStore.ConsumeRefreshToken(ctx, token)
	if err != nil {
		Fail(c, http.StatusUnauthorized, "Refresh Token 无效或已过期")
		return
	}

	var user models.User
	if revoked, rErr := h.stateStore.IsIssuedBeforeRevocation(ctx, rec.UserID, rec.IssuedAt); rErr != nil || revoked {
		Fail(c, http.StatusUnauthorized, "Refresh Token 无效或已过期")
		return
	}
	if err := h.db.First(&user, rec.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "用户不存在或已被禁用")
		return
	}
	// 库里的「凭据有效起点」是权威判定：改密 / 重置之后，此前签发的 refresh token 一律失效，
	// 即使 Redis 里的失效时间点已经丢失（重启、淘汰）也不能放行。
	if tokensRevokedAfter(user, rec.IssuedAt) {
		Fail(c, http.StatusUnauthorized, "Refresh Token 已失效，请重新登录")
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
	}, h.settingsSvc.Snapshot().JWTRefreshTTL); err != nil {
		Fail(c, http.StatusInternalServerError, "刷新会话失败")
		return
	}
	if rec.SessionID != "" {
		now := time.Now()
		_ = h.db.Model(&models.UserSession{}).Where("session_id = ?", rec.SessionID).Updates(map[string]interface{}{
			"refresh_token_hash": hashRefreshToken(newRefresh),
			"last_active_at":     now,
			"ip_address":         clientip.FromGin(c),
		}).Error
	}

	OK(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": h.deliverRefresh(c, newRefresh, h.settingsSvc.Snapshot().JWTRefreshTTL),
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

	var unreadNotifs int64
	_ = h.db.Model(&models.Notification{}).
		Where("(user_id = ? OR (category = ? AND user_id = 0)) AND is_read = ?", uid, notify.CategoryAnnouncement, false).
		Count(&unreadNotifs).Error

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
		if req.OldPassword == "" || !security.VerifyPassword(user.PasswordHash, req.OldPassword) {
			Fail(c, http.StatusBadRequest, "原密码不正确")
			return
		}
	}
	// 新口令不得与当前口令相同：否则强制改密账号可以把已知的默认口令原样提交一次，
	// 标记被清掉、默认口令继续可用，等于绕过整套初始凭据修复。
	if security.VerifyPassword(user.PasswordHash, req.NewPassword) {
		Fail(c, http.StatusBadRequest, "新密码不能与当前密码相同")
		return
	}
	if security.IsLegacyDefaultPassword(req.NewPassword) {
		Fail(c, http.StatusBadRequest, "新密码不能使用历史默认口令")
		return
	}
	// 强制改密（初始管理员）沿用初始口令策略，避免用 8 位弱口令替代初始强口令。
	if user.MustChangePassword {
		if vErr := security.ValidateInitialPassword(req.NewPassword); vErr != nil {
			Fail(c, http.StatusBadRequest, "新密码不符合初始口令策略: "+vErr.Error())
			return
		}
	}
	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "密码加密失败")
		return
	}
	// 改密成功即清除强制改密标记，并把「凭据有效起点」推到当前时刻：
	// 凭据有效起点与口令哈希在同一条 UPDATE 里落库，旧刷新令牌从这一刻起再也换不出新令牌。
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"password_hash":        hash,
		"must_change_password": false,
		"tokens_valid_after":   time.Now().UnixMilli(),
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
	if err := h.stateStore.RevokeUserTokens(c.Request.Context(), user.ID); err != nil {
		Fail(c, http.StatusInternalServerError, "密码已修改，但撤销旧会话失败，请重新登录后重试")
		return
	}
	OK(c, gin.H{"changed": true, "relogin_required": true})
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
	authURL, state, err := h.pluginSvc.StartLogin(c.Request.Context(), providerName, redirectOverride)
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
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
			Fail(c, http.StatusBadRequest, "回调参数无效: "+err.Error())
			return
		}
	}

	result, err := h.pluginSvc.HandleCallback(
		c.Request.Context(),
		providerName,
		req.Code,
		req.State,
		req.RedirectURI,
		clientip.FromGin(c),
		c.Request.UserAgent(),
	)
	if err != nil {
		Fail(c, http.StatusBadRequest, "联合登录失败: "+err.Error())
		return
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(result.User.ID)
	OK(c, gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": h.deliverRefresh(c, result.RefreshToken, h.settingsSvc.Snapshot().JWTRefreshTTL),
		"expires_in":    result.ExpiresIn,
		"user":          result.User,
		"roles":         rolesMap,
		"is_new_user":   result.IsNewUser,
	})
}

type mfaChallengeState struct {
	UserID      uint64   `json:"user_id"`
	Methods     []string `json:"methods"`
	RiskLevel   string   `json:"risk_level"`
	RiskReasons []string `json:"risk_reasons"`
}

type sendMFACodeReq struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Channel  string `json:"channel" binding:"required"` // sms | email
}

// SendMFACode 在二步验证阶段向当前用户的绑定手机或邮箱发送一次性验证码。
func (h *AuthHandler) SendMFACode(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务未初始化")
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
	var user models.User
	if err := h.db.First(&user, ch.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "账号不可用")
		return
	}

	if h.mfaLocked(c, ch.UserID) {
		Fail(c, http.StatusTooManyRequests, "二步验证失败次数过多，账号已被临时限制，请稍后再试")
		return
	}

	code := strings.TrimSpace(req.Code)
	switch req.Method {
	case "totp":
		var row models.UserTOTP
		if err := h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&row).Error; err != nil {
			Fail(c, http.StatusBadRequest, "未启用 TOTP 验证器")
			return
		}
		if !totp.VerifyCode(row.Secret, code, time.Now()) {
			h.mfaFailed(c, req.MFAToken, user.ID, "验证器动态码不正确")
			return
		}
	case "recovery_code":
		var row models.UserTOTP
		if err := h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&row).Error; err != nil {
			Fail(c, http.StatusBadRequest, "未启用 TOTP 验证器")
			return
		}
		nextHashes, ok := consumeRecoveryCodeHash(parseRecoveryHashes(row.RecoveryCodesJSON), code)
		if !ok {
			h.mfaFailed(c, req.MFAToken, user.ID, "备用恢复码不正确或已被使用")
			return
		}
		b, _ := json.Marshal(nextHashes)
		_ = h.db.Model(&row).Update("recovery_codes_json", string(b)).Error
	case "email_otp":
		if h.otpSvc == nil || user.Email == "" {
			Fail(c, http.StatusBadRequest, "未配置邮箱验证码通道")
			return
		}
		if _, err := h.otpSvc.VerifyCode(ctx, "mfa", user.Email, code); err != nil {
			h.mfaFailed(c, req.MFAToken, user.ID, err.Error())
			return
		}
	case "sms_otp":
		if h.otpSvc == nil || user.Phone == "" {
			Fail(c, http.StatusBadRequest, "未配置短信验证码通道")
			return
		}
		if _, err := h.otpSvc.VerifyCode(ctx, "mfa", user.Phone, code); err != nil {
			h.mfaFailed(c, req.MFAToken, user.ID, err.Error())
			return
		}
	default:
		Fail(c, http.StatusBadRequest, "不支持的二次验证方式")
		return
	}

	_, _ = h.stateStore.ConsumeMFAChallenge(ctx, req.MFAToken)
	_ = h.stateStore.ClearFailures(ctx, "mfa_user", fmt.Sprintf("%d", user.ID))
	accessToken, refreshToken, _, expiresIn, err := createSessionAndTokens(c, h.db, h.jwtMgr, h.stateStore, h.settingsSvc, user)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发会话令牌失败")
		return
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(user.ID)
	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.mfa_verify",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		After:         map[string]interface{}{"method": req.Method},
		Status:        "success",
	})
	OK(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": h.deliverRefresh(c, refreshToken, h.settingsSvc.Snapshot().JWTRefreshTTL),
		"expires_in":    expiresIn,
		"user":          user,
		"roles":         rolesMap,
	})
}

type otpLoginReq struct {
	Target       string `json:"target" binding:"required"`
	Code         string `json:"code" binding:"required"`
	CaptchaToken string `json:"captcha_token"`
}

// OTPLogin 使用一次性邮箱或短信验证码无密码登录。
func (h *AuthHandler) OTPLogin(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务未初始化")
		return
	}
	var req otpLoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	if h.pluginMgr != nil {
		if cErr := h.pluginMgr.VerifyCaptchaForScene(c.Request.Context(), "login", req.CaptchaToken); cErr != nil {
			Fail(c, http.StatusBadRequest, cErr.Error())
			return
		}
	}
	target := strings.TrimSpace(req.Target)
	rec, err := h.otpSvc.VerifyCode(c.Request.Context(), "login", target, req.Code)
	if err != nil {
		Fail(c, http.StatusUnauthorized, err.Error())
		return
	}
	var user models.User
	if rec.UserID > 0 {
		err = h.db.First(&user, rec.UserID).Error
	} else {
		err = h.db.Where("email = ? OR phone = ?", target, target).First(&user).Error
	}
	if err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "该邮箱或手机号尚未绑定有效账号")
		return
	}
	// 已启用 TOTP 的账号不允许仅凭邮箱或短信验证码登录，否则等于绕过二步验证
	var otpUserTOTP models.UserTOTP
	if h.db.Where("user_id = ? AND enabled = ?", user.ID, true).First(&otpUserTOTP).Error == nil {
		Fail(c, http.StatusForbidden, "该账号已启用二步验证，请使用账号密码登录并完成二步验证")
		return
	}
	now := time.Now()
	_ = h.db.Model(&user).Updates(map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": clientip.FromGin(c),
	}).Error

	accessToken, refreshToken, _, expiresIn, err := createSessionAndTokens(c, h.db, h.jwtMgr, h.stateStore, h.settingsSvc, user)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发会话失败")
		return
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(user.ID)
	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.otp_login",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		After:         map[string]interface{}{"channel": rec.Channel},
		Status:        "success",
	})
	OK(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": h.deliverRefresh(c, refreshToken, h.settingsSvc.Snapshot().JWTRefreshTTL),
		"expires_in":    expiresIn,
		"user":          user,
		"roles":         rolesMap,
	})
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
