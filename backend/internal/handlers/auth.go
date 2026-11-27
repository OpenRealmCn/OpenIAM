package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/rbac"
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
}

func NewAuthHandler(
	db *gorm.DB,
	jwtMgr *security.JWTManager,
	stateStore *security.StateStore,
	enforcer *rbac.Enforcer,
	auditSvc *audit.Service,
	pluginSvc *oauthplugin.Service,
	settingsSvc *settings.Service,
) *AuthHandler {
	return &AuthHandler{
		db:          db,
		jwtMgr:      jwtMgr,
		stateStore:  stateStore,
		enforcer:    enforcer,
		auditSvc:    auditSvc,
		pluginSvc:   pluginSvc,
		settingsSvc: settingsSvc,
	}
}

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入用户名和密码")
		return
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
		Fail(c, http.StatusForbidden, "账号已被禁用")
		return
	}

	if !security.VerifyPassword(user.PasswordHash, req.Password) {
		count, locked, _ := h.stateStore.RecordLoginFailure(ctx, username, snap.MaxLoginFailures, time.Duration(snap.LockoutMinutes)*time.Minute)
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
	now := time.Now()
	_ = h.db.Model(&user).Updates(map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": c.ClientIP(),
	}).Error

	accessToken, _, _, err := h.jwtMgr.GenerateAccessToken(user.ID, user.Username, user.Email, "openid profile email", "")
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发令牌失败")
		return
	}
	refreshToken := uuid.NewString()
	if err := h.stateStore.SaveRefreshToken(ctx, refreshToken, security.RefreshTokenRecord{
		UserID:   user.ID,
		Username: user.Username,
	}, snap.JWTRefreshTTL); err != nil {
		Fail(c, http.StatusInternalServerError, "保存会话失败")
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
		"refresh_token": refreshToken,
		"expires_in":    int64(h.jwtMgr.AccessTTL().Seconds()),
		"user":          user,
		"roles":         rolesMap,
	})
}

type registerReq struct {
	Username    string `json:"username" binding:"required,min=3,max=64"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=6"`
	DisplayName string `json:"display_name"`
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
		Fail(c, http.StatusInternalServerError, "创建用户失败: "+err.Error())
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
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "缺少 refresh_token")
		return
	}
	ctx := c.Request.Context()
	rec, err := h.stateStore.ConsumeRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		Fail(c, http.StatusUnauthorized, "Refresh Token 无效或已过期")
		return
	}

	var user models.User
	if err := h.db.First(&user, rec.UserID).Error; err != nil || user.Status != "active" {
		Fail(c, http.StatusUnauthorized, "用户不存在或已被禁用")
		return
	}

	accessToken, _, _, err := h.jwtMgr.GenerateAccessToken(user.ID, user.Username, user.Email, "openid profile email", "")
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发令牌失败")
		return
	}
	newRefresh := uuid.NewString()
	if err := h.stateStore.SaveRefreshToken(ctx, newRefresh, security.RefreshTokenRecord{
		UserID:   user.ID,
		Username: user.Username,
	}, h.settingsSvc.Snapshot().JWTRefreshTTL); err != nil {
		Fail(c, http.StatusInternalServerError, "刷新会话失败")
		return
	}

	OK(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefresh,
		"expires_in":    int64(h.jwtMgr.AccessTTL().Seconds()),
	})
}

type logoutReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req logoutReq
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
	policies, _ := h.enforcer.GetPolicies(domain, "")
	var identities []models.UserIdentity
	h.db.Where("user_id = ?", uid).Find(&identities)

	OK(c, gin.H{
		"user":       user,
		"roles":      rolesMap,
		"identities": identities,
		"policies":   policies,
	})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数无效: 新密码至少 6 位")
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if user.PasswordHash != "" && !security.VerifyPassword(user.PasswordHash, req.OldPassword) {
		Fail(c, http.StatusBadRequest, "原密码不正确")
		return
	}
	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "密码加密失败")
		return
	}
	if err := h.db.Model(&user).Update("password_hash", hash).Error; err != nil {
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
	OK(c, gin.H{"changed": true})
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
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		Fail(c, http.StatusBadRequest, "联合登录失败: "+err.Error())
		return
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(result.User.ID)
	OK(c, gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
		"user":          result.User,
		"roles":         rolesMap,
		"is_new_user":   result.IsNewUser,
	})
}
