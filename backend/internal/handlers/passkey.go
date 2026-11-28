package handlers

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type PasskeyHandler struct {
	db          *gorm.DB
	jwtMgr      *security.JWTManager
	stateStore  *security.StateStore
	enforcer    *rbac.Enforcer
	auditSvc    *audit.Service
	settingsSvc *settings.Service
}

func NewPasskeyHandler(
	db *gorm.DB,
	jwtMgr *security.JWTManager,
	stateStore *security.StateStore,
	enforcer *rbac.Enforcer,
	auditSvc *audit.Service,
	settingsSvc *settings.Service,
) *PasskeyHandler {
	return &PasskeyHandler{
		db:          db,
		jwtMgr:      jwtMgr,
		stateStore:  stateStore,
		enforcer:    enforcer,
		auditSvc:    auditSvc,
		settingsSvc: settingsSvc,
	}
}

type webAuthnUser struct {
	user  models.User
	creds []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, u.user.ID)
	return b
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.user.Username
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Username
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

func (h *PasskeyHandler) loadWebAuthnUser(userID uint64) (*webAuthnUser, error) {
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		return nil, err
	}
	var rows []models.UserPasskey
	if err := h.db.Where("user_id = ?", userID).Find(&rows).Error; err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(r.CredentialJSON), &cred); err == nil {
			creds = append(creds, cred)
		}
	}
	return &webAuthnUser{user: user, creds: creds}, nil
}

func (h *PasskeyHandler) buildWebAuthn(c *gin.Context) (*webauthn.WebAuthn, error) {
	snap := h.settingsSvc.Snapshot()
	rpName := snap.SiteName
	if rpName == "" {
		rpName = "OpenIAM"
	}

	origins := make([]string, 0, 4)
	seen := make(map[string]bool)
	addOrigin := func(raw string) {
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
			o := u.Scheme + "://" + u.Host
			if !seen[o] {
				seen[o] = true
				origins = append(origins, o)
			}
		}
	}

	reqOrigin := strings.TrimSpace(c.GetHeader("Origin"))
	addOrigin(reqOrigin)
	addOrigin(snap.OAuthServerIssuer)
	for _, o := range snap.CORSAllowOrigins {
		addOrigin(o)
	}

	scheme := "http"
	if isSecureRequest(c) {
		scheme = "https"
	}
	if c.Request.Host != "" {
		addOrigin(scheme + "://" + c.Request.Host)
	}

	rpID := "localhost"
	if reqOrigin != "" {
		if u, err := url.Parse(reqOrigin); err == nil && u.Hostname() != "" {
			rpID = u.Hostname()
		}
	} else if c.Request.Host != "" {
		if u, err := url.Parse(scheme + "://" + c.Request.Host); err == nil && u.Hostname() != "" {
			rpID = u.Hostname()
		}
	}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
}

// ListPasskeys 返回当前登录用户已绑定的通行密钥列表。
func (h *PasskeyHandler) ListPasskeys(c *gin.Context) {
	var rows []models.UserPasskey
	if err := h.db.Where("user_id = ?", CurrentUserID(c)).Order("id DESC").Find(&rows).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询通行密钥失败")
		return
	}
	OK(c, rows)
}

// BeginRegisterPasskey 生成 WebAuthn 注册 Challenge。
func (h *PasskeyHandler) BeginRegisterPasskey(c *gin.Context) {
	wa, err := h.buildWebAuthn(c)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "初始化通行密钥服务失败: "+err.Error())
		return
	}
	waUser, err := h.loadWebAuthnUser(CurrentUserID(c))
	if err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}

	exclude := make([]protocol.CredentialDescriptor, 0, len(waUser.creds))
	for _, cred := range waUser.creds {
		exclude = append(exclude, cred.Descriptor())
	}

	options, session, err := wa.BeginRegistration(
		waUser,
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成通行密钥注册参数失败: "+err.Error())
		return
	}

	sessionID := uuid.NewString()
	sessBytes, _ := json.Marshal(session)
	if err := h.stateStore.SavePasskeySession(c.Request.Context(), sessionID, sessBytes, 5*time.Minute); err != nil {
		Fail(c, http.StatusInternalServerError, "保存验证会话失败")
		return
	}

	OK(c, gin.H{
		"session_id": sessionID,
		"options":    options,
	})
}

// FinishRegisterPasskey 校验浏览器返回的 WebAuthn 凭证并持久化绑定。
func (h *PasskeyHandler) FinishRegisterPasskey(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Query("session_id"))
	keyName := strings.TrimSpace(c.Query("name"))
	if sessionID == "" {
		Fail(c, http.StatusBadRequest, "缺少 session_id")
		return
	}
	if keyName == "" {
		keyName = "通行密钥 " + time.Now().Format("01-02 15:04")
	}
	if len(keyName) > 128 {
		keyName = keyName[:128]
	}

	rawSess, err := h.stateStore.ConsumePasskeySession(c.Request.Context(), sessionID)
	if err != nil {
		Fail(c, http.StatusBadRequest, "验证会话已过期，请重新发起绑定")
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(rawSess, &session); err != nil {
		Fail(c, http.StatusBadRequest, "验证会话数据无效")
		return
	}

	wa, err := h.buildWebAuthn(c)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "初始化通行密钥服务失败")
		return
	}
	waUser, err := h.loadWebAuthnUser(CurrentUserID(c))
	if err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}

	credential, err := wa.FinishRegistration(waUser, session, c.Request)
	if err != nil {
		Fail(c, http.StatusBadRequest, "通行密钥校验失败: "+err.Error())
		return
	}

	credJSON, err := json.Marshal(credential)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "序列化凭证失败")
		return
	}
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	row := models.UserPasskey{
		UserID:         waUser.user.ID,
		CredentialID:   credIDStr,
		Name:           keyName,
		CredentialJSON: string(credJSON),
	}
	if err := h.db.Create(&row).Error; err != nil {
		Fail(c, http.StatusConflict, "该通行密钥已绑定")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.passkey.register",
		ResourceType: "user_passkey",
		ResourceID:   fmt.Sprintf("%d", row.ID),
		After:        map[string]interface{}{"name": row.Name},
		Status:       "success",
	})
	Created(c, row)
}

// DeletePasskey 删除当前用户的指定通行密钥。
func (h *PasskeyHandler) DeletePasskey(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的通行密钥 ID")
		return
	}
	uid := CurrentUserID(c)
	var row models.UserPasskey
	if err := h.db.Where("id = ? AND user_id = ?", id, uid).First(&row).Error; err != nil {
		Fail(c, http.StatusNotFound, "通行密钥不存在")
		return
	}
	if err := h.db.Delete(&row).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除通行密钥失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.passkey.delete",
		ResourceType: "user_passkey",
		ResourceID:   fmt.Sprintf("%d", id),
		Before:       map[string]interface{}{"name": row.Name},
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true})
}

type passkeyLoginBeginReq struct {
	Username string `json:"username"`
}

// BeginPasskeyLogin 发起通行密钥无密码登录（支持填用户名或 Discoverable 无输入登录）。
func (h *PasskeyHandler) BeginPasskeyLogin(c *gin.Context) {
	var req passkeyLoginBeginReq
	_ = c.ShouldBindJSON(&req)

	wa, err := h.buildWebAuthn(c)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "初始化通行密钥服务失败: "+err.Error())
		return
	}

	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData

	username := strings.TrimSpace(req.Username)
	if username != "" {
		var user models.User
		if err := h.db.Where("(username = ? OR email = ?) AND status = ?", username, username, "active").First(&user).Error; err != nil {
			Fail(c, http.StatusBadRequest, "未找到该账号或未绑定通行密钥")
			return
		}
		waUser, err := h.loadWebAuthnUser(user.ID)
		if err != nil || len(waUser.creds) == 0 {
			Fail(c, http.StatusBadRequest, "该账号尚未绑定通行密钥")
			return
		}
		options, session, err = wa.BeginLogin(waUser)
		if err != nil {
			Fail(c, http.StatusInternalServerError, "生成登录挑战失败: "+err.Error())
			return
		}
	} else {
		options, session, err = wa.BeginDiscoverableLogin()
		if err != nil {
			Fail(c, http.StatusInternalServerError, "生成登录挑战失败: "+err.Error())
			return
		}
	}

	sessionID := uuid.NewString()
	sessBytes, _ := json.Marshal(session)
	if err := h.stateStore.SavePasskeySession(c.Request.Context(), sessionID, sessBytes, 5*time.Minute); err != nil {
		Fail(c, http.StatusInternalServerError, "保存登录会话失败")
		return
	}

	OK(c, gin.H{
		"session_id": sessionID,
		"options":    options,
	})
}

// FinishPasskeyLogin 验证通行密钥断言并签发 OpenIAM 登录会话。
func (h *PasskeyHandler) FinishPasskeyLogin(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Query("session_id"))
	if sessionID == "" {
		Fail(c, http.StatusBadRequest, "缺少 session_id")
		return
	}

	rawSess, err := h.stateStore.ConsumePasskeySession(c.Request.Context(), sessionID)
	if err != nil {
		Fail(c, http.StatusBadRequest, "登录会话已过期，请重试")
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(rawSess, &session); err != nil {
		Fail(c, http.StatusBadRequest, "登录会话无效")
		return
	}

	wa, err := h.buildWebAuthn(c)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "初始化通行密钥服务失败")
		return
	}

	var matchedUser *webAuthnUser
	var cred *webauthn.Credential

	if len(session.UserID) == 8 {
		uid := binary.BigEndian.Uint64(session.UserID)
		matchedUser, err = h.loadWebAuthnUser(uid)
		if err != nil {
			Fail(c, http.StatusUnauthorized, "用户不存在")
			return
		}
		cred, err = wa.FinishLogin(matchedUser, session, c.Request)
	} else {
		cred, err = wa.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			if len(userHandle) == 8 {
				uid := binary.BigEndian.Uint64(userHandle)
				u, uErr := h.loadWebAuthnUser(uid)
				if uErr == nil {
					matchedUser = u
					return u, nil
				}
			}
			credIDStr := base64.RawURLEncoding.EncodeToString(rawID)
			var row models.UserPasskey
			if qErr := h.db.Where("credential_id = ?", credIDStr).First(&row).Error; qErr != nil {
				return nil, qErr
			}
			u, uErr := h.loadWebAuthnUser(row.UserID)
			if uErr != nil {
				return nil, uErr
			}
			matchedUser = u
			return u, nil
		}, session, c.Request)
	}
	if err != nil || matchedUser == nil || cred == nil {
		Fail(c, http.StatusUnauthorized, "通行密钥验证失败")
		return
	}
	if matchedUser.user.Status != "active" {
		Fail(c, http.StatusForbidden, "账号已被禁用")
		return
	}

	// 更新通行密钥签名计数与最后使用时间
	now := time.Now()
	credIDStr := base64.RawURLEncoding.EncodeToString(cred.ID)
	if updatedJSON, mErr := json.Marshal(cred); mErr == nil {
		_ = h.db.Model(&models.UserPasskey{}).
			Where("credential_id = ?", credIDStr).
			Updates(map[string]interface{}{
				"credential_json": string(updatedJSON),
				"last_used_at":    &now,
			}).Error
	}
	_ = h.db.Model(&matchedUser.user).Updates(map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": c.ClientIP(),
	}).Error

	accessToken, refreshToken, _, expiresIn, err := createSessionAndTokens(c, h.db, h.jwtMgr, h.stateStore, h.settingsSvc, matchedUser.user)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发令牌与保存会话失败")
		return
	}

	snap := h.settingsSvc.Snapshot()
	setRefreshCookie(c, refreshToken, snap.JWTRefreshTTL)
	resp := gin.H{
		"access_token": accessToken,
		"expires_in":   expiresIn,
		"user":         matchedUser.user,
	}
	if c.GetHeader("X-Token-Delivery") == "body" {
		resp["refresh_token"] = refreshToken
	}
	rolesMap, _ := h.enforcer.GetAllUserRoles(matchedUser.user.ID)
	resp["roles"] = rolesMap

	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       matchedUser.user.ID,
		ActorUsername: matchedUser.user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.passkey_login",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", matchedUser.user.ID),
		Status:        "success",
	})
	OK(c, resp)
}
