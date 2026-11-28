package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
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
	"github.com/openrealm/openiam/internal/clientip"
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

// errPasskeyOriginRejected 表示请求来源不在服务端白名单内（属于调用方问题，返回 400）。
var errPasskeyOriginRejected = errors.New("通行密钥请求来源被拒绝")

// failPasskeyInit 把「来源被拒」映射成 400，其余初始化问题（配置缺失等）仍是 500。
func failPasskeyInit(c *gin.Context, err error) {
	if errors.Is(err, errPasskeyOriginRejected) {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	Fail(c, http.StatusInternalServerError, "初始化通行密钥服务失败: "+err.Error())
}

// buildWebAuthn 依据服务端配置构建 WebAuthn 实例，并校验本次请求的来源。
// RP ID 与允许来源只来自服务端配置（webauthn.rp_id / webauthn.allowed_origins），
// 绝不采信请求里的 Origin，也不再拿 Host 兜底：否则任何域名都能让用户在这里注册/登录通行密钥，
// 攻击者用自己的站点即可拿到一把能登录受害者账号的「钥匙」。
func (h *PasskeyHandler) buildWebAuthn(c *gin.Context) (*webauthn.WebAuthn, error) {
	snap := h.settingsSvc.Snapshot()
	rpName := snap.SiteName
	if rpName == "" {
		rpName = "OpenIAM"
	}
	// 允许来源与 RP ID 只取服务端配置，绝不采信请求里的 Origin / X-Forwarded-Host，也不拿 Host 兜底。
	// 未单独配置 webauthn.* 时，沿用站点已配置的公开地址（OAuth 签发地址 + CORS 白名单），避免升级后通行密钥直接不可用。
	origins := make([]string, 0, 4)
	allowed := make(map[string]bool, 4)
	addOrigin := func(raw string) {
		o := normalizeOrigin(raw)
		if o == "" || allowed[o] {
			return
		}
		allowed[o] = true
		origins = append(origins, o)
	}
	for _, raw := range snap.WebAuthnAllowedOrigins {
		addOrigin(raw)
	}
	if len(origins) == 0 {
		addOrigin(snap.OAuthServerIssuer)
		for _, raw := range snap.CORSAllowOrigins {
			addOrigin(raw)
		}
	}
	if len(origins) == 0 {
		return nil, errors.New("通行密钥未配置允许来源：请设置 webauthn.allowed_origins 或 server.oauth_server_issuer")
	}

	rpID := strings.TrimSpace(snap.WebAuthnRPID)
	if rpID == "" {
		// 回退取值同样来自服务端配置：第一个允许来源的主机名。
		if u, err := url.Parse(origins[0]); err == nil {
			rpID = u.Hostname()
		}
	}
	if rpID == "" {
		return nil, errors.New("通行密钥未配置 RP ID：请设置 webauthn.rp_id")
	}

	reqOrigin := normalizeOrigin(c.GetHeader("Origin"))
	if reqOrigin == "" {
		h.recordPasskeyOriginRejected(c, "缺少 Origin 头")
		return nil, fmt.Errorf("%w: 缺少 Origin 头，无法校验请求来源", errPasskeyOriginRejected)
	}
	if !allowed[reqOrigin] {
		h.recordPasskeyOriginRejected(c, "来源不在白名单: "+reqOrigin)
		return nil, fmt.Errorf("%w: 请求来源不在通行密钥允许列表中", errPasskeyOriginRejected)
	}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
}

// recordPasskeyOriginRejected 把被拒绝的通行密钥来源写成安全事件，便于值守时发现探测行为。
func (h *PasskeyHandler) recordPasskeyOriginRejected(c *gin.Context, detail string) {
	if h.auditSvc == nil {
		return
	}
	h.auditSvc.Record(audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.passkey.origin_rejected",
		ResourceType: "user_passkey",
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Status:       "failed",
		ErrorMessage: detail,
	})
}

// normalizeOrigin 把来源收敛成 scheme://host[:port]，解析失败返回空串。
func normalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
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
		failPasskeyInit(c, err)
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
		// 通行密钥在本平台是无密码登录的唯一因子，注册时必须强制用户验证（PIN / 生物识别）。
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
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
		failPasskeyInit(c, err)
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
	// 服务端复核 UV 标志：没有完成用户验证的凭证不能作为唯一登录因子存在。
	if !credential.Flags.UserVerified {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "auth.passkey.register",
			ResourceType: "user_passkey",
			Status:       "failed",
			ErrorMessage: "registration response without user verification flag",
		})
		Fail(c, http.StatusBadRequest, "通行密钥注册未完成用户验证（PIN 或生物识别），已拒绝")
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

	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	// 统计「删掉这把之后」还剩多少种登录方式：密码 / 其余通行密钥 / 外部身份。
	var otherPasskeys, identities int64
	if err := h.db.Model(&models.UserPasskey{}).Where("user_id = ? AND id <> ?", uid, id).Count(&otherPasskeys).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询通行密钥失败")
		return
	}
	if err := h.db.Model(&models.UserIdentity{}).Where("user_id = ?", uid).Count(&identities).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询绑定账号失败")
		return
	}
	forced := false
	if remainingLoginMethods(user.PasswordHash != "", otherPasskeys, identities) == 0 {
		// 超管在明确要求时可以强制删除，但必须显式 force=true 并留下审计。
		if c.Query("force") == "true" && h.enforcer != nil && h.enforcer.IsSuperAdmin(uid) {
			forced = true
		} else {
			Fail(c, http.StatusBadRequest, "不能删除最后一个登录方式，请先设置登录密码或绑定其它登录方式")
			return
		}
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
		After:        map[string]interface{}{"forced": forced},
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true, "forced": forced})
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
		failPasskeyInit(c, err)
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
		options, session, err = wa.BeginLogin(waUser, webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			Fail(c, http.StatusInternalServerError, "生成登录挑战失败: "+err.Error())
			return
		}
	} else {
		options, session, err = wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
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
		failPasskeyInit(c, err)
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

	// 无密码登录同样必须完成用户验证：一把没有 PIN 的安全密钥碰一下就能登录，等于没有第二因子。
	if !cred.Flags.UserVerified {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "auth.passkey_login",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", matchedUser.user.ID),
			Status:       "failed",
			ErrorMessage: "assertion without user verification flag",
		})
		Fail(c, http.StatusUnauthorized, "通行密钥登录未完成用户验证（PIN 或生物识别），已拒绝")
		return
	}
	// 签名计数器只增不减：新值不大于已存值说明可能是克隆的凭证。
	if stored := findStoredCredential(matchedUser.creds, cred.ID); stored != nil {
		if signCountRejected(stored.Authenticator.SignCount, cred.Authenticator.SignCount) {
			h.auditSvc.RecordFromContext(c, audit.Entry{
				DomainCode:   rbac.DefaultDomain,
				Action:       "auth.passkey_login",
				ResourceType: "user_passkey",
				ResourceID:   base64.RawURLEncoding.EncodeToString(cred.ID),
				Status:       "failed",
				ErrorMessage: fmt.Sprintf("signature counter did not increase (%d -> %d), possible cloned authenticator",
					stored.Authenticator.SignCount, cred.Authenticator.SignCount),
			})
			Fail(c, http.StatusUnauthorized, "通行密钥签名计数器异常（疑似克隆凭证），已拒绝本次登录")
			return
		}
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
		"last_login_ip": clientip.FromGin(c),
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

// findStoredCredential 在已加载的凭证里按 ID 找到对应记录。
func findStoredCredential(creds []webauthn.Credential, id []byte) *webauthn.Credential {
	for i := range creds {
		if bytes.Equal(creds[i].ID, id) {
			return &creds[i]
		}
	}
	return nil
}

// signCountRejected 判断通行密钥签名计数器是否异常：认证器支持计数器（已存值大于 0）时，
// 新值必须严格大于已存值，否则说明凭证可能被克隆，登录必须拒绝并记录安全事件。
func signCountRejected(stored, presented uint32) bool {
	return stored > 0 && presented <= stored
}
