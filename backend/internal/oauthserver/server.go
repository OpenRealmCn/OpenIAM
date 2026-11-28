package oauthserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	oautherrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// JWTAccessGenerator 使用 OpenIAM 的 RS256 JWTManager 签发 OAuth2 Access Token。
type JWTAccessGenerator struct {
	jwtMgr *security.JWTManager
	db     *gorm.DB
}

func (g *JWTAccessGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	var userID uint64
	username := ""
	email := ""
	if data.UserID != "" {
		// 用户主体必须可解析且处于可用状态；查询失败按拒绝处理，避免为已禁用或已删除的账号签发令牌
		id, parseErr := strconv.ParseUint(data.UserID, 10, 64)
		if parseErr != nil {
			return "", "", oautherrors.ErrInvalidGrant
		}
		userID = id
		var user models.User
		if err := g.db.WithContext(ctx).Select("id, username, email, status, must_change_password").First(&user, id).Error; err != nil {
			return "", "", oautherrors.ErrInvalidGrant
		}
		if user.Status != "active" {
			return "", "", oautherrors.ErrAccessDenied
		}
		if user.MustChangePassword {
			return "", "", security.ErrPasswordChangeRequired
		}
		username = user.Username
		if scopeHas(data.TokenInfo.GetScope(), "email") {
			email = user.Email
		}
	}

	var ttl time.Duration
	if data.TokenInfo != nil && data.TokenInfo.GetAccessExpiresIn() > 0 {
		ttl = data.TokenInfo.GetAccessExpiresIn()
	}

	access, _, _, err = g.jwtMgr.GenerateAccessToken(
		userID,
		username,
		email,
		data.TokenInfo.GetScope(),
		data.Client.GetID(),
		ttl,
	)
	if err != nil {
		return "", "", err
	}
	if isGenRefresh {
		refresh = strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	}
	return access, refresh, nil
}

// Server 封装 OpenIAM OAuth 2.0 / OIDC 授权服务端能力。
type Server struct {
	db          *gorm.DB
	rdb         *redis.Client
	stateStore  *security.StateStore
	jwtMgr      *security.JWTManager
	auditSvc    *audit.Service
	settingsSvc *settings.Service
	manager     *manage.Manager
	oauthSrv    *server.Server
	tokenStore  *RedisTokenStore
}

func NewServer(
	db *gorm.DB,
	rdb *redis.Client,
	stateStore *security.StateStore,
	jwtMgr *security.JWTManager,
	auditSvc *audit.Service,
	settingsSvc *settings.Service,
) *Server {
	mgr := manage.NewDefaultManager()
	snap := settingsSvc.Snapshot()
	codeTTL := snap.OAuthServerAuthCodeTTL
	if codeTTL <= 0 {
		codeTTL = 10 * time.Minute
	}
	accessTTL := snap.OAuthServerAccessTokenTTL
	if accessTTL <= 0 {
		accessTTL = time.Hour
	}
	refreshTTL := snap.OAuthServerRefreshTokenTTL
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * time.Hour
	}

	mgr.SetAuthorizeCodeExp(codeTTL)
	mgr.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    accessTTL,
		RefreshTokenExp:   refreshTTL,
		IsGenerateRefresh: true,
	})
	mgr.SetClientTokenCfg(&manage.Config{
		AccessTokenExp:    accessTTL,
		IsGenerateRefresh: false,
	})
	mgr.SetRefreshTokenCfg(&manage.RefreshingConfig{
		AccessTokenExp:     accessTTL,
		RefreshTokenExp:    refreshTTL,
		IsGenerateRefresh:  true,
		IsResetRefreshTime: true,
		IsRemoveAccess:     true,
		IsRemoveRefreshing: true,
	})

	clientStore := NewMySQLClientStore(db)
	tokenStore := NewRedisTokenStore(rdb, "openiam:oauth2:token:")
	mgr.MapClientStorage(clientStore)
	mgr.MapTokenStorage(tokenStore)
	mgr.MapAccessGenerate(&JWTAccessGenerator{jwtMgr: jwtMgr, db: db})

	// 支持基于 oauth_clients.redirect_uris 数组的多回调地址校验
	mgr.SetValidateURIHandler(func(baseURI, redirectURI string) error {
		if redirectURI == "" {
			return oautherrors.ErrInvalidRedirectURI
		}
		// baseURI 来自 ClientRecord.GetDomain，即「当前请求所属客户端」登记的全部回调地址（换行分隔），
		// 因此只会在该客户端自己的白名单内匹配，不会借用其他客户端的回调地址
		for _, u := range strings.Split(baseURI, "\n") {
			if u == redirectURI {
				return nil
			}
		}
		return oautherrors.ErrInvalidRedirectURI
	})

	srv := server.NewDefaultServer(mgr)
	srv.SetAllowGetAccessRequest(false)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	// 也支持 HTTP Basic Auth 传递 client_id / client_secret
	srv.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
		if cid, csec, ok := server.ClientBasicHandler(r); ok == nil && cid != "" {
			return cid, csec, nil
		}
		return server.ClientFormHandler(r)
	})
	srv.SetAllowedGrantType(
		oauth2.AuthorizationCode,
		oauth2.Refreshing,
		oauth2.ClientCredentials,
	)

	s := &Server{
		db:          db,
		rdb:         rdb,
		stateStore:  stateStore,
		jwtMgr:      jwtMgr,
		auditSvc:    auditSvc,
		settingsSvc: settingsSvc,
		manager:     mgr,
		oauthSrv:    srv,
		tokenStore:  tokenStore,
	}

	srv.SetClientAuthorizedHandler(func(clientID string, grant oauth2.GrantType) (bool, error) {
		cli, err := clientStore.GetByID(context.Background(), clientID)
		if err != nil {
			return false, err
		}
		rec, ok := cli.(*ClientRecord)
		if !ok {
			return false, nil
		}
		// 公共客户端没有可验证的身份，不能以自身名义取得令牌
		if grant == oauth2.ClientCredentials && rec.IsPublic() {
			return false, nil
		}
		return rec.AllowsGrantType(string(grant)), nil
	})

	// client_credentials 请求的 scope 必须落在该应用登记的范围内；未设置处理器时 go-oauth2 会接受任意 scope
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (bool, error) {
		cli, err := clientStore.GetByID(context.Background(), tgr.ClientID)
		if err != nil {
			return false, nil
		}
		rec, ok := cli.(*ClientRecord)
		if !ok {
			return false, nil
		}
		for _, sc := range strings.Fields(tgr.Scope) {
			if !slices.Contains(rec.Model.Scopes, sc) {
				return false, nil
			}
		}
		return true, nil
	})

	// 刷新时只能缩小 scope，不能借刷新扩大原授权范围
	srv.SetRefreshingScopeHandler(func(tgr *oauth2.TokenGenerateRequest, oldScope string) (bool, error) {
		old := strings.Fields(oldScope)
		for _, sc := range strings.Fields(tgr.Scope) {
			if !slices.Contains(old, sc) {
				return false, nil
			}
		}
		return true, nil
	})

	// 刷新前复核应用与用户的当前状态：应用停用、用户被禁用/删除/强制改密，或在改密、禁用后统一吊销的令牌都不能续期
	srv.SetRefreshingValidationHandler(func(ti oauth2.TokenInfo) (bool, error) {
		ctx := context.Background()
		if _, err := clientStore.GetByID(ctx, ti.GetClientID()); err != nil {
			return false, oautherrors.ErrInvalidGrant
		}
		if ti.GetUserID() == "" {
			return true, nil
		}
		uid, err := strconv.ParseUint(ti.GetUserID(), 10, 64)
		if err != nil {
			return false, oautherrors.ErrInvalidGrant
		}
		var user models.User
		if err := db.WithContext(ctx).Select("id, status, must_change_password").First(&user, uid).Error; err != nil {
			return false, oautherrors.ErrInvalidGrant
		}
		if user.Status != "active" || user.MustChangePassword {
			return false, oautherrors.ErrInvalidGrant
		}
		if revoked, rErr := stateStore.IsIssuedBeforeRevocation(ctx, uid, ti.GetRefreshCreateAt().UnixMilli()); rErr != nil || revoked {
			return false, oautherrors.ErrInvalidGrant
		}
		return true, nil
	})

	srv.SetResponseErrorHandler(func(ctx context.Context, re *oautherrors.Response) {
		if re != nil && re.Error != nil && auditSvc != nil {
			auditSvc.Record(audit.Entry{
				DomainCode:   rbac.DefaultDomain,
				Action:       "oauth2.server.error",
				ResourceType: "oauth_client",
				Status:       "failed",
				ErrorMessage: re.Error.Error(),
			})
		}
	})

	return s
}

// Authorize 处理 GET /oauth2/authorize：校验参数并重定向至前端授权同意页面。
func (s *Server) Authorize(c *gin.Context) {
	req, err := s.oauthSrv.ValidationAuthorizeRequest(c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	var client models.OAuthClient
	if err := s.db.Where("client_id = ? AND status = ?", req.ClientID, "active").First(&client).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "OAuth 应用不存在或未启用",
		})
		return
	}

	rec := &ClientRecord{Model: client}
	if !rec.AllowsRedirectURI(req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_redirect_uri",
			"error_description": "redirect_uri 未在该应用白名单中注册",
		})
		return
	}
	// 公共客户端无法保管密钥，授权码一旦被截获即可兑换，因此无论配置如何都必须使用 PKCE
	if (client.RequirePKCE || !client.IsConfidential) && req.CodeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "该应用强制要求启用 PKCE (code_challenge)",
		})
		return
	}
	if err := security.ValidateClientRedirectURI(req.RedirectURI, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_redirect_uri",
			"error_description": "redirect_uri 协议不受支持",
		})
		return
	}
	nonce := c.Query("nonce")
	if len(nonce) > 512 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "nonce 过长"})
		return
	}

	if req.CodeChallenge != "" && req.CodeChallengeMethod != oauth2.CodeChallengeS256 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "仅支持 S256 方式的 PKCE (code_challenge_method=S256)",
		})
		return
	}

	scopes := strings.Fields(req.Scope)
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	for _, sc := range scopes {
		if !slices.Contains(client.Scopes, sc) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "请求的 scope 超出该应用已登记的授权范围: " + sc,
			})
			return
		}
	}

	consentID := uuid.NewString()
	consentReq := security.OAuthConsentRequest{
		ID:                  consentID,
		ClientID:            client.ClientID,
		ClientName:          client.Name,
		DomainCode:          client.DomainCode,
		RedirectURI:         req.RedirectURI,
		Scopes:              scopes,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		Nonce:               nonce,
		CreatedAt:           time.Now().Unix(),
	}
	if err := s.stateStore.SaveConsentRequest(c.Request.Context(), consentReq, 10*time.Minute); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "保存授权请求失败"})
		return
	}

	consentURL := s.settingsSvc.Snapshot().OAuthServerFrontendConsentURL
	if consentURL == "" {
		consentURL = "http://localhost:5173/oauth2/consent"
	}
	u, err := url.Parse(consentURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "invalid frontend_consent_url"})
		return
	}
	q := u.Query()
	q.Set("request_id", consentID)
	u.RawQuery = q.Encode()

	// 若请求 Accept: application/json（如 API 客户端或测试），返回 JSON；否则 302 跳转前端同意页
	if strings.Contains(c.GetHeader("Accept"), "application/json") {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"data": gin.H{
				"request_id":  consentID,
				"consent_url": u.String(),
				"client_name": client.Name,
				"scopes":      scopes,
			},
		})
		return
	}
	c.Redirect(http.StatusFound, u.String())
}

// GetConsentRequest 供前端授权同意页查询待审批的 OAuth2 应用信息。
func (s *Server) GetConsentRequest(c *gin.Context) {
	id := c.Param("id")
	req, err := s.stateStore.GetConsentRequest(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "授权请求不存在或已过期"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "ok", "data": req})
}

type ConsentDecision struct {
	Approved bool `json:"approved"`
}

// SubmitConsentDecision 处理用户在前端同意页的“允许”或“拒绝”操作，生成授权码或拒绝重定向 URL。
func (s *Server) SubmitConsentDecision(c *gin.Context) {
	id := c.Param("id")
	var body ConsentDecision
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "请求参数错误"})
		return
	}

	reqData, err := s.stateStore.ConsumeConsentRequest(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "授权请求不存在或已过期"})
		return
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint64)
	usernameVal, _ := c.Get("username")
	username, _ := usernameVal.(string)

	redirectURL, err := url.Parse(reqData.RedirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "无效的 redirect_uri"})
		return
	}

	if !body.Approved {
		q := redirectURL.Query()
		q.Set("error", "access_denied")
		if reqData.State != "" {
			q.Set("state", reqData.State)
		}
		redirectURL.RawQuery = q.Encode()
		s.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   reqData.DomainCode,
			Action:       "oauth2.consent.deny",
			ResourceType: "oauth_client",
			ResourceID:   reqData.ClientID,
			Status:       "success",
		})
		c.JSON(http.StatusOK, gin.H{"code": 0, "message": "ok", "data": gin.H{"redirect_uri": redirectURL.String()}})
		return
	}

	authReq := &server.AuthorizeRequest{
		ResponseType:        oauth2.Code,
		ClientID:            reqData.ClientID,
		Scope:               strings.Join(reqData.Scopes, " "),
		RedirectURI:         reqData.RedirectURI,
		State:               reqData.State,
		UserID:              fmt.Sprintf("%d", userID),
		CodeChallenge:       reqData.CodeChallenge,
		CodeChallengeMethod: oauth2.CodeChallengeMethod(reqData.CodeChallengeMethod),
	}

	ti, err := s.oauthSrv.GetAuthorizeToken(c.Request.Context(), authReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "生成授权码失败"})
		return
	}
	if reqData.Nonce != "" {
		if err := s.stateStore.SaveCodeNonce(c.Request.Context(), ti.GetCode(), reqData.Nonce, s.codeTTL()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "生成授权码失败"})
			return
		}
	}

	data := s.oauthSrv.GetAuthorizeData(oauth2.Code, ti)
	finalRedirect, err := s.oauthSrv.GetRedirectURI(authReq, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "构建回调地址失败"})
		return
	}

	s.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       userID,
		ActorUsername: username,
		DomainCode:    reqData.DomainCode,
		Action:        "oauth2.consent.approve",
		ResourceType:  "oauth_client",
		ResourceID:    reqData.ClientID,
		After: map[string]interface{}{
			"scopes": reqData.Scopes,
		},
		Status: "success",
	})

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "ok",
		"data": gin.H{
			"redirect_uri": finalRedirect,
			"code":         ti.GetCode(),
		},
	})
}

type createAuthCodeReq struct {
	ClientID            string   `json:"client_id" binding:"required"`
	RedirectURI         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
}

// CreateAuthorizationCode 允许已登录且具备 oauth_clients:authorize 权限的用户为指定 OAuth 应用生成一次性授权码 (Code)。
func (s *Server) CreateAuthorizationCode(c *gin.Context) {
	var req createAuthCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "参数错误：缺少 client_id"})
		return
	}

	var client models.OAuthClient
	if err := s.db.Where("client_id = ? AND status = ?", req.ClientID, "active").First(&client).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "OAuth 应用不存在或未启用"})
		return
	}

	redirectURI := strings.TrimSpace(req.RedirectURI)
	if redirectURI == "" && len(client.RedirectURIs) > 0 {
		redirectURI = client.RedirectURIs[0]
	}
	rec := &ClientRecord{Model: client}
	if !rec.AllowsRedirectURI(redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "回调地址不在该应用白名单中"})
		return
	}
	if err := security.ValidateClientRedirectURI(redirectURI, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "回调地址协议不受支持"})
		return
	}
	// 与 /oauth2/authorize 相同的 PKCE 约束，避免借此接口绕过应用的 PKCE 要求
	if (client.RequirePKCE || !client.IsConfidential) && req.CodeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "该应用强制要求启用 PKCE (code_challenge)"})
		return
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != string(oauth2.CodeChallengeS256) {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "仅支持 S256 方式的 PKCE (code_challenge_method=S256)"})
		return
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	for _, sc := range scopes {
		if !slices.Contains(client.Scopes, sc) {
			c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "请求的 scope 超出该应用已登记的授权范围: " + sc})
			return
		}
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint64)
	usernameVal, _ := c.Get("username")
	username, _ := usernameVal.(string)

	authReq := &server.AuthorizeRequest{
		ResponseType:        oauth2.Code,
		ClientID:            client.ClientID,
		Scope:               strings.Join(scopes, " "),
		RedirectURI:         redirectURI,
		State:               req.State,
		UserID:              fmt.Sprintf("%d", userID),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: oauth2.CodeChallengeMethod(req.CodeChallengeMethod),
	}

	ti, err := s.oauthSrv.GetAuthorizeToken(c.Request.Context(), authReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "生成授权码失败"})
		return
	}

	data := s.oauthSrv.GetAuthorizeData(oauth2.Code, ti)
	finalRedirect, _ := s.oauthSrv.GetRedirectURI(authReq, data)

	s.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       userID,
		ActorUsername: username,
		DomainCode:    client.DomainCode,
		Action:        "oauth2.code.create",
		ResourceType:  "oauth_client",
		ResourceID:    client.ClientID,
		After: map[string]interface{}{
			"redirect_uri": redirectURI,
			"scopes":       scopes,
		},
		Status: "success",
	})

	c.JSON(http.StatusCreated, gin.H{
		"code":    0,
		"message": "created",
		"data": gin.H{
			"code":         ti.GetCode(),
			"client_id":    client.ClientID,
			"redirect_uri": finalRedirect,
			"scopes":       scopes,
			"expires_in":   int64(ti.GetCodeExpiresIn().Seconds()),
		},
	})
}

func (s *Server) codeTTL() time.Duration {
	if ttl := s.settingsSvc.Snapshot().OAuthServerAuthCodeTTL; ttl > 0 {
		return ttl
	}
	return 10 * time.Minute
}

func (s *Server) refreshTTL() time.Duration {
	if ttl := s.settingsSvc.Snapshot().OAuthServerRefreshTokenTTL; ttl > 0 {
		return ttl
	}
	return 30 * 24 * time.Hour
}

func scopeHas(scope, want string) bool {
	return slices.Contains(strings.Fields(scope), want)
}

// bufferedResponse 暂存 go-oauth2 写出的令牌响应，便于在返回客户端前补充 ID Token。
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) WriteHeader(code int)        { b.status = code }

// Token 处理 POST /oauth2/token。
func (s *Server) Token(c *gin.Context) {
	if s.rejectPasswordChangeGrant(c) {
		return
	}
	ctx := c.Request.Context()
	grantType := c.Request.PostForm.Get("grant_type")
	nonce := ""
	// 授权码与刷新令牌都只能兑换一次。go-oauth2 的「读取→删除」不是原子的，并发提交同一凭据可能各自换到令牌，
	// 因此先用 SETNX 抢占：只有第一个请求能进入兑换流程。
	switch grantType {
	case string(oauth2.AuthorizationCode):
		code := c.Request.PostForm.Get("code")
		if code != "" {
			if ok, err := s.stateStore.AcquireOnce(ctx, "oauth_code", code, s.codeTTL()); err != nil || !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "授权码已被使用或已失效"})
				return
			}
			nonce = s.stateStore.ConsumeCodeNonce(ctx, code)
		}
	case string(oauth2.Refreshing):
		if rt := c.Request.PostForm.Get("refresh_token"); rt != "" {
			if ok, err := s.stateStore.AcquireOnce(ctx, "oauth_refresh", rt, s.refreshTTL()); err != nil || !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "刷新令牌已被使用或已失效"})
				return
			}
		}
	}

	buf := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
	err := s.oauthSrv.HandleTokenRequest(buf, c.Request)
	if err != nil {
		s.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "oauth2.token.exchange",
			ResourceType: "oauth_token",
			Status:       "failed",
			ErrorMessage: err.Error(),
		})
	}
	body := buf.body.Bytes()
	if buf.status == http.StatusOK {
		body = s.attachIDToken(ctx, body, nonce)
	}
	for k, vs := range buf.header {
		for _, v := range vs {
			c.Writer.Header().Add(k, v)
		}
	}
	c.Writer.Header().Del("Content-Length")
	c.Writer.WriteHeader(buf.status)
	_, _ = c.Writer.Write(body)
}

// attachIDToken 为包含 openid scope 的用户令牌响应签发 ID Token：只放入已授予 scope 对应的声明，并带上授权请求的 nonce。
func (s *Server) attachIDToken(ctx context.Context, body []byte, nonce string) []byte {
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}
	access, _ := resp["access_token"].(string)
	scope, _ := resp["scope"].(string)
	if access == "" || !scopeHas(scope, "openid") {
		return body
	}
	claims, err := s.jwtMgr.ParseAccessToken(access)
	if err != nil || claims.UserID == 0 {
		return body
	}
	var user models.User
	if err := s.db.WithContext(ctx).First(&user, claims.UserID).Error; err != nil {
		return body
	}
	opts := security.IDTokenOptions{
		UserID:   user.ID,
		ClientID: claims.ClientID,
		Nonce:    nonce,
		TTL:      s.settingsSvc.Snapshot().OAuthServerAccessTokenTTL,
	}
	if scopeHas(scope, "profile") {
		opts.Username = user.Username
		opts.DisplayName = user.DisplayName
		opts.AvatarURL = user.AvatarURL
	}
	if scopeHas(scope, "email") && user.Email != "" {
		verified := user.EmailVerified
		opts.Email = user.Email
		opts.EmailVerified = &verified
	}
	idToken, err := s.jwtMgr.GenerateIDTokenWithOptions(opts)
	if err != nil {
		return body
	}
	resp["id_token"] = idToken
	out, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return out
}

// rejectPasswordChangeGrant 在 OAuth2 令牌端点拦下强制改密账号的 refresh_token 续期请求。
// authorization_code 授权码在同意阶段就已被 AuthMiddleware 拦截，签发阶段再由 JWTAccessGenerator 兜底拒绝。
func (s *Server) rejectPasswordChangeGrant(c *gin.Context) bool {
	if err := c.Request.ParseForm(); err != nil {
		return false
	}
	if c.Request.PostForm.Get("grant_type") != string(oauth2.Refreshing) {
		return false
	}
	token := c.Request.PostForm.Get("refresh_token")
	if token == "" {
		return false
	}
	ti, err := s.tokenStore.GetByRefresh(c.Request.Context(), token)
	if err != nil || ti == nil {
		return false
	}
	uid, err := strconv.ParseUint(ti.GetUserID(), 10, 64)
	if err != nil || uid == 0 {
		return false
	}
	var user models.User
	if err := s.db.WithContext(c.Request.Context()).Select("id, must_change_password").First(&user, uid).Error; err != nil {
		return false
	}
	if !user.MustChangePassword {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{
		"error":             "password_change_required",
		"error_description": "当前账号处于强制改密状态，请先修改密码",
	})
	return true
}

// UserInfo 处理 GET /oauth2/userinfo，校验 OAuth2 Bearer Token 并返回 OIDC 用户信息。
func (s *Server) UserInfo(c *gin.Context) {
	ti, err := s.oauthSrv.ValidationBearerToken(c.Request)
	if err != nil {
		// 兼容直接使用 OpenIAM 登录颁发的 Access JWT：须与业务接口的鉴权中间件执行同等校验
		// （单个令牌吊销、所属会话下线、用户级统一吊销、强制改密受限令牌）
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if claims, jwtErr := s.jwtMgr.ParseAccessToken(tokenStr); jwtErr == nil && claims.UserID > 0 {
				if !s.loginTokenUsable(c.Request.Context(), claims) {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
					return
				}
				scope := claims.Scope
				if claims.ClientID == "" {
					// 控制台登录令牌代表用户本人，可读取完整资料
					scope = "openid profile email"
				}
				s.writeUserInfo(c, claims.UserID, scope)
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	if ti.GetUserID() == "" {
		c.JSON(http.StatusOK, gin.H{
			"sub":       ti.GetClientID(),
			"client_id": ti.GetClientID(),
		})
		return
	}
	uid, err := strconv.ParseUint(ti.GetUserID(), 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	if s.userRevoked(c.Request.Context(), uid, ti.GetAccessCreateAt().UnixMilli()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "令牌已失效"})
		return
	}
	if !scopeHas(ti.GetScope(), "openid") {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_scope", "error_description": "访问 userinfo 需要 openid scope"})
		return
	}
	s.writeUserInfo(c, uid, ti.GetScope())
}

// loginTokenUsable 校验 OpenIAM 自签 Access JWT 的吊销状态；Redis 异常时按不可用处理。
func (s *Server) loginTokenUsable(ctx context.Context, claims *security.AccessClaims) bool {
	if claims.Scope == security.ScopePasswordChange {
		return false
	}
	if revoked, err := s.stateStore.IsAccessTokenRevoked(ctx, claims.ID); err != nil || revoked {
		return false
	}
	if claims.SessionID != "" {
		if revoked, err := s.stateStore.IsSessionRevoked(ctx, claims.SessionID); err != nil || revoked {
			return false
		}
	}
	return !s.userRevoked(ctx, claims.UserID, claims.IssuedAtMs)
}

// writeUserInfo 按授予的 scope 返回 OIDC 标准声明：profile 才返回资料字段，email 才返回邮箱及其验证状态。
func (s *Server) writeUserInfo(c *gin.Context, uid uint64, scope string) {
	var user models.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	if user.Status != "active" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "用户已被禁用"})
		return
	}
	if user.MustChangePassword {
		c.JSON(http.StatusForbidden, gin.H{"error": "password_change_required", "error_description": "当前账号处于强制改密状态，请先修改密码"})
		return
	}
	out := gin.H{"sub": fmt.Sprintf("%d", user.ID)}
	if scopeHas(scope, "profile") {
		out["preferred_username"] = user.Username
		out["name"] = user.DisplayName
		out["picture"] = user.AvatarURL
	}
	if scopeHas(scope, "email") && user.Email != "" {
		out["email"] = user.Email
		out["email_verified"] = user.EmailVerified
	}
	c.JSON(http.StatusOK, out)
}

// subjectActive 判断用户主体当前是否可用（存在且未被禁用）；查询失败按不可用处理。
func (s *Server) subjectActive(ctx context.Context, uid uint64) bool {
	var user models.User
	if err := s.db.WithContext(ctx).Select("id, status").First(&user, uid).Error; err != nil {
		return false
	}
	return user.Status == "active"
}

// Revoke 处理 POST /oauth2/revoke (RFC 7009)。
func (s *Server) Revoke(c *gin.Context) {
	clientID, authed := s.authenticateClient(c, true)
	if !authed {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	token := c.PostForm("token")
	if token == "" {
		var body struct {
			Token string `json:"token"`
		}
		_ = c.ShouldBindJSON(&body)
		token = body.Token
	}
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "missing token"})
		return
	}

	ctx := c.Request.Context()
	// 只能撤销属于自己的令牌；归属不符时静默成功（RFC 7009），避免泄露令牌是否存在
	if owner, found := s.tokenOwner(ctx, token); found && owner == clientID {
		_ = s.manager.RemoveAccessToken(ctx, token)
		_ = s.manager.RemoveRefreshToken(ctx, token)
		if claims, err := s.jwtMgr.ParseAccessToken(token); err == nil && claims.ID != "" && claims.ExpiresAt != nil {
			_ = s.stateStore.RevokeAccessToken(ctx, claims.ID, time.Until(claims.ExpiresAt.Time))
		}
	}

	s.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "oauth2.token.revoke",
		ResourceType: "oauth_token",
		Status:       "success",
	})
	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

// Introspect 处理 POST /oauth2/introspect (RFC 7662)。
func (s *Server) Introspect(c *gin.Context) {
	clientID, authed := s.authenticateClient(c, false)
	if !authed {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	token := c.PostForm("token")
	if token == "" {
		var body struct {
			Token string `json:"token"`
		}
		_ = c.ShouldBindJSON(&body)
		token = body.Token
	}
	if token == "" {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	ctx := c.Request.Context()
	if ti, err := s.manager.LoadAccessToken(ctx, token); err == nil && ti != nil {
		if ti.GetClientID() != clientID {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		if uid, pErr := strconv.ParseUint(ti.GetUserID(), 10, 64); pErr == nil && uid > 0 &&
			(s.userRevoked(ctx, uid, ti.GetAccessCreateAt().UnixMilli()) || !s.subjectActive(ctx, uid)) {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		// 强制改密账号的令牌对外一律视为不可用。这条判定必须和下面的 JWT 回退分支共用，
		// 否则早已签发的真实 OAuth access token 在账号被标记后依然内省为 active。
		// 客户端凭据令牌没有用户主体，不参与账号态判定。
		if subject := userTokenSubject(ti.GetUserID(), 0); subject != "" &&
			s.subjectRequiresPasswordChange(ctx, subject) {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		exp := ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix()
		c.JSON(http.StatusOK, gin.H{
			"active":    true,
			"client_id": ti.GetClientID(),
			"sub":       ti.GetUserID(),
			"scope":     ti.GetScope(),
			"exp":       exp,
		})
		return
	}

	if claims, err := s.jwtMgr.ParseAccessToken(token); err == nil && claims.ClientID == clientID {
		revoked, rErr := s.stateStore.IsAccessTokenRevoked(ctx, claims.ID)
		if rErr != nil {
			revoked = true
		}
		if !revoked && claims.UserID > 0 {
			revoked = !s.loginTokenUsable(ctx, claims) || !s.subjectActive(ctx, claims.UserID)
		}
		if !revoked {
			// 与上面的令牌存储分支共用同一个主体判定：账号处于强制改密、已被删除、
			// 或查询失败时一律按不可用处理（fail-closed），不再由本分支自己查库、
			// 避免两条分支对内省结果给出不一致的结论。
			// 客户端凭据令牌没有用户主体（签发器把 userID=0 写成 sub="0"），不参与账号态判定。
			if subject := userTokenSubject(claims.Subject, claims.UserID); subject != "" &&
				s.subjectRequiresPasswordChange(ctx, subject) {
				revoked = true
			}
		}
		if !revoked {
			c.JSON(http.StatusOK, gin.H{
				"active":    true,
				"client_id": claims.ClientID,
				"sub":       claims.Subject,
				"username":  claims.Username,
				"scope":     claims.Scope,
				"exp":       claims.ExpiresAt.Unix(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"active": false})
}

// userTokenSubject 从令牌主体里取出代表用户账号的部分。
// 客户端凭据（client_credentials）令牌不属于任何用户：go-oauth2 签发时不设置 UserID，
// 令牌存储里的 GetUserID() 为空，JWT 签发器又把 userID=0 写成 sub="0"。若把这种主体
// 交给账号态判定，合法的机器对机器令牌会一律内省为 inactive（空主体按 fail-closed 处理），
// 因此这里显式区分：返回空串表示该令牌不代表任何用户账号。
func userTokenSubject(subject string, userID uint64) string {
	subject = strings.TrimSpace(subject)
	if subject == "" && userID > 0 {
		subject = strconv.FormatUint(userID, 10)
	}
	if subject == "" {
		return ""
	}
	if id, err := strconv.ParseUint(subject, 10, 64); err == nil && id == 0 {
		return ""
	}
	return subject
}

// subjectRequiresPasswordChange 判断令牌主体当前是否处于强制改密状态。
// 主体无法解析为账号、或账号已不存在时按「不可用」处理（fail-closed）。
func (s *Server) subjectRequiresPasswordChange(ctx context.Context, subject string) bool {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return true
	}
	var user models.User
	q := s.db.WithContext(ctx).Select("id, must_change_password")
	if id, err := strconv.ParseUint(subject, 10, 64); err == nil {
		if err := q.First(&user, id).Error; err != nil {
			return true
		}
	} else if err := q.Where("username = ?", subject).First(&user).Error; err != nil {
		return true
	}
	return user.MustChangePassword
}

// authenticateClient 校验调用方客户端身份（HTTP Basic 或表单 client_id/client_secret）并返回其 client_id。
// 机密客户端必须提供正确密钥；allowPublic 为 true 时公共客户端仅凭 client_id 即可通过（用于 RFC 7009 撤销自己的令牌）。
func (s *Server) authenticateClient(c *gin.Context, allowPublic bool) (string, bool) {
	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		id = c.PostForm("client_id")
		secret = c.PostForm("client_secret")
	}
	if id == "" {
		return "", false
	}
	cli, err := s.manager.GetClient(c.Request.Context(), id)
	if err != nil || cli == nil {
		return "", false
	}
	if cli.IsPublic() {
		return id, allowPublic
	}
	verifier, isVerifier := cli.(oauth2.ClientPasswordVerifier)
	if secret == "" || !isVerifier || !verifier.VerifyPassword(secret) {
		return "", false
	}
	return id, true
}

// tokenOwner 返回令牌所属的 client_id；令牌无法识别时 found 为 false。
func (s *Server) tokenOwner(ctx context.Context, token string) (owner string, found bool) {
	if ti, err := s.manager.LoadAccessToken(ctx, token); err == nil && ti != nil {
		return ti.GetClientID(), true
	}
	if ti, err := s.manager.LoadRefreshToken(ctx, token); err == nil && ti != nil {
		return ti.GetClientID(), true
	}
	if claims, err := s.jwtMgr.ParseAccessToken(token); err == nil {
		return claims.ClientID, true
	}
	return "", false
}

// userRevoked 判断令牌签发时间是否早于该用户的令牌失效时间点（改密、禁用、删除后生效）；Redis 异常时按已失效处理。
func (s *Server) userRevoked(ctx context.Context, userID uint64, issuedAtMs int64) bool {
	revoked, err := s.stateStore.IsIssuedBeforeRevocation(ctx, userID, issuedAtMs)
	return err != nil || revoked
}

// ApplySettings 热更新 OAuth2 授权码与令牌有效期。
func (s *Server) ApplySettings(snap settings.RuntimeSettings) {
	if snap.OAuthServerAuthCodeTTL > 0 {
		s.manager.SetAuthorizeCodeExp(snap.OAuthServerAuthCodeTTL)
	}
	accessTTL := snap.OAuthServerAccessTokenTTL
	if accessTTL <= 0 {
		accessTTL = time.Hour
	}
	refreshTTL := snap.OAuthServerRefreshTokenTTL
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * time.Hour
	}
	s.manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    accessTTL,
		RefreshTokenExp:   refreshTTL,
		IsGenerateRefresh: true,
	})
	s.manager.SetClientTokenCfg(&manage.Config{
		AccessTokenExp:    accessTTL,
		IsGenerateRefresh: false,
	})
	s.manager.SetRefreshTokenCfg(&manage.RefreshingConfig{
		AccessTokenExp:     accessTTL,
		RefreshTokenExp:    refreshTTL,
		IsGenerateRefresh:  true,
		IsResetRefreshTime: true,
		IsRemoveAccess:     true,
		IsRemoveRefreshing: true,
	})
}

// Discovery 处理 GET /.well-known/openid-configuration。
func (s *Server) Discovery(c *gin.Context) {
	issuer := strings.TrimRight(s.settingsSvc.Snapshot().OAuthServerIssuer, "/")
	if issuer == "" {
		scheme := c.GetHeader("X-Forwarded-Proto")
		if scheme == "" {
			scheme = "http"
			if c.Request.TLS != nil {
				scheme = "https"
			}
		}
		issuer = scheme + "://" + c.Request.Host
	}
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// JWKS 处理 GET /.well-known/jwks.json。
func (s *Server) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, s.jwtMgr.JWKS())
}
