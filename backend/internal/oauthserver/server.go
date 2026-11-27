package oauthserver

import (
	"context"
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
		if id, parseErr := strconv.ParseUint(data.UserID, 10, 64); parseErr == nil {
			userID = id
			var user models.User
			if err := g.db.WithContext(ctx).Select("id, username, email").First(&user, id).Error; err == nil {
				username = user.Username
				email = user.Email
			}
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
		var client models.OAuthClient
		// 首先尝试精准匹配 baseURI，随后在授权和同意接口中也会基于 ClientRecord 校验完整数组
		if baseURI == redirectURI {
			return nil
		}
		if err := db.Where("status = ?", "active").Find(&[]models.OAuthClient{}).Error; err == nil {
			_ = client
		}
		// 如果 baseURI 为空或只是首地址，校验同一个客户端是否包含 redirectURI
		var clients []models.OAuthClient
		db.Where("status = ?", "active").Find(&clients)
		for _, c := range clients {
			if len(c.RedirectURIs) == 0 || c.RedirectURIs[0] != baseURI {
				continue
			}
			for _, u := range c.RedirectURIs {
				if u == redirectURI {
					return nil
				}
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
		return rec.AllowsGrantType(string(grant)), nil
	})

	srv.SetExtensionFieldsHandler(func(ti oauth2.TokenInfo) map[string]interface{} {
		ext := make(map[string]interface{})
		scopes := strings.Fields(ti.GetScope())
		hasOpenID := false
		for _, sc := range scopes {
			if sc == "openid" {
				hasOpenID = true
				break
			}
		}
		if hasOpenID && ti.GetUserID() != "" {
			if uid, err := strconv.ParseUint(ti.GetUserID(), 10, 64); err == nil {
				var user models.User
				if err := db.First(&user, uid).Error; err == nil {
					ttl := settingsSvc.Snapshot().OAuthServerAccessTokenTTL
					if ttl <= 0 {
						ttl = time.Hour
					}
					if idToken, err := jwtMgr.GenerateIDToken(
						user.ID,
						user.Username,
						user.Email,
						user.DisplayName,
						user.AvatarURL,
						ti.GetClientID(),
						ttl,
					); err == nil {
						ext["id_token"] = idToken
					}
				}
			}
		}
		return ext
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
	if client.RequirePKCE && req.CodeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "该应用强制要求启用 PKCE (code_challenge)",
		})
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
		CreatedAt:           time.Now().Unix(),
	}
	if err := s.stateStore.SaveConsentRequest(c.Request.Context(), consentReq, 10*time.Minute); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "生成授权码失败: " + err.Error()})
		return
	}

	data := s.oauthSrv.GetAuthorizeData(oauth2.Code, ti)
	finalRedirect, err := s.oauthSrv.GetRedirectURI(authReq, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "构建回调地址失败: " + err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "参数错误: " + err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "生成授权码失败: " + err.Error()})
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

// Token 处理 POST /oauth2/token。
func (s *Server) Token(c *gin.Context) {
	if err := s.oauthSrv.HandleTokenRequest(c.Writer, c.Request); err != nil {
		s.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "oauth2.token.exchange",
			ResourceType: "oauth_token",
			Status:       "failed",
			ErrorMessage: err.Error(),
		})
	}
}

// UserInfo 处理 GET /oauth2/userinfo，校验 OAuth2 Bearer Token 并返回 OIDC 用户信息。
func (s *Server) UserInfo(c *gin.Context) {
	ti, err := s.oauthSrv.ValidationBearerToken(c.Request)
	if err != nil {
		// 兼容直接使用 OpenIAM 登录颁发的 Access JWT
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if claims, jwtErr := s.jwtMgr.ParseAccessToken(tokenStr); jwtErr == nil && claims.UserID > 0 {
				s.writeUserInfo(c, claims.UserID)
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": err.Error()})
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
	s.writeUserInfo(c, uid)
}

func (s *Server) writeUserInfo(c *gin.Context, uid uint64) {
	var user models.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
		return
	}
	if user.Status != "active" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "用户已被禁用"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"sub":                fmt.Sprintf("%d", user.ID),
		"preferred_username": user.Username,
		"name":               user.DisplayName,
		"email":              user.Email,
		"picture":            user.AvatarURL,
	})
}

// Revoke 处理 POST /oauth2/revoke (RFC 7009)。
func (s *Server) Revoke(c *gin.Context) {
	if !s.authenticateClient(c) {
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
	_ = s.manager.RemoveAccessToken(ctx, token)
	_ = s.manager.RemoveRefreshToken(ctx, token)
	if claims, err := s.jwtMgr.ParseAccessToken(token); err == nil && claims.ID != "" && claims.ExpiresAt != nil {
		_ = s.stateStore.RevokeAccessToken(ctx, claims.ID, time.Until(claims.ExpiresAt.Time))
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
	if !s.authenticateClient(c) {
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

	if claims, err := s.jwtMgr.ParseAccessToken(token); err == nil {
		revoked, _ := s.stateStore.IsAccessTokenRevoked(ctx, claims.ID)
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

// authenticateClient 校验调用方为已登记的机密客户端（HTTP Basic 或表单 client_id/client_secret）。
func (s *Server) authenticateClient(c *gin.Context) bool {
	id, secret, ok := c.Request.BasicAuth()
	if !ok {
		id = c.PostForm("client_id")
		secret = c.PostForm("client_secret")
	}
	if id == "" || secret == "" {
		return false
	}
	cli, err := s.manager.GetClient(c.Request.Context(), id)
	if err != nil || cli == nil || cli.IsPublic() {
		return false
	}
	verifier, ok := cli.(oauth2.ClientPasswordVerifier)
	return ok && verifier.VerifyPassword(secret)
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
