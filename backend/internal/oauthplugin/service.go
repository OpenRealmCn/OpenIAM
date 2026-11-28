package oauthplugin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type LoginResult struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresIn    int64       `json:"expires_in"`
	User         models.User `json:"user"`
	IsNewUser    bool        `json:"is_new_user"`
}

// Service 编排 OAuth 联合登录的发起与回调流程。
type Service struct {
	db          *gorm.DB
	registry    *Registry
	stateStore  *security.StateStore
	jwtMgr      *security.JWTManager
	enforcer    *rbac.Enforcer
	auditSvc    *audit.Service
	settingsSvc *settings.Service
}

func NewService(
	db *gorm.DB,
	registry *Registry,
	stateStore *security.StateStore,
	jwtMgr *security.JWTManager,
	enforcer *rbac.Enforcer,
	auditSvc *audit.Service,
	settingsSvc *settings.Service,
) *Service {
	return &Service{
		db:          db,
		registry:    registry,
		stateStore:  stateStore,
		jwtMgr:      jwtMgr,
		enforcer:    enforcer,
		auditSvc:    auditSvc,
		settingsSvc: settingsSvc,
	}
}

func (s *Service) Registry() *Registry {
	return s.registry
}

func (s *Service) buildRedirectURI(providerName string) string {
	base := "http://localhost:5173/oauth/callback"
	if s.settingsSvc != nil {
		if v := strings.TrimSpace(s.settingsSvc.Snapshot().OAuthPluginCallbackBaseURL); v != "" {
			base = v
		}
	}
	return strings.TrimRight(base, "/") + "/" + providerName
}

func (s *Service) refreshTTL() time.Duration {
	if s.settingsSvc != nil {
		if ttl := s.settingsSvc.Snapshot().JWTRefreshTTL; ttl > 0 {
			return ttl
		}
	}
	return 7 * 24 * time.Hour
}

// StartLogin 生成 state 与 PKCE 并调用插件生成授权跳转 URL。
func (s *Service) StartLogin(ctx context.Context, providerName, redirectOverride string) (authURL string, state string, err error) {
	return s.startFlow(ctx, providerName, redirectOverride, 0, BindSession{})
}

// BindSession 描述「是谁在发起这次绑定」：发起请求的 Access Token 标识与签发时刻。
// 绑定 state 里保存它，回调时才能确认这次绑定仍然由同一次有效会话发起。
type BindSession struct {
	SessionID  string
	IssuedAtMs int64
}

// StartBind 为已登录用户生成绑定第三方 OAuth 账号的授权跳转 URL。
func (s *Service) StartBind(ctx context.Context, providerName, redirectOverride string, bindUserID uint64, session BindSession) (authURL string, state string, err error) {
	if bindUserID == 0 {
		return "", "", errors.New("invalid bind user id")
	}
	if session.SessionID == "" {
		return "", "", errors.New("missing bind session id")
	}
	return s.startFlow(ctx, providerName, redirectOverride, bindUserID, session)
}

func (s *Service) startFlow(ctx context.Context, providerName, redirectOverride string, bindUserID uint64, session BindSession) (authURL string, state string, err error) {
	if vErr := s.validateRedirectOverride(providerName, redirectOverride); vErr != nil {
		return "", "", vErr
	}
	ctx = withUpstreamClient(ctx)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var provider models.OAuthProvider
	if err := s.db.Where("name = ? AND enabled = ?", providerName, true).First(&provider).Error; err != nil {
		return "", "", fmt.Errorf("oauth provider %q not found or disabled", providerName)
	}

	plugin, ok := s.registry.Get(provider.PluginType)
	if !ok {
		return "", "", fmt.Errorf("oauth plugin %q is not registered", provider.PluginType)
	}

	state = uuid.NewString()
	verifier, challenge := generatePKCE()

	saved := security.OAuthPluginState{
		ProviderName: provider.Name,
		CodeVerifier: verifier,
		BindUserID:   bindUserID,
	}
	if bindUserID > 0 {
		// 绑定流程额外记录「发起会话 + 凭据状态快照」，回调阶段逐项复核。
		var bindUser models.User
		if err := s.db.WithContext(ctx).Select("id, tokens_valid_after").First(&bindUser, bindUserID).Error; err != nil {
			return "", "", fmt.Errorf("load bind user: %w", err)
		}
		saved.BindSessionID = session.SessionID
		saved.BindIssuedAtMs = session.IssuedAtMs
		if bindUser.TokensValidAfterMs != nil {
			saved.BindTokensValidAt = *bindUser.TokensValidAfterMs
		}
	}
	if err := s.stateStore.SaveOAuthPluginState(ctx, state, saved, 10*time.Minute); err != nil {
		return "", "", fmt.Errorf("save oauth state: %w", err)
	}

	redirectURI := s.buildRedirectURI(provider.Name)
	if redirectOverride != "" {
		redirectURI = redirectOverride
	}

	authURL, err = plugin.AuthCodeURL(ctx, AuthURLParams{
		Provider:      provider,
		RedirectURI:   redirectURI,
		State:         state,
		CodeChallenge: challenge,
	})
	if err != nil {
		return "", "", err
	}
	return authURL, state, nil
}

// HandleCallback 处理联合登录回调，查找或创建用户并签发 OpenIAM Token。
func (s *Service) HandleCallback(ctx context.Context, providerName, code, state, redirectOverride, clientIP, userAgent string) (*LoginResult, error) {
	if vErr := s.validateRedirectOverride(providerName, redirectOverride); vErr != nil {
		return nil, vErr
	}
	ctx = withUpstreamClient(ctx)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	savedState, err := s.stateStore.ConsumeOAuthPluginState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state: %w", err)
	}
	if savedState.ProviderName != providerName {
		return nil, errors.New("state provider mismatch")
	}

	var provider models.OAuthProvider
	if err := s.db.Where("name = ? AND enabled = ?", providerName, true).First(&provider).Error; err != nil {
		return nil, fmt.Errorf("oauth provider %q not found or disabled", providerName)
	}

	plugin, ok := s.registry.Get(provider.PluginType)
	if !ok {
		return nil, fmt.Errorf("oauth plugin %q is not registered", provider.PluginType)
	}

	redirectURI := s.buildRedirectURI(provider.Name)
	if redirectOverride != "" {
		redirectURI = redirectOverride
	}

	extUser, err := plugin.ExchangeAndFetchUser(ctx, ExchangeParams{
		Provider:     provider,
		RedirectURI:  redirectURI,
		Code:         code,
		CodeVerifier: savedState.CodeVerifier,
	})
	if err != nil {
		s.auditSvc.Record(audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "auth.oauth_login",
			ResourceType: "oauth_provider",
			ResourceID:   providerName,
			IPAddress:    clientIP,
			UserAgent:    userAgent,
			Status:       "failed",
			ErrorMessage: err.Error(),
		})
		return nil, err
	}

	var identity models.UserIdentity
	var user models.User
	isNewUser := false

	// 已登录用户主动发起的第三方账号绑定流程
	if savedState.BindUserID > 0 {
		if err := s.db.First(&user, savedState.BindUserID).Error; err != nil {
			return nil, fmt.Errorf("target user not found: %w", err)
		}
		if user.Status != "active" {
			return nil, errors.New("账号已被禁用")
		}
		// 先确认这次绑定仍由同一次有效会话发起：会话被踢下线、或凭据有效起点已经推进，
		// 都必须拒绝并作废这次绑定，堵住「先发起绑定，等受害者改密后再完成」的接管路径。
		revoked, rErr := s.stateStore.IsAccessTokenRevoked(ctx, savedState.BindSessionID)
		if rErr != nil {
			return nil, fmt.Errorf("verify bind session: %w", rErr)
		}
		if vErr := bindStateError(*savedState, user, revoked); vErr != nil {
			s.auditSvc.Record(audit.Entry{
				ActorID:      savedState.BindUserID,
				DomainCode:   rbac.DefaultDomain,
				Action:       "user.oauth_bind",
				ResourceType: "user_identity",
				ResourceID:   fmt.Sprintf("%s:%s", providerName, extUser.ExternalUserID),
				IPAddress:    clientIP,
				UserAgent:    userAgent,
				Status:       "failed",
				ErrorMessage: vErr.Error(),
			})
			return nil, vErr
		}
		err = s.db.Where("provider_name = ? AND external_user_id = ?", providerName, extUser.ExternalUserID).First(&identity).Error
		if err == nil {
			if identity.UserID != savedState.BindUserID {
				return nil, errors.New("该第三方账号已绑定到其他用户，无法重复绑定")
			}
			identity.ExternalUsername = extUser.Username
			identity.ExternalEmail = extUser.Email
			identity.RawProfile = extUser.RawProfile
			_ = s.db.Save(&identity).Error
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			identity = models.UserIdentity{
				UserID:           user.ID,
				ProviderName:     providerName,
				ExternalUserID:   extUser.ExternalUserID,
				ExternalUsername: extUser.Username,
				ExternalEmail:    extUser.Email,
				RawProfile:       extUser.RawProfile,
			}
			if err := s.db.Create(&identity).Error; err != nil {
				return nil, fmt.Errorf("bind user identity: %w", err)
			}
		} else {
			return nil, err
		}
		accessToken, _, _, err := s.jwtMgr.GenerateAccessToken(user.ID, user.Username, user.Email, "openid profile email", "")
		if err != nil {
			return nil, err
		}
		refreshToken := uuid.NewString()
		if err := s.stateStore.SaveRefreshToken(ctx, refreshToken, security.RefreshTokenRecord{
			UserID:   user.ID,
			Username: user.Username,
		}, s.refreshTTL()); err != nil {
			return nil, err
		}
		s.auditSvc.Record(audit.Entry{
			ActorID:       user.ID,
			ActorUsername: user.Username,
			DomainCode:    rbac.DefaultDomain,
			Action:        "user.oauth_bind",
			ResourceType:  "user_identity",
			ResourceID:    fmt.Sprintf("%s:%s", providerName, extUser.ExternalUserID),
			After: map[string]interface{}{
				"provider":          providerName,
				"external_username": extUser.Username,
			},
			IPAddress: clientIP,
			UserAgent: userAgent,
			Status:    "success",
		})
		return &LoginResult{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(s.jwtMgr.AccessTTL().Seconds()),
			User:         user,
			IsNewUser:    false,
		}, nil
	}

	err = s.db.Where("provider_name = ? AND external_user_id = ?", providerName, extUser.ExternalUserID).First(&identity).Error
	if err == nil {
		if err := s.db.First(&user, identity.UserID).Error; err != nil {
			return nil, fmt.Errorf("linked user not found: %w", err)
		}
		// 同步最新外部资料
		identity.ExternalUsername = extUser.Username
		identity.ExternalEmail = extUser.Email
		identity.RawProfile = extUser.RawProfile
		_ = s.db.Save(&identity).Error
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		// 外部邮箱未必经过验证，禁止按邮箱自动关联本地账号；用户需先登录再在个人中心主动绑定
		// 邮箱冲突一律拒绝，不存在按邮箱自动关联的分支
		if extUser.Email != "" {
			if eErr := s.db.Where("email = ?", extUser.Email).First(&user).Error; eErr == nil {
				s.auditSvc.Record(audit.Entry{
					DomainCode:   rbac.DefaultDomain,
					Action:       "auth.oauth_login",
					ResourceType: "oauth_provider",
					ResourceID:   providerName,
					IPAddress:    clientIP,
					UserAgent:    userAgent,
					Status:       "failed",
					ErrorMessage: "external email conflicts with an existing local account; auto-link refused",
				})
				return nil, errors.New("该邮箱已被本地账号占用，出于安全原因不允许自动关联：请先使用账号密码登录，再在个人中心绑定该第三方账号")
			}
		}

		{
			if !provider.AutoRegister {
				return nil, errors.New("未绑定本地账号且该身份源未开启自动注册")
			}
			isNewUser = true
			username := s.uniqueUsername(extUser.Username, providerName)
			email := extUser.Email
			if email == "" {
				email = fmt.Sprintf("%s@%s.oauth.openiam.local", username, providerName)
			}
			user = models.User{
				Username:    username,
				Email:       email,
				DisplayName: firstNonEmpty(extUser.DisplayName, username),
				AvatarURL:   extUser.AvatarURL,
				Status:      "active",
			}
			if err := s.db.Create(&user).Error; err != nil {
				return nil, fmt.Errorf("create federated user: %w", err)
			}
			if s.enforcer != nil {
				_, _ = s.enforcer.AddRoleForUserInDomain(user.ID, "viewer", rbac.DefaultDomain)
			}
		}

		identity = models.UserIdentity{
			UserID:           user.ID,
			ProviderName:     providerName,
			ExternalUserID:   extUser.ExternalUserID,
			ExternalUsername: extUser.Username,
			ExternalEmail:    extUser.Email,
			RawProfile:       extUser.RawProfile,
		}
		if err := s.db.Create(&identity).Error; err != nil {
			return nil, fmt.Errorf("link user identity: %w", err)
		}
	} else {
		return nil, err
	}

	if user.Status != "active" {
		return nil, errors.New("账号已被禁用，无法登录")
	}

	now := time.Now()
	_ = s.db.Model(&user).Updates(map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": clientIP,
	}).Error

	accessToken, _, _, err := s.jwtMgr.GenerateAccessToken(user.ID, user.Username, user.Email, "openid profile email", "")
	if err != nil {
		return nil, err
	}
	refreshToken := uuid.NewString()
	if err := s.stateStore.SaveRefreshToken(ctx, refreshToken, security.RefreshTokenRecord{
		UserID:   user.ID,
		Username: user.Username,
	}, s.refreshTTL()); err != nil {
		return nil, err
	}

	s.auditSvc.Record(audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        "auth.oauth_login",
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		After: map[string]interface{}{
			"provider":         providerName,
			"external_user_id": extUser.ExternalUserID,
			"is_new_user":      isNewUser,
		},
		IPAddress: clientIP,
		UserAgent: userAgent,
		Status:    "success",
	})

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtMgr.AccessTTL().Seconds()),
		User:         user,
		IsNewUser:    isNewUser,
	}, nil
}

// bindStateError 校验绑定 state 里的会话与凭据快照是否仍然成立（纯函数，便于回归测试）。
func bindStateError(st security.OAuthPluginState, user models.User, sessionRevoked bool) error {
	if st.BindSessionID == "" {
		return errors.New("绑定请求缺少会话标识，请重新发起绑定")
	}
	if sessionRevoked {
		return errors.New("发起绑定的会话已失效，请重新登录后再发起绑定")
	}
	current := int64(0)
	if user.TokensValidAfterMs != nil {
		current = *user.TokensValidAfterMs
	}
	if current != st.BindTokensValidAt {
		return errors.New("账号凭据已变更，本次绑定请求已作废，请重新发起绑定")
	}
	if current > 0 && st.BindIssuedAtMs <= current {
		return errors.New("发起绑定的会话早于凭据变更时间，请重新登录后再发起绑定")
	}
	return nil
}

func (s *Service) uniqueUsername(base, provider string) string {
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, base)
	if clean == "" {
		clean = provider + "_user"
	}
	if len(clean) > 48 {
		clean = clean[:48]
	}

	candidate := clean
	for i := 0; i < 10; i++ {
		var count int64
		s.db.Model(&models.User{}).Where("username = ?", candidate).Count(&count)
		if count == 0 {
			return candidate
		}
		candidate = fmt.Sprintf("%s_%s", clean, uuid.NewString()[:6])
	}
	return fmt.Sprintf("%s_%s", provider, uuid.NewString()[:8])
}

func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}
