package oauthplugin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

// CallbackResult 是联合登录回调的处理结果。服务层只负责解析出本地用户，令牌签发（二步验证、强制改密、会话登记）
// 统一交给 HTTP 层的登录出口，避免联合登录绕过本地账号的安全策略。
type CallbackResult struct {
	User      models.User
	IsNewUser bool
	// Bound 为 true 表示这是已登录用户发起的绑定流程，只建立了关联，调用方不应签发新会话。
	Bound bool
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

// loadEnabledProvider 读取已启用的身份源并解密 client secret。
func (s *Service) loadEnabledProvider(providerName string) (models.OAuthProvider, error) {
	var provider models.OAuthProvider
	if err := s.db.Where("name = ? AND enabled = ?", providerName, true).First(&provider).Error; err != nil {
		return provider, publicErr("该身份源不存在或未启用")
	}
	secret, err := security.OpenField(provider.ClientSecret)
	if err != nil {
		return provider, fmt.Errorf("decrypt client secret of provider %q: %w", providerName, err)
	}
	provider.ClientSecret = secret
	return provider, nil
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

// StartLogin 生成 state 与 PKCE 并调用插件生成授权跳转 URL。
// browserBinding 是写入发起方浏览器 HttpOnly Cookie 的随机值，回调时必须由同一浏览器带回。
func (s *Service) StartLogin(ctx context.Context, providerName, redirectOverride, browserBinding string) (authURL string, state string, err error) {
	return s.startFlow(ctx, providerName, redirectOverride, browserBinding, 0)
}

// StartBind 为已登录用户生成绑定第三方 OAuth 账号的授权跳转 URL。
func (s *Service) StartBind(ctx context.Context, providerName, redirectOverride, browserBinding string, bindUserID uint64) (authURL string, state string, err error) {
	if bindUserID == 0 {
		return "", "", errors.New("invalid bind user id")
	}
	return s.startFlow(ctx, providerName, redirectOverride, browserBinding, bindUserID)
}

func (s *Service) startFlow(ctx context.Context, providerName, redirectOverride, browserBinding string, bindUserID uint64) (authURL string, state string, err error) {
	if browserBinding == "" {
		return "", "", errors.New("missing browser binding")
	}
	if vErr := s.validateRedirectOverride(providerName, redirectOverride); vErr != nil {
		return "", "", vErr
	}
	ctx = withUpstreamClient(ctx)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	provider, err := s.loadEnabledProvider(providerName)
	if err != nil {
		return "", "", err
	}

	plugin, ok := s.registry.Get(provider.PluginType)
	if !ok {
		return "", "", fmt.Errorf("oauth plugin %q is not registered", provider.PluginType)
	}

	state = uuid.NewString()
	verifier, challenge := generatePKCE()

	if err := s.stateStore.SaveOAuthPluginState(ctx, state, security.OAuthPluginState{
		ProviderName:   provider.Name,
		CodeVerifier:   verifier,
		BindUserID:     bindUserID,
		BrowserBinding: security.BrowserBindingDigest(browserBinding),
	}, 10*time.Minute); err != nil {
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

func (s *Service) recordFailure(providerName, clientIP, userAgent, reason string) {
	s.auditSvc.Record(audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.oauth_login",
		ResourceType: "oauth_provider",
		ResourceID:   providerName,
		IPAddress:    clientIP,
		UserAgent:    userAgent,
		Status:       "failed",
		ErrorMessage: reason,
	})
}

// HandleCallback 处理联合登录回调：校验 state 与浏览器绑定，换取外部身份，并查找、创建或绑定本地用户。
func (s *Service) HandleCallback(ctx context.Context, providerName, code, state, redirectOverride, browserBinding, clientIP, userAgent string) (*CallbackResult, error) {
	if vErr := s.validateRedirectOverride(providerName, redirectOverride); vErr != nil {
		return nil, vErr
	}
	ctx = withUpstreamClient(ctx)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	savedState, err := s.stateStore.ConsumeOAuthPluginState(ctx, state)
	if err != nil {
		return nil, publicErr("登录请求已过期，请重新发起")
	}
	if savedState.ProviderName != providerName {
		return nil, publicErr("登录请求无效，请重新发起")
	}
	// state 只能由发起授权的那个浏览器完成，防止攻击者把自己的授权回调链接诱导受害者打开
	expected := savedState.BrowserBinding
	got := ""
	if browserBinding != "" {
		got = security.BrowserBindingDigest(browserBinding)
	}
	if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
		s.recordFailure(providerName, clientIP, userAgent, "browser binding mismatch")
		return nil, publicErr("登录请求与当前浏览器不匹配，请在同一浏览器中重新发起")
	}

	provider, err := s.loadEnabledProvider(providerName)
	if err != nil {
		return nil, err
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
		s.recordFailure(providerName, clientIP, userAgent, err.Error())
		return nil, err
	}

	var identity models.UserIdentity
	var user models.User

	// 已登录用户主动发起的第三方账号绑定流程
	if savedState.BindUserID > 0 {
		if err := s.db.First(&user, savedState.BindUserID).Error; err != nil {
			return nil, fmt.Errorf("target user not found: %w", err)
		}
		if user.Status != "active" {
			return nil, publicErr("账号已被禁用")
		}
		err = s.db.Where("provider_name = ? AND external_user_id = ?", providerName, extUser.ExternalUserID).First(&identity).Error
		if err == nil {
			if identity.UserID != savedState.BindUserID {
				return nil, publicErr("该第三方账号已绑定到其他用户，无法重复绑定")
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
		return &CallbackResult{User: user, Bound: true}, nil
	}

	isNewUser := false
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
		if extUser.Email != "" {
			if eErr := s.db.Where("LOWER(email) = ?", strings.ToLower(extUser.Email)).First(&user).Error; eErr == nil {
				s.recordFailure(providerName, clientIP, userAgent, "external email conflicts with an existing local account; auto-link refused")
				return nil, publicErr("该邮箱已被本地账号占用，出于安全原因不允许自动关联：请先使用账号密码登录，再在个人中心绑定该第三方账号")
			}
		}
		if !provider.AutoRegister {
			return nil, publicErr("未绑定本地账号且该身份源未开启自动注册")
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
		if err := s.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&user).Error; err != nil {
				return fmt.Errorf("create federated user: %w", err)
			}
			identity = models.UserIdentity{
				UserID:           user.ID,
				ProviderName:     providerName,
				ExternalUserID:   extUser.ExternalUserID,
				ExternalUsername: extUser.Username,
				ExternalEmail:    extUser.Email,
				RawProfile:       extUser.RawProfile,
			}
			if err := tx.Create(&identity).Error; err != nil {
				return fmt.Errorf("link user identity: %w", err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if s.enforcer != nil {
			_, _ = s.enforcer.AddRoleForUserInDomain(user.ID, "viewer", rbac.DefaultDomain)
		}
	} else {
		return nil, err
	}

	if user.Status != "active" {
		return nil, publicErr("账号已被禁用，无法登录")
	}
	return &CallbackResult{User: user, IsNewUser: isNewUser}, nil
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
