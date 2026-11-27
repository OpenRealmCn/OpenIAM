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

	if err := s.stateStore.SaveOAuthPluginState(ctx, state, security.OAuthPluginState{
		ProviderName: provider.Name,
		CodeVerifier: verifier,
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

// HandleCallback 处理联合登录回调，查找或创建用户并签发 OpenIAM Token。
func (s *Service) HandleCallback(ctx context.Context, providerName, code, state, redirectOverride, clientIP, userAgent string) (*LoginResult, error) {
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
		// 先尝试按已验证邮箱关联现有账号
		matchedByEmail := false
		if extUser.Email != "" {
			if eErr := s.db.Where("email = ?", extUser.Email).First(&user).Error; eErr == nil {
				matchedByEmail = true
			}
		}

		if !matchedByEmail {
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
		IPAddress:     clientIP,
		UserAgent:     userAgent,
		Status:        "success",
	})

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtMgr.AccessTTL().Seconds()),
		User:         user,
		IsNewUser:    isNewUser,
	}, nil
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
