package oauthplugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/openrealm/openiam/internal/models"
	"golang.org/x/oauth2"
)

// GenericOIDCPlugin 支持标准 OIDC Discovery（issuer_url）或自定义 OAuth2 端点配置。
type GenericOIDCPlugin struct{}

func NewGenericOIDCPlugin() *GenericOIDCPlugin {
	return &GenericOIDCPlugin{}
}

func (p *GenericOIDCPlugin) Type() string {
	return "generic_oidc"
}

func (p *GenericOIDCPlugin) Metadata() PluginMetadata {
	return PluginMetadata{
		Type:          p.Type(),
		DisplayName:   "通用 OIDC / OAuth2",
		Description:   "支持任意遵循 OpenID Connect Discovery 或标准 OAuth2 Authorization Code 协议的身份提供商。",
		DefaultScopes: "openid profile email",
		ConfigFields: []ConfigField{
			{Key: "issuer_url", Label: "OIDC Issuer URL", Type: "url", Required: false, Placeholder: "https://idp.example.com", Description: "若填写则自动通过 .well-known/openid-configuration 发现端点"},
			{Key: "auth_url", Label: "Authorization URL", Type: "url", Required: false, Placeholder: "https://idp.example.com/oauth2/authorize", Description: "未使用 OIDC 自动发现时必填"},
			{Key: "token_url", Label: "Token URL", Type: "url", Required: false, Placeholder: "https://idp.example.com/oauth2/token", Description: "未使用 OIDC 自动发现时必填"},
			{Key: "userinfo_url", Label: "UserInfo URL", Type: "url", Required: false, Placeholder: "https://idp.example.com/oauth2/userinfo", Description: "未使用 OIDC 自动发现时必填"},
		},
	}
}

func (p *GenericOIDCPlugin) buildConfig(ctx context.Context, provider models.OAuthProvider, redirectURI string) (*oauth2.Config, *oidc.Provider, string, error) {
	issuer := extraString(provider.ExtraConfig, "issuer_url", "")
	scopes := splitScopes(provider.Scopes, "openid profile email")

	if issuer != "" {
		oidcProvider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			return nil, nil, "", fmt.Errorf("oidc discovery failed: %w", err)
		}
		cfg := &oauth2.Config{
			ClientID:     provider.ClientID,
			ClientSecret: provider.ClientSecret,
			RedirectURL:  redirectURI,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       scopes,
		}
		return cfg, oidcProvider, extraString(provider.ExtraConfig, "userinfo_url", ""), nil
	}

	authURL := extraString(provider.ExtraConfig, "auth_url", "")
	tokenURL := extraString(provider.ExtraConfig, "token_url", "")
	userInfoURL := extraString(provider.ExtraConfig, "userinfo_url", "")
	if authURL == "" || tokenURL == "" {
		return nil, nil, "", errors.New("generic_oidc requires either issuer_url or auth_url + token_url")
	}
	cfg := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  redirectURI,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: scopes,
	}
	return cfg, nil, userInfoURL, nil
}

func (p *GenericOIDCPlugin) AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error) {
	cfg, _, _, err := p.buildConfig(ctx, params.Provider, params.RedirectURI)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{}
	if params.CodeChallenge != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", params.CodeChallenge))
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	return cfg.AuthCodeURL(params.State, opts...), nil
}

func (p *GenericOIDCPlugin) ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error) {
	cfg, oidcProvider, userInfoURL, err := p.buildConfig(ctx, params.Provider, params.RedirectURI)
	if err != nil {
		return nil, err
	}

	opts := []oauth2.AuthCodeOption{}
	if params.CodeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", params.CodeVerifier))
	}
	token, err := cfg.Exchange(ctx, params.Code, opts...)
	if err != nil {
		return nil, fmt.Errorf("exchange code failed: %w", err)
	}

	var claims struct {
		Sub               string `json:"sub"`
		ID                string `json:"id"`
		PreferredUsername string `json:"preferred_username"`
		Username          string `json:"username"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		Picture           string `json:"picture"`
	}
	var rawMap map[string]interface{}

	if oidcProvider != nil {
		ui, err := oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, fmt.Errorf("fetch oidc userinfo failed: %w", err)
		}
		if err := ui.Claims(&claims); err != nil {
			return nil, err
		}
		_ = ui.Claims(&rawMap)
	} else {
		if userInfoURL == "" {
			return nil, errors.New("userinfo_url is required when issuer_url is not configured")
		}
		req, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
		if err != nil {
			return nil, err
		}
		client := cfg.Client(ctx, token)
		rawMap, err = fetchJSON(ctx, client, req, &claims)
		if err != nil {
			return nil, fmt.Errorf("fetch oauth2 userinfo failed: %w", err)
		}
	}

	extID := firstNonEmpty(claims.Sub, claims.ID)
	if extID == "" {
		return nil, errors.New("external user id (sub/id) is empty")
	}
	username := firstNonEmpty(claims.PreferredUsername, claims.Username, strings.Split(claims.Email, "@")[0], extID)
	displayName := firstNonEmpty(claims.Name, username)

	return &ExternalUserInfo{
		ExternalUserID: extID,
		Username:       username,
		Email:          claims.Email,
		DisplayName:    displayName,
		AvatarURL:      claims.Picture,
		RawProfile:     rawMap,
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
