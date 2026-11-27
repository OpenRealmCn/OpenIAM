package oauthplugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openrealm/openiam/internal/models"
	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
)

// GooglePlugin 实现 Google OAuth 2.0 / OIDC 联合登录适配器。
type GooglePlugin struct{}

func NewGooglePlugin() *GooglePlugin {
	return &GooglePlugin{}
}

func (p *GooglePlugin) Type() string {
	return "google"
}

func (p *GooglePlugin) Metadata() PluginMetadata {
	return PluginMetadata{
		Type:          p.Type(),
		DisplayName:   "Google",
		Description:   "使用 Google Cloud OAuth 2.0 客户端进行联合登录。",
		DefaultScopes: "openid profile email",
		ConfigFields: []ConfigField{
			{Key: "userinfo_url", Label: "UserInfo URL", Type: "url", Required: false, Placeholder: "https://openidconnect.googleapis.com/v1/userinfo", Description: "可选，默认使用 Google OIDC UserInfo 端点"},
			{Key: "auth_url", Label: "自定义 Auth URL", Type: "url", Required: false, Placeholder: "https://accounts.google.com/o/oauth2/v2/auth", Description: "可选"},
			{Key: "token_url", Label: "自定义 Token URL", Type: "url", Required: false, Placeholder: "https://oauth2.googleapis.com/token", Description: "可选"},
		},
	}
}

func (p *GooglePlugin) buildConfig(provider models.OAuthProvider, redirectURI string) *oauth2.Config {
	endpoint := googleoauth.Endpoint
	if authURL := extraString(provider.ExtraConfig, "auth_url", ""); authURL != "" {
		endpoint.AuthURL = authURL
	}
	if tokenURL := extraString(provider.ExtraConfig, "token_url", ""); tokenURL != "" {
		endpoint.TokenURL = tokenURL
	}
	return &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     endpoint,
		Scopes:       splitScopes(provider.Scopes, "openid profile email"),
	}
}

func (p *GooglePlugin) AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error) {
	cfg := p.buildConfig(params.Provider, params.RedirectURI)
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if params.CodeChallenge != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", params.CodeChallenge))
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	return cfg.AuthCodeURL(params.State, opts...), nil
}

func (p *GooglePlugin) ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error) {
	cfg := p.buildConfig(params.Provider, params.RedirectURI)
	opts := []oauth2.AuthCodeOption{}
	if params.CodeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", params.CodeVerifier))
	}
	token, err := cfg.Exchange(ctx, params.Code, opts...)
	if err != nil {
		return nil, fmt.Errorf("google token exchange failed: %w", err)
	}

	userInfoURL := extraString(params.Provider.ExtraConfig, "userinfo_url", "https://openidconnect.googleapis.com/v1/userinfo")
	req, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	var gUser struct {
		Sub     string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}
	rawMap, err := fetchJSON(ctx, cfg.Client(ctx, token), req, &gUser)
	if err != nil {
		return nil, fmt.Errorf("fetch google userinfo failed: %w", err)
	}
	if gUser.Sub == "" {
		return nil, errors.New("google returned empty sub")
	}

	username := gUser.Sub
	if gUser.Email != "" {
		username = strings.Split(gUser.Email, "@")[0]
	}
	return &ExternalUserInfo{
		ExternalUserID: gUser.Sub,
		Username:       username,
		Email:          gUser.Email,
		DisplayName:    firstNonEmpty(gUser.Name, username),
		AvatarURL:      gUser.Picture,
		RawProfile:     rawMap,
	}, nil
}
