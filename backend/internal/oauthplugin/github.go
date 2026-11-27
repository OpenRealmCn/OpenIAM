package oauthplugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/openrealm/openiam/internal/models"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
)

// GitHubPlugin 实现 GitHub OAuth 2.0 联合登录适配器。
type GitHubPlugin struct{}

func NewGitHubPlugin() *GitHubPlugin {
	return &GitHubPlugin{}
}

func (p *GitHubPlugin) Type() string {
	return "github"
}

func (p *GitHubPlugin) Metadata() PluginMetadata {
	return PluginMetadata{
		Type:          p.Type(),
		DisplayName:   "GitHub",
		Description:   "使用 GitHub OAuth App 进行联合登录，自动读取 GitHub 用户资料与主邮箱。",
		DefaultScopes: "read:user user:email",
		ConfigFields: []ConfigField{
			{Key: "api_base_url", Label: "GitHub API Base URL", Type: "url", Required: false, Placeholder: "https://api.github.com", Description: "可选，GitHub Enterprise 或测试 Mock 服务可覆盖此地址"},
			{Key: "auth_url", Label: "自定义 Auth URL", Type: "url", Required: false, Placeholder: "https://github.com/login/oauth/authorize", Description: "可选，默认使用官方 GitHub 端点"},
			{Key: "token_url", Label: "自定义 Token URL", Type: "url", Required: false, Placeholder: "https://github.com/login/oauth/access_token", Description: "可选，默认使用官方 GitHub 端点"},
		},
	}
}

func (p *GitHubPlugin) buildConfig(provider models.OAuthProvider, redirectURI string) *oauth2.Config {
	endpoint := githuboauth.Endpoint
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
		Scopes:       splitScopes(provider.Scopes, "read:user user:email"),
	}
}

func (p *GitHubPlugin) AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error) {
	cfg := p.buildConfig(params.Provider, params.RedirectURI)
	return cfg.AuthCodeURL(params.State), nil
}

func (p *GitHubPlugin) ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error) {
	cfg := p.buildConfig(params.Provider, params.RedirectURI)
	token, err := cfg.Exchange(ctx, params.Code)
	if err != nil {
		return nil, fmt.Errorf("github token exchange failed: %w", err)
	}

	apiBase := strings.TrimRight(extraString(params.Provider.ExtraConfig, "api_base_url", "https://api.github.com"), "/")
	client := cfg.Client(ctx, token)

	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	req, err := http.NewRequest(http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	rawMap, err := fetchJSON(ctx, client, req, &ghUser)
	if err != nil {
		return nil, fmt.Errorf("fetch github user failed: %w", err)
	}
	if ghUser.ID == 0 {
		return nil, errors.New("github returned empty user id")
	}

	email := ghUser.Email
	if email == "" {
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		eReq, _ := http.NewRequest(http.MethodGet, apiBase+"/user/emails", nil)
		eReq.Header.Set("Accept", "application/vnd.github+json")
		if _, err := fetchJSON(ctx, client, eReq, &emails); err == nil {
			for _, item := range emails {
				if item.Primary && item.Verified {
					email = item.Email
					break
				}
				if email == "" && item.Verified {
					email = item.Email
				}
			}
		}
	}

	return &ExternalUserInfo{
		ExternalUserID: strconv.FormatInt(ghUser.ID, 10),
		Username:       ghUser.Login,
		Email:          email,
		DisplayName:    firstNonEmpty(ghUser.Name, ghUser.Login),
		AvatarURL:      ghUser.AvatarURL,
		RawProfile:     rawMap,
	}, nil
}
