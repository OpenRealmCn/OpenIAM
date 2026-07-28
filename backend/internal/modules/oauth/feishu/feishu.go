package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	AppID       string
	AppSecret   string
	RedirectURI string
	BaseURL     string
}

type UserInfo struct {
	OpenID    string
	UnionID   string
	Name      string
	Email     string
	AvatarURL string
}

type Provider interface {
	AuthorizeURL(state string) string
	Exchange(ctx context.Context, code string) (*UserInfo, error)
}

type HTTPProvider struct {
	cfg    Config
	client *http.Client
}

func NewHTTPProvider(cfg Config, client *http.Client) *HTTPProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://open.feishu.cn/open-apis"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &HTTPProvider{cfg: cfg, client: client}
}

func (p *HTTPProvider) AuthorizeURL(state string) string {
	query := url.Values{}
	query.Set("app_id", p.cfg.AppID)
	query.Set("redirect_uri", p.cfg.RedirectURI)
	query.Set("response_type", "code")
	query.Set("state", state)
	return p.cfg.BaseURL + "/authen/v1/authorize?" + query.Encode()
}

func (p *HTTPProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	appToken, err := p.appAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	userToken, err := p.userAccessToken(ctx, appToken, code)
	if err != nil {
		return nil, err
	}
	return p.userInfo(ctx, userToken)
}

type envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (p *HTTPProvider) appAccessToken(ctx context.Context) (string, error) {
	body := map[string]string{
		"app_id":     p.cfg.AppID,
		"app_secret": p.cfg.AppSecret,
	}

	var resp struct {
		Code           int    `json:"code"`
		Msg            string `json:"msg"`
		AppAccessToken string `json:"app_access_token"`
	}
	if err := p.postJSON(ctx, "/auth/v3/app_access_token/internal", "", body, &resp); err != nil {
		return "", err
	}
	if resp.Code != 0 || resp.AppAccessToken == "" {
		return "", fmt.Errorf("feishu app token: code=%d msg=%s", resp.Code, resp.Msg)
	}
	return resp.AppAccessToken, nil
}

func (p *HTTPProvider) userAccessToken(ctx context.Context, appToken, code string) (string, error) {
	body := map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	}

	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := p.postJSON(ctx, "/authen/v1/oidc/access_token", appToken, body, &resp); err != nil {
		return "", err
	}
	if resp.Code != 0 || resp.Data.AccessToken == "" {
		return "", fmt.Errorf("feishu user token: code=%d msg=%s", resp.Code, resp.Msg)
	}
	return resp.Data.AccessToken, nil
}

func (p *HTTPProvider) userInfo(ctx context.Context, userToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.BaseURL+"/authen/v1/user_info", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+userToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var env struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			OpenID    string `json:"open_id"`
			UnionID   string `json:"union_id"`
			Name      string `json:"name"`
			Email     string `json:"email"`
			EntEmail  string `json:"enterprise_email"`
			AvatarURL string `json:"avatar_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("feishu user info: code=%d msg=%s", env.Code, env.Msg)
	}

	email := env.Data.Email
	if email == "" {
		email = env.Data.EntEmail
	}

	return &UserInfo{
		OpenID:    env.Data.OpenID,
		UnionID:   env.Data.UnionID,
		Name:      env.Data.Name,
		Email:     email,
		AvatarURL: env.Data.AvatarURL,
	}, nil
}

func (p *HTTPProvider) postJSON(ctx context.Context, path, bearer string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.BaseURL+path, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return errors.New("feishu request failed with status " + resp.Status)
	}
	return json.Unmarshal(raw, out)
}
