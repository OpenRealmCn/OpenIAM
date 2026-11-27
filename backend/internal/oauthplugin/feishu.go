package oauthplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// FeishuPlugin 实现飞书 (Feishu/Lark) 网页应用 OAuth 2.0 联合登录适配器。
type FeishuPlugin struct{}

func NewFeishuPlugin() *FeishuPlugin {
	return &FeishuPlugin{}
}

func (p *FeishuPlugin) Type() string {
	return "feishu"
}

func (p *FeishuPlugin) Metadata() PluginMetadata {
	return PluginMetadata{
		Type:          p.Type(),
		DisplayName:   "飞书 (Feishu)",
		Description:   "接入飞书自建应用或商店应用 OAuth 2.0 登录，支持获取飞书用户 OpenID、UnionID、姓名、头像和企业邮箱。",
		DefaultScopes: "contact:user.base:readonly contact:user.email:readonly",
		ConfigFields: []ConfigField{
			{Key: "api_base_url", Label: "飞书 OpenAPI Base URL", Type: "url", Required: false, Placeholder: "https://open.feishu.cn", Description: "可选，国际版 Lark 可填 https://open.larksuite.com"},
			{Key: "auth_base_url", Label: "飞书授权页 Base URL", Type: "url", Required: false, Placeholder: "https://accounts.feishu.cn", Description: "可选，默认使用 https://accounts.feishu.cn"},
		},
	}
}

func (p *FeishuPlugin) AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error) {
	authBase := strings.TrimRight(extraString(params.Provider.ExtraConfig, "auth_base_url", "https://accounts.feishu.cn"), "/")
	q := url.Values{}
	q.Set("client_id", params.Provider.ClientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("state", params.State)
	if scopes := strings.Join(splitScopes(params.Provider.Scopes, ""), " "); scopes != "" {
		q.Set("scope", scopes)
	}
	return authBase + "/open-apis/authen/v1/authorize?" + q.Encode(), nil
}

func (p *FeishuPlugin) ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error) {
	apiBase := strings.TrimRight(extraString(params.Provider.ExtraConfig, "api_base_url", "https://open.feishu.cn"), "/")

	// 1. 获取 app_access_token
	appTokenReqBody, _ := json.Marshal(map[string]string{
		"app_id":     params.Provider.ClientID,
		"app_secret": params.Provider.ClientSecret,
	})
	appReq, err := http.NewRequest(http.MethodPost, apiBase+"/open-apis/auth/v3/app_access_token/internal", bytes.NewReader(appTokenReqBody))
	if err != nil {
		return nil, err
	}
	appReq.Header.Set("Content-Type", "application/json; charset=utf-8")

	var appResp struct {
		Code           int    `json:"code"`
		Msg            string `json:"msg"`
		AppAccessToken string `json:"app_access_token"`
	}
	if _, err := fetchJSON(ctx, http.DefaultClient, appReq, &appResp); err != nil {
		return nil, fmt.Errorf("feishu app_access_token request failed: %w", err)
	}
	if appResp.Code != 0 || appResp.AppAccessToken == "" {
		return nil, fmt.Errorf("feishu app_access_token error (%d): %s", appResp.Code, appResp.Msg)
	}

	// 2. 用授权码换取 user_access_token
	oidcReqBody, _ := json.Marshal(map[string]string{
		"grant_type": "authorization_code",
		"code":       params.Code,
	})
	oidcReq, err := http.NewRequest(http.MethodPost, apiBase+"/open-apis/authen/v1/oidc/access_token", bytes.NewReader(oidcReqBody))
	if err != nil {
		return nil, err
	}
	oidcReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	oidcReq.Header.Set("Authorization", "Bearer "+appResp.AppAccessToken)

	var tokenResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if _, err := fetchJSON(ctx, http.DefaultClient, oidcReq, &tokenResp); err != nil {
		return nil, fmt.Errorf("feishu oidc access_token request failed: %w", err)
	}
	if tokenResp.Code != 0 || tokenResp.Data.AccessToken == "" {
		return nil, fmt.Errorf("feishu oidc access_token error (%d): %s", tokenResp.Code, tokenResp.Msg)
	}

	// 3. 查询飞书用户信息
	userReq, err := http.NewRequest(http.MethodGet, apiBase+"/open-apis/authen/v1/user_info", nil)
	if err != nil {
		return nil, err
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.Data.AccessToken)

	var userResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			OpenID          string `json:"open_id"`
			UnionID         string `json:"union_id"`
			UserID          string `json:"user_id"`
			Name            string `json:"name"`
			EnName          string `json:"en_name"`
			AvatarURL       string `json:"avatar_url"`
			Email           string `json:"email"`
			EnterpriseEmail string `json:"enterprise_email"`
		} `json:"data"`
	}
	rawMap, err := fetchJSON(ctx, http.DefaultClient, userReq, &userResp)
	if err != nil {
		return nil, fmt.Errorf("feishu user_info request failed: %w", err)
	}
	if userResp.Code != 0 {
		return nil, fmt.Errorf("feishu user_info error (%d): %s", userResp.Code, userResp.Msg)
	}

	extID := firstNonEmpty(userResp.Data.UnionID, userResp.Data.OpenID, userResp.Data.UserID)
	if extID == "" {
		return nil, errors.New("feishu returned empty open_id/union_id")
	}
	email := firstNonEmpty(userResp.Data.EnterpriseEmail, userResp.Data.Email)
	username := firstNonEmpty(userResp.Data.UserID, strings.Split(email, "@")[0], userResp.Data.OpenID)

	return &ExternalUserInfo{
		ExternalUserID: extID,
		Username:       username,
		Email:          email,
		DisplayName:    firstNonEmpty(userResp.Data.Name, userResp.Data.EnName, username),
		AvatarURL:      userResp.Data.AvatarURL,
		RawProfile:     rawMap,
	}, nil
}
