package oauthplugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WeComPlugin 实现企业微信 (WeCom) 网页授权联合登录适配器。
type WeComPlugin struct{}

func NewWeComPlugin() *WeComPlugin {
	return &WeComPlugin{}
}

func (p *WeComPlugin) Type() string {
	return "wecom"
}

func (p *WeComPlugin) Metadata() PluginMetadata {
	return PluginMetadata{
		Type:          p.Type(),
		DisplayName:   "企业微信 (WeCom)",
		Description:   "接入企业微信扫码/网页授权登录（支持填写企业 CorpID、应用 AgentID 与 Secret）。",
		DefaultScopes: "snsapi_base",
		ConfigFields: []ConfigField{
			{Key: "agent_id", Label: "应用 AgentID", Type: "text", Required: true, Placeholder: "1000002", Description: "企业微信自建应用 AgentID（在 Client ID 字段填写企业 CorpID）"},
			{Key: "api_base_url", Label: "企业微信 API Base URL", Type: "url", Required: false, Placeholder: "https://qyapi.weixin.qq.com", Description: "可选，私有化或测试 Mock 服务可覆盖"},
			{Key: "auth_base_url", Label: "扫码授权 Base URL", Type: "url", Required: false, Placeholder: "https://login.work.weixin.qq.com", Description: "可选，默认使用官方企业微信登录地址"},
		},
	}
}

func (p *WeComPlugin) AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error) {
	agentID := extraString(params.Provider.ExtraConfig, "agent_id", "")
	if agentID == "" {
		return "", errors.New("wecom requires extra_config.agent_id")
	}
	authBase := strings.TrimRight(extraString(params.Provider.ExtraConfig, "auth_base_url", "https://login.work.weixin.qq.com"), "/")
	q := url.Values{}
	q.Set("login_type", "CorpApp")
	q.Set("appid", params.Provider.ClientID)
	q.Set("agentid", agentID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("state", params.State)
	return authBase + "/wwlogin/sso/login?" + q.Encode(), nil
}

func (p *WeComPlugin) ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error) {
	apiBase := strings.TrimRight(extraString(params.Provider.ExtraConfig, "api_base_url", "https://qyapi.weixin.qq.com"), "/")

	// 1. 获取企业 access_token
	tokenURL := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		apiBase, url.QueryEscape(params.Provider.ClientID), url.QueryEscape(params.Provider.ClientSecret))
	tokenReq, err := http.NewRequest(http.MethodGet, tokenURL, nil)
	if err != nil {
		return nil, err
	}
	var tokenResp struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
	}
	if _, err := fetchJSON(ctx, http.DefaultClient, tokenReq, &tokenResp); err != nil {
		return nil, fmt.Errorf("wecom gettoken failed: %w", err)
	}
	if tokenResp.ErrCode != 0 || tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("wecom gettoken error (%d): %s", tokenResp.ErrCode, tokenResp.ErrMsg)
	}

	// 2. 用 code 获取用户 UserID
	userInfoURL := fmt.Sprintf("%s/cgi-bin/auth/getuserinfo?access_token=%s&code=%s",
		apiBase, url.QueryEscape(tokenResp.AccessToken), url.QueryEscape(params.Code))
	uiReq, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	var uiResp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		UserID  string `json:"userid"`
		OpenID  string `json:"openid"`
	}
	rawMap, err := fetchJSON(ctx, http.DefaultClient, uiReq, &uiResp)
	if err != nil {
		return nil, fmt.Errorf("wecom getuserinfo failed: %w", err)
	}
	if uiResp.ErrCode != 0 {
		return nil, fmt.Errorf("wecom getuserinfo error (%d): %s", uiResp.ErrCode, uiResp.ErrMsg)
	}

	extID := firstNonEmpty(uiResp.UserID, uiResp.OpenID)
	if extID == "" {
		return nil, errors.New("wecom returned empty userid/openid")
	}

	displayName := extID
	email := ""
	avatar := ""

	// 3. 如果是企业成员 userid，尝试进一步拉取成员详情（姓名、邮箱、头像）
	if uiResp.UserID != "" {
		detailURL := fmt.Sprintf("%s/cgi-bin/user/get?access_token=%s&userid=%s",
			apiBase, url.QueryEscape(tokenResp.AccessToken), url.QueryEscape(uiResp.UserID))
		dReq, _ := http.NewRequest(http.MethodGet, detailURL, nil)
		var dResp struct {
			ErrCode int    `json:"errcode"`
			Name    string `json:"name"`
			Email   string `json:"email"`
			BizMail string `json:"biz_mail"`
			Avatar  string `json:"avatar"`
		}
		if detailRaw, err := fetchJSON(ctx, http.DefaultClient, dReq, &dResp); err == nil && dResp.ErrCode == 0 {
			displayName = firstNonEmpty(dResp.Name, displayName)
			email = firstNonEmpty(dResp.BizMail, dResp.Email)
			avatar = dResp.Avatar
			rawMap = detailRaw
		}
	}

	return &ExternalUserInfo{
		ExternalUserID: extID,
		Username:       extID,
		Email:          email,
		DisplayName:    displayName,
		AvatarURL:      avatar,
		RawProfile:     rawMap,
	}, nil
}
