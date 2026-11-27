package oauthplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/openrealm/openiam/internal/models"
)

// ConfigField 描述插件在前端管理界面动态渲染的配置字段。
type ConfigField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Type        string `json:"type"` // text | password | url
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder"`
	Description string `json:"description"`
}

// PluginMetadata 描述一个联合登录插件的元信息。
type PluginMetadata struct {
	Type          string        `json:"type"`
	DisplayName   string        `json:"display_name"`
	Description   string        `json:"description"`
	DefaultScopes string        `json:"default_scopes"`
	ConfigFields  []ConfigField `json:"config_fields"`
}

// ExternalUserInfo 是所有插件适配器归一化输出的外部身份信息。
type ExternalUserInfo struct {
	ExternalUserID string                 `json:"external_user_id"`
	Username       string                 `json:"username"`
	Email          string                 `json:"email"`
	DisplayName    string                 `json:"display_name"`
	AvatarURL      string                 `json:"avatar_url"`
	RawProfile     map[string]interface{} `json:"raw_profile"`
}

// AuthURLParams 传递给插件生成授权跳转 URL 的参数。
type AuthURLParams struct {
	Provider      models.OAuthProvider
	RedirectURI   string
	State         string
	CodeChallenge string
}

// ExchangeParams 传递给插件完成回调换票与用户信息获取的参数。
type ExchangeParams struct {
	Provider     models.OAuthProvider
	RedirectURI  string
	Code         string
	CodeVerifier string
}

// OAuthProviderPlugin 定义可插拔联合登录适配器的标准契约。
// 第三方或企业内部身份源只需实现此接口并调用 Registry.Register 即可接入 OpenIAM。
type OAuthProviderPlugin interface {
	Type() string
	Metadata() PluginMetadata
	AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error)
	ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error)
}

// Registry 维护已注册的联合登录插件映射。
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]OAuthProviderPlugin
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]OAuthProviderPlugin),
	}
}

// NewDefaultRegistry 创建并注册全部内置联合登录插件。
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGenericOIDCPlugin())
	r.Register(NewGitHubPlugin())
	r.Register(NewGooglePlugin())
	r.Register(NewFeishuPlugin())
	r.Register(NewWeComPlugin())
	return r
}

func (r *Registry) Register(p OAuthProviderPlugin) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[p.Type()] = p
}

func (r *Registry) Get(pluginType string) (OAuthProviderPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[pluginType]
	return p, ok
}

func (r *Registry) ListMetadata() []PluginMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]PluginMetadata, 0, len(r.plugins))
	for _, p := range r.plugins {
		list = append(list, p.Metadata())
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Type < list[j].Type
	})
	return list
}

func splitScopes(scopesStr, fallback string) []string {
	raw := strings.TrimSpace(scopesStr)
	if raw == "" {
		raw = fallback
	}
	raw = strings.ReplaceAll(raw, ",", " ")
	fields := strings.Fields(raw)
	return fields
}

func extraString(cfg models.JSONMap, key, fallback string) string {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key]; ok {
		if s, ok2 := v.(string); ok2 && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return fallback
}

func fetchJSON(ctx context.Context, client *http.Client, req *http.Request, out interface{}) (map[string]interface{}, error) {
	if client == nil || client == http.DefaultClient {
		client = upstreamClient
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rawMap map[string]interface{}
	_ = json.Unmarshal(body, &rawMap)
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return rawMap, err
		}
	}
	return rawMap, nil
}
