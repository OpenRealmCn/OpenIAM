package handlers

import (
	"net/url"
	"slices"
	"strings"
)

// validateSelfServiceClient 校验普通用户自助创建或修改的 OAuth 应用参数，防止通过自助接口申请高权限授权。
// 返回非空字符串表示校验失败的原因。
func validateSelfServiceClient(grantTypes, scopes, redirectURIs []string) string {
	for _, g := range grantTypes {
		if !slices.Contains([]string{"authorization_code", "refresh_token"}, g) {
			return "个人应用仅允许 authorization_code 与 refresh_token 授权类型"
		}
	}
	for _, s := range scopes {
		if !slices.Contains([]string{"openid", "profile", "email"}, s) {
			return "个人应用仅允许申请 openid、profile、email 范围"
		}
	}
	for _, raw := range redirectURIs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "*") {
			return "回调地址格式无效"
		}
		host := u.Hostname()
		local := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if u.Scheme != "https" && !(u.Scheme == "http" && local) {
			return "回调地址必须使用 https（本机回环地址允许 http）"
		}
	}
	return ""
}
