package handlers

import (
	"slices"

	"github.com/openrealm/openiam/internal/security"
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
		if err := security.ValidateClientRedirectURI(raw, false); err != nil {
			return err.Error()
		}
	}
	return ""
}

// validateClientCommon 对所有 OAuth 应用（含管理员创建）执行的基础校验：回调地址协议安全，
// 公共客户端（无法保管密钥）必须强制 PKCE，且不能使用 client_credentials。
func validateClientCommon(redirectURIs, grantTypes []string, isConfidential, requirePKCE bool) string {
	for _, raw := range redirectURIs {
		if err := security.ValidateClientRedirectURI(raw, true); err != nil {
			return err.Error()
		}
	}
	if !isConfidential {
		if !requirePKCE {
			return "公共客户端必须启用 PKCE"
		}
		if slices.Contains(grantTypes, "client_credentials") {
			return "公共客户端不能使用 client_credentials 授权类型"
		}
	}
	return ""
}
