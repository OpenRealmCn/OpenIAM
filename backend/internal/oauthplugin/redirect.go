package oauthplugin

import (
	"strings"
)

// validateRedirectOverride 校验请求方提供的 redirect_uri 覆盖值：
// 只允许系统配置的回调地址，或已登记 CORS 来源下的 /oauth/callback/{provider}，防止授权码被投递到攻击者站点。
func (s *Service) validateRedirectOverride(providerName, override string) error {
	if override == "" {
		return nil
	}
	if override == s.buildRedirectURI(providerName) {
		return nil
	}
	if s.settingsSvc != nil {
		for _, origin := range s.settingsSvc.Snapshot().CORSAllowOrigins {
			if override == strings.TrimRight(origin, "/")+"/oauth/callback/"+providerName {
				return nil
			}
		}
	}
	return publicErr("redirect_uri 不在允许的回调地址范围内")
}
