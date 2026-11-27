package settings

import (
	"errors"
	"fmt"
	"net/url"
)

// intBounds 为各整数型设置项的合法取值范围 [min, max]，防止配置成极端值导致安全策略失效或资源耗尽。
var intBounds = map[string][2]int{
	KeySecurityMaxLoginFailures:        {1, 100},
	KeySecurityLockoutMinutes:          {1, 1440},
	KeyJWTAccessTokenTTLMin:            {1, 1440},
	KeyJWTRefreshTokenTTLHours:         {1, 8760},
	KeyOAuthServerAuthCodeTTLMin:       {1, 60},
	KeyOAuthServerAccessTokenTTLMin:    {1, 1440},
	KeyOAuthServerRefreshTokenTTLHours: {1, 8760},
}

// urlKeys 为必须是合法 http(s) 绝对地址的设置项。
var urlKeys = map[string]bool{
	KeyJWTIssuer:                     true,
	KeyOAuthServerIssuer:             true,
	KeyOAuthServerFrontendConsentURL: true,
	KeyOAuthPluginCallbackBaseURL:    true,
}

func checkIntBounds(key string, n int) error {
	if b, ok := intBounds[key]; ok && (n < b[0] || n > b[1]) {
		return fmt.Errorf("设置项 %s 的取值范围为 %d~%d", key, b[0], b[1])
	}
	return nil
}

func validateURLSetting(key, raw string) error {
	if !urlKeys[key] {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("设置项 %s 必须是有效的 http(s) 地址，且不得包含用户信息或片段", key)
	}
	return nil
}

// validateCORSOrigin 校验单个 CORS 来源：必须形如 scheme://host[:port]，不允许通配符、路径或查询串。
func validateCORSOrigin(origin string) error {
	if origin == "*" {
		return errors.New("出于安全考虑不允许使用通配符 *，请显式列出允许的来源")
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("无效的跨域来源 %q，应形如 https://console.example.com", origin)
	}
	return nil
}
