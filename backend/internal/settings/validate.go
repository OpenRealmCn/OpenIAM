package settings

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	"github.com/openrealm/openiam/internal/clientip"
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
	KeySMTPPort:                        {1, 65535},
	KeyOTPCooldownSeconds:              {10, 600},
	KeyOTPMaxPerHourTarget:             {1, 100},
	KeyOTPMaxPerIPHour:                 {1, 500},
	KeyOTPSMSCostCents:                 {1, 1000},
	KeyOTPSMSDailyBudgetCents:          {1, 10000000},
	KeyRiskMediumThreshold:             {10, 90},
	KeyRiskHighThreshold:               {20, 100},
}

// urlKeys 为必须是合法 http(s) 绝对地址的设置项。
var urlKeys = map[string]bool{
	KeyJWTIssuer:                     true,
	KeyOAuthServerIssuer:             true,
	KeyOAuthServerFrontendConsentURL: true,
	KeyOAuthPluginCallbackBaseURL:    true,
}

// assetURLKeys 允许站内相对路径（以 / 开头）或合法 http(s) URL，防止 javascript: XSS 注入。
var assetURLKeys = map[string]bool{
	KeySiteLogoURL:    true,
	KeySiteFaviconURL: true,
}

// optionalEmptyKeys 允许留空的字符串设置项。
var optionalEmptyKeys = map[string]bool{
	KeySiteSubtitle:            true,
	KeySiteLogoURL:             true,
	KeySiteFaviconURL:          true,
	KeySiteAnnouncementTitle:   true,
	KeySiteAnnouncementContent: true,
	KeySiteFooterText:          true,
	KeySMTPHost:                true,
	KeySMTPUsername:            true,
	KeySMTPPassword:            true,
	KeySMTPFromName:            true,
	KeySMTPFromEmail:              true,
	KeyRiskBlockedIPs:             true,
	KeyServerClientIPCustomHeader: true,
	KeyServerTrustedProxies:       true,
}

// secretKeys 为敏感凭据字段，返回前端与写入审计日志时自动脱敏。
var secretKeys = map[string]bool{
	KeySMTPPassword: true,
}

func IsSecretKey(key string) bool {
	return secretKeys[key]
}

func checkIntBounds(key string, n int) error {
	if b, ok := intBounds[key]; ok && (n < b[0] || n > b[1]) {
		return fmt.Errorf("设置项 %s 的取值范围为 %d~%d", key, b[0], b[1])
	}
	return nil
}

func validateURLSetting(key, raw string) error {
	if assetURLKeys[key] {
		if raw == "" {
			return nil
		}
		if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
			return nil
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("设置项 %s 必须是站内路径（如 /logo.png）或有效的 http(s) 地址", key)
		}
		return nil
	}
	if !urlKeys[key] {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("设置项 %s 必须是有效的 http(s) 地址，且不得包含用户信息或片段", key)
	}
	return nil
}

func validateEnumOrSpecialSetting(key, raw string) error {
	switch key {
	case KeySiteAnnouncementType:
		switch raw {
		case "info", "success", "warning", "error":
			return nil
		default:
			return fmt.Errorf("公告类型必须为 info、success、warning 或 error")
		}
	case KeySMTPEncryption:
		switch strings.ToLower(raw) {
		case "starttls", "tls", "none":
			return nil
		default:
			return fmt.Errorf("SMTP 加密方式必须为 starttls、tls 或 none")
		}
	case KeySMTPFromEmail:
		if raw == "" {
			return nil
		}
		if _, err := mail.ParseAddress(raw); err != nil {
			return fmt.Errorf("发件人邮箱格式无效")
		}
	case KeyRiskHighAction:
		switch raw {
		case "challenge_mfa", "notify", "block":
			return nil
		default:
			return fmt.Errorf("高风险处置策略必须为 challenge_mfa、notify 或 block")
		}
	case KeyServerClientIPMethod:
		if !clientip.IsValidMethod(raw) {
			return fmt.Errorf("不支持的客户端 IP 获取方式: %s", raw)
		}
	case KeyServerClientIPCustomHeader:
		return clientip.ValidateCustomHeader(raw)
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
