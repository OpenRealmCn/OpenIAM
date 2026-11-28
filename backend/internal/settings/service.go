package settings

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/models"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"
)

const (
	KeySecurityMaxLoginFailures     = "security.max_login_failures"
	KeySecurityLockoutMinutes       = "security.lockout_minutes"
	KeySecurityAllowPublicRegister  = "security.allow_public_register"
	KeySecurityAllowPrivateUpstream = "security.allow_private_upstream"

	KeyJWTIssuer               = "jwt.issuer"
	KeyJWTAccessTokenTTLMin    = "jwt.access_token_ttl_minutes"
	KeyJWTRefreshTokenTTLHours = "jwt.refresh_token_ttl_hours"

	KeyRateLimitEnabled     = "ratelimit.enabled"
	KeyRateLimitGeneralRate = "ratelimit.general_rate"
	KeyRateLimitAuthRate    = "ratelimit.auth_rate"

	KeyOAuthServerIssuer               = "oauth_server.issuer"
	KeyOAuthServerFrontendConsentURL   = "oauth_server.frontend_consent_url"
	KeyOAuthServerAuthCodeTTLMin       = "oauth_server.auth_code_ttl_minutes"
	KeyOAuthServerAccessTokenTTLMin    = "oauth_server.access_token_ttl_minutes"
	KeyOAuthServerRefreshTokenTTLHours = "oauth_server.refresh_token_ttl_hours"

	KeyOAuthPluginCallbackBaseURL = "oauth_plugin.callback_base_url"

	KeyServerCORSAllowOrigins     = "server.cors_allow_origins"
	KeyServerClientIPMethod       = "server.client_ip_method"
	KeyServerClientIPCustomHeader = "server.client_ip_custom_header"
	KeyServerTrustedProxies       = "server.trusted_proxies"

	// 站点品牌与首页公告
	KeySiteName                = "site.name"
	KeySiteSubtitle            = "site.subtitle"
	KeySiteLogoURL             = "site.logo_url"
	KeySiteFaviconURL          = "site.favicon_url"
	KeySiteAnnouncementEnabled = "site.announcement_enabled"
	KeySiteAnnouncementTitle   = "site.announcement_title"
	KeySiteAnnouncementContent = "site.announcement_content"
	KeySiteAnnouncementType    = "site.announcement_type"
	KeySiteFooterText          = "site.footer_text"

	// SMTP 邮件服务
	KeySMTPEnabled    = "smtp.enabled"
	KeySMTPHost       = "smtp.host"
	KeySMTPPort       = "smtp.port"
	KeySMTPUsername   = "smtp.username"
	KeySMTPPassword   = "smtp.password"
	KeySMTPFromName   = "smtp.from_name"
	KeySMTPFromEmail  = "smtp.from_email"
	KeySMTPEncryption = "smtp.encryption"

	// 验证码频控、成本与降级
	KeyOTPCooldownSeconds     = "otp.cooldown_seconds"
	KeyOTPMaxPerHourTarget    = "otp.max_per_hour_target"
	KeyOTPMaxPerIPHour        = "otp.max_per_ip_hour"
	KeyOTPSMSCostCents        = "otp.sms_cost_cents"
	KeyOTPSMSDailyBudgetCents = "otp.sms_daily_budget_cents"
	KeyOTPFallbackToEmail     = "otp.fallback_to_email"

	// 风险自适应认证
	KeyRiskEnabled         = "risk.enabled"
	KeyRiskMediumThreshold = "risk.medium_threshold"
	KeyRiskHighThreshold   = "risk.high_threshold"
	KeyRiskHighAction      = "risk.high_action"
	KeyRiskBlockedIPs      = "risk.blocked_ips"
	KeyRiskTrustGeoHeader  = "risk.trust_geo_header"

	// 人机验证触发场景
	KeyCaptchaProtectLogin    = "captcha.protect_login"
	KeyCaptchaProtectRegister = "captcha.protect_register"
	KeyCaptchaProtectOTP      = "captcha.protect_otp"
)

// RuntimeSettings 为从数据库加载并缓存在内存中的强类型运行时配置快照。
type RuntimeSettings struct {
	MaxLoginFailures     int
	LockoutMinutes       int
	AllowPublicRegister  bool
	AllowPrivateUpstream bool

	JWTIssuer     string
	JWTAccessTTL  time.Duration
	JWTRefreshTTL time.Duration

	RateLimitEnabled     bool
	RateLimitGeneralRate string
	RateLimitAuthRate    string

	OAuthServerIssuer             string
	OAuthServerFrontendConsentURL string
	OAuthServerAuthCodeTTL        time.Duration
	OAuthServerAccessTokenTTL     time.Duration
	OAuthServerRefreshTokenTTL    time.Duration

	OAuthPluginCallbackBaseURL string

	CORSAllowOrigins     []string
	ClientIPMethod       string
	ClientIPCustomHeader string
	TrustedProxies       []string

	SiteName                string
	SiteSubtitle            string
	SiteLogoURL             string
	SiteFaviconURL          string
	SiteAnnouncementEnabled bool
	SiteAnnouncementTitle   string
	SiteAnnouncementContent string
	SiteAnnouncementType    string
	SiteFooterText          string

	SMTPEnabled    bool
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	SMTPFromName   string
	SMTPFromEmail  string
	SMTPEncryption string

	OTPCooldownSeconds     int
	OTPMaxPerHourTarget    int
	OTPMaxPerIPHour        int
	OTPSMSCostCents        int
	OTPSMSDailyBudgetCents int
	OTPFallbackToEmail     bool

	RiskEnabled         bool
	RiskMediumThreshold int
	RiskHighThreshold   int
	RiskHighAction      string
	RiskBlockedIPs      []string
	RiskTrustGeoHeader  bool

	CaptchaProtectLogin    bool
	CaptchaProtectRegister bool
	CaptchaProtectOTP      bool
}

type settingSpec struct {
	Key         string
	Category    string
	DefaultVal  string
	ValueType   string
	Label       string
	Description string
}

var defaultSpecs = []settingSpec{
	{
		Key:         KeySecurityMaxLoginFailures,
		Category:    "security",
		DefaultVal:  "5",
		ValueType:   "int",
		Label:       "登录失败锁定阈值",
		Description: "连续密码错误达到此次数后，将临时锁定账号。",
	},
	{
		Key:         KeySecurityLockoutMinutes,
		Category:    "security",
		DefaultVal:  "15",
		ValueType:   "int",
		Label:       "账号锁定时长（分钟）",
		Description: "触发登录保护后的锁定持续时间。",
	},
	{
		Key:         KeySecurityAllowPublicRegister,
		Category:    "security",
		DefaultVal:  "true",
		ValueType:   "bool",
		Label:       "开放用户自主注册",
		Description: "关闭后仅允许管理员在控制台创建账号。",
	},
	{
		Key:         KeySecurityAllowPrivateUpstream,
		Category:    "security",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "允许身份源与插件访问内网地址",
		Description: "默认关闭以防止内网探测风险；仅在需要对接内网身份源、内网告警地址或私有验证服务时开启。",
	},
	{
		Key:         KeyJWTIssuer,
		Category:    "jwt",
		DefaultVal:  "http://localhost:5173",
		ValueType:   "string",
		Label:       "令牌签发者（Issuer）",
		Description: "访问令牌的签发方标识，建议填写平台对外访问地址。",
	},
	{
		Key:         KeyJWTAccessTokenTTLMin,
		Category:    "jwt",
		DefaultVal:  "30",
		ValueType:   "int",
		Label:       "访问令牌有效期（分钟）",
		Description: "单次签发的访问令牌有效时长。",
	},
	{
		Key:         KeyJWTRefreshTokenTTLHours,
		Category:    "jwt",
		DefaultVal:  "168",
		ValueType:   "int",
		Label:       "刷新令牌有效期（小时）",
		Description: "登录会话最长免密续期时长，默认 168 小时（7 天）。",
	},
	{
		Key:         KeyRateLimitEnabled,
		Category:    "ratelimit",
		DefaultVal:  "true",
		ValueType:   "bool",
		Label:       "启用请求频率限制",
		Description: "按客户端来源 IP 限制高频请求，防止暴力尝试与接口滥用。",
	},
	{
		Key:         KeyRateLimitGeneralRate,
		Category:    "ratelimit",
		DefaultVal:  "120-M",
		ValueType:   "string",
		Label:       "常规接口限流规则",
		Description: "支持按秒/分/小时配置，如 120-M、20-S、1000-H。",
	},
	{
		Key:         KeyRateLimitAuthRate,
		Category:    "ratelimit",
		DefaultVal:  "15-M",
		ValueType:   "string",
		Label:       "认证接口限流规则",
		Description: "应用于登录、注册与令牌签发接口，建议设置更严格的阈值。",
	},
	{
		Key:         KeyOAuthServerIssuer,
		Category:    "oauth_server",
		DefaultVal:  "http://localhost:5173",
		ValueType:   "string",
		Label:       "OIDC 服务标识（Issuer）",
		Description: "对外暴露的 OIDC 服务根地址，用于自动发现与身份令牌签发。",
	},
	{
		Key:         KeyOAuthServerFrontendConsentURL,
		Category:    "oauth_server",
		DefaultVal:  "http://localhost:5173/oauth2/consent",
		ValueType:   "string",
		Label:       "授权确认页地址",
		Description: "外部应用发起 OAuth 授权时跳转的用户确认页面地址。",
	},
	{
		Key:         KeyOAuthServerAuthCodeTTLMin,
		Category:    "oauth_server",
		DefaultVal:  "10",
		ValueType:   "int",
		Label:       "授权码有效期（分钟）",
		Description: "OAuth 2.0 一次性授权码（Code）的有效时长。",
	},
	{
		Key:         KeyOAuthServerAccessTokenTTLMin,
		Category:    "oauth_server",
		DefaultVal:  "60",
		ValueType:   "int",
		Label:       "应用访问令牌有效期（分钟）",
		Description: "第三方接入应用获取的访问令牌有效时长。",
	},
	{
		Key:         KeyOAuthServerRefreshTokenTTLHours,
		Category:    "oauth_server",
		DefaultVal:  "720",
		ValueType:   "int",
		Label:       "应用刷新令牌有效期（小时）",
		Description: "第三方接入应用刷新令牌的有效时长，默认 720 小时（30 天）。",
	},
	{
		Key:         KeyOAuthPluginCallbackBaseURL,
		Category:    "oauth_plugin",
		DefaultVal:  "http://localhost:5173/oauth/callback",
		ValueType:   "string",
		Label:       "第三方登录回调前缀",
		Description: "外部身份源完成认证后的统一回调地址前缀。",
	},
	{
		Key:         KeyServerCORSAllowOrigins,
		Category:    "server",
		DefaultVal:  "http://localhost:5173,http://127.0.0.1:5173",
		ValueType:   "string_list",
		Label:       "允许跨域来源（CORS）",
		Description: "允许访问平台接口的前端域名列表，多个地址以英文逗号分隔。",
	},
	{
		Key:         KeyServerClientIPMethod,
		Category:    "server",
		DefaultVal:  clientip.MethodXForwardedFor,
		ValueType:   "string",
		Label:       "真实客户端 IP 获取方式",
		Description: "选择系统识别登录、审计与限流来源 IP 的方式，可在下方实时核对每种方式的预览 IP。",
	},
	{
		Key:         KeyServerClientIPCustomHeader,
		Category:    "server",
		DefaultVal:  "",
		ValueType:   "string",
		Label:       "自定义真实 IP 请求头名称",
		Description: "当获取方式选择「自定义请求头」时读取该请求头（如 X-Forwarded-Client-IP 或 EO-Client-IP）。",
	},
	{
		Key:         KeyServerTrustedProxies,
		Category:    "server",
		DefaultVal:  "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		ValueType:   "string_list",
		Label:       "可信反向代理网段（IP / CIDR）",
		Description: "仅当 TCP 直连来源命中此处列出的代理 IP 或网段时，才采信反向代理或 CDN 透传的客户端 IP 请求头，防止伪造来源。",
	},
	// 站点品牌与公告
	{
		Key:         KeySiteName,
		Category:    "site",
		DefaultVal:  "OpenIAM",
		ValueType:   "string",
		Label:       "站点名称",
		Description: "展示在登录页、导航栏及浏览器标签页标题中的平台名称。",
	},
	{
		Key:         KeySiteSubtitle,
		Category:    "site",
		DefaultVal:  "OpenRealm 统一身份与访问管理平台",
		ValueType:   "string",
		Label:       "站点副标题",
		Description: "展示在登录页标题下方的简短说明。",
	},
	{
		Key:         KeySiteLogoURL,
		Category:    "site",
		DefaultVal:  "/logo.png",
		ValueType:   "string",
		Label:       "全局图标（Logo URL）",
		Description: "展示在导航栏与登录页的品牌图标，支持站内路径（如 /logo.png）或 https:// 图片地址。",
	},
	{
		Key:         KeySiteFaviconURL,
		Category:    "site",
		DefaultVal:  "/logo.png",
		ValueType:   "string",
		Label:       "浏览器标签图标（Favicon）",
		Description: "浏览器标签页显示的小图标地址，支持站内路径或 https:// 图片地址。",
	},
	{
		Key:         KeySiteAnnouncementEnabled,
		Category:    "site",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "启用首页公告",
		Description: "开启后将在登录页与控制台顶部展示全局通知公告。",
	},
	{
		Key:         KeySiteAnnouncementTitle,
		Category:    "site",
		DefaultVal:  "系统公告",
		ValueType:   "string",
		Label:       "公告标题",
		Description: "全局公告横幅的标题文字。",
	},
	{
		Key:         KeySiteAnnouncementContent,
		Category:    "site",
		DefaultVal:  "",
		ValueType:   "text",
		Label:       "公告内容",
		Description: "向所有用户展示的维护通知、安全提醒或运维公告。",
	},
	{
		Key:         KeySiteAnnouncementType,
		Category:    "site",
		DefaultVal:  "info",
		ValueType:   "string",
		Label:       "公告级别",
		Description: "控制公告横幅的视觉样式，可根据紧急程度选择普通通知、成功提示、维护警告或重要告警。",
	},
	{
		Key:         KeySiteFooterText,
		Category:    "site",
		DefaultVal:  "© OpenRealm · OpenIAM",
		ValueType:   "string",
		Label:       "页脚版权文字",
		Description: "展示在登录页底部的版权与归属说明。",
	},
	// SMTP 邮件服务
	{
		Key:         KeySMTPEnabled,
		Category:    "smtp",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "启用 SMTP 发信",
		Description: "开启后支持发送测试邮件、密码重置验证码与安全通知。",
	},
	{
		Key:         KeySMTPHost,
		Category:    "smtp",
		DefaultVal:  "",
		ValueType:   "string",
		Label:       "SMTP 服务器地址",
		Description: "邮件服务商提供的 SMTP 主机名，例如 smtp.exmail.qq.com 或 smtp.gmail.com。",
	},
	{
		Key:         KeySMTPPort,
		Category:    "smtp",
		DefaultVal:  "587",
		ValueType:   "int",
		Label:       "SMTP 端口",
		Description: "常见端口：587（STARTTLS）、465（SSL/TLS）、25（无加密）。",
	},
	{
		Key:         KeySMTPUsername,
		Category:    "smtp",
		DefaultVal:  "",
		ValueType:   "string",
		Label:       "SMTP 认证账号",
		Description: "用于登录 SMTP 服务器的用户名或发信邮箱。",
	},
	{
		Key:         KeySMTPPassword,
		Category:    "smtp",
		DefaultVal:  "",
		ValueType:   "secret",
		Label:       "SMTP 授权码 / 密码",
		Description: "SMTP 认证密码或应用专用授权码（留空保存将保留原密码）。",
	},
	{
		Key:         KeySMTPFromName,
		Category:    "smtp",
		DefaultVal:  "OpenIAM",
		ValueType:   "string",
		Label:       "发件人名称",
		Description: "收件人看到的发件人显示名称。",
	},
	{
		Key:         KeySMTPFromEmail,
		Category:    "smtp",
		DefaultVal:  "",
		ValueType:   "string",
		Label:       "发件人邮箱",
		Description: "对外发送邮件使用的 From 邮箱地址（留空时默认使用 SMTP 认证账号）。",
	},
	{
		Key:         KeySMTPEncryption,
		Category:    "smtp",
		DefaultVal:  "starttls",
		ValueType:   "string",
		Label:       "传输加密方式",
		Description: "选择与邮件服务器的加密连接方式，推荐使用 STARTTLS（587 端口）或隐式 SSL/TLS（465 端口）。",
	},
	{
		Key:         KeyOTPCooldownSeconds,
		Category:    "otp",
		DefaultVal:  "60",
		ValueType:   "int",
		Label:       "验证码发送冷却（秒）",
		Description: "同一账号或手机号/邮箱两次发送验证码的最小间隔秒数。",
	},
	{
		Key:         KeyOTPMaxPerHourTarget,
		Category:    "otp",
		DefaultVal:  "5",
		ValueType:   "int",
		Label:       "单目标每小时发送上限",
		Description: "同一邮箱或手机号每小时最多允许发送的验证码次数。",
	},
	{
		Key:         KeyOTPMaxPerIPHour,
		Category:    "otp",
		DefaultVal:  "20",
		ValueType:   "int",
		Label:       "单 IP 每小时发送上限",
		Description: "同一来源 IP 每小时最多发起的验证码发送请求数。",
	},
	{
		Key:         KeyOTPSMSCostCents,
		Category:    "otp",
		DefaultVal:  "5",
		ValueType:   "int",
		Label:       "单条短信估算成本（分）",
		Description: "用于统计当日短信通道消耗及触发预算告警的折算单价（人民币分）。",
	},
	{
		Key:         KeyOTPSMSDailyBudgetCents,
		Category:    "otp",
		DefaultVal:  "5000",
		ValueType:   "int",
		Label:       "短信日预算告警阈值（分）",
		Description: "当日累计短信折算费用超过该阈值时向超级管理员发送告警通知，并允许触发通道降级。",
	},
	{
		Key:         KeyOTPFallbackToEmail,
		Category:    "otp",
		DefaultVal:  "true",
		ValueType:   "bool",
		Label:       "短信通道异常自动降级邮件",
		Description: "当短信通道发送失败或超出当日预算且用户已绑定邮箱时，自动降级为邮件发送验证码。",
	},
	{
		Key:         KeyRiskEnabled,
		Category:    "risk",
		DefaultVal:  "true",
		ValueType:   "bool",
		Label:       "启用风险自适应认证",
		Description: "登录时综合评估 IP 信誉、异地、设备指纹变化与非常用时间并计算风险评分。",
	},
	{
		Key:         KeyRiskMediumThreshold,
		Category:    "risk",
		DefaultVal:  "30",
		ValueType:   "int",
		Label:       "中风险评分阈值",
		Description: "风险分达到该阈值时写入风险事件与日志，并向用户发送安全提醒。",
	},
	{
		Key:         KeyRiskHighThreshold,
		Category:    "risk",
		DefaultVal:  "70",
		ValueType:   "int",
		Label:       "高风险评分阈值",
		Description: "风险分达到该阈值时触发强管控动作（要求二次验证或直接阻断）。",
	},
	{
		Key:         KeyRiskHighAction,
		Category:    "risk",
		DefaultVal:  "challenge_mfa",
		ValueType:   "string",
		Label:       "高风险处置策略",
		Description: "当登录风险分达到高风险阈值时自动执行的保护动作，推荐强制二次身份验证。",
	},
	{
		Key:         KeyRiskBlockedIPs,
		Category:    "risk",
		DefaultVal:  "",
		ValueType:   "string_list",
		Label:       "高危拦截 IP 黑名单",
		Description: "逗号分隔的高危 IP 列表，命中将直接计入高风险分并阻断/告警。",
	},
	{
		Key:         KeyRiskTrustGeoHeader,
		Category:    "risk",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "采信前置网关地理请求头（X-Geo-Location）",
		Description: "默认关闭以防客户端伪造登录地点绕过风控；仅当前置网关强制覆写该头时开启。",
	},
	{
		Key:         KeyCaptchaProtectLogin,
		Category:    "captcha",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "登录启用人机验证",
		Description: "开启后，用户登录账号前需先完成已启用的人机安全验证。",
	},
	{
		Key:         KeyCaptchaProtectRegister,
		Category:    "captcha",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "注册启用人机验证",
		Description: "开启后自助注册需先完成人机验证。",
	},
	{
		Key:         KeyCaptchaProtectOTP,
		Category:    "captcha",
		DefaultVal:  "false",
		ValueType:   "bool",
		Label:       "发送验证码启用人机验证",
		Description: "开启后请求发送短信或邮件验证码需先完成人机验证。",
	},
}

// Service 管理持久化在数据库中的全部动态系统设置及热更新通知。
type Service struct {
	db       *gorm.DB
	mu       sync.RWMutex
	snapshot RuntimeSettings
	hooks    []func(RuntimeSettings)
}

func NewService(db *gorm.DB) (*Service, error) {
	s := &Service{db: db}
	if err := s.EnsureDefaults(); err != nil {
		return nil, err
	}
	return s, nil
}

// RegisterOnChange 注册配置变更回调，当管理员在控制台更新配置时自动触发。
func (s *Service) RegisterOnChange(fn func(RuntimeSettings)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	s.hooks = append(s.hooks, fn)
	snap := s.snapshot
	s.mu.Unlock()
	fn(snap)
}

// EnsureDefaults 幂等初始化默认系统设置并同步最新中文元数据说明（不覆盖已保存的值）。
func (s *Service) EnsureDefaults() error {
	for _, spec := range defaultSpecs {
		var existing models.SystemSetting
		if err := s.db.Where("setting_key = ?", spec.Key).First(&existing).Error; err != nil {
			row := models.SystemSetting{
				SettingKey:  spec.Key,
				Category:    spec.Category,
				Value:       spec.DefaultVal,
				ValueType:   spec.ValueType,
				Label:       spec.Label,
				Description: spec.Description,
			}
			if createErr := s.db.Create(&row).Error; createErr != nil {
				return fmt.Errorf("seed setting %s: %w", spec.Key, createErr)
			}
		} else if existing.Label != spec.Label || existing.Description != spec.Description {
			_ = s.db.Model(&existing).Updates(map[string]interface{}{
				"label":       spec.Label,
				"description": spec.Description,
			}).Error
		}
	}
	return s.Reload()
}

// Reload 从数据库重新读取全部设置并构建强类型快照。
func (s *Service) Reload() error {
	var rows []models.SystemSetting
	if err := s.db.Order("category ASC, id ASC").Find(&rows).Error; err != nil {
		return err
	}
	kv := make(map[string]string, len(rows))
	for _, r := range rows {
		kv[r.SettingKey] = r.Value
	}

	snap := RuntimeSettings{
		MaxLoginFailures:              parseInt(kv[KeySecurityMaxLoginFailures], 5),
		LockoutMinutes:                parseInt(kv[KeySecurityLockoutMinutes], 15),
		AllowPublicRegister:           parseBool(kv[KeySecurityAllowPublicRegister], true),
		AllowPrivateUpstream:          parseBool(kv[KeySecurityAllowPrivateUpstream], false),
		JWTIssuer:                     fallbackStr(kv[KeyJWTIssuer], "http://localhost:5173"),
		JWTAccessTTL:                  time.Duration(parseInt(kv[KeyJWTAccessTokenTTLMin], 30)) * time.Minute,
		JWTRefreshTTL:                 time.Duration(parseInt(kv[KeyJWTRefreshTokenTTLHours], 168)) * time.Hour,
		RateLimitEnabled:              parseBool(kv[KeyRateLimitEnabled], true),
		RateLimitGeneralRate:          fallbackStr(kv[KeyRateLimitGeneralRate], "120-M"),
		RateLimitAuthRate:             fallbackStr(kv[KeyRateLimitAuthRate], "15-M"),
		OAuthServerIssuer:             fallbackStr(kv[KeyOAuthServerIssuer], "http://localhost:5173"),
		OAuthServerFrontendConsentURL: fallbackStr(kv[KeyOAuthServerFrontendConsentURL], "http://localhost:5173/oauth2/consent"),
		OAuthServerAuthCodeTTL:        time.Duration(parseInt(kv[KeyOAuthServerAuthCodeTTLMin], 10)) * time.Minute,
		OAuthServerAccessTokenTTL:     time.Duration(parseInt(kv[KeyOAuthServerAccessTokenTTLMin], 60)) * time.Minute,
		OAuthServerRefreshTokenTTL:    time.Duration(parseInt(kv[KeyOAuthServerRefreshTokenTTLHours], 720)) * time.Hour,
		OAuthPluginCallbackBaseURL:    fallbackStr(kv[KeyOAuthPluginCallbackBaseURL], "http://localhost:5173/oauth/callback"),
		CORSAllowOrigins:              splitCSV(fallbackStr(kv[KeyServerCORSAllowOrigins], "http://localhost:5173,http://127.0.0.1:5173")),
		ClientIPMethod:                clientip.NormalizeMethod(fallbackStr(kv[KeyServerClientIPMethod], clientip.MethodXForwardedFor)),
		ClientIPCustomHeader:          strings.TrimSpace(kv[KeyServerClientIPCustomHeader]),
		TrustedProxies:                splitCSV(fallbackStr(kv[KeyServerTrustedProxies], strings.Join(clientip.DefaultTrustedProxies, ","))),
		SiteName:                      fallbackStr(kv[KeySiteName], "OpenIAM"),
		SiteSubtitle:                  strings.TrimSpace(kv[KeySiteSubtitle]),
		SiteLogoURL:                   fallbackStr(kv[KeySiteLogoURL], "/logo.png"),
		SiteFaviconURL:                fallbackStr(kv[KeySiteFaviconURL], "/logo.png"),
		SiteAnnouncementEnabled:       parseBool(kv[KeySiteAnnouncementEnabled], false),
		SiteAnnouncementTitle:         fallbackStr(kv[KeySiteAnnouncementTitle], "系统公告"),
		SiteAnnouncementContent:       strings.TrimSpace(kv[KeySiteAnnouncementContent]),
		SiteAnnouncementType:          fallbackStr(kv[KeySiteAnnouncementType], "info"),
		SiteFooterText:                fallbackStr(kv[KeySiteFooterText], "© OpenRealm · OpenIAM"),
		SMTPEnabled:                   parseBool(kv[KeySMTPEnabled], false),
		SMTPHost:                      strings.TrimSpace(kv[KeySMTPHost]),
		SMTPPort:                      parseInt(kv[KeySMTPPort], 587),
		SMTPUsername:                  strings.TrimSpace(kv[KeySMTPUsername]),
		SMTPPassword:                  kv[KeySMTPPassword],
		SMTPFromName:                  fallbackStr(kv[KeySMTPFromName], "OpenIAM"),
		SMTPFromEmail:                 strings.TrimSpace(kv[KeySMTPFromEmail]),
		SMTPEncryption:                fallbackStr(kv[KeySMTPEncryption], "starttls"),
		OTPCooldownSeconds:            parseInt(kv[KeyOTPCooldownSeconds], 60),
		OTPMaxPerHourTarget:           parseInt(kv[KeyOTPMaxPerHourTarget], 5),
		OTPMaxPerIPHour:               parseInt(kv[KeyOTPMaxPerIPHour], 20),
		OTPSMSCostCents:               parseInt(kv[KeyOTPSMSCostCents], 5),
		OTPSMSDailyBudgetCents:        parseInt(kv[KeyOTPSMSDailyBudgetCents], 5000),
		OTPFallbackToEmail:            parseBool(kv[KeyOTPFallbackToEmail], true),
		RiskEnabled:                   parseBool(kv[KeyRiskEnabled], true),
		RiskMediumThreshold:           parseInt(kv[KeyRiskMediumThreshold], 30),
		RiskHighThreshold:             parseInt(kv[KeyRiskHighThreshold], 70),
		RiskHighAction:                fallbackStr(kv[KeyRiskHighAction], "challenge_mfa"),
		RiskBlockedIPs:                splitCSV(kv[KeyRiskBlockedIPs]),
		RiskTrustGeoHeader:            parseBool(kv[KeyRiskTrustGeoHeader], false),
		CaptchaProtectLogin:           parseBool(kv[KeyCaptchaProtectLogin], false),
		CaptchaProtectRegister:        parseBool(kv[KeyCaptchaProtectRegister], false),
		CaptchaProtectOTP:             parseBool(kv[KeyCaptchaProtectOTP], false),
	}

	s.mu.Lock()
	s.snapshot = snap
	hooks := append([]func(RuntimeSettings){}, s.hooks...)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn(snap)
	}
	return nil
}

func (s *Service) Snapshot() RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

// ListAll 返回全部设置项（对敏感密钥字段自动脱敏，不向前端明文回传）。
func (s *Service) ListAll() ([]models.SystemSetting, error) {
	var rows []models.SystemSetting
	if err := s.db.Order("category ASC, id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		if IsSecretKey(rows[i].SettingKey) && rows[i].Value != "" {
			rows[i].Value = ""
		}
	}
	return rows, nil
}

// UpdateBatch 批量校验并更新系统设置，返回变更前后的值快照以便写入审计日志。
func (s *Service) UpdateBatch(updates map[string]string, actorID uint64) (before map[string]string, after map[string]string, err error) {
	if len(updates) == 0 {
		return nil, nil, fmt.Errorf("未提供需要更新的设置项")
	}

	var rows []models.SystemSetting
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	byKey := make(map[string]models.SystemSetting, len(rows))
	for _, r := range rows {
		byKey[r.SettingKey] = r
	}

	before = make(map[string]string)
	after = make(map[string]string)
	validated := make(map[string]string, len(updates))

	for k, rawVal := range updates {
		item, ok := byKey[k]
		if !ok {
			return nil, nil, fmt.Errorf("未知的系统设置项: %s", k)
		}
		// 敏感密钥字段留空时表示保留原值，避免前端未修改密码时意外清空
		if IsSecretKey(k) && strings.TrimSpace(rawVal) == "" {
			continue
		}
		normVal, err := validateSettingValue(item.SettingKey, item.ValueType, rawVal)
		if err != nil {
			return nil, nil, err
		}
		if item.Value != normVal {
			if IsSecretKey(k) {
				before[k] = "***REDACTED***"
				after[k] = "***REDACTED***"
			} else {
				before[k] = item.Value
				after[k] = normVal
			}
			validated[k] = normVal
		}
	}

	if len(validated) > 0 {
		err = s.db.Transaction(func(tx *gorm.DB) error {
			for k, val := range validated {
				if err := tx.Model(&models.SystemSetting{}).
					Where("setting_key = ?", k).
					Updates(map[string]interface{}{
						"value":      val,
						"updated_by": actorID,
					}).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		if err := s.Reload(); err != nil {
			return nil, nil, err
		}
	}

	return before, after, nil
}

func validateSettingValue(key, valueType, raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	switch valueType {
	case "int":
		n, err := strconv.Atoi(trimmed)
		if err != nil || n <= 0 {
			return "", fmt.Errorf("设置项 %s 必须为正整数", key)
		}
		if err := checkIntBounds(key, n); err != nil {
			return "", err
		}
		return strconv.Itoa(n), nil
	case "bool":
		b, err := strconv.ParseBool(strings.ToLower(trimmed))
		if err != nil {
			return "", fmt.Errorf("设置项 %s 必须为布尔值 (true/false)", key)
		}
		return strconv.FormatBool(b), nil
	case "string_list":
		parts := splitCSV(trimmed)
		if key == KeyServerCORSAllowOrigins {
			for _, p := range parts {
				if err := validateCORSOrigin(p); err != nil {
					return "", err
				}
			}
		} else if key == KeyServerTrustedProxies {
			for _, p := range parts {
				if err := clientip.ValidateTrustedProxyEntry(p); err != nil {
					return "", err
				}
			}
		}
		return strings.Join(parts, ","), nil
	default:
		if key == KeyRateLimitGeneralRate || key == KeyRateLimitAuthRate {
			if _, err := limiter.NewRateFromFormatted(trimmed); err != nil {
				return "", fmt.Errorf("限流表达式 %s 格式无效（示例: 15-M, 120-M, 20-S）", trimmed)
			}
		}
		if trimmed == "" && !optionalEmptyKeys[key] {
			return "", fmt.Errorf("设置项 %s 不能为空", key)
		}
		if err := validateURLSetting(key, trimmed); err != nil {
			return "", err
		}
		if err := validateEnumOrSpecialSetting(key, trimmed); err != nil {
			return "", err
		}
		return trimmed, nil
	}
}

func parseInt(s string, fallback int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return fallback
}

func parseBool(s string, fallback bool) bool {
	if b, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
		return b
	}
	return fallback
}

func fallbackStr(s, fallback string) string {
	if strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
