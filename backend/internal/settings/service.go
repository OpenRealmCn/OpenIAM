package settings

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openrealm/openiam/internal/models"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"
)

const (
	KeySecurityMaxLoginFailures    = "security.max_login_failures"
	KeySecurityLockoutMinutes      = "security.lockout_minutes"
	KeySecurityAllowPublicRegister = "security.allow_public_register"

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

	KeyServerCORSAllowOrigins = "server.cors_allow_origins"
)

// RuntimeSettings 为从数据库加载并缓存在内存中的强类型运行时配置快照。
type RuntimeSettings struct {
	MaxLoginFailures    int
	LockoutMinutes      int
	AllowPublicRegister bool

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

	CORSAllowOrigins []string
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

func (s *Service) ListAll() ([]models.SystemSetting, error) {
	var rows []models.SystemSetting
	if err := s.db.Order("category ASC, id ASC").Find(&rows).Error; err != nil {
		return nil, err
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
		normVal, err := validateSettingValue(item.SettingKey, item.ValueType, rawVal)
		if err != nil {
			return nil, nil, err
		}
		if item.Value != normVal {
			before[k] = item.Value
			after[k] = normVal
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
		}
		return strings.Join(parts, ","), nil
	default:
		if key == KeyRateLimitGeneralRate || key == KeyRateLimitAuthRate {
			if _, err := limiter.NewRateFromFormatted(trimmed); err != nil {
				return "", fmt.Errorf("限流表达式 %s 格式无效（示例: 15-M, 120-M, 20-S）", trimmed)
			}
		}
		if trimmed == "" {
			return "", fmt.Errorf("设置项 %s 不能为空", key)
		}
		if err := validateURLSetting(key, trimmed); err != nil {
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
