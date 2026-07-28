package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment string
	HTTP        HTTPConfig
	Database    DatabaseConfig
	Redis       RedisConfig
	Session     SessionConfig
	Security    SecurityConfig
	SMTP        SMTPConfig
	Feishu      FeishuConfig
}

type HTTPConfig struct {
	Address        string
	FrontendOrigin string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
}

type DatabaseConfig struct {
	DSN string
}

type RedisConfig struct {
	Address   string
	Password  string
	Database  int
	KeyPrefix string
}

type SessionConfig struct {
	CookieName   string
	CookieSecure bool
	TTL          time.Duration
}

type SecurityConfig struct {
	PasswordMinLength int
	LoginAttemptLimit int
	LoginLockDuration time.Duration
}

type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	FromName    string
	TLS         string // off | starttls | implicit
}

func (s SMTPConfig) Enabled() bool { return s.Host != "" }

type FeishuConfig struct {
	AppID       string
	AppSecret   string
	RedirectURI string
	BaseURL     string
	FrontendURL string
}

func (f FeishuConfig) Enabled() bool { return f.AppID != "" && f.AppSecret != "" }

func Load() (Config, error) {
	redisDatabase, err := intValue("OPENIAM_REDIS_DATABASE", 0)
	if err != nil {
		return Config{}, err
	}

	cookieSecure, err := boolValue("OPENIAM_SESSION_COOKIE_SECURE", false)
	if err != nil {
		return Config{}, err
	}

	sessionTTL, err := durationValue("OPENIAM_SESSION_TTL", 12*time.Hour)
	if err != nil {
		return Config{}, err
	}

	loginAttemptLimit, err := intValue("OPENIAM_LOGIN_ATTEMPT_LIMIT", 5)
	if err != nil {
		return Config{}, err
	}

	loginLockDuration, err := durationValue("OPENIAM_LOGIN_LOCK_DURATION", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}

	passwordMinLength, err := intValue("OPENIAM_PASSWORD_MIN_LENGTH", 12)
	if err != nil {
		return Config{}, err
	}

	smtpPort, err := intValue("OPENIAM_SMTP_PORT", 587)
	if err != nil {
		return Config{}, err
	}

	frontendOrigin := value("OPENIAM_FRONTEND_ORIGIN", "http://localhost:3000")

	cfg := Config{
		Environment: value("OPENIAM_ENV", "development"),
		HTTP: HTTPConfig{
			Address:        value("OPENIAM_HTTP_ADDRESS", ":8080"),
			FrontendOrigin: frontendOrigin,
			ReadTimeout:    15 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    60 * time.Second,
		},
		Database: DatabaseConfig{
			DSN: value("OPENIAM_DATABASE_DSN", "openiam:openiam@tcp(localhost:3306)/openiam?charset=utf8mb4&parseTime=True&loc=UTC"),
		},
		Redis: RedisConfig{
			Address:   value("OPENIAM_REDIS_ADDRESS", "localhost:6379"),
			Password:  os.Getenv("OPENIAM_REDIS_PASSWORD"),
			Database:  redisDatabase,
			KeyPrefix: value("OPENIAM_REDIS_KEY_PREFIX", "openiam:dev:v1"),
		},
		Session: SessionConfig{
			CookieName:   value("OPENIAM_SESSION_COOKIE_NAME", "openiam_session"),
			CookieSecure: cookieSecure,
			TTL:          sessionTTL,
		},
		Security: SecurityConfig{
			PasswordMinLength: passwordMinLength,
			LoginAttemptLimit: loginAttemptLimit,
			LoginLockDuration: loginLockDuration,
		},
		SMTP: SMTPConfig{
			Host:        os.Getenv("OPENIAM_SMTP_HOST"),
			Port:        smtpPort,
			Username:    os.Getenv("OPENIAM_SMTP_USERNAME"),
			Password:    os.Getenv("OPENIAM_SMTP_PASSWORD"),
			FromAddress: value("OPENIAM_SMTP_FROM_ADDRESS", "no-reply@openrealm.io"),
			FromName:    value("OPENIAM_SMTP_FROM_NAME", "OpenIAM"),
			TLS:         value("OPENIAM_SMTP_TLS", "starttls"),
		},
		Feishu: FeishuConfig{
			AppID:       os.Getenv("OPENIAM_FEISHU_APP_ID"),
			AppSecret:   os.Getenv("OPENIAM_FEISHU_APP_SECRET"),
			RedirectURI: os.Getenv("OPENIAM_FEISHU_REDIRECT_URI"),
			BaseURL:     value("OPENIAM_FEISHU_BASE_URL", "https://open.feishu.cn/open-apis"),
			FrontendURL: value("OPENIAM_FRONTEND_URL", frontendOrigin),
		},
	}

	if cfg.Environment == "production" && !cfg.Session.CookieSecure {
		return Config{}, fmt.Errorf("OPENIAM_SESSION_COOKIE_SECURE must be true in production")
	}

	switch cfg.SMTP.TLS {
	case "off", "starttls", "implicit":
	default:
		return Config{}, fmt.Errorf("OPENIAM_SMTP_TLS must be one of off|starttls|implicit")
	}

	return cfg, nil
}

func value(key, fallback string) string {
	if current := os.Getenv(key); current != "" {
		return current
	}
	return fallback
}

func intValue(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}

func boolValue(key string, fallback bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}

func durationValue(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}
