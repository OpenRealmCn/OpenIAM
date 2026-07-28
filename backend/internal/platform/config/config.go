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
}

func Load() (Config, error) {
	redisDatabase, err := intValue("OPENIAM_REDIS_DATABASE", 0)
	if err != nil {
		return Config{}, err
	}

	cookieSecure, err := boolValue("OPENIAM_SESSION_COOKIE_SECURE", false)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Environment: value("OPENIAM_ENV", "development"),
		HTTP: HTTPConfig{
			Address:        value("OPENIAM_HTTP_ADDRESS", ":8080"),
			FrontendOrigin: value("OPENIAM_FRONTEND_ORIGIN", "http://localhost:3000"),
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
		},
	}

	if cfg.Environment == "production" && !cfg.Session.CookieSecure {
		return Config{}, fmt.Errorf("OPENIAM_SESSION_COOKIE_SECURE must be true in production")
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
