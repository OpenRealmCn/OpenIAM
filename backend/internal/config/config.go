package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	MySQL       MySQLConfig       `mapstructure:"mysql"`
	Redis       RedisConfig       `mapstructure:"redis"`
	JWT         JWTConfig         `mapstructure:"jwt"`
	RateLimit   RateLimitConfig   `mapstructure:"ratelimit"`
	Security    SecurityConfig    `mapstructure:"security"`
	Migration   MigrationConfig   `mapstructure:"migration"`
	OAuthServer OAuthServerConfig `mapstructure:"oauth_server"`
	OAuthPlugin OAuthPluginConfig `mapstructure:"oauth_plugin"`
	Seed        SeedConfig        `mapstructure:"seed"`
}

type ServerConfig struct {
	Host             string   `mapstructure:"host"`
	Port             int      `mapstructure:"port"`
	Mode             string   `mapstructure:"mode"`
	CORSAllowOrigins []string `mapstructure:"cors_allow_origins"`
}

type MySQLConfig struct {
	DSN                    string `mapstructure:"dsn"`
	MaxIdleConns           int    `mapstructure:"max_idle_conns"`
	MaxOpenConns           int    `mapstructure:"max_open_conns"`
	ConnMaxLifetimeMinutes int    `mapstructure:"conn_max_lifetime_minutes"`
}

type RedisConfig struct {
	Addr      string `mapstructure:"addr"`
	Password  string `mapstructure:"password"`
	DB        int    `mapstructure:"db"`
	KeyPrefix string `mapstructure:"key_prefix"`
}

type JWTConfig struct {
	Issuer                 string `mapstructure:"issuer"`
	PrivateKeyPath         string `mapstructure:"private_key_path"`
	AccessTokenTTLMinutes  int    `mapstructure:"access_token_ttl_minutes"`
	RefreshTokenTTLHours   int    `mapstructure:"refresh_token_ttl_hours"`
}

type RateLimitConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	GeneralRate string `mapstructure:"general_rate"`
	AuthRate    string `mapstructure:"auth_rate"`
}

type SecurityConfig struct {
	MaxLoginFailures int `mapstructure:"max_login_failures"`
	LockoutMinutes   int `mapstructure:"lockout_minutes"`
}

type MigrationConfig struct {
	AutoMigrate        bool `mapstructure:"auto_migrate"`
	StrictVersionCheck bool `mapstructure:"strict_version_check"`
}

type OAuthServerConfig struct {
	Issuer                 string `mapstructure:"issuer"`
	FrontendConsentURL     string `mapstructure:"frontend_consent_url"`
	AuthCodeTTLMinutes     int    `mapstructure:"auth_code_ttl_minutes"`
	AccessTokenTTLMinutes  int    `mapstructure:"access_token_ttl_minutes"`
	RefreshTokenTTLHours   int    `mapstructure:"refresh_token_ttl_hours"`
}

type OAuthPluginConfig struct {
	CallbackBaseURL string `mapstructure:"callback_base_url"`
}

type SeedConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	AdminUsername string `mapstructure:"admin_username"`
	AdminEmail    string `mapstructure:"admin_email"`
	AdminPassword string `mapstructure:"admin_password"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:             "0.0.0.0",
			Port:             8080,
			Mode:             "debug",
			CORSAllowOrigins: []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		},
		MySQL: MySQLConfig{
			DSN:                    "openiam:openiam_password@tcp(127.0.0.1:3306)/openiam?charset=utf8mb4&parseTime=True&loc=Local&multiStatements=true",
			MaxIdleConns:           10,
			MaxOpenConns:           100,
			ConnMaxLifetimeMinutes: 60,
		},
		Redis: RedisConfig{
			Addr:      "127.0.0.1:6379",
			Password:  "",
			DB:        0,
			KeyPrefix: "openiam:",
		},
		JWT: JWTConfig{
			Issuer:                "http://localhost:8080",
			AccessTokenTTLMinutes: 30,
			RefreshTokenTTLHours:  168,
		},
		RateLimit: RateLimitConfig{
			Enabled:     true,
			GeneralRate: "120-M",
			AuthRate:    "15-M",
		},
		Security: SecurityConfig{
			MaxLoginFailures: 5,
			LockoutMinutes:   15,
		},
		Migration: MigrationConfig{
			AutoMigrate:        true,
			StrictVersionCheck: true,
		},
		OAuthServer: OAuthServerConfig{
			Issuer:                "http://localhost:8080",
			FrontendConsentURL:    "http://localhost:5173/oauth2/consent",
			AuthCodeTTLMinutes:    10,
			AccessTokenTTLMinutes: 60,
			RefreshTokenTTLHours:  720,
		},
		OAuthPlugin: OAuthPluginConfig{
			CallbackBaseURL: "http://localhost:5173/oauth/callback",
		},
		Seed: SeedConfig{
			Enabled:       true,
			AdminUsername: "admin",
			AdminEmail:    "admin@openrealm.local",
			AdminPassword: "Admin@123456",
		},
	}
}

func Load(configPath string) (*Config, error) {
	v := viper.New()
	cfg := Default()

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./backend")
	}

	v.SetEnvPrefix("OPENIAM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && configPath != "" {
			return nil, fmt.Errorf("read config file: %w", err)
		}
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return cfg, nil
}
