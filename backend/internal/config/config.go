package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// BootstrapConfig 仅包含本地启动必需的基础设施连接与监听参数（环境变量 / .env）。
// 其余所有业务、安全、JWT、限流、CORS 与 OAuth 参数均存储在 MySQL system_settings 表中，
// 并可在管理员控制台实时修改。
type BootstrapConfig struct {
	Server    ServerConfig
	MySQL     MySQLConfig
	Redis     RedisConfig
	Migration MigrationConfig
	JWT       JWTBootstrapConfig
	Seed      SeedConfig
}

type ServerConfig struct {
	Host string
	Port int
	Mode string
	// TrustedProxies 为可信反向代理 IP/CIDR 列表，仅来自这些地址的 X-Forwarded-For 才会被采信。
	TrustedProxies []string
}

type MySQLConfig struct {
	DSN                    string
	MaxIdleConns           int
	MaxOpenConns           int
	ConnMaxLifetimeMinutes int
}

type RedisConfig struct {
	Addr      string
	Password  string
	DB        int
	KeyPrefix string
}

type MigrationConfig struct {
	AutoMigrate        bool
	StrictVersionCheck bool
}

type JWTBootstrapConfig struct {
	PrivateKeyPath string
}

type SeedConfig struct {
	Enabled       bool
	AdminUsername string
	AdminEmail    string
	// AdminPassword 为空库首次初始化的初始管理员口令，必须通过 OPENIAM_SEED_ADMIN_PASSWORD 显式提供。
	// 本字段不再有内置默认值；未提供、长度/复杂度不达标或仍为历史默认口令时，初始化会直接失败。
	AdminPassword string
}

func Default() *BootstrapConfig {
	return &BootstrapConfig{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
			Mode: "debug",
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
		Migration: MigrationConfig{
			AutoMigrate:        true,
			StrictVersionCheck: true,
		},
		JWT: JWTBootstrapConfig{
			PrivateKeyPath: "",
		},
		Seed: SeedConfig{
			Enabled:       true,
			AdminUsername: "admin",
			AdminEmail:    "admin@openrealm.local",
			// 故意留空：必须在部署时显式设置强口令，否则空库初始化失败。
			AdminPassword: "",
		},
	}
}

// Load 从环境变量与可选的本地 .env 文件加载基础启动配置，不再依赖 config.yaml。
func Load(envFilePath string) (*BootstrapConfig, error) {
	if envFilePath != "" {
		loadDotEnv(envFilePath)
	} else {
		loadDotEnv(".env")
		loadDotEnv("../.env")
	}

	cfg := Default()
	cfg.Server.Host = getEnv("OPENIAM_HOST", cfg.Server.Host)
	cfg.Server.Port = getEnvInt("OPENIAM_PORT", cfg.Server.Port)
	cfg.Server.Mode = getEnv("OPENIAM_MODE", cfg.Server.Mode)
	cfg.Server.TrustedProxies = splitList(getEnv("OPENIAM_TRUSTED_PROXIES", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))

	cfg.MySQL.DSN = getEnv("OPENIAM_MYSQL_DSN", cfg.MySQL.DSN)
	cfg.MySQL.MaxIdleConns = getEnvInt("OPENIAM_MYSQL_MAX_IDLE_CONNS", cfg.MySQL.MaxIdleConns)
	cfg.MySQL.MaxOpenConns = getEnvInt("OPENIAM_MYSQL_MAX_OPEN_CONNS", cfg.MySQL.MaxOpenConns)
	cfg.MySQL.ConnMaxLifetimeMinutes = getEnvInt("OPENIAM_MYSQL_CONN_MAX_LIFETIME_MINUTES", cfg.MySQL.ConnMaxLifetimeMinutes)

	cfg.Redis.Addr = getEnv("OPENIAM_REDIS_ADDR", cfg.Redis.Addr)
	cfg.Redis.Password = getEnv("OPENIAM_REDIS_PASSWORD", cfg.Redis.Password)
	cfg.Redis.DB = getEnvInt("OPENIAM_REDIS_DB", cfg.Redis.DB)
	cfg.Redis.KeyPrefix = getEnv("OPENIAM_REDIS_KEY_PREFIX", cfg.Redis.KeyPrefix)

	cfg.Migration.AutoMigrate = getEnvBool("OPENIAM_AUTO_MIGRATE", cfg.Migration.AutoMigrate)
	cfg.Migration.StrictVersionCheck = getEnvBool("OPENIAM_STRICT_VERSION_CHECK", cfg.Migration.StrictVersionCheck)

	cfg.JWT.PrivateKeyPath = getEnv("OPENIAM_JWT_PRIVATE_KEY_PATH", cfg.JWT.PrivateKeyPath)

	cfg.Seed.Enabled = getEnvBool("OPENIAM_SEED_ENABLED", cfg.Seed.Enabled)
	cfg.Seed.AdminUsername = getEnv("OPENIAM_SEED_ADMIN_USERNAME", cfg.Seed.AdminUsername)
	cfg.Seed.AdminEmail = getEnv("OPENIAM_SEED_ADMIN_EMAIL", cfg.Seed.AdminEmail)
	cfg.Seed.AdminPassword = getEnv("OPENIAM_SEED_ADMIN_PASSWORD", cfg.Seed.AdminPassword)

	return cfg, nil
}

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k != "" && os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func getEnvInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
			return b
		}
	}
	return fallback
}
