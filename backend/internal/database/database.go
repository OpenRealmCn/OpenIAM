package database

import (
	"context"
	"fmt"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/openrealm/openiam/internal/config"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NormalizeMySQLDSN 自动补全连接/读写超时与 parseTime，防止因防火墙 DROP 导致启动无限卡死。
// 业务连接池强制关闭 multiStatements：一旦出现 SQL 注入，多语句模式会把影响从读数据放大为任意写入；
// 迁移所需的多语句能力只在迁移器的独立连接上开启（见 version.newIsolatedMigrator）。
func NormalizeMySQLDSN(rawDSN string) (string, string, error) {
	parsed, err := mysqldriver.ParseDSN(rawDSN)
	if err != nil {
		return rawDSN, rawDSN, fmt.Errorf("invalid mysql dsn: %w", err)
	}
	if parsed.Timeout == 0 {
		parsed.Timeout = 5 * time.Second
	}
	if parsed.ReadTimeout == 0 {
		parsed.ReadTimeout = 15 * time.Second
	}
	if parsed.WriteTimeout == 0 {
		parsed.WriteTimeout = 15 * time.Second
	}
	parsed.ParseTime = true
	parsed.MultiStatements = false

	safeAddr := fmt.Sprintf("%s/%s", parsed.Addr, parsed.DBName)
	return parsed.FormatDSN(), safeAddr, nil
}

// InitMySQL 初始化 MySQL 连接并配置连接池参数。
func InitMySQL(cfg config.MySQLConfig, debug bool) (*gorm.DB, string, error) {
	dsn, _, err := NormalizeMySQLDSN(cfg.DSN)
	if err != nil {
		return nil, "", err
	}

	logLevel := logger.Warn
	if debug {
		logLevel = logger.Info
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, "", fmt.Errorf("connect mysql: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, "", fmt.Errorf("unwrap sql.DB: %w", err)
	}
	if cfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.ConnMaxLifetimeMinutes > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, "", fmt.Errorf("ping mysql: %w", err)
	}

	return db, dsn, nil
}

// InitRedis 初始化 Redis 客户端并校验连通性。
func InitRedis(cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return client, nil
}
