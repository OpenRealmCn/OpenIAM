package main

import (
	"flag"
	"fmt"
	"os"
	_ "time/tzdata"

	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/database"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/oauthserver"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/router"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/seed"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/openrealm/openiam/internal/version"
	"go.uber.org/zap"
)

func main() {
	envFile := flag.String("env-file", "", "optional path to .env file for bootstrap MySQL/Redis connection")
	migrateOnly := flag.Bool("migrate-only", false, "run database migrations and exit")
	checkVersion := flag.Bool("check-version", false, "check database schema version against app version and exit")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	cfg, err := config.Load(*envFile)
	if err != nil {
		logger.Fatal("failed to load bootstrap config", zap.Error(err))
	}
	if cfg.Server.Mode == "debug" {
		if devLog, err := zap.NewDevelopment(); err == nil {
			logger = devLog
		}
	}

	_, safeMySQLTarget, _ := database.NormalizeMySQLDSN(cfg.MySQL.DSN)
	logger.Info("bootstrapping OpenIAM",
		zap.String("app_version", version.AppVersion),
		zap.String("mode", cfg.Server.Mode),
		zap.String("mysql", safeMySQLTarget),
		zap.String("redis", cfg.Redis.Addr),
	)

	db, normalizedDSN, err := database.InitMySQL(cfg.MySQL, cfg.Server.Mode == "debug")
	if err != nil {
		logger.Fatal("failed to initialize MySQL", zap.String("mysql", safeMySQLTarget), zap.Error(err))
	}
	logger.Info("MySQL connected", zap.String("mysql", safeMySQLTarget))

	// 数据库迁移与版本检查
	if *migrateOnly {
		status, err := version.MigrateMySQLUp(db, normalizedDSN)
		if err != nil {
			logger.Fatal("database migration failed", zap.Error(err))
		}
		logger.Info("database migration finished",
			zap.String("app_version", status.AppVersion),
			zap.Uint("schema_version", status.CurrentSchemaVersion),
			zap.String("message", status.Message),
		)
		os.Exit(0)
	}

	if *checkVersion {
		status, err := version.CheckMySQLVersion(db, normalizedDSN, cfg.Migration.StrictVersionCheck)
		if err != nil {
			logger.Fatal("database version check failed", zap.Error(err))
		}
		logger.Info("database version check passed",
			zap.String("app_version", status.AppVersion),
			zap.Uint("schema_version", status.CurrentSchemaVersion),
			zap.String("message", status.Message),
		)
		os.Exit(0)
	}

	if cfg.Migration.AutoMigrate {
		logger.Info("running database auto-migration...")
		status, err := version.MigrateMySQLUp(db, normalizedDSN)
		if err != nil {
			logger.Fatal("auto migration failed", zap.Error(err))
		}
		logger.Info("auto migration completed", zap.Uint("schema_version", status.CurrentSchemaVersion))
	}

	if _, err := version.CheckMySQLVersion(db, normalizedDSN, cfg.Migration.StrictVersionCheck); err != nil {
		logger.Fatal("database schema version mismatch", zap.Error(err))
	}

	logger.Info("connecting to Redis...", zap.String("redis", cfg.Redis.Addr))
	rdb, err := database.InitRedis(cfg.Redis)
	if err != nil {
		logger.Fatal("failed to initialize Redis", zap.String("redis", cfg.Redis.Addr), zap.Error(err))
	}
	defer func() { _ = rdb.Close() }()
	logger.Info("Redis connected", zap.String("redis", cfg.Redis.Addr))

	// 从数据库初始化与加载系统运行时配置
	settingsSvc, err := settings.NewService(db)
	if err != nil {
		logger.Fatal("failed to initialize database system settings", zap.Error(err))
	}
	snap := settingsSvc.Snapshot()

	jwtMgr, err := security.NewJWTManager(
		snap.JWTIssuer,
		cfg.JWT.PrivateKeyPath,
		snap.JWTAccessTTL,
	)
	if err != nil {
		logger.Fatal("failed to initialize JWT manager", zap.Error(err))
	}

	stateStore := security.NewStateStore(rdb, cfg.Redis.KeyPrefix)

	enforcer, err := rbac.NewEnforcer(db)
	if err != nil {
		logger.Fatal("failed to initialize Casbin RBAC enforcer", zap.Error(err))
	}

	if err := seed.EnsureDefaults(db, enforcer, cfg.Seed); err != nil {
		logger.Fatal("failed to seed default data", zap.Error(err))
	}

	auditSvc := audit.NewService(db, logger)
	pluginReg := oauthplugin.NewDefaultRegistry()
	pluginSvc := oauthplugin.NewService(
		db,
		pluginReg,
		stateStore,
		jwtMgr,
		enforcer,
		auditSvc,
		settingsSvc,
	)
	oauthSrv := oauthserver.NewServer(db, rdb, stateStore, jwtMgr, auditSvc, settingsSvc)

	engine, err := router.Setup(router.Dependencies{
		Config:      cfg,
		DB:          db,
		Redis:       rdb,
		Logger:      logger,
		JWTManager:  jwtMgr,
		StateStore:  stateStore,
		Enforcer:    enforcer,
		AuditSvc:    auditSvc,
		SettingsSvc: settingsSvc,
		PluginSvc:   pluginSvc,
		OAuthSrv:    oauthSrv,
	})
	if err != nil {
		logger.Fatal("failed to setup router", zap.Error(err))
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("OpenIAM server starting",
		zap.String("addr", addr),
		zap.String("app_version", version.AppVersion),
	)
	if err := engine.Run(addr); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}
