package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
	_ "time/tzdata"

	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/database"
	"github.com/openrealm/openiam/internal/jit"
	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"github.com/openrealm/openiam/internal/oauthserver"
	"github.com/openrealm/openiam/internal/otp"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/risk"
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

	// 初始口令保护：本函数此前只是定义、从未被调用，导致「release 模式拒绝弱初始口令」实际没生效。
	// 现在在初始化管理员之前强制检查：release 模式下弱口令直接拒绝启动，其它模式只告警。
	if cfg.Seed.Enabled && isWeakSeedPassword(cfg.Seed.AdminPassword) {
		if cfg.Server.Mode == "release" {
			logger.Fatal("refusing to start: OPENIAM_SEED_ADMIN_PASSWORD is empty or a publicly known default password",
				zap.String("mode", cfg.Server.Mode))
		}
		logger.Warn("seed admin password is empty or a publicly known default password; set OPENIAM_SEED_ADMIN_PASSWORD before production")
	}

	if err := seed.EnsureDefaults(db, enforcer, cfg.Seed, stateStore); err != nil {
		logger.Fatal("failed to seed default data", zap.Error(err))
	}

	auditSvc := audit.NewService(db, logger)
	mailerSvc := mailer.NewService(settingsSvc)
	pluginMgr := plugins.NewManager(db, stateStore, settingsSvc)
	if err := pluginMgr.EnsureDefaults(); err != nil {
		logger.Fatal("failed to initialize plugin defaults", zap.Error(err))
	}
	notifySvc := notify.NewService(db, mailerSvc, enforcer, pluginMgr)
	if err := notifySvc.EnsureDefaultTemplates(); err != nil {
		logger.Fatal("failed to seed notification templates", zap.Error(err))
	}
	otpSvc := otp.NewService(db, stateStore, settingsSvc, mailerSvc, notifySvc, pluginMgr)
	riskEngine := risk.NewEngine(db, stateStore, settingsSvc, notifySvc, auditSvc)
	jitSvc := jit.NewService(db, enforcer, notifySvc, auditSvc, logger)

	schedCtx, cancelSched := context.WithCancel(context.Background())
	defer cancelSched()
	jitSvc.StartScheduler(schedCtx, 30*time.Second)

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
		MailerSvc:   mailerSvc,
		PluginSvc:   pluginSvc,
		OAuthSrv:    oauthSrv,
		PluginMgr:   pluginMgr,
		NotifySvc:   notifySvc,
		OTPSvc:      otpSvc,
		RiskEngine:  riskEngine,
		JITSvc:      jitSvc,
	})
	if err != nil {
		logger.Fatal("failed to setup router", zap.Error(err))
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("OpenIAM server starting",
		zap.String("addr", addr),
		zap.String("app_version", version.AppVersion),
	)
	srv := &http.Server{
		Addr:              addr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}
