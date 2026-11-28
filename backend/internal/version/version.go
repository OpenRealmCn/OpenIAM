package version

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/migrations"
	"gorm.io/gorm"
)

const (
	AppVersion            = "0.1.0"
	ExpectedSchemaVersion = uint(8)
)

// Status 描述当前应用版本与数据库 Schema 版本状态。
type Status struct {
	AppVersion            string    `json:"app_version"`
	ExpectedSchemaVersion uint      `json:"expected_schema_version"`
	CurrentSchemaVersion  uint      `json:"current_schema_version"`
	Dirty                 bool      `json:"dirty"`
	UpToDate              bool      `json:"up_to_date"`
	CheckedAt             time.Time `json:"checked_at"`
	Message               string    `json:"message"`
}

// newIsolatedMigrator 使用独立数据库连接创建 migrate 实例，调用方务必 defer m.Close()，
// 避免与 GORM 连接池共享导致连接或 MySQL 锁泄漏。
func newIsolatedMigrator(dsn string) (*migrate.Migrate, error) {
	sourceDriver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("create iofs migration source: %w", err)
	}
	rawDB, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql for migration: %w", err)
	}
	dbDriver, err := mysql.WithInstance(rawDB, &mysql.Config{})
	if err != nil {
		_ = rawDB.Close()
		return nil, fmt.Errorf("create mysql migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "mysql", dbDriver)
	if err != nil {
		_ = rawDB.Close()
		return nil, fmt.Errorf("create migrate instance: %w", err)
	}
	return m, nil
}

// CheckMySQLVersion 检查 MySQL 当前 schema 版本并与 ExpectedSchemaVersion 比对。
func CheckMySQLVersion(db *gorm.DB, dsn string, strict bool) (*Status, error) {
	m, err := newIsolatedMigrator(dsn)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = m.Close() }()

	ver, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		ver = 0
		dirty = false
	} else if err != nil {
		return nil, fmt.Errorf("read schema version: %w", err)
	}

	status := buildStatus(ver, dirty)
	recordHistory(db, ver, "version_check", boolToStatus(status.UpToDate), status.Message)

	if strict && !status.UpToDate {
		return status, errors.New(status.Message)
	}
	return status, nil
}

// MigrateMySQLUp 将 MySQL Schema 升级至最新版本并记录历史。
func MigrateMySQLUp(db *gorm.DB, dsn string) (*Status, error) {
	m, err := newIsolatedMigrator(dsn)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = m.Close() }()

	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		ver, _, _ := m.Version()
		recordHistory(db, ver, "migrate_up", "failed", err.Error())
		return nil, fmt.Errorf("migrate up failed: %w", err)
	}

	ver, dirty, vErr := m.Version()
	if errors.Is(vErr, migrate.ErrNilVersion) {
		ver = 0
	} else if vErr != nil {
		return nil, vErr
	}

	msg := "数据库已处于最新版本"
	if err == nil {
		msg = fmt.Sprintf("数据库成功升级至 v%d", ver)
	}
	recordHistory(db, ver, "migrate_up", "success", msg)

	return &Status{
		AppVersion:            AppVersion,
		ExpectedSchemaVersion: ExpectedSchemaVersion,
		CurrentSchemaVersion:  ver,
		Dirty:                 dirty,
		UpToDate:              !dirty && ver == ExpectedSchemaVersion,
		CheckedAt:             time.Now(),
		Message:               msg,
	}, nil
}

// AutoMigrateForTesting 仅用于 SQLite 测试环境自动建表与记录版本。
func AutoMigrateForTesting(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&models.Domain{},
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.OAuthClient{},
		&models.OAuthProvider{},
		&models.UserIdentity{},
		&models.AuditLog{},
		&models.SystemVersionHistory{},
		&models.SystemSetting{},
		&models.UserPasskey{},
		&models.UserTOTP{},
		&models.UserSession{},
		&models.Notification{},
		&models.NotificationTemplate{},
		&models.NotificationDelivery{},
		&models.RiskEvent{},
		&models.TempRoleGrant{},
		&models.PluginInstance{},
	); err != nil {
		return err
	}
	recordHistory(db, ExpectedSchemaVersion, "test_automigrate", "success", "测试环境初始化表结构")
	return nil
}

// GetVersionStatus 轻量查询当前数据库版本状态（直接读取 schema_migrations 表，避免额外建立迁移连接）。
func GetVersionStatus(db *gorm.DB) (*Status, error) {
	if db.Dialector.Name() == "mysql" {
		var row struct {
			Version uint `gorm:"column:version"`
			Dirty   bool `gorm:"column:dirty"`
		}
		if err := db.Table("schema_migrations").Select("version, dirty").Limit(1).Scan(&row).Error; err == nil {
			return buildStatus(row.Version, row.Dirty), nil
		}
	}

	var latest models.SystemVersionHistory
	err := db.Order("id DESC").First(&latest).Error
	ver := ExpectedSchemaVersion
	if err == nil {
		ver = uint(latest.SchemaVersion)
	}
	return &Status{
		AppVersion:            AppVersion,
		ExpectedSchemaVersion: ExpectedSchemaVersion,
		CurrentSchemaVersion:  ver,
		Dirty:                 false,
		UpToDate:              ver == ExpectedSchemaVersion,
		CheckedAt:             time.Now(),
		Message:               fmt.Sprintf("当前运行于 %s 驱动 (v%d)", db.Dialector.Name(), ver),
	}, nil
}

func buildStatus(ver uint, dirty bool) *Status {
	status := &Status{
		AppVersion:            AppVersion,
		ExpectedSchemaVersion: ExpectedSchemaVersion,
		CurrentSchemaVersion:  ver,
		Dirty:                 dirty,
		UpToDate:              !dirty && ver == ExpectedSchemaVersion,
		CheckedAt:             time.Now(),
	}
	switch {
	case dirty:
		status.Message = fmt.Sprintf("数据库迁移处于 dirty 状态 (version=%d)，请人工修复后重试", ver)
	case ver < ExpectedSchemaVersion:
		status.Message = fmt.Sprintf("数据库版本落后: 当前 v%d, 期望 v%d，需要执行升级迁移", ver, ExpectedSchemaVersion)
	case ver > ExpectedSchemaVersion:
		status.Message = fmt.Sprintf("数据库版本高于当前程序: 当前 v%d, 期望 v%d", ver, ExpectedSchemaVersion)
	default:
		status.Message = fmt.Sprintf("数据库版本校验通过 (v%d)", ver)
	}
	return status
}

func recordHistory(db *gorm.DB, schemaVersion uint, action, status, details string) {
	if db == nil || !db.Migrator().HasTable(&models.SystemVersionHistory{}) {
		return
	}
	_ = db.Create(&models.SystemVersionHistory{
		AppVersion:    AppVersion,
		SchemaVersion: uint64(schemaVersion),
		Action:        action,
		Status:        status,
		Details:       details,
	}).Error
}

func boolToStatus(ok bool) string {
	if ok {
		return "success"
	}
	return "mismatch"
}
