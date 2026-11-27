package oauthplugin_test

import (
	"github.com/glebarez/sqlite"
	"github.com/openrealm/openiam/internal/oauthplugin"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	// 测试使用本机 httptest 服务器作为 Mock 身份源，需要允许回环地址
	oauthplugin.SetAllowPrivateUpstream(true)
}

func gormOpenMemory() (*gorm.DB, error) {
	return gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}
