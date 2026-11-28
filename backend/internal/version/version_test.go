package version

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationsMatchExpectedSchemaVersion(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err)

	upFiles := 0
	downFiles := 0
	var allUpSQL strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > 7 && name[len(name)-7:] == ".up.sql" {
			upFiles++
			b, readErr := migrations.FS.ReadFile(name)
			require.NoError(t, readErr)
			allUpSQL.Write(b)
			allUpSQL.WriteString("\n")
		}
		if len(name) > 9 && name[len(name)-9:] == ".down.sql" {
			downFiles++
		}
	}

	assert.Equal(t, int(ExpectedSchemaVersion), upFiles, "up migration count should match ExpectedSchemaVersion")
	assert.Equal(t, upFiles, downFiles, "every up migration must have a matching down migration")

	expectedPrefix := fmt.Sprintf("%06d_", ExpectedSchemaVersion)
	foundLatest := false
	for _, entry := range entries {
		if len(entry.Name()) >= len(expectedPrefix) && entry.Name()[:len(expectedPrefix)] == expectedPrefix {
			foundLatest = true
			break
		}
	}
	assert.True(t, foundLatest, "latest migration file for ExpectedSchemaVersion should exist")

	// 确保所有 GORM 模型的表名都在 SQL 迁移脚本中存在对应的 CREATE TABLE
	sqlText := allUpSQL.String()
	tableNames := []string{
		models.Domain{}.TableName(),
		models.User{}.TableName(),
		models.Role{}.TableName(),
		models.Permission{}.TableName(),
		models.OAuthClient{}.TableName(),
		models.OAuthProvider{}.TableName(),
		models.UserIdentity{}.TableName(),
		models.AuditLog{}.TableName(),
		models.SystemVersionHistory{}.TableName(),
		models.SystemSetting{}.TableName(),
		models.UserPasskey{}.TableName(),
	}
	for _, tbl := range tableNames {
		assert.Contains(t, sqlText, "CREATE TABLE IF NOT EXISTS "+tbl, "migration SQL missing table %s", tbl)
	}
}
