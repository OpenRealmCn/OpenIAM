package version

import (
	"fmt"
	"testing"

	"github.com/openrealm/openiam/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationsMatchExpectedSchemaVersion(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err)

	upFiles := 0
	downFiles := 0
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > 7 && name[len(name)-7:] == ".up.sql" {
			upFiles++
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
}
