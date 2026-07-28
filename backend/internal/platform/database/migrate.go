package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

var migrationFilePattern = regexp.MustCompile(`^(\d+)_.+\.up\.sql$`)

type migration struct {
	version int64
	path    string
}

func RunMigrations(db *sql.DB, dir string) (int, error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT NOT NULL PRIMARY KEY,
		applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
	)`); err != nil {
		return 0, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	var current int64
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&current); err != nil {
		return 0, fmt.Errorf("read current version: %w", err)
	}

	pending, err := loadMigrations(dir, current)
	if err != nil {
		return 0, err
	}

	for _, m := range pending {
		statement, err := os.ReadFile(m.path)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", m.path, err)
		}
		if _, err := db.Exec(string(statement)); err != nil {
			return 0, fmt.Errorf("apply migration %d: %w", m.version, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, m.version); err != nil {
			return 0, fmt.Errorf("record migration %d: %w", m.version, err)
		}
		fmt.Printf("applied migration %d (%s)\n", m.version, filepath.Base(m.path))
	}

	return len(pending), nil
}

func loadMigrations(dir string, current int64) ([]migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	var migrations []migration
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := migrationFilePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		version, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse version from %s: %w", entry.Name(), err)
		}
		if version <= current {
			continue
		}
		migrations = append(migrations, migration{version: version, path: filepath.Join(dir, entry.Name())})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	return migrations, nil
}
