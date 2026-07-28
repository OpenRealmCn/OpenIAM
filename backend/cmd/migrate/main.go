package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/database"
)

func main() {
	var migrationsDir string
	flag.StringVar(&migrationsDir, "dir", "migrations", "path to the migrations directory")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := sql.Open("mysql", withMultiStatements(cfg.Database.DSN))
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	absDir, err := filepath.Abs(migrationsDir)
	if err != nil {
		log.Fatalf("resolve migrations dir: %v", err)
	}

	applied, err := database.RunMigrations(db, absDir)
	if err != nil {
		log.Fatalf("run migrations: %v", err)
	}

	if applied == 0 {
		fmt.Println("database schema is up to date")
		return
	}
	fmt.Printf("applied %d migration(s)\n", applied)
}

func withMultiStatements(dsn string) string {
	base := dsn
	query := ""
	if idx := strings.Index(dsn, "?"); idx >= 0 {
		base = dsn[:idx]
		query = dsn[idx+1:]
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: parse dsn query: %v\n", err)
		return dsn + "&multiStatements=true"
	}
	values.Set("multiStatements", "true")
	values.Set("parseTime", "true")

	return base + "?" + values.Encode()
}
