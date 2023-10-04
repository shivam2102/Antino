package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"

	// load file driver to read migration files
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"

	// load pq as database driver
	_ "github.com/lib/pq"
)

var AssignmentDB *sqlx.DB

type SSLMode string

const (
	SSLModeEnable  SSLMode = "enable"
	SSLModeDisable SSLMode = "disable"
)

func MigrateStart(db *sqlx.DB) error {
	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
	if err != nil {
		return err
	}

	m, newErr := migrate.NewWithDatabaseInstance("file://database/migration/", "postgres", driver)
	if newErr != nil {
		return newErr
	}
	if migrateErr := m.Up(); migrateErr != nil && migrateErr != migrate.ErrNoChange {
		return migrateErr
	}

	return nil
}

// SetupBindVars prepares the SQL statement for batch insert
func SetupBindVars(stmt, bindVars string, length int) string {
	bindVars += ","
	stmt = fmt.Sprintf(stmt, strings.Repeat(bindVars, length))
	return replaceSQL(strings.TrimSuffix(stmt, ","), "?")
}

// replaceSQL replaces the instance occurrence of any string pattern with an increasing $n based sequence
func replaceSQL(old, searchPattern string) string {
	tmpCount := strings.Count(old, searchPattern)
	for m := 1; m <= tmpCount; m++ {
		old = strings.Replace(old, searchPattern, "$"+strconv.Itoa(m), 1)
	}
	return old
}

func findMigrationsFolderRoot() string {
	workingDirectory, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	lastDir := workingDirectory
	myUniqueRelativePath := "database/migrations"
	for {
		currentPath := fmt.Sprintf("%s/%s", lastDir, myUniqueRelativePath)
		fi, statErr := os.Stat(currentPath)
		if statErr == nil {
			mode := fi.Mode()
			if mode.IsDir() {
				return currentPath
			}
		}
		newDir := filepath.Dir(lastDir)
		if newDir == "/" || newDir == lastDir {
			return ""
		}
		lastDir = newDir
	}
}
