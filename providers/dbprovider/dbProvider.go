package dbprovider

import (
	"Assignment/providers"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"time"
)

type psqlProvider struct {
	db *sqlx.DB
}

func NewPSQLProvider(connectionString string, maxConnections, maxIdleConnections int) providers.DBProvider {
	var (
		db          *sqlx.DB
		err         error
		maxAttempts = 3
	)

	for i := 0; i < maxAttempts; i++ {
		db, err = sqlx.Connect("postgres", connectionString)
		if err != nil {
			logrus.Errorf("unable to connect to postgres PSQL %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		db.SetMaxOpenConns(maxConnections)
		db.SetMaxIdleConns(maxIdleConnections)
		break
	}

	if err != nil {
		logrus.Fatalf("Failed to initialize PSQL: %v", err)
	}

	return &psqlProvider{
		db: db,
	}
}

func (pp *psqlProvider) Ping() error {
	return pp.db.Ping()
}

func (pp *psqlProvider) DB() *sqlx.DB {
	return pp.db
}
