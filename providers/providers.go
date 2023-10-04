package providers

import (
	"Assignment/models"
	"github.com/go-chi/chi"
	"github.com/jmoiron/sqlx"
	"net/http"
)

type DBProvider interface {
	Ping() error
	PSQLProvider
}

type PSQLProvider interface {
	DB() *sqlx.DB
}

type ConfigProvider interface {
	Read()
	GetString(key string) string
	GetInt(key string) int
	GetAny(key string) interface{}
	GetServerPort() string
}

type CacheProvider interface {
	Get(key string) (string, error)
	Set(key string, value interface{}) error
	Delete(key string) int64
}

type MiddlewareProvider interface {
	GetUserContext(req *http.Request) *models.UserContext
	AUTH() chi.Middlewares
	Default() chi.Middlewares
}
