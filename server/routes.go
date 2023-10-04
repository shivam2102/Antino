package server

import (
	"github.com/go-chi/chi"
)

func (srv *Server) InjectRoutes() *chi.Mux {
	r := chi.NewRouter()

	r.Route("/api", func(api chi.Router) {
		api.Use(srv.Middlewares.Default()...)
		api.Route("/admin", func(admin chi.Router) {
			admin.Post("/login", srv.login)
			admin.Route("/", func(admin chi.Router) {
				admin.Use(srv.Middlewares.AUTH()...)
				admin.Get("/create_token", srv.GenerateToken())
				admin.Delete("/disable_token/{tokenID}", srv.disableToken)
				admin.Get("/tokens", srv.GetTokens)

			})
		})

		api.Post("/verify", srv.VerifyUser)
	})
	return r
}
