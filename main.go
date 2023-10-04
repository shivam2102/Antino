package main

import (
	"Assignment/database"
	"Assignment/server"
	"github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	srv := server.SrvInit()
	go srv.Start()

	err := database.MigrateStart(srv.PSQL.DB())
	if err != nil {
		logrus.Errorf("error in migration running: %v", err)
	}
	<-done
	logrus.Info("Graceful shutdown")
	srv.Stop()
}
