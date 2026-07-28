package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openrealm/openiam/backend/internal/bootstrap"
	"github.com/openrealm/openiam/backend/internal/platform/cache"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/database"
	"github.com/openrealm/openiam/backend/internal/platform/httpserver"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	log, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer func() { _ = log.Sync() }()

	db, err := database.Open(cfg.Database)
	if err != nil {
		log.Fatal("connect to MySQL", zap.Error(err))
	}

	redisClient := cache.Open(cfg.Redis)
	defer redisClient.Close()

	router := httpserver.NewRouter(cfg.HTTP, log)
	app := bootstrap.New(router, cfg, db, redisClient, log)

	server := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           app.Router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	go func() {
		log.Info("HTTP server started", zap.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("HTTP server failed", zap.Error(err))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error("HTTP server shutdown", zap.Error(err))
	}
}
