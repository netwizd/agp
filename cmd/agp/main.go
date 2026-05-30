package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/httpapi"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		info := version.Info()
		fmt.Printf("agp %s commit=%s built_at=%s go=%s\n", info["version"], info["commit"], info["built_at"], info["go_version"])
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		logger.Error("storage open failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("storage close failed", "error", err)
		}
	}()

	if err := store.Migrate(ctx); err != nil {
		logger.Error("storage migration failed", "error", err)
		os.Exit(1)
	}
	if err := store.ApplyRetention(ctx, time.Now().UTC(), cfg.AuditRetention, cfg.SessionRetention); err != nil {
		logger.Error("storage retention cleanup failed", "error", err)
		os.Exit(1)
	}

	api := httpapi.NewServer(cfg, store, logger)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("agp backend started", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("http server graceful shutdown failed", "error", err)
			os.Exit(1)
		}
		logger.Info("agp backend stopped")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}
}
