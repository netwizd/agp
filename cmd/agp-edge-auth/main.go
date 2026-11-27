package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/edgeauth"
)

func run() error {
	configFile := flag.String("config", "", "private immutable EdgeAuth JSON configuration")
	flag.Parse()
	if *configFile == "" {
		return fmt.Errorf("-config is required")
	}
	f, err := os.Open(*configFile)
	if err != nil {
		return err
	}
	defer f.Close()
	var cfg edgeauth.Config
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&cfg); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing configuration data")
	}
	if err = cfg.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(cfg.SocketPath) || len(cfg.SocketPath) > 100 {
		return fmt.Errorf("socket path must be absolute and fit a Unix socket")
	}
	parent, err := os.Stat(filepath.Dir(cfg.SocketPath))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("socket directory must not be writable by other accounts")
	}
	// Never unlink an existing listener: starting another node must not steal
	// a running node's endpoint. RuntimeDirectory cleanup belongs to the service.
	if _, err = os.Lstat(cfg.SocketPath); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("socket path exists or cannot be inspected")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	state, err := edgeauth.OpenStateStore(ctx, cfg.StatePath)
	if err != nil {
		return err
	}
	defer state.Close()
	central, err := edgeauth.NewClient(cfg)
	if err != nil {
		return err
	}
	defer central.Close()
	edge, err := edgeauth.NewServer(cfg, state, central)
	if err != nil {
		return err
	}
	defer edge.Close()
	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(cfg.SocketPath)
	if err = os.Chmod(cfg.SocketPath, 0660); err != nil {
		return err
	}
	server := &http.Server{Handler: edge.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	slog.Info("EdgeAuth started", "node", cfg.NodeID, "gateway", cfg.GatewayID, "generation", cfg.DeploymentGeneration)
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
func main() {
	if err := run(); err != nil {
		slog.Error("EdgeAuth stopped", "error", err)
		os.Exit(1)
	}
}
