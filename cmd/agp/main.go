package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/httpapi"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nodeidentity"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		info := version.Info()
		fmt.Printf("agp %s commit=%s built_at=%s go=%s\n", info["version"], info["commit"], info["built_at"], info["go_version"])
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("agp stopped", "error", err)
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	store, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("storage open: %w", err)
	}
	defer store.Close()
	if err = store.Migrate(ctx); err != nil {
		return fmt.Errorf("storage migration: %w", err)
	}
	if err = configuration.CheckProfile(ctx, store, cfg.ConfigurationEnabled); err != nil {
		return fmt.Errorf("configuration profile: %w", err)
	}
	if err = store.CheckSessionProfile(ctx, cfg.SessionProfile()); err != nil {
		return fmt.Errorf("session profile activation required: %w", err)
	}
	apiStore := store
	var identityRuntime *runtime.IdentityRuntime
	if cfg.SecureProfile {
		identityRuntime, err = runtime.OpenIdentityRuntime(ctx, store, cfg.SessionProfile())
		if err != nil {
			return fmt.Errorf("secure identity startup: %w", err)
		}
		defer identityRuntime.Close()
		apiStore = identityRuntime.Store
	}
	resources, err := apiStore.ListResources(ctx)
	if err != nil {
		return fmt.Errorf("resource validation: %w", err)
	}
	for _, resource := range resources {
		if err = cfg.ValidateResourceHost(resource.PublicHost); err != nil {
			return fmt.Errorf("resource %s collides with a reserved origin: %w", resource.ID, err)
		}
	}
	if err = apiStore.ApplyRetention(ctx, time.Now().UTC(), cfg.AuditRetention, cfg.SessionRetention); err != nil {
		return fmt.Errorf("storage retention: %w", err)
	}
	api := httpapi.NewServer(cfg, apiStore, logger)
	if os.Getenv("AGP_EXECUTION_CONFIG") != "" && (!cfg.ConfigurationEnabled || identityRuntime == nil) {
		return runtime.ErrExecutionRuntime
	}
	var inventoryService *inventory.Service
	if identityRuntime != nil {
		api.SetIdentity(identityRuntime.Service)
		api.SetDirectory(identityRuntime.Directory)
		api.SetEmail(identityRuntime.Email)
		api.SetOIDC(identityRuntime.OIDC)
		if cfg.NodeIdentityConfig != "" {
			issuer, e := nodeidentity.LoadClientConfig(cfg.NodeIdentityConfig)
			if e != nil {
				return fmt.Errorf("node issuer trust configuration: %w", e)
			}
			defer issuer.CloseIdleConnections()
			inventoryService, err = inventory.NewWithRegistry(identityRuntime.Coordinator, identityRuntime.Journal, issuer)
			if err != nil {
				return fmt.Errorf("managed agent inventory: %w", err)
			}
			identities, e := nodeidentity.New(identityRuntime.Coordinator, issuer, inventoryService, cfg.ManagementOrigin)
			if e != nil {
				return fmt.Errorf("managed node identity: %w", e)
			}
			api.SetNodeIdentity(identities)
			api.SetInventory(inventoryService)
		} else if cfg.AgentRegistryFile != "" {
			inventoryService, err = inventory.New(identityRuntime.Coordinator, identityRuntime.Journal, cfg.AgentRegistryFile)
			if err != nil {
				return fmt.Errorf("agent inventory: %w", err)
			}
			api.SetInventory(inventoryService)
		}
		if cfg.ConfigurationEnabled {
			options, e := runtime.CompilerOptions(cfg.ManagementOrigin, cfg.LoginOrigin)
			if e != nil {
				return fmt.Errorf("compiler identity: %w", e)
			}
			service := configuration.New(identityRuntime.Coordinator, cfg.ManagementOrigin, options).WithDirectorySubjects(identityRuntime.Directory)
			if e = runtime.ConfigurePlanReviewSigner(service, cfg.PlanReviewKeyID, cfg.PlanReviewKeyFile); e != nil {
				return e
			}
			provider, e := runtime.OpenWAFProvider(identityRuntime.Journal, options)
			if e != nil {
				return fmt.Errorf("WAF trust configuration: %w", e)
			}
			if provider != nil {
				service.WithWAFQualifier(provider)
				if inventoryService != nil {
					service.WithTrustedInventory(&runtime.TrustedInventory{Inventory: inventoryService, Provider: provider})
				}
			}
			api.SetConfiguration(service)
			execution, e := runtime.OpenExecutionRuntime(ctx, identityRuntime, inventoryService, cfg.ManagementOrigin)
			if e != nil {
				return fmt.Errorf("execution runtime: %w", e)
			}
			if execution != nil {
				defer execution.Close()
				api.SetExecution(execution.Service)
				api.SetExecutionBaselines(execution.Sources)
			}
		}
	}
	public := &http.Server{Addr: cfg.HTTPAddr, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	servers := []*http.Server{public}
	var edge *http.Server
	if cfg.SecureProfile {
		tlsConfig, e := securityjournal.LoadServerTLS(cfg.AuthMTLSCertFile, cfg.AuthMTLSKeyFile, cfg.AuthMTLSClientCAFile)
		if e != nil {
			return fmt.Errorf("central auth mTLS: %w", e)
		}
		edge = &http.Server{Addr: cfg.AuthMTLSAddr, Handler: api.EdgeHandler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, edge)
	}
	var agent *http.Server
	if inventoryService != nil {
		tlsConfig, e := securityjournal.LoadServerTLS(cfg.AgentMTLSCertFile, cfg.AgentMTLSKeyFile, cfg.AgentMTLSClientCAFile)
		if e != nil {
			return fmt.Errorf("agent inventory mTLS: %w", e)
		}
		agent = &http.Server{Addr: cfg.AgentMTLSAddr, Handler: api.AgentHandler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, agent)
	}
	var enrollment *http.Server
	if cfg.NodeIdentityConfig != "" {
		tlsConfig, e := runtime.EnrollmentTLS(cfg)
		if e != nil {
			return fmt.Errorf("enrollment TLS: %w", e)
		}
		enrollment = &http.Server{Addr: cfg.EnrollmentTLSAddr, Handler: api.EnrollmentHandler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, enrollment)
	}
	errCh := make(chan error, len(servers))
	go func() {
		logger.Info("agp backend started", "addr", cfg.HTTPAddr, "secure_profile", cfg.SecureProfile)
		errCh <- public.ListenAndServe()
	}()
	if edge != nil {
		go func() {
			logger.Info("central auth mTLS started", "addr", cfg.AuthMTLSAddr)
			errCh <- edge.ListenAndServeTLS("", "")
		}()
	}
	if agent != nil {
		go func() {
			logger.Info("agent inventory mTLS started", "addr", cfg.AgentMTLSAddr)
			errCh <- agent.ListenAndServeTLS("", "")
		}()
	}
	if enrollment != nil {
		go func() {
			logger.Info("node enrollment TLS started", "addr", cfg.EnrollmentTLSAddr)
			errCh <- enrollment.ListenAndServeTLS("", "")
		}()
	}
	select {
	case <-ctx.Done():
	case err = <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	for _, server := range servers {
		if e := server.Shutdown(shutdown); e != nil {
			_ = server.Close()
			if err == nil {
				err = e
			}
		}
	}
	logger.Info("agp backend stopped")
	return err
}
