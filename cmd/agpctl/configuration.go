package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/runtime"
)

func configurationProfile(args []string) error {
	f := flag.NewFlagSet("configuration-profile", flag.ContinueOnError)
	activate := f.Bool("activate", false, "persist canonical-only authoring and fence legacy resource writes; CP must be stopped")
	preview := f.Bool("preview", false, "read persisted profile without activation")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || (*activate && *preview) {
		return errors.New("use --preview or --activate")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.ConfigurationEnabled || !cfg.SecureProfile || cfg.DatabaseDriver != "postgres" {
		return errors.New("configuration profile requires AGP_CONFIGURATION_ENABLED=true, activated secure identity and PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer base.Close()
	if !*activate {
		p, e := configuration.InspectProfile(ctx, base)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	if err = base.Migrate(ctx); err != nil {
		return err
	}
	if err = base.CheckSessionProfile(ctx, cfg.SessionProfile()); err != nil {
		return err
	}
	identity, err := runtime.OpenIdentityRuntime(ctx, base, cfg.SessionProfile())
	if err != nil {
		return err
	}
	defer identity.Close()
	options, err := runtime.CompilerOptions(cfg.ManagementOrigin, cfg.LoginOrigin)
	if err != nil {
		return err
	}
	service := configuration.New(identity.Coordinator, cfg.ManagementOrigin, options)
	if err = service.Activate(ctx); err != nil {
		return err
	}
	p, err := configuration.InspectProfile(ctx, base)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(p)
}
