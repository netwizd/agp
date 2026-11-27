package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/runtime"
)

func configurationAccess(args []string) error {
	f := flag.NewFlagSet("configuration-access", flag.ContinueOnError)
	path := f.String("bootstrap-manifest", "", "initial pre-secure scoped access manifest; CP must be stopped")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *path == "" {
		return errors.New("use --bootstrap-manifest PATH before secure activation")
	}
	cfg, e := config.Load()
	if e != nil {
		return e
	}
	if cfg.DatabaseDriver != "postgres" {
		return errors.New("scoped bootstrap requires PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	file, e := os.Open(*path)
	if e != nil {
		return e
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, (20<<20)+1))
	if e != nil {
		return e
	}
	if len(raw) > 20<<20 {
		return errors.New("bootstrap manifest too large")
	}
	var m configuration.BootstrapManifest
	if e = configmodel.DecodeEnvelopeJSONWithArrayLimits(bytes.TrimSpace(raw), &m, map[string]int{"/scopeGraph/resources": 100000, "/scopeGraph/resourceRoutes": 100000}); e != nil {
		return e
	}
	store, e := runtime.OpenStore(ctx, cfg)
	if e != nil {
		return e
	}
	defer store.Close()
	if e = store.Migrate(ctx); e != nil {
		return e
	}
	release, e := acquireIdentityLease(ctx, store)
	if e != nil {
		return e
	}
	defer release()
	client, e := runtime.OpenJournalClient()
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	head, e := client.Head(ctx)
	if e != nil {
		return e
	}
	if e = configuration.BootstrapAccess(ctx, store, int64(head.Epoch), m); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"bootstrapped": true, "authorityEpoch": head.Epoch, "grantCount": len(m.Grants), "ownershipCount": len(m.Ownership)})
}
