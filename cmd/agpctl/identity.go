package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func identityProfile(args []string) error {
	f := flag.NewFlagSet("identity-profile", flag.ContinueOnError)
	activate := f.Bool("activate", false, "activate the PostgreSQL local-MFA and independent-journal profile")
	preview := f.Bool("preview", false, "preview activation without writes")
	revoke := f.Bool("revoke-sessions", false, "explicitly revoke every existing session")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || (*activate && *preview) || (*revoke && !*activate) || (*activate && !*revoke) {
		return errors.New("use --preview or --activate --revoke-sessions")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.SecureProfile || cfg.DatabaseDriver != "postgres" {
		return errors.New("identity activation requires AGP_SECURE_PROFILE=true and PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer base.Close()
	client, err := runtime.OpenJournalClient()
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	if !*activate {
		h, err := client.Head(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"profile": cfg.SessionProfile(), "fingerprint": cfg.SessionProfile().Fingerprint(), "authority": h, "activated": false})
	}
	if _, err = identity.LoadKeyring(cfg.MFAKeyFile); err != nil {
		return err
	}
	if err = base.Migrate(ctx); err != nil {
		return err
	}
	release, err := acquireIdentityLease(ctx, base)
	if err != nil {
		return err
	}
	defer release()
	var admins []string
	if err = base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		var e error
		admins, e = securitystate.Strings(ctx, tx, `SELECT id FROM users WHERE is_admin=? AND blocked_at IS NULL`, true)
		return e
	}); err != nil {
		return err
	}
	if len(admins) == 0 {
		return errors.New("create a local bootstrap administrator before activation")
	}
	coord := securitystate.New(base, client)
	profile := cfg.SessionProfile()
	if err = coord.ActivateProfile(ctx, &profile); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"profile": profile, "fingerprint": profile.Fingerprint(), "activated": true, "sessions_revoked": true})
}
func acquireIdentityLease(ctx context.Context, s storage.Store) (func(), error) {
	lease, ok := s.(interface {
		AcquireIdentityLease(context.Context) (func(), error)
	})
	if !ok {
		return nil, errors.New("PostgreSQL identity writer lease unavailable")
	}
	return lease.AcquireIdentityLease(ctx)
}
func gatewayRegister(args []string) error {
	f := flag.NewFlagSet("gateway-register", flag.ContinueOnError)
	id := f.String("id", "", "stable gateway ID")
	node := f.String("node", "", "mTLS node ID")
	origin := f.String("origin", "", "canonical HTTPS app origin")
	callback := f.String("callback", "", "exact app callback URI")
	resource := f.String("resource", "", "resource/route ID")
	generation := f.String("generation", "", "deployment generation")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *id == "" || *node == "" || *origin == "" || *callback == "" || *resource == "" || *generation == "" {
		return errors.New("gateway-register requires --id --node --origin --callback --resource --generation")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.SecureProfile {
		return errors.New("gateway registry requires activated secure profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer base.Close()
	if err = base.CheckSessionProfile(ctx, cfg.SessionProfile()); err != nil {
		return err
	}
	rt, err := runtime.OpenIdentityRuntime(ctx, base, cfg.SessionProfile())
	if err != nil {
		return err
	}
	defer rt.Close()
	g := domain.GatewayRegistration{ID: *id, NodeID: *node, Origin: *origin, Callback: *callback, ResourceID: *resource, Generation: *generation}
	if err = rt.Service.RegisterGateway(ctx, g); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "gateway registered:", g.ID)
	return nil
}
