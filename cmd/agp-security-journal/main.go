// agp-security-journal runs independently of agp and its database/backup domain.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
)

type config struct {
	AuthorityID        string   `json:"authorityId"`
	KeyID              string   `json:"keyId"`
	SigningKeyFile     string   `json:"signingKeyFile"`
	ListenAddress      string   `json:"listenAddress"`
	TLSCertificateFile string   `json:"tlsCertificateFile"`
	TLSKeyFile         string   `json:"tlsKeyFile"`
	ClientCAFile       string   `json:"clientCAFile"`
	ReadClientURIs     []string `json:"readClientURIs"`
	AppendClientURIs   []string `json:"appendClientURIs"`
	ApprovalKeys       map[string]struct {
		PrincipalID  string   `json:"principalId"`
		PublicKey    string   `json:"publicKey"`
		AllowedKinds []string `json:"allowedKinds"`
	} `json:"approvalKeys"`
}

func main() {
	if e := run(); e != nil {
		slog.Error("security journal failed", "error", e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: agp-security-journal {migrate|verify|serve|approve} -config FILE")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configFile := flags.String("config", "", "configuration JSON (database DSN from AGP_JOURNAL_DATABASE_DSN)")
	requestFile := flags.String("request", "", "approval request JSON")
	approvalKey := flags.String("approval-key", "", "independently held PKCS8 Ed25519 signing key")
	approvalID := flags.String("approval-key-id", "", "registered approver key ID")
	approver := flags.String("approver", "", "independent approver principal ID")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if command == "approve" {
		if *requestFile == "" || *approvalKey == "" || *approvalID == "" || *approver == "" {
			return errors.New("approve requires -request, -approval-key, -approval-key-id, -approver")
		}
		var req securityjournal.AppendRequest
		if e := readJSON(*requestFile, &req); e != nil {
			return e
		}
		key, e := securityjournal.ReadSigningKey(*approvalKey)
		if e != nil {
			return e
		}
		req.ApprovalKeyID = *approvalID
		req.ApproverID = *approver
		if e = securityjournal.SignApproval(&req, key); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(req)
	}
	if command != "migrate" && command != "verify" && command != "serve" {
		return errors.New("unknown command")
	}
	if *configFile == "" {
		return errors.New("-config is required")
	}
	var cfg config
	if e := readJSON(*configFile, &cfg); e != nil {
		return e
	}
	key, e := securityjournal.ReadSigningKey(cfg.SigningKeyFile)
	if e != nil {
		return e
	}
	approvalKeys := map[string]securityjournal.ApprovalKey{}
	for id, value := range cfg.ApprovalKeys {
		pub, e := securityjournal.DecodePublicKey(value.PublicKey)
		if e != nil {
			return e
		}
		approvalKeys[id] = securityjournal.ApprovalKey{PrincipalID: value.PrincipalID, PublicKey: pub, AllowedKinds: value.AllowedKinds}
	}
	dsn := os.Getenv("AGP_JOURNAL_DATABASE_DSN")
	if dsn == "" {
		return errors.New("AGP_JOURNAL_DATABASE_DSN is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	openCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	store, e := securityjournal.Open(openCtx, securityjournal.StoreConfig{DSN: dsn, AuthorityID: cfg.AuthorityID, KeyID: cfg.KeyID, SigningKey: key, ApprovalKeys: approvalKeys})
	if e != nil {
		return e
	}
	defer store.Close()
	if command == "migrate" {
		if e = store.Migrate(openCtx); e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, "journal schema initialized")
		return nil
	}
	if e = store.ValidateChain(ctx); e != nil {
		return e
	}
	if command == "verify" {
		fmt.Fprintln(os.Stdout, "journal chain verified")
		return nil
	}
	if len(cfg.ReadClientURIs) == 0 || len(cfg.AppendClientURIs) == 0 {
		return errors.New("readClientURIs and appendClientURIs are required")
	}
	tlsConfig, e := securityjournal.LoadServerTLS(cfg.TLSCertificateFile, cfg.TLSKeyFile, cfg.ClientCAFile)
	if e != nil {
		return e
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:9444"
	}
	srv := &http.Server{Addr: cfg.ListenAddress, TLSConfig: tlsConfig, Handler: securityjournal.Handler(store, securityjournal.ServerConfig{ReadClientURIs: cfg.ReadClientURIs, AppendClientURIs: cfg.AppendClientURIs}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServeTLS("", "") }()
	slog.Info("security journal started", "address", cfg.ListenAddress)
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
func readJSON(path string, value any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 262145))
	d.DisallowUnknownFields()
	if e = d.Decode(value); e != nil {
		return errors.New("invalid JSON configuration/request")
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
