// agp-issuer holds the issuing CA and a durable enrollment ledger independently
// of the control plane. It never loads an offline root private key.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nodeidentity"
	"github.com/netwizd/agp/internal/securityjournal"
)

type config struct {
	Issuer             nodeidentity.IssuerConfig `json:"issuer"`
	ListenAddress      string                    `json:"listenAddress"`
	TLSCertificateFile string                    `json:"tlsCertificateFile"`
	TLSKeyFile         string                    `json:"tlsKeyFile"`
	ClientCAFile       string                    `json:"clientCAFile"`
	Journal            struct {
		URL             string `json:"url"`
		AuthorityID     string `json:"authorityId"`
		KeyID           string `json:"keyId"`
		PublicKey       string `json:"publicKey"`
		CertificateFile string `json:"certificateFile"`
		KeyFile         string `json:"keyFile"`
		CAFile          string `json:"caFile"`
		ServerName      string `json:"serverName"`
	} `json:"journal"`
}

func main() {
	if e := run(); e != nil {
		slog.Error("agent issuer stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("agp-issuer", flag.ContinueOnError)
	path := flags.String("config", "", "protected issuer JSON configuration")
	if e := flags.Parse(os.Args[1:]); e != nil {
		return e
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("usage: agp-issuer -config FILE")
	}
	raw, e := inventory.ReadProtectedFile(*path, false)
	if e != nil {
		return errors.New("issuer configuration unavailable")
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid issuer configuration")
	}
	if cfg.ListenAddress == "" {
		return errors.New("dedicated issuer listenAddress required")
	}
	if cfg.Issuer.IssuingKeyFile == cfg.TLSKeyFile || cfg.Issuer.IssuingKeyFile == cfg.Journal.KeyFile || cfg.TLSKeyFile == cfg.Journal.KeyFile {
		return errors.New("issuer, transport and journal keys must be separate")
	}
	for _, p := range []struct {
		name    string
		private bool
	}{{cfg.Journal.CertificateFile, false}, {cfg.Journal.KeyFile, true}, {cfg.Journal.CAFile, false}} {
		if _, e = inventory.ReadProtectedFile(p.name, p.private); e != nil {
			return errors.New("journal transport file unavailable")
		}
	}
	journalTLS, e := securityjournal.LoadClientTLS(cfg.Journal.CertificateFile, cfg.Journal.KeyFile, cfg.Journal.CAFile, cfg.Journal.ServerName)
	if e != nil {
		return e
	}
	pub, e := securityjournal.DecodePublicKey(cfg.Journal.PublicKey)
	if e != nil {
		return e
	}
	journal, e := securityjournal.NewClient(securityjournal.ClientConfig{URL: cfg.Journal.URL, AuthorityID: cfg.Journal.AuthorityID, KeyID: cfg.Journal.KeyID, PublicKey: pub, TLSConfig: journalTLS, Timeout: 3 * time.Second})
	if e != nil {
		return e
	}
	defer journal.CloseIdleConnections()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	issuer, e := nodeidentity.OpenIssuer(ctx, cfg.Issuer, journal)
	if e != nil {
		return e
	}
	defer issuer.Close()
	tlsConfig, e := nodeidentity.LoadIssuerTLS(cfg.TLSCertificateFile, cfg.TLSKeyFile, cfg.ClientCAFile)
	if e != nil {
		return e
	}
	server := &http.Server{Addr: cfg.ListenAddress, TLSConfig: tlsConfig, Handler: nodeidentity.Handler(issuer), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
