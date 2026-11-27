// agp-agent-validate is a one-shot local, read-only native syntax probe.
// It has no remote task transport, root helper, install, active switch or reload.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/agentvalidation"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/version"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func run() error {
	var store repository.Store
	var receipt, profile, runtimeRoot, scratch string
	var cfg securityjournal.ClientConfig
	var cert, key, ca, public string
	var uid, gid uint
	flag.StringVar(&store.Dir, "repository", "", "Installation-owned independent signed component repository")
	flag.StringVar(&store.AnchorPath, "anchor", "", "Installation-owned public trust anchor")
	flag.StringVar(&receipt, "receipts", "", "Existing private local durable result directory (0700)")
	flag.StringVar(&profile, "component-profile", "", "Installed exact public component profile")
	flag.StringVar(&runtimeRoot, "runtime-root", "", "Root of installed observed component files")
	flag.StringVar(&scratch, "scratch", "", "Installation-owned scratch directory (default OS private temporary workspace)")
	flag.StringVar(&cfg.URL, "journal-url", "", "Independent journal HTTPS origin")
	flag.StringVar(&cfg.AuthorityID, "journal-authority", "", "Pinned independent journal authority ID")
	flag.StringVar(&cfg.KeyID, "journal-key-id", "", "Pinned independent journal signing key ID")
	flag.StringVar(&public, "journal-public-key", "", "Pinned public journal Ed25519 key, base64")
	flag.StringVar(&cert, "journal-certificate", "", "Distinct read-only journal client certificate PEM")
	flag.StringVar(&key, "journal-key", "", "Local read-only journal client private key PEM (0600)")
	flag.StringVar(&ca, "journal-ca", "", "Independent journal server CA PEM")
	flag.UintVar(&uid, "execution-uid", 0, "Explicit nonroot child UID required only for a root supervisor")
	flag.UintVar(&gid, "execution-gid", 0, "Explicit nonroot child GID required only for a root supervisor")
	flag.Parse()
	if flag.NArg() != 0 || uid > 1<<32-1 || gid > 1<<32-1 || store.Dir == "" || store.AnchorPath == "" || receipt == "" || profile == "" || runtimeRoot == "" {
		return agentvalidation.ErrInvalid
	}
	if e := agentvalidation.ApplyLocalProcessLimits(); e != nil {
		return e
	}
	// A human installation command supplies local credentials and trust pins.
	// The typed stdin request cannot change paths, URL, executable or argv.
	st, e := os.Lstat(key)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return errors.New("private journal key required")
	}
	cfg.PublicKey, e = securityjournal.DecodePublicKey(public)
	if e != nil {
		return e
	}
	cfg.TLSConfig, e = securityjournal.LoadClientTLS(cert, key, ca, "")
	if e != nil {
		return e
	}
	cfg.Timeout = 3 * time.Second
	journal, e := securityjournal.NewClient(cfg)
	if e != nil {
		return e
	}
	defer journal.CloseIdleConnections()
	in, e := agentvalidation.Decode(os.Stdin)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	native := &agentvalidation.Native{Store: store, TempDir: scratch, ExecutionUID: uint32(uid), ExecutionGID: uint32(gid), Clock: func(ctx context.Context) (time.Time, error) {
		h, e := journal.Head(ctx)
		if e != nil {
			return time.Time{}, e
		}
		if h.Epoch != in.AuthorityEpoch {
			return time.Time{}, agentvalidation.ErrStale
		}
		return h.RecordedAt, nil
	}}
	local := &agentvalidation.Local{Native: native, Authority: journal, ReceiptDir: receipt, Collector: inventory.CollectorOptions{AgentVersion: version.Version, DiskPath: "/", ProfilePath: profile, RuntimeRoot: runtimeRoot}}
	out, e := local.Validate(ctx, *in)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(os.Stdout).Encode(out); e != nil {
		return e
	}
	if out.State != "validated" {
		return errors.New("local syntax probe did not validate")
	}
	return nil
}
