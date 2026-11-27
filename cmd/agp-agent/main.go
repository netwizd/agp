// agp-agent sends Linux inventory and optionally forwards immutable execution
// tasks to a separately installed root helper over its protected Unix socket.
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

	"github.com/netwizd/agp/internal/agentexecution"
	"github.com/netwizd/agp/internal/helpertransport"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/version"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	var cfg inventory.ClientConfig
	var opts inventory.CollectorOptions
	var once bool
	var executionEnabled bool
	var helperSocket string
	var interval time.Duration
	flag.StringVar(&cfg.URL, "url", "", "Control plane agent HTTPS origin")
	flag.StringVar(&cfg.CAFile, "ca", "", "Preprovisioned public server CA PEM")
	flag.StringVar(&cfg.CAFingerprint, "ca-fingerprint", "", "Pinned SHA-256 DER CA fingerprint")
	flag.StringVar(&cfg.CertificateFile, "certificate", "", "Externally provisioned agent certificate PEM")
	flag.StringVar(&cfg.KeyFile, "key", "", "Local agent private key file (mode 0600)")
	flag.StringVar(&opts.DiskPath, "disk-path", "/", "Filesystem for free-space observation")
	flag.StringVar(&opts.ProfilePath, "component-profile", "", "Optional public typed component profile JSON")
	flag.StringVar(&opts.RuntimeRoot, "runtime-root", "", "Root of files named by component profile")
	flag.BoolVar(&once, "once", false, "Send one observation and exit")
	flag.BoolVar(&executionEnabled, "execution-enabled", false, "Forward execution tasks to the separately installed root helper")
	flag.StringVar(&helperSocket, "helper-socket", "", "Protected root helper Unix socket (requires --execution-enabled)")
	flag.DurationVar(&interval, "interval", 30*time.Second, "Inventory interval (10s..60s)")
	flag.Parse()
	if flag.NArg() != 0 || interval < 10*time.Second || interval > time.Minute || executionEnabled != (helperSocket != "") {
		return inventory.ErrInvalid
	}
	opts.AgentVersion = version.Version
	client, e := inventory.NewClient(cfg)
	if e != nil {
		return e
	}
	defer client.Close()
	var execution *agentexecution.Agent
	if executionEnabled {
		local, err := helpertransport.NewClient(helperSocket)
		if err != nil {
			return agentexecution.ErrUnavailable
		}
		defer local.Close()
		execution, err = agentexecution.New(client, local)
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		call, cancel := context.WithTimeout(ctx, 45*time.Second)
		receipt, reportErr := client.Report(call, opts)
		cancel()
		if reportErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "inventory report failed")
		} else {
			if e = json.NewEncoder(os.Stdout).Encode(receipt); e != nil {
				return e
			}
		}
		// A transient inventory failure does not suppress reconciliation of an
		// already dispatched task. The helper independently rechecks authority.
		var executionErr error
		if execution != nil {
			outcome, err := execution.RunOnce(ctx)
			executionErr = err
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "execution cycle failed")
			} else if outcome != nil {
				if err := json.NewEncoder(os.Stdout).Encode(outcome); err != nil {
					return err
				}
			}
		}
		if once {
			return errors.Join(reportErr, executionErr)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
