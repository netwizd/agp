// agp-agent-identity bootstraps a role-bound agent identity with owner approval.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nodebootstrap"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return nodebootstrap.ErrInvalid
	}
	mode := args[0]
	f := flag.NewFlagSet("agp-agent-identity "+mode, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var cfg nodebootstrap.ClientConfig
	var tokenFile string
	f.StringVar(&cfg.Directory, "directory", "", "Existing private identity directory (0700)")
	if mode != "keygen" {
		f.StringVar(&cfg.URL, "url", "", "Dedicated enrollment HTTPS origin")
		f.StringVar(&cfg.CAFile, "ca", "", "Preprovisioned enrollment TLS CA")
		f.StringVar(&cfg.CAFingerprint, "ca-fingerprint", "", "Pinned SHA-256 enrollment TLS CA fingerprint")
		f.StringVar(&cfg.IdentityCAFile, "identity-ca", "", "Preprovisioned agent identity root CA")
		f.StringVar(&cfg.IdentityCAFingerprint, "identity-ca-fingerprint", "", "Pinned SHA-256 identity root CA fingerprint")
		f.StringVar(&cfg.NodeID, "node", "", "Operator-assigned node ID")
		if mode == "renew" {
			f.StringVar(&cfg.CurrentDirectory, "current-directory", "", "Existing active identity directory for mTLS")
		} else {
			f.StringVar(&tokenFile, "token-file", "", "Private one-time token file; omitted reads stdin")
		}
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return nodebootstrap.ErrInvalid
	}
	if mode == "keygen" {
		pin, err := nodebootstrap.Generate(cfg.Directory)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"publicKeyDigest": pin})
	}
	if mode != "request" && mode != "enroll" && mode != "renew" {
		return nodebootstrap.ErrInvalid
	}
	c, err := nodebootstrap.NewClient(cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if mode == "renew" {
		out, err := c.Renew(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]any{"nodeId": out.NodeID, "serial": out.Serial, "expiresAt": out.ExpiresAt, "certificateFile": cfg.Directory + "/certificate.pem"})
	}
	tokenReader := stdin
	if tokenFile != "" {
		data, err := inventory.ReadProtectedFile(tokenFile, true)
		if err != nil {
			return nodebootstrap.ErrProtectedPath
		}
		defer clear(data)
		tokenReader = &tokenBytes{data: data}
	}
	token, err := nodebootstrap.ReadToken(tokenReader)
	if err != nil {
		return err
	}
	if mode == "request" {
		out, err := c.Request(ctx, token)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(out)
	}
	out, err := c.Enroll(ctx, token)
	if err != nil {
		return err
	}
	if tokenFile != "" {
		if err = nodebootstrap.RemoveTokenFile(tokenFile, token); err != nil {
			return err
		}
	}
	// Print only public issuance metadata, never token, key or CSR body.
	return json.NewEncoder(stdout).Encode(map[string]any{"nodeId": out.NodeID, "serial": out.Serial, "expiresAt": out.ExpiresAt, "certificateFile": cfg.Directory + "/certificate.pem"})
}

type tokenBytes struct{ data []byte }

func (r *tokenBytes) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
