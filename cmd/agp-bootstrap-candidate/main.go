// agp-bootstrap-candidate is a root-only, one-shot local syntax evidence tool.
// It never changes the protected tree, installs a service, applies or reloads.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/agentvalidation"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nativesandbox"
	"github.com/netwizd/agp/internal/ownedtree"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
)

const localConfigVersion = "agp.bootstrap-candidate-config/v1alpha1"

var (
	errArguments   = errors.New("bootstrap_candidate_invalid_local_arguments")
	errRoot        = errors.New("bootstrap_candidate_local_root_required")
	errUnavailable = errors.New("bootstrap_candidate_unavailable")
)

type localConfig struct {
	APIVersion        string        `json:"apiVersion"`
	OwnershipManifest string        `json:"ownershipManifest"`
	OwnershipDigest   string        `json:"ownershipDigest"`
	Repository        string        `json:"repository"`
	RepositoryAnchor  string        `json:"repositoryAnchor"`
	SandboxTool       string        `json:"sandboxTool"`
	SandboxToolDigest string        `json:"sandboxToolDigest"`
	ExecutionUID      int           `json:"executionUid"`
	ExecutionGID      int           `json:"executionGid"`
	Journal           journalConfig `json:"journal"`
}
type journalConfig struct {
	URL               string `json:"url"`
	AuthorityID       string `json:"authorityId"`
	KeyID             string `json:"keyId"`
	PublicKey         string `json:"publicKey"`
	ClientCertificate string `json:"clientCertificate"`
	ClientKey         string `json:"clientKey"`
	ServerCA          string `json:"serverCa"`
}

func main() {
	// This dedicated process receives limits before loading any installation
	// inputs. Library entrypoints do not mutate caller-global resource limits.
	if e := nativesandbox.ApplyLocalProcessLimits(); e != nil {
		fmt.Fprintln(os.Stderr, errUnavailable)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	if e := run(ctx, os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("agp-bootstrap-candidate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var name string
	flags.StringVar(&name, "config", "", "Protected root-owned local installation configuration")
	e := flags.Parse(args)
	if errors.Is(e, flag.ErrHelp) {
		if out == nil {
			return errArguments
		}
		_, e = io.WriteString(out, "Usage: agp-bootstrap-candidate -config /protected/bootstrap-candidate.json\nRoot-only local syntax candidate; sandbox execution drops to explicit nonroot UID/GID. No stdin, active-baseline proof, apply or reload.\n")
		if e != nil {
			return errUnavailable
		}
		return nil
	}
	if e != nil || flags.NArg() != 0 || len(args) != 2 || !localPath(name) {
		return errArguments
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRoot
	}
	return generate(ctx, name, out)
}
func generate(ctx context.Context, name string, out io.Writer) error {
	if ctx == nil || out == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || nativesandbox.CheckLimits() != nil {
		return errUnavailable
	}
	raw, e := inventory.ReadProtectedFile(name, true)
	if e != nil {
		return errUnavailable
	}
	defer clear(raw)
	cfg, e := parseConfig(raw)
	if e != nil {
		return errUnavailable
	}
	tree, e := ownedtree.Load(cfg.OwnershipManifest, cfg.OwnershipDigest)
	if e != nil {
		return errUnavailable
	}
	defer tree.Close()
	sandbox, e := nativesandbox.NewAsUser(nativesandbox.Tool{Path: cfg.SandboxTool, Digest: cfg.SandboxToolDigest}, uint32(cfg.ExecutionUID), uint32(cfg.ExecutionGID))
	if e != nil {
		return errUnavailable
	}
	tlsConfig, e := protectedTLS(cfg.Journal)
	if e != nil {
		return errUnavailable
	}
	public, e := securityjournal.DecodePublicKey(cfg.Journal.PublicKey)
	if e != nil {
		return errUnavailable
	}
	journal, e := securityjournal.NewClient(securityjournal.ClientConfig{URL: cfg.Journal.URL, AuthorityID: cfg.Journal.AuthorityID, KeyID: cfg.Journal.KeyID, PublicKey: public, TLSConfig: tlsConfig, Timeout: 3 * time.Second})
	if e != nil {
		return errUnavailable
	}
	defer journal.CloseIdleConnections()
	validator := agentvalidation.BootstrapValidator{Repository: repository.Store{Dir: cfg.Repository, AnchorPath: cfg.RepositoryAnchor}, Tree: tree, Sandbox: sandbox, Authority: journal}
	candidate, e := validator.Validate(ctx)
	if e != nil || candidate == nil || ctx.Err() != nil {
		return errUnavailable
	}
	raw, e = json.Marshal(candidate)
	if e != nil || len(raw) > 64<<10 {
		return errUnavailable
	}
	if _, e = agentvalidation.ParseBootstrapCandidate(bytes.NewReader(raw)); e != nil || ctx.Err() != nil {
		return errUnavailable
	}
	raw = append(raw, '\n')
	n, e := out.Write(raw)
	if e != nil || n != len(raw) {
		return errUnavailable
	}
	return nil
}
func parseConfig(raw []byte) (*localConfig, error) {
	var c localConfig
	if configmodel.StrictJSON(bytes.NewReader(raw), &c, 16<<10) != nil || c.APIVersion != localConfigVersion || !configmodel.ValidDigest(c.OwnershipDigest) || !configmodel.ValidDigest(c.SandboxToolDigest) || c.ExecutionUID <= 0 || c.ExecutionGID <= 0 || uint64(c.ExecutionUID) >= uint64(^uint32(0)) || uint64(c.ExecutionGID) >= uint64(^uint32(0)) || !configmodel.ValidID(c.Journal.AuthorityID) || !configmodel.ValidID(c.Journal.KeyID) {
		return nil, errUnavailable
	}
	for _, p := range []string{c.OwnershipManifest, c.Repository, c.RepositoryAnchor, c.SandboxTool, c.Journal.ClientCertificate, c.Journal.ClientKey, c.Journal.ServerCA} {
		if !localPath(p) {
			return nil, errUnavailable
		}
	}
	u, e := url.Parse(c.Journal.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || len(c.Journal.URL) > 2048 {
		return nil, errUnavailable
	}
	if _, e = securityjournal.DecodePublicKey(c.Journal.PublicKey); e != nil {
		return nil, errUnavailable
	}
	return &c, nil
}
func localPath(s string) bool {
	return len(s) > 1 && len(s) <= 1024 && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

// The existing path-based journal TLS helper reads through os.ReadFile. Root
// inputs here instead use the repository's bounded no-symlink protected reader.
func protectedTLS(c journalConfig) (*tls.Config, error) {
	cert, e := inventory.ReadProtectedFile(c.ClientCertificate, false)
	if e != nil {
		return nil, errUnavailable
	}
	key, e := inventory.ReadProtectedFile(c.ClientKey, true)
	if e != nil {
		return nil, errUnavailable
	}
	defer clear(key)
	ca, e := inventory.ReadProtectedFile(c.ServerCA, false)
	if e != nil {
		return nil, errUnavailable
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, errUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errUnavailable
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots}, nil
}
