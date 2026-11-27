//go:build linux

// Package helperruntime assembles installer-selected transports and the native
// executor. Starting it never creates or resets an execution ledger.
package helperruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/helpertransport"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nativeactivation"
	"github.com/netwizd/agp/internal/securityjournal"
)

var ErrRuntime = errors.New("helper_runtime_unavailable")

const Version = "agp.helper-runtime/v1alpha1"

type PublicTrust struct{ PermitKeyID, PermitPublicKey, ControlKeyID, ControlPublicKey, JournalKeyID, JournalPublicKey string }
type JournalConfig struct{ URL, AuthorityID, CAFile, CAFingerprint, CertificateFile, KeyFile string }
type Config struct {
	APIVersion       string                  `json:"apiVersion"`
	Anchor           helper.ExecutionAnchor  `json:"anchor"`
	Trust            PublicTrust             `json:"trust"`
	Native           nativeactivation.Config `json:"native"`
	LedgerDir        string                  `json:"ledgerDir"`
	RepositoryDir    string                  `json:"repositoryDir"`
	RepositoryDigest string                  `json:"repositoryDigest"`
	ReceiptKeyFile   string                  `json:"receiptKeyFile"`
	Socket           helpertransport.Config  `json:"socket"`
	ControlPlane     inventory.ClientConfig  `json:"controlPlane"`
	Journal          JournalConfig           `json:"journal"`
}

func DecodeConfig(b []byte) (Config, error) {
	var c Config
	if inventory.Decode(bytes.NewReader(b), &c) != nil || c.APIVersion != Version || !configmodel.ValidDigest(c.RepositoryDigest) || c.Anchor.Installation.NodeID != c.Native.NodeID || c.Anchor.Installation.SiteID != c.Native.SiteID || c.Anchor.LayoutDigest != c.Native.LayoutDigest {
		return c, ErrRuntime
	}
	return c, nil
}
func public(v string) (ed25519.PublicKey, error) {
	b, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil || len(b) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(b) != v {
		return nil, ErrRuntime
	}
	return ed25519.PublicKey(b), nil
}
func trust(v PublicTrust) (helper.Trust, error) {
	p, e := public(v.PermitPublicKey)
	if e != nil {
		return helper.Trust{}, e
	}
	c, e := public(v.ControlPublicKey)
	if e != nil {
		return helper.Trust{}, e
	}
	j, e := public(v.JournalPublicKey)
	if e != nil {
		return helper.Trust{}, e
	}
	return helper.Trust{PermitKeyID: v.PermitKeyID, PermitKey: p, ControlKeyID: v.ControlKeyID, ControlKey: c, JournalKeyID: v.JournalKeyID, JournalKey: j}, nil
}
func receiptKey(path string) (ed25519.PrivateKey, error) {
	b, e := helpertransport.ReadRootFile(path, true, 8192)
	if e != nil {
		return nil, ErrRuntime
	}
	defer clear(b)
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "PRIVATE KEY" || len(p.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrRuntime
	}
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, ErrRuntime
	}
	v, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrRuntime
	}
	return v, nil
}
func journalTLS(c JournalConfig) (*tls.Config, []byte, error) {
	ca, e := helpertransport.ReadRootFile(c.CAFile, false, 65536)
	if e != nil {
		return nil, nil, ErrRuntime
	}
	p, rest := pem.Decode(ca)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, ErrRuntime
	}
	cert, e := x509.ParseCertificate(p.Bytes)
	if e != nil || !cert.IsCA || configmodel.DigestBytes(cert.Raw) != c.CAFingerprint {
		return nil, nil, ErrRuntime
	}
	b, e := helpertransport.ReadRootFile(c.CertificateFile, false, 65536)
	if e != nil {
		return nil, nil, ErrRuntime
	}
	key, e := helpertransport.ReadRootFile(c.KeyFile, true, 65536)
	if e != nil {
		return nil, nil, ErrRuntime
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(b, key)
	if e != nil || len(pair.Certificate) == 0 {
		return nil, nil, ErrRuntime
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool}, pair.Certificate[0], nil
}

type control interface {
	ExecutionAuthorize(context.Context, helper.StartQuery) ([]byte, error)
	ExecutionRecord(context.Context, helper.ExecutionReceipt) error
	ExecutionBaselineChallenge(context.Context) (*helper.BaselineChallenge, error)
	ExecutionCapture(context.Context, helper.BaselineCapture) error
}
type authority interface {
	HeadWithChallenge(context.Context, string) (securityjournal.Head, error)
}
type sources struct {
	control   control
	authority authority
	witness   func() error
}

func (s *sources) Head(ctx context.Context, challenge string) ([]byte, error) {
	if s.witness() != nil {
		return nil, ErrRuntime
	}
	h, e := s.authority.HeadWithChallenge(ctx, challenge)
	if e != nil {
		return nil, ErrRuntime
	}
	return json.Marshal(h)
}
func (s *sources) Authorize(ctx context.Context, q helper.StartQuery) ([]byte, error) {
	if s.witness() != nil {
		return nil, ErrRuntime
	}
	return s.control.ExecutionAuthorize(ctx, q)
}

type Runtime struct {
	Config     Config
	Store      executionStore
	Executor   executionEngine
	control    control
	client     *inventory.Client
	journal    *securityjournal.Client
	driver     *nativeactivation.Driver
	repository *nativeactivation.Repository
	syncMu     sync.Mutex
}

type executionStore interface {
	Outbox(context.Context) ([]helper.ExecutionReceipt, error)
	Acknowledge(context.Context, string) error
	Status(context.Context) (*helper.ExecutionState, error)
	Close() error
}
type executionEngine interface {
	Execute(context.Context, io.Reader) (*helper.ExecutionReceipt, error)
	CaptureBaseline(context.Context, helper.BaselineChallenge) (*helper.BaselineCapture, error)
	RecoverPending(context.Context) (*helper.ExecutionReceipt, error)
}

func load(path string) (Config, []byte, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return Config{}, nil, ErrRuntime
	}
	b, e := helpertransport.ReadRootFile(path, true, 1<<20)
	if e != nil {
		return Config{}, nil, ErrRuntime
	}
	c, e := DecodeConfig(b)
	return c, b, e
}

// Initialize is an explicit installation operation. The native service must
// already serve the exact initial generation and pass all functional probes.
func Initialize(ctx context.Context, path string) error {
	c, _, e := load(path)
	if e != nil {
		return e
	}
	repo, e := nativeactivation.OpenRepository(c.RepositoryDir, c.RepositoryDigest)
	if e != nil {
		return ErrRuntime
	}
	defer repo.Close()
	d, e := nativeactivation.Open(c.Native, repo)
	if e != nil {
		return ErrRuntime
	}
	defer d.Close()
	s, e := helper.CreateExecutionStore(ctx, c.LedgerDir, c.Anchor, d)
	if e != nil {
		return ErrRuntime
	}
	return s.Close()
}

// StageInitial writes the installer-pinned first tree into an empty native
// directory. It neither starts Nginx nor creates the verified execution ledger.
func StageInitial(ctx context.Context, path string) error {
	c, _, e := load(path)
	if e != nil {
		return e
	}
	r, e := nativeactivation.OpenRepository(c.RepositoryDir, c.RepositoryDigest)
	if e != nil {
		return ErrRuntime
	}
	defer r.Close()
	g, e := r.InitialGeneration(ctx, c.Native, c.Anchor.Installation.Baseline)
	if e != nil {
		return ErrRuntime
	}
	if nativeactivation.Initialize(c.Native, r, g) != nil {
		return ErrRuntime
	}
	return nil
}

func Open(path string) (r *Runtime, err error) {
	c, initial, e := load(path)
	if e != nil {
		return nil, e
	}
	r = &Runtime{Config: c}
	opened := r
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	r.repository, e = nativeactivation.OpenRepository(c.RepositoryDir, c.RepositoryDigest)
	if e != nil {
		return nil, ErrRuntime
	}
	r.driver, e = nativeactivation.Open(c.Native, r.repository)
	if e != nil {
		return nil, ErrRuntime
	}
	store, e := helper.OpenExecutionStore(c.LedgerDir, c.Anchor)
	if e != nil {
		return nil, ErrRuntime
	}
	r.Store = store
	// Root-selected CP credentials are a protected provisioned copy of the
	// exact registered agent leaf; the independent journal uses another identity.
	for _, file := range []struct {
		name    string
		private bool
	}{{c.ControlPlane.CAFile, false}, {c.ControlPlane.CertificateFile, false}, {c.ControlPlane.KeyFile, true}} {
		if _, e = helpertransport.ReadRootFile(file.name, file.private, 65536); e != nil {
			return nil, ErrRuntime
		}
	}
	r.client, e = inventory.NewClient(c.ControlPlane)
	if e != nil {
		return nil, ErrRuntime
	}
	r.control = r.client
	jTLS, jLeaf, e := journalTLS(c.Journal)
	if e != nil {
		return nil, e
	}
	cpPEM, e := helpertransport.ReadRootFile(c.ControlPlane.CertificateFile, false, 65536)
	if e != nil {
		return nil, ErrRuntime
	}
	cpBlock, _ := pem.Decode(cpPEM)
	if cpBlock == nil || bytes.Equal(cpBlock.Bytes, jLeaf) {
		return nil, ErrRuntime
	}
	cpLeaf, e := x509.ParseCertificate(cpBlock.Bytes)
	journalLeaf, je := x509.ParseCertificate(jLeaf)
	if e != nil || je != nil || len(cpLeaf.URIs) != 1 || cpLeaf.URIs[0].String() != "spiffe://agp/agent/"+c.Anchor.Installation.NodeID || c.Journal.AuthorityID != c.Anchor.Installation.AuthorityID {
		return nil, ErrRuntime
	}
	t, e := trust(c.Trust)
	if e != nil {
		return nil, e
	}
	receiptPublic, e := public(c.Anchor.ReceiptPublicKey)
	if e != nil {
		return nil, ErrRuntime
	}
	for _, key := range []ed25519.PublicKey{t.PermitKey, t.ControlKey, t.JournalKey, receiptPublic} {
		for _, leaf := range []*x509.Certificate{cpLeaf, journalLeaf} {
			if tlsKey, ok := leaf.PublicKey.(ed25519.PublicKey); ok && bytes.Equal(key, tlsKey) {
				return nil, ErrRuntime
			}
		}
	}
	r.journal, e = securityjournal.NewClient(securityjournal.ClientConfig{URL: c.Journal.URL, AuthorityID: c.Journal.AuthorityID, KeyID: t.JournalKeyID, PublicKey: t.JournalKey, TLSConfig: jTLS, Timeout: 3 * time.Second})
	if e != nil {
		return nil, ErrRuntime
	}
	key, e := receiptKey(c.ReceiptKeyFile)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	src := &sources{control: r.control, authority: r.journal, witness: func() error {
		b, e := helpertransport.ReadRootFile(path, true, 1<<20)
		if e != nil || !bytes.Equal(b, initial) {
			return ErrRuntime
		}
		return nil
	}}
	r.Executor, e = helper.NewExecutor(store, t, src, r.driver, key)
	if e != nil {
		return nil, ErrRuntime
	}
	return r, nil
}

// FlushOutbox acknowledges only an actual successful CP response observed by
// this root runtime. The agent has no local acknowledge capability.
func (r *Runtime) FlushOutbox(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	out, e := r.Store.Outbox(ctx)
	if e != nil {
		return e
	}
	for _, receipt := range out {
		if e = r.control.ExecutionRecord(ctx, receipt); e != nil {
			return ErrRuntime
		}
		if e = r.Store.Acknowledge(ctx, receipt.ReceiptID); e != nil {
			return e
		}
	}
	return nil
}
func (r *Runtime) Capture(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	q, e := r.control.ExecutionBaselineChallenge(ctx)
	if e != nil || q == nil {
		return ErrRuntime
	}
	c, e := r.Executor.CaptureBaseline(ctx, *q)
	if e != nil {
		return e
	}
	if r.control.ExecutionCapture(ctx, *c) != nil {
		return ErrRuntime
	}
	return nil
}
func (r *Runtime) Execute(ctx context.Context, in io.Reader) (*helper.ExecutionReceipt, error) {
	return r.Executor.Execute(ctx, in)
}
func (r *Runtime) Run(ctx context.Context) error {
	if e := r.recover(ctx); e != nil {
		return e
	}
	server, e := helpertransport.NewServer(r.Config.Socket, r)
	if e != nil {
		return e
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		server.Close(c)
	}()
	ch := make(chan error, 1)
	go func() { ch <- server.Serve() }()
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()
	for {
		call, cancel := context.WithTimeout(ctx, 25*time.Second)
		_ = r.sync(call)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if _, err := r.Store.Status(ctx); err != nil {
			return ErrRuntime
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-ch:
			return err
		case <-timer.C:
		}
	}
}

func (r *Runtime) recover(ctx context.Context) error {
	state, e := r.Store.Status(ctx)
	if e != nil {
		return e
	}
	if state.Attempt != nil {
		if _, e = r.Executor.RecoverPending(ctx); e != nil && !errors.Is(e, helper.ErrPending) {
			return e
		}
	}
	return nil
}

func (r *Runtime) sync(ctx context.Context) error {
	if err := r.FlushOutbox(ctx); err != nil {
		return err
	}
	return r.Capture(ctx)
}
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	if r.Store != nil {
		r.Store.Close()
	}
	if r.driver != nil {
		r.driver.Close()
	}
	if r.repository != nil {
		r.repository.Close()
	}
	if r.client != nil {
		r.client.Close()
	}
	if r.journal != nil {
		r.journal.CloseIdleConnections()
	}
}
