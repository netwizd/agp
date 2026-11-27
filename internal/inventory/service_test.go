package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type testAuthority struct {
	mu          sync.Mutex
	now         time.Time
	epoch       securityjournal.UInt63
	unavailable bool
}

func (a *testAuthority) Head(context.Context) (securityjournal.Head, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unavailable {
		return securityjournal.Head{}, securityjournal.ErrUnavailable
	}
	return securityjournal.Head{AuthorityID: "inventory_test", Epoch: a.epoch, RecordedAt: a.now}, nil
}
func (a *testAuthority) Append(context.Context, securityjournal.AppendRequest) (securityjournal.Event, error) {
	return securityjournal.Event{}, errors.New("unexpected inventory mutation")
}
func (a *testAuthority) Operation(context.Context, string) (securityjournal.Event, error) {
	return securityjournal.Event{}, storage.ErrNotFound
}
func (a *testAuthority) Events(context.Context, securityjournal.UInt63, int) ([]securityjournal.Event, error) {
	return nil, nil
}
func (a *testAuthority) advance(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.now = a.now.Add(d)
}

type testFixture struct {
	t         *testing.T
	store     storage.Store
	service   *Service
	current   *securitystate.Coordinator
	authority *testAuthority
	dir       string
	registry  Registry
	ca        *x509.Certificate
	caKey     ed25519.PrivateKey
	agent     tls.Certificate
	agentLeaf *x509.Certificate
	server    tls.Certificate
	peer      *tls.ConnectionState
}

func createCert(t *testing.T, tmpl, parent *x509.Certificate, pub ed25519.PublicKey, signer ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	der, e := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func writePair(t *testing.T, dir, name string, cert *x509.Certificate, key ed25519.PrivateKey) (tls.Certificate, string, string) {
	t.Helper()
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0600); e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(certPath, keyPath)
	if e != nil {
		t.Fatal(e)
	}
	return pair, certPath, keyPath
}
func fixture(t *testing.T, pg bool) *testFixture {
	t.Helper()
	ctx := context.Background()
	f := &testFixture{t: t, dir: privateTestDir(t)}
	var e error
	if pg {
		dsn := os.Getenv("AGP_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("AGP_TEST_POSTGRES_DSN is not set")
		}
		admin, e := pgxpool.New(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		schema := strings.ToLower(securitystate.ID("inventory"))
		q := pgx.Identifier{schema}.Sanitize()
		if _, e = admin.Exec(ctx, `CREATE SCHEMA `+q); e != nil {
			admin.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = admin.Exec(ctx, `DROP SCHEMA `+q+` CASCADE`); admin.Close() })
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, e := url.Parse(dsn)
			if e != nil {
				t.Fatal(e)
			}
			query := u.Query()
			query.Set("search_path", schema)
			u.RawQuery = query.Encode()
			dsn = u.String()
		} else {
			dsn += " search_path=" + schema
		}
		f.store, e = postgres.Open(ctx, dsn)
	} else {
		f.store, e = sqlite.Open(filepath.Join(f.dir, "inventory.db"))
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	if e = f.store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if pg {
		release, e := f.store.(interface {
			AcquireIdentityLease(context.Context) (func(), error)
		}).AcquireIdentityLease(ctx)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.authority = &testAuthority{now: now, epoch: 1}
	e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,'inventory_test',1,0,'',TRUE)`)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	f.current = securitystate.New(f.store, f.authority)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f.caKey = key
	f.ca = createCert(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inventory-test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inventory-test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, pub, key)
	if e = os.WriteFile(filepath.Join(f.dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	pub, key, e = ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse("spiffe://agp/agent/node_one")
	f.agentLeaf = createCert(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, f.ca, pub, f.caKey)
	f.agent, _, _ = writePair(t, f.dir, "agent", f.agentLeaf, key)
	pub, key, e = ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serverLeaf := createCert(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, f.ca, pub, f.caKey)
	f.server, _, _ = writePair(t, f.dir, "server", serverLeaf, key)
	f.registry = Registry{APIVersion: "agp.agent-registry/v1alpha1", AuthorityID: "inventory_test", Nodes: []Registration{{NodeID: "node_one", SiteID: "site_msk", Name: "Native node", Labels: map[string]string{"environment": "test"}, GroupIDs: []string{"group_one"}, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.agentLeaf.Raw})), CertificateDigest: hash(f.agentLeaf.Raw), PublicKeyDigest: hash(f.agentLeaf.RawSubjectPublicKeyInfo), IssuerDigest: hash(f.ca.Raw), Serial: "2", IssuanceEpoch: 1}}}
	f.writeRegistry()
	f.service, e = New(f.current, f.authority, filepath.Join(f.dir, "registry.json"))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.ca)
	f.peer = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{f.agentLeaf}, VerifiedChains: [][]*x509.Certificate{{f.agentLeaf, f.ca}}}
	return f
}
func (f *testFixture) writeRegistry() {
	f.t.Helper()
	b, e := json.Marshal(f.registry)
	if e != nil {
		f.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.dir, "registry.json"), b, 0644); e != nil {
		f.t.Fatal(e)
	}
}
func observation() Observation {
	return Observation{BootID: "1879150d-f787-4d0f-a3bf-1d706ed6c06b", FreeBytes: 1000, Capabilities: Capabilities{AgentVersion: "test", ProtocolVersion: ProtocolVersion, OS: OS{ID: "ubuntu", VersionID: "24.04", Kernel: "6.8.0-test", Architecture: "amd64"}}}
}
func (f *testFixture) submission(id string) Submission {
	f.t.Helper()
	c, e := f.service.Challenge(context.Background(), f.peer)
	if e != nil {
		f.t.Fatal(e)
	}
	return Submission{RequestID: id, ChallengeID: c.ID, Challenge: c.Challenge, Observation: observation()}
}
func (f *testFixture) currentNodes() ([]Node, error) {
	var out []Node
	e := f.current.Current(context.Background(), func(tx storage.IdentityTx, h securityjournal.Head) error {
		var e error
		out, e = f.service.CurrentNodes(context.Background(), tx, h.Epoch, "site_msk")
		return e
	})
	return out, e
}

func TestInventorySQLite(t *testing.T)   { inventoryLifecycle(t, false) }
func TestInventoryPostgres(t *testing.T) { inventoryLifecycle(t, true) }
func inventoryLifecycle(t *testing.T, pg bool) {
	f := fixture(t, pg)
	ctx := context.Background()
	if _, e := f.currentNodes(); !errors.Is(e, ErrNotFresh) {
		t.Fatalf("missing observation: %v", e)
	}
	in := f.submission("request_one")
	receipt, e := f.service.Submit(ctx, f.peer, in)
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := f.currentNodes()
	if e != nil || len(nodes) != 1 || nodes[0].CapabilityDigest != receipt.CapabilityDigest || nodes[0].SiteID != "site_msk" {
		t.Fatalf("current nodes: %+v %v", nodes, e)
	}
	f.authority.advance(10 * time.Second)
	retry, e := f.service.Submit(ctx, f.peer, in)
	if e != nil || *retry != *receipt {
		t.Fatalf("retry refreshed receipt: %+v %v", retry, e)
	}
	changed := in
	changed.Observation.FreeBytes++
	if _, e = f.service.Submit(ctx, f.peer, changed); !errors.Is(e, ErrConflict) {
		t.Fatalf("request mismatch: %v", e)
	}
	replay := in
	replay.RequestID = "request_two"
	if _, e = f.service.Submit(ctx, f.peer, replay); !errors.Is(e, ErrChallenge) {
		t.Fatalf("nonce replay: %v", e)
	}
	in = f.submission("request_new_boot")
	in.Observation.BootID = "2879150d-f787-4d0f-a3bf-1d706ed6c06b"
	in.Observation.FreeBytes = 2000
	newReceipt, e := f.service.Submit(ctx, f.peer, in)
	if e != nil || newReceipt.CapabilityDigest != receipt.CapabilityDigest || newReceipt.ObservationDigest == receipt.ObservationDigest {
		t.Fatalf("capability churn: %+v %v", newReceipt, e)
	}
	var count int64
	e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(ctx, tx, `SELECT COUNT(*) FROM fleet_capability_snapshots`, nil, func(r storage.IdentityRows) error { return r.Scan(&count) })
	})
	if e != nil || count != 1 {
		t.Fatalf("capability snapshots=%d: %v", count, e)
	}
	// Identical authority timestamps must still select the last accepted facts.
	drift := f.submission("request_capability_drift")
	drift.Observation.Capabilities.AgentVersion = "test2"
	driftReceipt, e := f.service.Submit(ctx, f.peer, drift)
	if e != nil || driftReceipt.Sequence != newReceipt.Sequence+1 {
		t.Fatalf("receipt ordering: %+v %v", driftReceipt, e)
	}
	nodes, e = f.currentNodes()
	if e != nil || len(nodes) != 1 || nodes[0].CapabilityDigest != driftReceipt.CapabilityDigest {
		t.Fatalf("same-time capability reorder: %+v %v", nodes, e)
	}
	f.authority.advance(Freshness)
	if _, e = f.currentNodes(); !errors.Is(e, ErrNotFresh) {
		t.Fatalf("stale snapshot: %v", e)
	}
	old, e := f.service.Submit(ctx, f.peer, in)
	if e != nil || *old != *newReceipt {
		t.Fatalf("stale retry: %+v %v", old, e)
	}
	if _, e = f.currentNodes(); !errors.Is(e, ErrNotFresh) {
		t.Fatalf("stale retry extended freshness: %v", e)
	}
	in = f.submission("request_fresh")
	if _, e = f.service.Submit(ctx, f.peer, in); e != nil {
		t.Fatal(e)
	}
	f.registry.Nodes[0].Labels["environment"] = "changed"
	f.writeRegistry()
	if _, e = f.currentNodes(); !errors.Is(e, ErrNotFresh) {
		t.Fatalf("registry drift accepted: %v", e)
	}
	in = f.submission("request_after_drift")
	if _, e = f.service.Submit(ctx, f.peer, in); e != nil {
		t.Fatal(e)
	}
	e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `INSERT INTO security_node_revocations(node_id,event_id) VALUES('node_one','revoke_one')`)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Challenge(ctx, f.peer); !errors.Is(e, ErrIdentity) {
		t.Fatalf("revoked challenge: %v", e)
	}
	if _, e = f.service.Submit(ctx, f.peer, in); !errors.Is(e, ErrIdentity) {
		t.Fatalf("revoked retry: %v", e)
	}
	if _, e = f.currentNodes(); !errors.Is(e, ErrIdentity) {
		t.Fatalf("revoked snapshot: %v", e)
	}
}

func TestInventoryImmutableDatabaseFacts(t *testing.T) {
	inventoryImmutableDatabaseFacts(t, false)
}
func TestInventoryImmutableDatabaseFactsPostgres(t *testing.T) {
	inventoryImmutableDatabaseFacts(t, true)
}
func inventoryImmutableDatabaseFacts(t *testing.T, pg bool) {
	f := fixture(t, pg)
	ctx := context.Background()
	in := f.submission("immutable")
	receipt, e := f.service.Submit(ctx, f.peer, in)
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{`UPDATE fleet_inventory_receipts SET receipt_json='{}'`, `DELETE FROM fleet_inventory_receipts`, `UPDATE fleet_capability_snapshots SET canonical_json='{}'`, `DELETE FROM fleet_capability_snapshots`, `UPDATE fleet_inventory_challenges SET consumed_request_id=NULL`, `UPDATE fleet_inventory_challenges SET token_hash='changed'`} {
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q); return e })
		if e == nil {
			t.Fatalf("immutable database fact accepted %s", q)
		}
	}
	retry, e := f.service.Submit(ctx, f.peer, in)
	if e != nil || *retry != *receipt {
		t.Fatalf("failed mutation changed receipt: %+v %v", retry, e)
	}
}

func TestInventoryChallengeConcurrencyPostgres(t *testing.T) {
	f := fixture(t, true)
	in := f.submission("race_request")
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := in
			request.RequestID = fmt.Sprintf("racing_request_%d", i)
			_, e := f.service.Submit(ctx, f.peer, request)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				success++
			} else if !errors.Is(e, ErrChallenge) {
				t.Errorf("unexpected concurrent rejection: %v", e)
			}
		}(i)
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("one nonce accepted %d requests", success)
	}
}

func TestInventoryClockRollback(t *testing.T) {
	f := fixture(t, false)
	ctx := context.Background()
	in := f.submission("first")
	if _, e := f.service.Submit(ctx, f.peer, in); e != nil {
		t.Fatal(e)
	}
	f.authority.advance(-time.Second)
	next := f.submission("clock_rollback")
	if _, e := f.service.Submit(ctx, f.peer, next); !errors.Is(e, ErrNotFresh) {
		t.Fatalf("clock rollback accepted: %v", e)
	}
}

func TestInventoryAdmissionFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testFixture)
	}{
		{"unverified", func(f *testFixture) { f.peer.VerifiedChains = nil }},
		{"tls12", func(f *testFixture) { f.peer.Version = tls.VersionTLS12 }},
		{"expired_keepalive", func(f *testFixture) { f.authority.advance(25 * time.Hour) }},
		{"expired_issuer", func(f *testFixture) {
			c := *f.ca
			c.NotAfter = f.authority.now.Add(time.Minute)
			f.peer.VerifiedChains[0][1] = &c
		}},
		{"wrong_issuer", func(f *testFixture) {
			f.registry.Nodes[0].IssuerDigest = "sha256:" + strings.Repeat("0", 64)
			f.writeRegistry()
		}},
		{"restore_epoch", func(f *testFixture) {
			f.authority.epoch = 2
			_ = f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
				_, e := tx.Exec(context.Background(), `UPDATE security_state SET epoch=2`)
				return e
			})
		}},
		{"wrong_node_certificate", func(f *testFixture) { f.peer.PeerCertificates[0] = f.ca }},
		{"journal_outage", func(f *testFixture) { f.authority.unavailable = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t, false)
			tc.mutate(f)
			if _, e := f.service.Challenge(context.Background(), f.peer); e == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}
func TestInventoryChallengeExpiryAndConcurrency(t *testing.T) {
	f := fixture(t, false)
	ctx := context.Background()
	in := f.submission("expired")
	f.authority.advance(ChallengeTTL)
	if _, e := f.service.Submit(ctx, f.peer, in); !errors.Is(e, ErrChallenge) {
		t.Fatalf("expired nonce: %v", e)
	}
	in = f.submission("concurrent")
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	ids := map[string]bool{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.service.Submit(ctx, f.peer, in)
			mu.Lock()
			defer mu.Unlock()
			if e != nil {
				t.Errorf("exact concurrent retry: %v", e)
				return
			}
			success++
			ids[r.ID] = true
		}()
	}
	wg.Wait()
	if success != 8 || len(ids) != 1 {
		t.Fatalf("receipts %d/%v", success, ids)
	}
}
func TestInventoryClosedDecoder(t *testing.T) {
	for _, s := range []string{`{"requestId":"a","requestId":"b"}`, `{"nodeId":"attacker"}`, `{"freeBytes":1}`, `{} {}`, `{"challenge":"x","unknown":true}`} {
		var in Submission
		if Decode(strings.NewReader(s), &in) == nil {
			t.Errorf("accepted %s", s)
		}
	}
	var in Submission
	if Decode(strings.NewReader(strings.Repeat("x", MaxObservationBytes+1)), &in) == nil {
		t.Fatal("oversize accepted")
	}
}

func TestInventoryRealMTLSClient(t *testing.T) {
	f := fixture(t, false)
	pool := x509.NewCertPool()
	pool.AddCert(f.ca)
	var connectionsMu sync.Mutex
	connections := map[net.Conn]bool{}
	var mediaTypeMu sync.Mutex
	responseMediaType := "application/json; charset=utf-8"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mediaTypeMu.Lock()
		contentType := responseMediaType
		mediaTypeMu.Unlock()
		w.Header().Set("Content-Type", contentType)
		var out any
		var e error
		switch r.URL.Path {
		case "/agent/v1/inventory-challenges":
			out, e = f.service.Challenge(r.Context(), r.TLS)
		case "/agent/v1/inventories":
			var in Submission
			if e = Decode(r.Body, &in); e == nil {
				out, e = f.service.Submit(r.Context(), r.TLS, in)
			}
		default:
			w.WriteHeader(404)
			return
		}
		if e != nil {
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "rejected"})
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(out)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connectionsMu.Lock()
			connections[c] = true
			connectionsMu.Unlock()
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, e := NewClient(ClientConfig{URL: server.URL, CAFile: filepath.Join(f.dir, "ca.crt"), CAFingerprint: hash(f.ca.Raw), CertificateFile: filepath.Join(f.dir, "agent.crt"), KeyFile: filepath.Join(f.dir, "agent.key")})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	c, e := client.Challenge(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	in := Submission{RequestID: "real_tls_request", ChallengeID: c.ID, Challenge: c.Challenge, Observation: observation()}
	if _, e = client.Submit(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	connectionsMu.Lock()
	before := len(connections)
	connectionsMu.Unlock()
	f.authority.advance(25 * time.Hour)
	if _, e = client.Challenge(context.Background()); e == nil {
		t.Fatal("expired cert accepted on existing connection")
	}
	connectionsMu.Lock()
	after := len(connections)
	connectionsMu.Unlock()
	if before != 1 || after != 1 {
		t.Fatalf("keepalive boundary not exercised: before=%d after=%d", before, after)
	}
	f.authority.advance(-25 * time.Hour)
	mediaTypeMu.Lock()
	responseMediaType = "application/json; charset=iso-8859-1"
	mediaTypeMu.Unlock()
	if _, e = client.Challenge(context.Background()); !errors.Is(e, ErrInvalid) {
		t.Fatalf("non-UTF8 response accepted: %v", e)
	}
	if _, e = NewClient(ClientConfig{URL: server.URL, CAFile: filepath.Join(f.dir, "ca.crt"), CAFingerprint: "sha256:" + strings.Repeat("0", 64), CertificateFile: filepath.Join(f.dir, "agent.crt"), KeyFile: filepath.Join(f.dir, "agent.key")}); !errors.Is(e, ErrIdentity) {
		t.Fatalf("wrong pin accepted: %v", e)
	}
}

func TestInventoryCollectorRealMetadata(t *testing.T) {
	got, e := Collect(context.Background(), CollectorOptions{AgentVersion: "test", DiskPath: "/"})
	if e != nil {
		t.Fatal(e)
	}
	if got.Capabilities.OS.ID == "" || got.BootID == "" || got.FreeBytes == 0 || got.Capabilities.Component != nil {
		t.Fatalf("collector fabricated incomplete metadata: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = Collect(ctx, CollectorOptions{AgentVersion: "test", DiskPath: "/"}); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation: %v", e)
	}
	var out Submission
	if Decode(bytes.NewBufferString(`{"observation":{"bootId":"a","freeBytes":"9223372036854775808"}}`), &out) == nil {
		t.Fatal("UInt63 overflow")
	}
}

func TestInventoryAdministrativeSessionGuard(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutation string
		args     []any
	}{
		{"active", "", nil},
		{"nonadmin", `UPDATE users SET is_admin=FALSE WHERE id='inventory_admin'`, nil},
		{"blocked", `UPDATE users SET blocked_at=? WHERE id='inventory_admin'`, []any{time.Now().UTC()}},
		{"revoked", `UPDATE sessions SET revoked_at=? WHERE id='inventory_session'`, []any{time.Now().UTC()}},
		{"expired", `UPDATE sessions SET expires_at=? WHERE id='inventory_session'`, []any{time.Now().UTC().Add(-time.Hour)}},
		{"idle", `UPDATE sessions SET last_seen_at=? WHERE id='inventory_session'`, []any{time.Now().UTC().Add(-time.Hour)}},
		{"wrong_audience", `UPDATE sessions SET audience='legacy' WHERE id='inventory_session'`, nil},
		{"wrong_origin", `UPDATE sessions SET audience_origin='https://other.test' WHERE id='inventory_session'`, nil},
		{"old_epoch", `UPDATE sessions SET authority_epoch=2 WHERE id='inventory_session'`, nil},
		{"old_security_version", `UPDATE sessions SET security_version=2 WHERE id='inventory_session'`, nil},
		{"no_mfa", `UPDATE sessions SET mfa_at=NULL WHERE id='inventory_session'`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t, false)
			ctx := context.Background()
			now := f.authority.now
			e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES('inventory_admin','inventory_admin','hash',TRUE)`); e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES('inventory_session','inventory_admin','inventory_token','csrf','','',?,?,'management','https://management.test',1,1,?,?)`, now.Add(time.Hour), now, now, now); e != nil {
					return e
				}
				if tc.mutation != "" {
					_, e := tx.Exec(ctx, tc.mutation, tc.args...)
					return e
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			view, e := f.service.ListForAdmin(ctx, "inventory_token", "https://management.test")
			if tc.name == "active" {
				if e != nil || len(view) != 1 || view[0].IdentityState != "active" || view[0].Connectivity != "offline" {
					t.Fatalf("admin view: %+v %v", view, e)
				}
			} else if !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatalf("session guard bypass: %+v %v", view, e)
			}
		})
	}
}

func TestInventoryCollectorRuntimeClosure(t *testing.T) {
	dir := privateTestDir(t)
	runtimeRoot := filepath.Join(dir, "runtime")
	if e := os.Mkdir(runtimeRoot, 0700); e != nil {
		t.Fatal(e)
	}
	actual := []byte("observed bytes, not a qualification fixture")
	if e := os.WriteFile(filepath.Join(runtimeRoot, "module.so"), actual, 0400); e != nil {
		t.Fatal(e)
	}
	p := repository.ComponentProfile{APIVersion: "agp.component-profile/v1alpha1", ID: "profile_unit", Files: []repository.ProfileFile{{Path: "module.so", Digest: hash([]byte("different expected bytes"))}}}
	// Preserve the exact artifact digest, including noncanonical whitespace.
	raw, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	profilePath := filepath.Join(dir, "profile.json")
	if e = os.WriteFile(profilePath, raw, 0644); e != nil {
		t.Fatal(e)
	}
	got, e := Collect(context.Background(), CollectorOptions{AgentVersion: "test", DiskPath: "/", ProfilePath: profilePath, RuntimeRoot: runtimeRoot})
	if e != nil {
		t.Fatal(e)
	}
	component := got.Capabilities.Component
	if component == nil || component.ProfileDigest != hash(raw) || len(component.Files) != 1 || component.Files[0].Digest != hash(actual) || component.Files[0].Digest == p.Files[0].Digest {
		t.Fatalf("collector repeated declared hash instead of bytes: %+v", component)
	}
	if e = os.Remove(filepath.Join(runtimeRoot, "module.so")); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(profilePath, filepath.Join(runtimeRoot, "module.so")); e != nil {
		t.Fatal(e)
	}
	if _, e = Collect(context.Background(), CollectorOptions{AgentVersion: "test", DiskPath: "/", ProfilePath: profilePath, RuntimeRoot: runtimeRoot}); e == nil {
		t.Fatal("runtime symlink accepted")
	}
}
