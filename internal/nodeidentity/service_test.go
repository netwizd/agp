package nodeidentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type fakeAuthority struct {
	mu         sync.Mutex
	head       securityjournal.Head
	events     []securityjournal.Event
	offline    bool
	failAppend bool
}

func (a *fakeAuthority) Head(context.Context) (securityjournal.Head, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.offline {
		return a.head, ErrUnavailable
	}
	return a.head, nil
}
func (a *fakeAuthority) Append(_ context.Context, r securityjournal.AppendRequest) (securityjournal.Event, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.offline || a.failAppend {
		return securityjournal.Event{}, ErrUnavailable
	}
	if r.ExpectedEpoch != a.head.Epoch || r.ExpectedSequence != a.head.Sequence || r.ExpectedDigest != a.head.Digest {
		return securityjournal.Event{}, securityjournal.ErrConflict
	}
	rd, _ := securityjournal.RequestDigest(r)
	e := securityjournal.Event{AuthorityID: a.head.AuthorityID, ID: securitystate.ID("ev"), Epoch: a.head.Epoch, Sequence: a.head.Sequence + 1, Request: r, RequestDigest: rd, PreviousDigest: a.head.Digest, RecordedAt: a.head.RecordedAt}
	e.Digest = digest(e)
	a.events = append(a.events, e)
	a.head.Sequence = e.Sequence
	a.head.Digest = e.Digest
	return e, nil
}
func (a *fakeAuthority) Operation(_ context.Context, id string) (securityjournal.Event, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Request.OperationID == id {
			return e, nil
		}
	}
	return securityjournal.Event{}, securityjournal.ErrNotFound
}
func (a *fakeAuthority) Events(_ context.Context, after securityjournal.UInt63, limit int) ([]securityjournal.Event, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []securityjournal.Event
	for _, e := range a.events {
		if e.Sequence > after && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}
func (a *fakeAuthority) advance(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.head.RecordedAt = a.head.RecordedAt.Add(d)
}

type fixture struct {
	t              *testing.T
	ctx            context.Context
	dir            string
	store          storage.Store
	authority      *fakeAuthority
	coordinator    *securitystate.Coordinator
	issuer         *LocalIssuer
	cfg            IssuerConfig
	service        *Service
	inventory      *inventory.Service
	actor          Actor
	ca, root       *x509.Certificate
	caKey, rootKey ed25519.PrivateKey
}

func cert(t *testing.T, tmpl, parent *x509.Certificate, pub ed25519.PublicKey, key ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	der, e := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func privateDir(t *testing.T) string {
	t.Helper()
	d, e := os.MkdirTemp("/tmp", "agp-nodeidentity-test.")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
func writePair(t *testing.T, dir, name string, c *x509.Certificate, key ed25519.PrivateKey) (string, string) {
	t.Helper()
	p := filepath.Join(dir, name+".crt")
	k := filepath.Join(dir, name+".key")
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); e != nil {
		t.Fatal(e)
	}
	return p, k
}
func setup(t *testing.T, pg bool) *fixture {
	t.Helper()
	return setupWithScopeGraph(t, pg, nil)
}
func setupWithScopeGraph(t *testing.T, pg bool, graph *rolescope.Manifest) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), dir: privateDir(t), actor: Actor{TokenHash: auth.TokenHash("management-session"), Origin: "https://management.test"}}
	var e error
	if pg {
		dsn := os.Getenv("AGP_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("AGP_TEST_POSTGRES_DSN is not set")
		}
		admin, e := pgxpool.New(f.ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		schema := strings.ToLower(securitystate.ID("nodeidentity"))
		q := pgx.Identifier{schema}.Sanitize()
		if _, e = admin.Exec(f.ctx, `CREATE SCHEMA `+q); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { admin.Exec(f.ctx, `DROP SCHEMA `+q+` CASCADE`); admin.Close() })
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, _ := url.Parse(dsn)
			query := u.Query()
			query.Set("search_path", schema)
			u.RawQuery = query.Encode()
			dsn = u.String()
		} else {
			dsn += " search_path=" + schema
		}
		f.store, e = postgres.Open(f.ctx, dsn)
	} else {
		f.store, e = sqlite.Open(filepath.Join(f.dir, "cp.db"))
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.store.Close() })
	if e = f.store.Migrate(f.ctx); e != nil {
		t.Fatal(e)
	}
	if pg {
		release, e := f.store.(interface {
			AcquireIdentityLease(context.Context) (func(), error)
		}).AcquireIdentityLease(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.authority = &fakeAuthority{head: securityjournal.Head{AuthorityID: "nodeidentity_test", Epoch: 1, RecordedAt: now}}
	e = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		if graph != nil {
			if e := rolescope.BootstrapTx(f.ctx, tx, 1, *graph); e != nil {
				return e
			}
		}
		for _, q := range []struct {
			q    string
			args []any
		}{{`INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,'nodeidentity_test',1,0,'',TRUE)`, nil}, {`INSERT INTO users(id,username,password_hash,is_admin,security_version,password_version) VALUES('admin','admin','unused',TRUE,1,1)`, nil}, {`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES('session','admin',?,'csrf','127.0.0.1','test',?,?,'management',?,1,1,?,?)`, []any{f.actor.TokenHash, now.Add(8 * time.Hour), now, f.actor.Origin, now, now}}} {
			if _, e := tx.Exec(f.ctx, q.q, q.args...); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	f.coordinator = securitystate.New(f.store, f.authority)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f.rootKey = key
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline-root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	f.root = cert(t, rootTemplate, rootTemplate, pub, key)
	pub, key, _ = ed25519.GenerateKey(rand.Reader)
	f.caKey = key
	f.ca = cert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agent-issuing-ca"}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}, f.root, pub, f.rootKey)
	cp, kp := writePair(t, f.dir, "issuer", f.ca, key)
	raw, _ := os.ReadFile(cp)
	raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})...)
	os.WriteFile(cp, raw, 0644)
	f.cfg = IssuerConfig{LedgerFile: filepath.Join(f.dir, "external-issuer.db"), IssuingCertificateFile: cp, IssuingKeyFile: kp, CertificateLifetimeSeconds: 86400, RenewalOverlapSeconds: 300}
	f.issuer, e = OpenIssuer(f.ctx, f.cfg, f.authority)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.issuer.Close() })
	f.inventory, e = inventory.NewWithRegistry(f.coordinator, f.authority, f.issuer)
	if e != nil {
		t.Fatal(e)
	}
	f.service, e = New(f.coordinator, f.issuer, f.inventory, f.actor.Origin)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func csr(t *testing.T) (string, ed25519.PrivateKey, string) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	raw, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificateRequest(raw)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), key, hash(c.RawSubjectPublicKeyInfo)
}
func (f *fixture) node(id string) Node {
	f.t.Helper()
	n, e := f.service.CreateNode(f.ctx, f.actor, "create_"+id, CreateNodeRequest{ID: id, SiteID: "site_one", Name: "Test agent", Labels: map[string]string{"environment": "test"}})
	if e != nil {
		f.t.Fatal(e)
	}
	return n
}
func (f *fixture) enrollment(id string) Enrollment {
	f.t.Helper()
	out, e := f.service.CreateEnrollment(f.ctx, f.actor, id, "enroll_"+id, EnrollmentRequest{Role: "agent"})
	if e != nil {
		f.t.Fatal(e)
	}
	return out
}
func (f *fixture) approve(in EnrollmentSubmission) EnrollmentRequestView {
	f.t.Helper()
	pending, e := f.service.RequestEnrollment(f.ctx, in)
	if e != nil {
		f.t.Fatal(e)
	}
	out, e := f.service.ApproveEnrollment(f.ctx, f.actor, in.NodeID, pending.EnrollmentID, "approve_"+pending.EnrollmentID, ApprovalRequest{ExpectedPublicKeyDigest: pending.PublicKeyDigest, RequestDigest: pending.RequestDigest})
	if e != nil {
		f.t.Fatal(e)
	}
	return out
}
func (f *fixture) issued(id string) (EnrollmentSubmission, CertificateResult, *tls.ConnectionState) {
	f.t.Helper()
	f.node(id)
	en := f.enrollment(id)
	request, _, _ := csr(f.t)
	in := EnrollmentSubmission{NodeID: id, EnrollmentToken: en.EnrollmentToken, CSRPEM: request}
	f.approve(in)
	out, e := f.service.Enroll(f.ctx, in)
	if e != nil {
		f.t.Fatal(e)
	}
	return in, out, f.peer(out)
}
func (f *fixture) peer(out CertificateResult) *tls.ConnectionState {
	f.t.Helper()
	chain, e := parseCertificates([]byte(out.CertificateChainPEM))
	if e != nil {
		f.t.Fatal(e)
	}
	return &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: chain[:1], VerifiedChains: [][]*x509.Certificate{chain}}
}
func suite(t *testing.T, pg bool) {
	t.Run("owner-confirmation-and-hash-only-idempotency", func(t *testing.T) {
		f := setup(t, pg)
		f.node("node_one")
		en := f.enrollment("node_one")
		if !en.TokenAvailable || len(en.EnrollmentToken) != 43 || en.ExpiresAt.Sub(f.authority.head.RecordedAt) != 10*time.Minute {
			t.Fatal("token policy")
		}
		retry, e := f.service.CreateEnrollment(f.ctx, f.actor, "node_one", "enroll_node_one", EnrollmentRequest{Role: "agent"})
		if e != nil || retry.ID != en.ID || retry.TokenAvailable || retry.EnrollmentToken != "" {
			t.Fatal("raw token replay", e)
		}
		request, _, _ := csr(t)
		in := EnrollmentSubmission{"node_one", en.EnrollmentToken, request}
		if _, e = f.service.Enroll(f.ctx, in); !errors.Is(e, ErrDenied) {
			t.Fatal("issued before owner approval", e)
		}
		pending, e := f.service.RequestEnrollment(f.ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.ApproveEnrollment(f.ctx, f.actor, "node_one", en.ID, "wrong_fingerprint", ApprovalRequest{ExpectedPublicKeyDigest: hash([]byte("wrong")), RequestDigest: pending.RequestDigest}); !errors.Is(e, ErrDenied) {
			t.Fatal("wrong fingerprint accepted", e)
		}
		f.approve(in)
		out, e := f.service.Enroll(f.ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		f.authority.advance(time.Second)
		again, e := f.service.Enroll(f.ctx, in)
		if e != nil || again != out {
			t.Fatal("certificate retry minted or changed", e)
		}
		if e = f.inventory.WithIdentity(f.ctx, f.peer(out), func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e != nil {
			t.Fatal("issued identity not admitted", e)
		}
		e = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var raw string
			if e := securitystate.One(f.ctx, tx, `SELECT token_hash FROM node_enrollments WHERE id=?`, []any{en.ID}, func(r storage.IdentityRows) error { return r.Scan(&raw) }); e != nil {
				return e
			}
			if raw == en.EnrollmentToken || raw != hash([]byte(en.EnrollmentToken)) {
				t.Fatal("token persisted raw")
			}
			rows, e := tx.Query(f.ctx, `SELECT result_json FROM node_identity_requests`)
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var s string
				rows.Scan(&s)
				if strings.Contains(s, en.EnrollmentToken) {
					t.Fatal("token in idempotency response")
				}
			}
			return rows.Err()
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("one-CSR-and-external-restore-floor", func(t *testing.T) {
		f := setup(t, pg)
		f.node("node_one")
		en := f.enrollment("node_one")
		first, _, _ := csr(t)
		second, _, _ := csr(t)
		in := EnrollmentSubmission{"node_one", en.EnrollmentToken, first}
		if _, e := f.service.RequestEnrollment(f.ctx, in); e != nil {
			t.Fatal(e)
		}
		in.CSRPEM = second
		if _, e := f.service.RequestEnrollment(f.ctx, in); !errors.Is(e, ErrConflict) {
			t.Fatal("different CSR reused token", e)
		}
		if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE node_enrollments SET state='issued',request_digest='',public_key_digest='',csr_pem='',reservation_json='' WHERE id=?`, en.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.RequestEnrollment(f.ctx, in); !errors.Is(e, ErrConflict) {
			t.Fatal("CP rollback bypassed external token burn", e)
		}
		in.CSRPEM = first
		if _, e := f.service.RequestEnrollment(f.ctx, in); e != nil {
			t.Fatal("exact recovery failed", e)
		}
		if _, e := f.service.RevokeEnrollment(f.ctx, f.actor, "node_one", en.ID, "revoke_enrollment"); e != nil {
			t.Fatal(e)
		}
		if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE node_enrollments SET state='issued',request_digest='',public_key_digest='',csr_pem='',reservation_json='' WHERE id=?`, en.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.RequestEnrollment(f.ctx, in); !errors.Is(e, ErrDenied) {
			t.Fatal("CP restore resurrected canceled token", e)
		}
	})
	t.Run("renewal-overlap-and-no-key-reuse", func(t *testing.T) {
		f := setup(t, pg)
		_, out, old := f.issued("node_one")
		next, _, _ := csr(t)
		renewed, e := f.service.Renew(f.ctx, old, RenewalRequest{next})
		if e != nil {
			t.Fatal(e)
		}
		if renewed.Serial == out.Serial || renewed.PublicKeyDigest == out.PublicKeyDigest {
			t.Fatal("identity key or serial reused")
		}
		same, e := f.service.Renew(f.ctx, old, RenewalRequest{next})
		if e != nil || same != renewed {
			t.Fatal("renewal replay changed", e)
		}
		if e = f.inventory.WithIdentity(f.ctx, old, func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e != nil {
			t.Fatal("overlap missing", e)
		}
		f.authority.advance(301 * time.Second)
		if e = f.inventory.WithIdentity(f.ctx, old, func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); !errors.Is(e, inventory.ErrIdentity) {
			t.Fatal("old cert survived overlap", e)
		}
		if e = f.inventory.WithIdentity(f.ctx, f.peer(renewed), func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e != nil {
			t.Fatal("new cert rejected", e)
		}
	})
	t.Run("duplicate-SPKI-keeps-fleet-available", func(t *testing.T) {
		f := setup(t, pg)
		in, _, _ := f.issued("node_one")
		f.node("node_two")
		en := f.enrollment("node_two")
		other := EnrollmentSubmission{"node_two", en.EnrollmentToken, in.CSRPEM}
		f.approve(other)
		if _, e := f.service.Enroll(f.ctx, other); !errors.Is(e, ErrConflict) {
			t.Fatal("duplicate key issued", e)
		}
		h, _ := f.authority.Head(f.ctx)
		reg, e := f.issuer.Registry(f.ctx, h)
		if e != nil || len(reg.Nodes) != 1 {
			t.Fatal("registry corrupted", e)
		}
	})
	t.Run("live-admin-session-required", func(t *testing.T) {
		f := setup(t, pg)
		f.authority.advance(6 * time.Minute)
		if _, e := f.service.CreateNode(f.ctx, f.actor, "stale_mfa", CreateNodeRequest{ID: "node_one", SiteID: "site_one", Name: "Test"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("stale MFA accepted", e)
		}
		f.authority.advance(-6 * time.Minute)
		if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET is_admin=FALSE WHERE id='admin'`)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.CreateNode(f.ctx, f.actor, "editor_attempt", CreateNodeRequest{ID: "node_one", SiteID: "site_one", Name: "Test"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("non-admin accepted", e)
		}
	})
	t.Run("revoke-journal-closes-existing-identity", func(t *testing.T) {
		f := setup(t, pg)
		_, _, peer := f.issued("node_one")
		op, e := f.service.RevokeNode(f.ctx, f.actor, "node_one", "revoke_node", RevokeNodeRequest{"retired"})
		if e != nil {
			t.Fatal(e)
		}
		again, e := f.service.RevokeNode(f.ctx, f.actor, "node_one", "revoke_node", RevokeNodeRequest{"retired"})
		if e != nil || again != op {
			t.Fatal("revoke replay", e)
		}
		if e = f.inventory.WithIdentity(f.ctx, peer, func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e == nil {
			t.Fatal("revoked identity admitted")
		}
		if _, e = f.service.Renew(f.ctx, peer, RenewalRequest{CSRPEM: mustCSR(t)}); e == nil {
			t.Fatal("revoked identity renewed")
		}
		h, _ := f.authority.Head(f.ctx)
		registry, e := f.issuer.Registry(f.ctx, h)
		if e != nil || (len(registry.Nodes) != 1 || !registry.Nodes[0].Revoked) {
			t.Fatal("external revoke floor missing", e)
		}
	})
}
func mustCSR(t *testing.T) string           { r, _, _ := csr(t); return r }
func TestNodeIdentitySQLite(t *testing.T)   { suite(t, false) }
func TestNodeIdentityPostgres(t *testing.T) { suite(t, true) }
func TestCSRRejectsClientIdentity(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://agp/agent/victim")
	for _, template := range []*x509.CertificateRequest{{Subject: pkix.Name{CommonName: "victim"}}, {DNSNames: []string{"*.test"}}, {URIs: []*url.URL{uri}}, {IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}} {
		raw, e := x509.CreateCertificateRequest(rand.Reader, template, key)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = parseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}))); !errors.Is(e, ErrInvalid) {
			t.Fatal("applicant identity accepted", e)
		}
	}
}
func TestIssuerDurableReopenAndEpochFloor(t *testing.T) {
	f := setup(t, false)
	_, out, _ := f.issued("node_one")
	if e := f.issuer.Close(); e != nil {
		t.Fatal(e)
	}
	issuer, e := OpenIssuer(f.ctx, f.cfg, f.authority)
	if e != nil {
		t.Fatal(e)
	}
	f.issuer = issuer
	h, _ := f.authority.Head(f.ctx)
	r, e := issuer.Registry(f.ctx, h)
	if e != nil || len(r.Nodes) != 1 || r.Nodes[0].Serial != out.Serial {
		t.Fatal("durable issuance lost", e)
	}
	f.authority.mu.Lock()
	f.authority.head.Epoch = 2
	f.authority.mu.Unlock()
	h, _ = f.authority.Head(f.ctx)
	r, e = issuer.Registry(f.ctx, h)
	if e != nil || (len(r.Nodes) != 1 || r.Nodes[0].IssuanceEpoch == h.Epoch) {
		t.Fatal("old epoch identity facts were hidden", e)
	}
	f.authority.mu.Lock()
	f.authority.head.Epoch = 1
	f.authority.mu.Unlock()
	h, _ = f.authority.Head(f.ctx)
	if _, e = issuer.Registry(f.ctx, h); !errors.Is(e, ErrDenied) {
		t.Fatal("external epoch rollback", e)
	}
}
func TestIssuerProtectedFiles(t *testing.T) {
	f := setup(t, false)
	if e := os.Chmod(f.cfg.IssuingKeyFile, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenIssuer(f.ctx, f.cfg, f.authority); e == nil {
		t.Fatal("readable private key accepted")
	}
	os.Chmod(f.cfg.IssuingKeyFile, 0600)
	link := filepath.Join(f.dir, "symlink.key")
	os.Symlink(f.cfg.IssuingKeyFile, link)
	cfg := f.cfg
	cfg.IssuingKeyFile = link
	if _, e := OpenIssuer(f.ctx, cfg, f.authority); e == nil {
		t.Fatal("key symlink accepted")
	}
}
func TestIssuerHandlerRoleAndKeepAliveExpiry(t *testing.T) {
	f := setup(t, false)
	now := time.Now().UTC()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	u, _ := url.Parse(IssuerWriterURI)
	leaf := cert(t, &x509.Certificate{SerialNumber: big.NewInt(90), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, f.root, pub, f.rootKey)
	state := &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, f.root}}}
	handler := Handler(f.issuer)
	call := func(path string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.TLS = state
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if call("/issuer/v1/registry") != http.StatusForbidden {
		t.Fatal("writer read registry role")
	}
	leaf.NotAfter = now.Add(-time.Second)
	if call("/issuer/v1/reservations") != http.StatusForbidden {
		t.Fatal("expired keepalive accepted")
	}
	leaf.NotAfter = now.Add(time.Hour)
	f.root.NotAfter = now.Add(-time.Second)
	if call("/issuer/v1/reservations") != http.StatusForbidden {
		t.Fatal("expired issuer chain accepted")
	}
}

func TestIssuerRealMTLS(t *testing.T) {
	f := setup(t, false)
	now := time.Now().UTC()
	makeTransport := func(name, role string, server bool) (string, string) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		u, _ := url.Parse(role)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + len(name))), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		leaf := cert(t, template, f.root, pub, f.rootKey)
		return writePair(t, f.dir, name, leaf, key)
	}
	serverCert, serverKey := makeTransport("transport", IssuerServerURI, true)
	writerCert, writerKey := makeTransport("writer", IssuerWriterURI, false)
	readerCert, readerKey := makeTransport("reader", IssuerReaderURI, false)
	caPath := filepath.Join(f.dir, "transport-root.crt")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}), 0644)
	serverTLS, e := LoadIssuerTLS(serverCert, serverKey, caPath)
	if e != nil {
		t.Fatal(e)
	}
	deadlines := make(chan time.Time, 1)
	server := httptest.NewUnstartedServer(Handler(&deadlineCapturingIssuer{Issuer: f.issuer, deadlines: deadlines}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	client, e := NewClient(ClientConfig{URL: server.URL, ServerName: "127.0.0.1", CertificateFile: writerCert, KeyFile: writerKey, RegistryCertificateFile: readerCert, RegistryKeyFile: readerKey, CAFile: caPath, CAFingerprint: hash(f.root.Raw)})
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	for _, c := range []*http.Client{client.writer, client.reader} {
		if !c.Transport.(*http.Transport).DisableKeepAlives {
			t.Fatal("issuer transport could reuse expired server TLS identity")
		}
	}
	agents, e := inventory.NewWithRegistry(f.coordinator, f.authority, client)
	if e != nil {
		t.Fatal(e)
	}
	service, e := New(f.coordinator, client, agents, f.actor.Origin)
	if e != nil {
		t.Fatal(e)
	}
	f.service = service
	_, out, peer := f.issued("node_tls")
	select {
	case deadline := <-deadlines:
		if !deadline.After(f.authority.head.RecordedAt) {
			t.Fatal("invalid wire deadline")
		}
	default:
		t.Fatal("real TLS request omitted authorization deadline")
	}
	if e = agents.WithIdentity(f.ctx, peer, func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if out.Serial == "" {
		t.Fatal("missing real TLS issuance")
	}
	request, e := http.NewRequest("POST", server.URL+"/issuer/v1/issuances", strings.NewReader(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Content-Type", "application/json")
	response, e := client.reader.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("registry reader issued certificates", response.StatusCode)
	}
}

func TestNodeIdentityValidationDoesNotPoisonRegistry(t *testing.T) {
	f := setup(t, false)
	for _, labels := range []map[string]string{{"UPPER": "test"}, {"valid": "\xff"}} {
		if _, e := f.service.CreateNode(f.ctx, f.actor, "invalid_labels", CreateNodeRequest{ID: "node_bad", SiteID: "site_one", Name: "bad", Labels: labels}); !errors.Is(e, ErrInvalid) {
			t.Fatal("registry-incompatible metadata accepted", e)
		}
	}
	f.node("node_one")
	if _, e := f.service.CreateEnrollment(f.ctx, f.actor, "node_one", "ttl_short", EnrollmentRequest{Role: "agent", TTLSeconds: 1}); !errors.Is(e, ErrInvalid) {
		t.Fatal("TTL below OpenAPI floor", e)
	}
}

func TestNodeRevokeStartupRecovery(t *testing.T) {
	f := setup(t, false)
	_, _, peer := f.issued("node_one")
	f.authority.mu.Lock()
	f.authority.failAppend = true
	f.authority.mu.Unlock()
	if _, e := f.service.RevokeNode(f.ctx, f.actor, "node_one", "restart_revoke", RevokeNodeRequest{Reason: "retired"}); e == nil {
		t.Fatal("fault injection did not stop pending append")
	}
	f.authority.mu.Lock()
	f.authority.failAppend = false
	f.authority.mu.Unlock()
	restarted := securitystate.New(f.store, f.authority)
	RegisterRecovery(restarted)
	if e := restarted.Recover(f.ctx); e != nil {
		t.Fatal("startup could not recover node_revoke before optional listener setup", e)
	}
	if e := f.inventory.WithIdentity(f.ctx, peer, func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e == nil {
		t.Fatal("recovered revoke did not close old identity")
	}
	op, e := f.service.RevokeNode(f.ctx, f.actor, "node_one", "restart_revoke", RevokeNodeRequest{Reason: "retired"})
	if e != nil || op.State != "completed" {
		t.Fatal("recovered operation not idempotently readable", e)
	}
}

type lostIssuer struct {
	Issuer
	once bool
}

func (s *lostIssuer) Issue(ctx context.Context, in IssueRequest) (CertificateResult, error) {
	out, e := s.Issuer.Issue(ctx, in)
	if e == nil && !s.once {
		s.once = true
		return CertificateResult{}, ErrUnavailable
	}
	return out, e
}
func TestIssuerLostResponseDoesNotReissue(t *testing.T) {
	f := setup(t, false)
	f.node("node_one")
	en := f.enrollment("node_one")
	in := EnrollmentSubmission{"node_one", en.EnrollmentToken, mustCSR(t)}
	f.approve(in)
	f.service.issuer = &lostIssuer{Issuer: f.issuer}
	if _, e := f.service.Enroll(f.ctx, in); !errors.Is(e, ErrUnavailable) {
		t.Fatal("lost issuer response not injected", e)
	}
	out, e := f.service.Enroll(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	again, e := f.service.Enroll(f.ctx, in)
	if e != nil || out != again {
		t.Fatal("lost response changed certificate", e)
	}
	var count int
	if e = f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate issuance", count, e)
	}
}
func TestIssuerClockRollbackFailsClosed(t *testing.T) {
	f := setup(t, false)
	h, _ := f.authority.Head(f.ctx)
	if _, e := f.issuer.Registry(f.ctx, h); e != nil {
		t.Fatal(e)
	}
	f.authority.advance(-time.Second)
	h, _ = f.authority.Head(f.ctx)
	if _, e := f.issuer.Registry(f.ctx, h); !errors.Is(e, ErrDenied) {
		t.Fatal("trusted head time rolled back external issuer", e)
	}
}

// The full acceptance harness creates and owns this exact disposable journal.
// Never migrate or append to an arbitrary inherited developer/production DSN.
func TestIssuerJournalPostgres(t *testing.T) {
	dsn := os.Getenv("AGP_TEST_JOURNAL_DSN")
	if dsn == "" {
		t.Skip("AGP_TEST_JOURNAL_DSN is not set")
	}
	conn, e := pgx.ParseConfig(dsn)
	if e != nil || os.Getenv("AGP_TEST_S0_DISPOSABLE") != "1" || !strings.HasPrefix(conn.Host, "/tmp/agp-s0-full.") || !strings.HasSuffix(conn.Host, "/journal/socket") || conn.Database != "agp_journal" || conn.User != "s0_journal" {
		t.Fatal("issuer journal integration requires the disposable full acceptance journal")
	}
	f := setup(t, false)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, e := securityjournal.Open(f.ctx, securityjournal.StoreConfig{DSN: dsn, AuthorityID: securitystate.ID("nodeissuer"), KeyID: "issuer_test_key", SigningKey: key})
	if e != nil {
		t.Fatal(e)
	}
	defer authority.Close()
	if e = authority.Migrate(f.ctx); e != nil {
		t.Fatal(e)
	}
	if e = f.issuer.Close(); e != nil {
		t.Fatal(e)
	}
	issuer, e := OpenIssuer(f.ctx, f.cfg, authority)
	if e != nil {
		t.Fatal(e)
	}
	f.issuer = issuer
	h, e := authority.Head(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	request, _, _ := csr(t)
	parsed, _, e := parseCSR(request)
	if e != nil {
		t.Fatal(e)
	}
	reservation := Reservation{EnrollmentID: "native_enrollment", TokenHash: hash([]byte("test-only-token-digest")), Node: Node{ID: "node_native", SiteID: "site_one", Name: "Native journal agent", Labels: map[string]string{}, GroupIDs: []string{}}, Role: "agent", Epoch: h.Epoch, CSRPEM: request, RequestDigest: hash(parsed.Raw), ExpiresAt: h.RecordedAt.Add(10 * time.Minute)}
	if e = issuer.Reserve(f.ctx, reservation); e != nil {
		t.Fatal(e)
	}
	issued, e := issuer.Issue(f.ctx, IssueRequest{AuthorizationHead: authorizationHead(h), Reservation: reservation, ApprovalDigest: hash([]byte("owner-approved"))})
	if e != nil {
		t.Fatal(e)
	}
	h, e = authority.Head(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = authority.Append(f.ctx, securityjournal.AppendRequest{OperationID: securitystate.ID("revoke"), ExpectedEpoch: h.Epoch, ExpectedSequence: h.Sequence, ExpectedDigest: h.Digest, Kind: "revoke_node", TargetType: "node", TargetID: "node_native", ActorID: "operator", AuthorizationDigest: hash([]byte("operator-revoke")), RecordedAt: time.Now().UTC(), Payload: securityjournal.Payload{NodeID: "node_native"}})
	if e != nil {
		t.Fatal(e)
	}
	h, e = authority.Head(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	registry, e := issuer.Registry(f.ctx, h)
	if e != nil || (len(registry.Nodes) != 1 || !registry.Nodes[0].Revoked) {
		t.Fatal("native deny journal was not materialized into independent issuer ledger", e)
	}
	chain, e := parseCertificates([]byte(issued.CertificateChainPEM))
	if e != nil {
		t.Fatal(e)
	}
	_, e = issuer.Renew(f.ctx, RenewRequest{NodeID: "node_native", CertificateDigest: hash(chain[0].Raw), CSRPEM: mustCSR(t), Epoch: h.Epoch})
	if !errors.Is(e, ErrDenied) {
		t.Fatal("revoked native identity renewed", e)
	}
}

func TestEnrollmentApprovalCurrentAuthority(t *testing.T) {
	for _, mutation := range []string{`UPDATE users SET is_admin=FALSE WHERE id='admin'`, `UPDATE users SET blocked_at=CURRENT_TIMESTAMP WHERE id='admin'`, `UPDATE users SET security_version=2 WHERE id='admin'`, `UPDATE users SET password_version=2 WHERE id='admin'`} {
		t.Run(mutation, func(t *testing.T) {
			f := setup(t, false)
			f.node("node_one")
			en := f.enrollment("node_one")
			in := EnrollmentSubmission{"node_one", en.EnrollmentToken, mustCSR(t)}
			f.approve(in)
			if e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(f.ctx, mutation); return e }); e != nil {
				t.Fatal(e)
			}
			if _, e := f.service.Enroll(f.ctx, in); !errors.Is(e, ErrDenied) {
				t.Fatal("stale approver minted a certificate", e)
			}
			var count int
			if e := f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&count); e != nil || count != 0 {
				t.Fatal("certificate minted despite withdrawn approval authority", e)
			}
		})
	}
}
func TestRenewalZeroOverlap(t *testing.T) {
	f := setup(t, false)
	_, _, peer := f.issued("node_one")
	f.issuer.overlap = 0
	out, e := f.service.Renew(f.ctx, peer, RenewalRequest{CSRPEM: mustCSR(t)})
	if e != nil {
		t.Fatal("zero-overlap renewal did not return committed new certificate", e)
	}
	if e = f.inventory.WithIdentity(f.ctx, peer, func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e == nil {
		t.Fatal("zero-overlap retained old identity")
	}
	if e = f.inventory.WithIdentity(f.ctx, f.peer(out), func(storage.IdentityTx, securityjournal.Head, inventory.Registration) error { return nil }); e != nil {
		t.Fatal("new identity not admitted", e)
	}
}

func TestManagedSiteUniverseDoesNotShrink(t *testing.T) {
	for _, state := range []string{"pending", "expired", "revoked"} {
		t.Run(state, func(t *testing.T) {
			f := setup(t, false)
			if state == "expired" {
				f.issuer.lifetime = time.Hour
			}
			_, _, one := f.issued("node_one")
			f.issuer.lifetime = 24 * time.Hour
			_, _, two := f.issued("node_two")
			submit := func(peer *tls.ConnectionState, id string) {
				challenge, e := f.inventory.Challenge(f.ctx, peer)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.inventory.Submit(f.ctx, peer, inventory.Submission{RequestID: id, ChallengeID: challenge.ID, Challenge: challenge.Challenge, Observation: inventory.Observation{BootID: "1879150d-f787-4d0f-a3bf-1d706ed6c06b", FreeBytes: 1000, Capabilities: inventory.Capabilities{AgentVersion: "test", ProtocolVersion: inventory.ProtocolVersion, OS: inventory.OS{ID: "ubuntu", VersionID: "24.04", Kernel: "test-kernel", Architecture: "amd64"}}}})
				if e != nil {
					t.Fatal(e)
				}
			}
			submit(one, "one")
			submit(two, "two")
			check := func() error {
				return f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					nodes, e := f.inventory.CurrentNodes(f.ctx, tx, h.Epoch, "site_one")
					if e == nil && len(nodes) != 2 {
						t.Fatalf("complete node closure changed without error: %d", len(nodes))
					}
					return e
				})
			}
			if e := check(); e != nil {
				t.Fatal(e)
			}
			switch state {
			case "pending":
				f.node("node_pending")
			case "expired":
				f.authority.advance(time.Hour + time.Second)
				submit(two, "two_fresh")
			case "revoked":
				if _, e := f.service.RevokeNode(f.ctx, f.actor, "node_one", "universe_revoke", RevokeNodeRequest{Reason: "retired"}); e != nil {
					t.Fatal(e)
				}
			}
			if e := check(); e == nil {
				t.Fatal("incomplete Site succeeded after identity unavailable")
			}
		})
	}
}

type revokeRaceRepository struct {
	store securitystate.Repository
	mu    sync.Mutex
	reads int
	ready chan struct{}
}
type revokeRaceTx struct {
	storage.IdentityTx
	read *bool
}

func (t revokeRaceTx) Query(ctx context.Context, q string, args ...any) (storage.IdentityRows, error) {
	if strings.Contains(q, "FROM node_identity_requests WHERE actor_id=") && len(args) > 1 && args[1] == "node_revoke" {
		*t.read = true
	}
	return t.IdentityTx.Query(ctx, q, args...)
}
func (s *revokeRaceRepository) WriteIdentity(ctx context.Context, fn func(storage.IdentityTx) error) error {
	read := false
	e := s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return fn(revokeRaceTx{tx, &read}) })
	if e != nil || !read {
		return e
	}
	s.mu.Lock()
	s.reads++
	first := s.reads <= 2
	if s.reads == 2 {
		close(s.ready)
	}
	s.mu.Unlock()
	if first {
		select {
		case <-s.ready:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func TestConcurrentNodeRevokeIdempotency(t *testing.T) {
	f := setup(t, false)
	f.issued("node_one")
	repo := &revokeRaceRepository{store: f.store, ready: make(chan struct{})}
	coordinator := securitystate.New(repo, f.authority)
	service, e := New(coordinator, f.issuer, f.inventory, f.actor.Origin)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	type result struct {
		op  NodeOperation
		err error
	}
	out := make(chan result, 2)
	for range 2 {
		go func() {
			op, e := service.RevokeNode(ctx, f.actor, "node_one", "same_concurrent_key", RevokeNodeRequest{Reason: "retired"})
			out <- result{op, e}
		}()
	}
	results := []result{<-out, <-out}
	for _, r := range results {
		if errors.Is(r.err, securitystate.ErrBarrier) {
			r.op, r.err = service.RevokeNode(ctx, f.actor, "node_one", "same_concurrent_key", RevokeNodeRequest{Reason: "retired"})
		}
		if r.err != nil || r.op.State != "completed" {
			t.Fatal("concurrent idempotent revoke failed", r.err)
		}
	}
	if e = coordinator.Ready(ctx); e != nil {
		t.Fatal("same-key revoke stranded global pending barrier", e)
	}
	h, _ := f.authority.Head(ctx)
	if h.Sequence != 1 {
		t.Fatal("duplicate node revoke appended", h.Sequence)
	}
}

// This issuer wrapper interposes after the CP's approver check while its writer
// transaction is still open. Only the independent journal advances; the CP
// principal projection remains unchanged until replay, as after an emergency
// action that arrives between authorization and the issuer's fresh head read.
type restrictionBeforeIssue struct {
	Issuer
	authority *fakeAuthority
	kind      string
}

func (s *restrictionBeforeIssue) Issue(ctx context.Context, in IssueRequest) (CertificateResult, error) {
	h, e := s.authority.Head(ctx)
	if e != nil {
		return CertificateResult{}, e
	}
	if !in.AuthorizationHead.valid() || !in.AuthorizationHead.matches(h) {
		return CertificateResult{}, errors.New("CP did not pass its checked authorization head")
	}
	restriction := securityjournal.AppendRequest{OperationID: securitystate.ID("interpose"), ExpectedEpoch: h.Epoch, ExpectedSequence: h.Sequence, ExpectedDigest: h.Digest, Kind: s.kind, TargetType: "principal", TargetID: "admin", ActorID: "emergency_operator", AuthorizationDigest: hash([]byte("test-emergency-restriction")), RecordedAt: h.RecordedAt, Payload: securityjournal.Payload{PrincipalID: "admin"}}
	if s.kind == "raise_security_floor" {
		restriction.Payload.MinimumVersion = 2
	}
	if _, e = s.authority.Append(ctx, restriction); e != nil {
		return CertificateResult{}, e
	}
	return s.Issuer.Issue(ctx, in)
}
func TestEnrollmentIssuanceAuthorizationHeadFence(t *testing.T) {
	for _, kind := range []string{"block_principal", "raise_security_floor"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t, false)
			f.node("node_one")
			en := f.enrollment("node_one")
			in := EnrollmentSubmission{NodeID: "node_one", EnrollmentToken: en.EnrollmentToken, CSRPEM: mustCSR(t)}
			f.approve(in)
			f.service.issuer = &restrictionBeforeIssue{Issuer: f.issuer, authority: f.authority, kind: kind}
			if _, e := f.service.Enroll(f.ctx, in); !errors.Is(e, ErrDenied) {
				t.Fatal("issuer accepted authorization checked before a principal restriction", e)
			}
			var certificates int
			if e := f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&certificates); e != nil || certificates != 0 {
				t.Fatal("issuer minted an independently admitted certificate after stale CP authorization", certificates, e)
			}
			h, e := f.authority.Head(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			registry, e := f.issuer.Registry(f.ctx, h)
			if e != nil || len(registry.Nodes) != 0 {
				t.Fatal("rejected issuance entered authoritative registry", e)
			}
			if e = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				row, e := enrollmentBy(f.ctx, tx, "id", en.ID)
				if e != nil {
					return e
				}
				if row.State != "approved" || row.CertificateJSON != "" {
					t.Fatal("CP marked rejected issuance complete", row.State)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			// Once the emergency restriction is projected, a retry fails its approver
			// check before reaching the signer and still cannot mint a certificate.
			if e = f.coordinator.Replay(f.ctx); e != nil {
				t.Fatal(e)
			}
			f.service.issuer = f.issuer
			if _, e = f.service.Enroll(f.ctx, in); !errors.Is(e, ErrDenied) {
				t.Fatal("replayed restriction did not invalidate pending approval", e)
			}
		})
	}
}
