package securityjournal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func nativeStore(t *testing.T) (*Store, ed25519.PrivateKey) {
	t.Helper()
	dsn := os.Getenv("AGP_TEST_JOURNAL_DSN")
	if dsn == "" {
		t.Skip("native independent journal PostgreSQL required: scripts/test-s0-full.sh")
	}
	id, e := randomID("test_")
	if e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub, approval, _ := ed25519.GenerateKey(rand.Reader)
	s, e := Open(context.Background(), StoreConfig{DSN: dsn, AuthorityID: id, KeyID: "signer", SigningKey: key, ApprovalKeys: map[string]ApprovalKey{"recovery": {PrincipalID: "other_admin", PublicKey: pub, AllowedKinds: []string{"unblock_principal", "advance_authority_epoch"}}}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return s, approval
}
func TestJournalNativeTransactions(t *testing.T) {
	s, approval := nativeStore(t)
	ctx := context.Background()
	head, e := s.Head(ctx)
	if e != nil {
		t.Fatal(e)
	}
	r := fixtureRequest(t, head, "block_principal")
	var wg sync.WaitGroup
	results := make(chan Event, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ev, e := s.Append(ctx, r); results <- ev; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first Event
	for ev := range results {
		if first.ID == "" {
			first = ev
		}
		if ev.ID != first.ID || ev.Signature != first.Signature || ev.Sequence != 1 {
			t.Fatal("idempotency allocated multiple receipts")
		}
	}
	changed := r
	changed.ActorID = "different"
	if _, e = s.Append(ctx, changed); !errors.Is(e, ErrConflict) {
		t.Fatalf("changed request: %v", e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE agp_security_journal.events SET kind='unblock_principal' WHERE authority_id=$1`, s.cfg.AuthorityID); e == nil {
		t.Fatal("event update allowed")
	}
	head, _ = s.Head(ctx)
	floor := fixtureRequest(t, head, "bump_authenticator_floor")
	floor.TargetType = "authenticator"
	floor.TargetID = "pw_usr_test"
	floor.Payload = Payload{PrincipalID: "usr_test", AuthenticatorID: floor.TargetID, MinimumVersion: 2}
	if _, e = s.Append(ctx, floor); e != nil {
		t.Fatal(e)
	}
	head, _ = s.Head(ctx)
	floor.OperationID, _ = randomID("op_")
	floor.ExpectedSequence = head.Sequence
	floor.ExpectedDigest = head.Digest
	floor.Payload.MinimumVersion = 1
	if _, e = s.Append(ctx, floor); !errors.Is(e, ErrConflict) {
		t.Fatalf("lower floor: %v", e)
	}
	lift := fixtureRequest(t, head, "unblock_principal")
	lift.Payload.OriginalEventID = first.ID
	if _, e = s.Append(ctx, lift); e == nil {
		t.Fatal("unsigned lift accepted")
	}
	lift.ApproverID = "other_admin"
	lift.ApprovalKeyID = "recovery"
	if e = SignApproval(&lift, approval); e != nil {
		t.Fatal(e)
	}

	alias := lift
	alias.ApproverID = "alias_of_actor"
	if e = SignApproval(&alias, approval); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Append(ctx, alias); e == nil {
		t.Fatal("approver key impersonated another principal")
	}
	expired := lift
	expired.RecordedAt = time.Now().Add(-10 * time.Minute)
	if e = SignApproval(&expired, approval); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Append(ctx, expired); e == nil {
		t.Fatal("expired signed lift accepted")
	}
	if _, e = s.Append(ctx, lift); e != nil {
		t.Fatal(e)
	}
	head, _ = s.Head(ctx)
	restore := fixtureRequest(t, head, "advance_authority_epoch")
	restore.TargetType = "authority"
	restore.TargetID = s.cfg.AuthorityID
	cutoff := time.Now().UTC()
	restore.Payload = Payload{NewEpoch: head.Epoch + 1, RestoreCutoff: cutoff, ReleaseAfter: cutoff.Add(95 * time.Second)}
	restore.ApproverID = "other_admin"
	restore.ApprovalKeyID = "recovery"
	if e = SignApproval(&restore, approval); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Append(ctx, restore); e != nil {
		t.Fatal(e)
	}
	after, e := s.Head(ctx)
	if e != nil || after.Epoch != 2 || after.Sequence != 4 || !after.ReleaseAfter.Equal(restore.Payload.ReleaseAfter.Truncate(time.Microsecond)) { // PG truncates timestamptz to microseconds; compare below with tolerance.
		if e != nil || after.Epoch != 2 || after.Sequence != 4 || after.ReleaseAfter.Sub(restore.Payload.ReleaseAfter) > time.Microsecond || restore.Payload.ReleaseAfter.Sub(after.ReleaseAfter) > time.Microsecond {
			t.Fatalf("restore head mismatch %+v %v", after, e)
		}
	}

	// UPDATE on the authority projection must not turn the service into a
	// signing oracle for a shorter restore quarantine.
	if _, e = s.pool.Exec(ctx, `UPDATE agp_security_journal.authorities SET release_after=restore_cutoff,row_version=row_version+1 WHERE id=$1`, s.cfg.AuthorityID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Head(ctx); e == nil {
		t.Fatal("signed shortened mutable restore quarantine")
	}
	if _, e = s.pool.Exec(ctx, `UPDATE agp_security_journal.authorities SET release_after=$2,row_version=row_version+1 WHERE id=$1`, s.cfg.AuthorityID, restore.Payload.ReleaseAfter); e != nil {
		t.Fatal(e)
	}
	if e = s.ValidateChain(ctx); e != nil {
		t.Fatal(e)
	}
	events, e := s.Events(ctx, 0, 100)
	if e != nil || len(events) != 4 {
		t.Fatalf("replay %d: %v", len(events), e)
	}
	// Historical actors are not referenced to or recreated in a CP user table.
	if events[0].Request.ActorID != "usr_admin" {
		t.Fatal("history lost")
	}
}
func TestJournalNativeMTLSAndLostResponse(t *testing.T) {
	s, _ := nativeStore(t)
	serverTLS, clientTLS := testPKI(t)
	handler := Handler(s, ServerConfig{ReadClientURIs: []string{"spiffe://agp/control-plane"}, AppendClientURIs: []string{"spiffe://agp/control-plane"}})
	var lose bool
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lost := lose && r.Method == "POST"
		if lost {
			lose = false
		}
		mu.Unlock()
		if lost {
			var req AppendRequest
			if e := strictJSON(r.Body, &req); e != nil {
				t.Error(e)
				return
			}
			if _, e := s.Append(r.Context(), req); e != nil {
				t.Error(e)
				return
			}
			conn, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			conn.Close()
			return
		}
		handler.ServeHTTP(w, r)
	}))
	srv.TLS = serverTLS
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client, e := NewClient(ClientConfig{URL: srv.URL, AuthorityID: s.cfg.AuthorityID, KeyID: s.cfg.KeyID, PublicKey: s.cfg.SigningKey.Public().(ed25519.PublicKey), TLSConfig: clientTLS})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.CloseIdleConnections)
	head, e := client.Head(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	req := fixtureRequest(t, head, "block_principal")
	mu.Lock()
	lose = true
	mu.Unlock()
	if _, e = client.Append(context.Background(), req); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("lost response %v", e)
	}
	ev, e := client.Operation(context.Background(), req.OperationID)
	if e != nil || ev.Sequence != 1 {
		t.Fatalf("lookup failed: %v", e)
	}
	again, e := client.Append(context.Background(), req)
	if e != nil || again.Signature != ev.Signature {
		t.Fatalf("retry changed receipt: %v", e)
	}
	page, e := client.Events(context.Background(), 0, 100)
	if e != nil || len(page) != 1 {
		t.Fatalf("verified replay: %v", e)
	}
	noCert := clientTLS.Clone()
	noCert.Certificates = nil
	h := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert}, Timeout: time.Second}
	if response, e := h.Get(srv.URL + "/checkpoint/v1/head?challenge=x"); e == nil {
		response.Body.Close()
		t.Fatal("certificate-free access accepted")
	}
	h.CloseIdleConnections()
	// A valid mTLS identity with the wrong URI role is denied.
	wrong := httptest.NewUnstartedServer(Handler(s, ServerConfig{ReadClientURIs: []string{"spiffe://agp/other-service"}}))
	wrongTLS := serverTLS.Clone()
	wrongTLS.ClientAuth = tls.RequireAndVerifyClientCert
	wrong.TLS = wrongTLS
	wrong.StartTLS()
	t.Cleanup(wrong.Close)
	goodH := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: time.Second}
	resp, e := goodH.Get(wrong.URL + "/checkpoint/v1/head?challenge=" + strings.Repeat("a", 43))
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong service role status %d", resp.StatusCode)
	}
	goodH.CloseIdleConnections()
	readOnly := httptest.NewUnstartedServer(Handler(s, ServerConfig{ReadClientURIs: []string{"spiffe://agp/control-plane"}}))
	readOnly.TLS = serverTLS.Clone()
	readOnly.StartTLS()
	defer readOnly.Close()
	reader, e := NewClient(ClientConfig{URL: readOnly.URL, AuthorityID: s.cfg.AuthorityID, KeyID: s.cfg.KeyID, PublicKey: s.cfg.SigningKey.Public().(ed25519.PublicKey), TLSConfig: clientTLS})
	if e != nil {
		t.Fatal(e)
	}
	defer reader.CloseIdleConnections()
	if _, e = reader.Head(context.Background()); e != nil {
		t.Fatalf("read-only Head: %v", e)
	}
	if _, e = reader.Events(context.Background(), 0, 100); e != nil {
		t.Fatalf("read-only Events: %v", e)
	}
	current, e := reader.Head(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reader.Append(context.Background(), fixtureRequest(t, current, "block_principal")); e == nil {
		t.Fatal("read-only mTLS principal appended an event")
	}

}
func testPKI(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "S0 synthetic journal CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	makeCert := func(serial int64, client bool) tls.Certificate {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			u, _ := url.Parse("spiffe://agp/control-plane")
			tpl.URIs = []*url.URL{u}
		} else {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tpl.DNSNames = []string{"journal.test"}
		}
		der, e := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		if e != nil {
			t.Fatal(e)
		}
		return pair
	}
	return &tls.Config{Certificates: []tls.Certificate{makeCert(2, false)}, MinVersion: tls.VersionTLS13, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, &tls.Config{Certificates: []tls.Certificate{makeCert(3, true)}, MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "journal.test"}
}
