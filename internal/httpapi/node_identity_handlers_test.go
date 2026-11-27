package httpapi

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/nodeidentity"
)

func enrollmentTestServer() *Server {
	s := NewServer(config.Config{SecureProfile: true, ConfigurationEnabled: true, NodeIdentityConfig: "/etc/agp/identity.json"}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Malformed bodies and ingress boundaries must be rejected before the
	// unconfigured service could reach a database or parse a CSR.
	s.SetNodeIdentity(new(nodeidentity.Service))
	return s
}

func TestEnrollmentIngressRealTLSAndSourceLimits(t *testing.T) {
	s := enrollmentTestServer()
	server := httptest.NewUnstartedServer(s.EnrollmentHandler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	for i := 0; i < 13; i++ {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/agent/v1/enrollment-requests", strings.NewReader(`{"unexpected":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+1))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		want := 400
		if i == 12 {
			want = 429
		}
		if resp.StatusCode != want {
			t.Fatalf("request %d: got%d want%d", i, resp.StatusCode, want)
		}
	}
	for _, header := range []string{"Origin", "Cookie", "Authorization"} {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/agent/v1/enroll", strings.NewReader("{}"))
		req.Header.Set(header, "forged-authority")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("%s accepted", header)
		}
	}
	for _, path := range []string{"//agent/v1/enroll", "/agent/v1/identities/renew", "/api/v2/nodes", "/agent/v1/enroll?token=secret"} {
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader("{}"))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("unexpected enrollment path accepted: %s", path)
		}
	}
}

type heldEnrollmentBody struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (b *heldEnrollmentBody) Read([]byte) (int, error) {
	b.entered <- struct{}{}
	<-b.release
	return 0, io.EOF
}
func (b *heldEnrollmentBody) Close() error { return nil }
func TestEnrollmentAdmissionBoundsBodyWork(t *testing.T) {
	s := enrollmentTestServer()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest("POST", "https://enrollment.test/agent/v1/enroll", nil)
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:3000", i+1)
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			r.Header.Set("Content-Type", "application/json")
			r.Body = &heldEnrollmentBody{entered, release}
			s.EnrollmentHandler().ServeHTTP(httptest.NewRecorder(), r)
		}(i)
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("body admission stalled")
		}
	}
	r := httptest.NewRequest("POST", "https://enrollment.test/agent/v1/enroll", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.9:3000"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.EnrollmentHandler().ServeHTTP(w, r)
	close(release)
	wg.Wait()
	if w.Code != 503 {
		t.Fatalf("fifth concurrent CSR admitted: %d", w.Code)
	}
	a := newEnrollmentAdmission()
	now := time.Now()
	for i := 0; i < 1024; i++ {
		if !a.allow(fmt.Sprintf("198.18.%d.%d:3000", i/256, i%256), now) {
			t.Fatal("unexpected early bucket exhaustion")
		}
	}
	if a.allow("192.0.2.99:3000", now) {
		t.Fatal("unbounded source map")
	}
	if !a.allow("192.0.2.99:3000", now.Add(time.Minute)) {
		t.Fatal("expired source slots retained")
	}
}
