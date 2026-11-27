package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

// Unit tests use a fixed authority to exercise the HTTP boundary without
// weakening production's authenticated journal client or PostgreSQL requirement.
type httpIdentityAuthority struct{}

type unavailableHTTPAuthority struct{ httpIdentityAuthority }

func (unavailableHTTPAuthority) Head(context.Context) (securityjournal.Head, error) {
	return securityjournal.Head{}, securityjournal.ErrUnavailable
}

func (httpIdentityAuthority) Head(context.Context) (securityjournal.Head, error) {
	return securityjournal.Head{AuthorityID: "http_test", Epoch: 1, RecordedAt: time.Now().UTC()}, nil
}
func (httpIdentityAuthority) Append(context.Context, securityjournal.AppendRequest) (securityjournal.Event, error) {
	return securityjournal.Event{}, errors.New("unexpected security mutation in HTTP boundary test")
}
func (httpIdentityAuthority) Operation(context.Context, string) (securityjournal.Event, error) {
	return securityjournal.Event{}, securityjournal.ErrNotFound
}
func (httpIdentityAuthority) Events(context.Context, securityjournal.UInt63, int) ([]securityjournal.Event, error) {
	return nil, nil
}

func secureHTTPFixture(t *testing.T) *Server {
	t.Helper()
	store, err := sqlite.Open(t.TempDir() + "/http.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("synthetic-http-test-password", auth.DefaultArgon2idParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "root", DisplayName: "Test", PasswordHash: hash, IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DatabaseDriver: "postgres", SecureProfile: true, PortalHost: "portal.test", LoginOrigin: "https://login.test", ManagementOrigin: "https://management.test", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour, LoginRateLimitMax: 30, LoginRateLimitWind: time.Minute, MFAKeyFile: "/synthetic-keyring", AuthMTLSAddr: "127.0.0.1:0", AuthMTLSCertFile: "/synthetic-cert", AuthMTLSKeyFile: "/synthetic-key", AuthMTLSClientCAFile: "/synthetic-ca"}
	if _, err := store.ApplySessionProfile(ctx, cfg.SessionProfile()); err != nil {
		t.Fatal(err)
	}
	coordinator := securitystate.New(store, httpIdentityAuthority{})
	if err := coordinator.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	keys := &identity.Keyring{Active: "test", Keys: map[string]string{"test": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32))}}
	service, err := identity.New(store, coordinator, keys, cfg.SessionProfile())
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetIdentity(service)
	return s
}

func identityHTTPRequest(t *testing.T, handler http.Handler, method, host, path string, body any, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, "https://"+host+path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestSecureProfileFlowBoundary(t *testing.T) {
	s := secureHTTPFixture(t)
	handler := s.Handler()
	bootstrap := identityHTTPRequest(t, handler, http.MethodGet, "management.test", "/auth/v2/bootstrap", nil, nil, nil)
	if bootstrap.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", bootstrap.Code, bootstrap.Body.String())
	}
	var settings map[string]string
	if err := json.Unmarshal(bootstrap.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	csrf := settings["csrfToken"]
	if !validFlowToken(csrf) || settings["csrfCookieName"] != flowCSRFCookie || settings["audience"] != "management" || settings["loginUrl"] != s.cfg.LoginOrigin {
		t.Fatalf("bootstrap contract: %v", settings)
	}
	cookies := bootstrap.Result().Cookies()
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.HttpOnly {
			t.Fatalf("prelogin csrf cookie scope: %#v", cookie)
		}
	}
	input := map[string]string{"purpose": "login", "audience": "management"}
	for _, bad := range []map[string]string{{}, {"Origin": "https://portal.test", "X-CSRF-Token": csrf}, {"Origin": s.cfg.ManagementOrigin}, {"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": strings.Repeat("A", 43)}} {
		w := identityHTTPRequest(t, handler, http.MethodPost, "management.test", "/auth/v2/flows", input, cookies, bad)
		if w.Code != http.StatusForbidden {
			t.Fatalf("accepted invalid prelogin CSRF/origin: %d %s", w.Code, w.Body.String())
		}
	}
	headers := map[string]string{"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": csrf}
	w := identityHTTPRequest(t, handler, http.MethodPost, "management.test", "/auth/v2/flows", input, cookies, headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	var flow identity.FlowView
	if err := json.Unmarshal(w.Body.Bytes(), &flow); err != nil {
		t.Fatal(err)
	}
	beforePrimaryBinding := cookieValue(w.Result().Cookies(), flowBindingCookie)
	if !validFlowToken(beforePrimaryBinding) {
		t.Fatal("missing pending binding")
	}
	for _, c := range w.Result().Cookies() {
		if !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" {
			t.Fatalf("pending scope: %#v", c)
		}
	}
	cookies = append(cookies, w.Result().Cookies()...)
	path := "/auth/v2/flows/" + flow.ID
	w = identityHTTPRequest(t, handler, http.MethodPost, "management.test", path+"/primary-proofs", map[string]string{"method": "local_password", "username": "root", "password": "synthetic-http-test-password"}, cookies, headers)
	if w.Code != http.StatusOK {
		t.Fatalf("primary: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &flow); err != nil {
		t.Fatal(err)
	}
	if flow.State != "pending_mfa" || flow.MFASatisfied || flow.NextStep != "totp_enrollment" {
		t.Fatalf("primary bypassed MFA: %+v", flow)
	}
	afterPrimaryBinding := cookieValue(w.Result().Cookies(), flowBindingCookie)
	if !validFlowToken(afterPrimaryBinding) || afterPrimaryBinding == beforePrimaryBinding {
		t.Fatal("primary did not rotate binding")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == domain.ManagementSessionCookieName || c.Name == domain.LoginSessionCookieName {
			t.Fatal("primary issued authenticated cookie")
		}
	}
	old := identityHTTPRequest(t, handler, http.MethodGet, "management.test", path, nil, cookies, nil)
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("old binding remained valid: %d", old.Code)
	}

	rotatedPath := "/auth/v2/flows/" + flow.ID
	if rotatedPath == path {
		t.Fatal("primary did not rotate flow ID")
	}
	oldIDNewBinding := identityHTTPRequest(t, handler, http.MethodGet, "management.test", path, nil, []*http.Cookie{{Name: flowBindingCookie, Value: afterPrimaryBinding}}, nil)
	if oldIDNewBinding.Code != http.StatusUnauthorized {
		t.Fatal("old flow ID accepted new binding")
	}
	path = rotatedPath
	cookies = []*http.Cookie{{Name: flowCSRFCookie, Value: csrf}, {Name: flowBindingCookie, Value: afterPrimaryBinding}}
	for _, protected := range []string{"/api/v1/me", "/api/v1/admin/users", "/api/v1/admin/dashboard"} {
		w := identityHTTPRequest(t, handler, http.MethodGet, "management.test", protected, nil, cookies, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("pending flow authorized %s: %d %s", protected, w.Code, w.Body.String())
		}
	}
	w = identityHTTPRequest(t, handler, http.MethodPost, "management.test", path+"/completions", struct{}{}, cookies, headers)
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("first-factor completion bypass: %d %s", w.Code, w.Body.String())
	}
	w = identityHTTPRequest(t, handler, http.MethodPost, "management.test", "/api/v1/auth/login", map[string]string{"username": "root", "password": "synthetic-http-test-password"}, cookies, headers)
	if w.Code < 400 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("legacy password bypass: %d %s", w.Code, w.Body.String())
	}
	w = identityHTTPRequest(t, handler, http.MethodGet, "login.test", path, nil, cookies, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-origin pending audience accepted: %d", w.Code)
	}
	w = identityHTTPRequest(t, handler, http.MethodGet, "portal.test", path, nil, cookies, map[string]string{"X-Forwarded-Host": "management.test"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("forwarded host selected flow authority: %d", w.Code)
	}
	duplicate := append(append([]*http.Cookie{}, cookies...), &http.Cookie{Name: flowBindingCookie, Value: beforePrimaryBinding})
	w = identityHTTPRequest(t, handler, http.MethodGet, "management.test", path, nil, duplicate, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ambiguous pending cookie accepted: %d", w.Code)
	}
	w = identityHTTPRequest(t, handler, http.MethodPost, "management.test", path+"/cancellations", struct{}{}, cookies, headers)
	if w.Code != http.StatusOK || cookieValue(w.Result().Cookies(), flowBindingCookie) != "" {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
}

func TestSecureProfileAudienceAndPublicRedeem(t *testing.T) {
	s := secureHTTPFixture(t)
	h := s.Handler()
	for _, host := range []string{"management.test", "login.test"} {
		w := identityHTTPRequest(t, h, http.MethodPost, host, "/auth/v2/handoffs/redeem", map[string]string{}, nil, map[string]string{"X-AGP-Node": "node", "X-SSL-Client-Verify": "SUCCESS"})
		if w.Code != http.StatusForbidden {
			t.Fatalf("public redeem trusted headers: %d", w.Code)
		}
	}
	w := identityHTTPRequest(t, h, http.MethodGet, "login.test", "/auth/v2/bootstrap", nil, nil, nil)
	csrf := cookieValue(w.Result().Cookies(), flowCSRFCookie)
	w = identityHTTPRequest(t, h, http.MethodPost, "login.test", "/auth/v2/flows", map[string]string{"purpose": "login", "audience": "management"}, w.Result().Cookies(), map[string]string{"Origin": "https://login.test", "X-CSRF-Token": csrf})
	if w.Code != http.StatusForbidden {
		t.Fatalf("login origin selected management audience: %d", w.Code)
	}
	q := url.Values{"gatewayId": {"gateway"}, "redirectUri": {"https://app.test/_agp/callback"}, "state": {"state"}, "codeChallenge": {strings.Repeat("A", 43)}, "codeChallengeMethod": {"S256"}}
	w = identityHTTPRequest(t, h, http.MethodGet, "login.test", "/auth/v2/authorize?"+q.Encode(), nil, nil, nil)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/auth-ui/login?return=") {
		t.Fatalf("handoff login continuation: %d %s", w.Code, w.Header().Get("Location"))
	}
	q.Add("gatewayId", "other")
	w = identityHTTPRequest(t, h, http.MethodGet, "login.test", "/auth/v2/authorize?"+q.Encode(), nil, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous handoff query: %d", w.Code)
	}
}

func TestSecureProfileRejectsAmbiguousJSONAndUnavailableAuthority(t *testing.T) {
	s := secureHTTPFixture(t)
	h := s.Handler()
	w := identityHTTPRequest(t, h, http.MethodGet, "login.test", "/auth/v2/bootstrap", nil, nil, nil)
	cookies := w.Result().Cookies()
	csrf := cookieValue(cookies, flowCSRFCookie)
	for _, payload := range []string{
		`{"purpose":"login","audience":"login","audience":"management"}`,
		`{"purpose":"login","audience":"login","extra":true}`,
		`{"purpose":"login","audience":"login"} {}`,
		`null`,
		`[]`,
		`{"purpose":"` + strings.Repeat("x", 17000) + `","audience":"login"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "https://login.test/auth/v2/flows", strings.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", s.cfg.LoginOrigin)
		r.Header.Set("X-CSRF-Token", csrf)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		if out.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous body accepted: status=%d size=%d", out.Code, len(payload))
		}
	}
	s.identity.Coordinator.Authority = unavailableHTTPAuthority{}
	w = identityHTTPRequest(t, h, http.MethodGet, "login.test", "/auth/v2/bootstrap", nil, nil, nil)
	if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
		t.Fatalf("authority outage issued bootstrap: %d %s", w.Code, w.Body.String())
	}
	var problem map[string]any
	if json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem["code"] != "security_state_unavailable" || problem["retryable"] != true || w.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("redacted Problem contract: %s", w.Body.String())
	}
}

func TestSecureProfileEdgeActualMTLS(t *testing.T) {
	s := secureHTTPFixture(t)
	serverTLS, makeClient := edgeHTTPTestPKI(t)
	srv := httptest.NewUnstartedServer(s.EdgeHandler())
	srv.TLS = serverTLS
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	for _, tc := range []struct {
		name, role string
		extra      bool
		want       int
	}{
		{"edge", "spiffe://agp/edge/node/gateway", false, http.StatusBadRequest},
		{"wrong role", "spiffe://agp/control-plane/writer", false, http.StatusForbidden},
		{"multiple identities", "spiffe://agp/edge/node/gateway", true, http.StatusForbidden},
		{"escaped identity", "spiffe://agp/edge/node/gate%77ay", false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: makeClient(tc.role, tc.extra)}, Timeout: 3 * time.Second}
			defer client.CloseIdleConnections()
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/v2/decisions", strings.NewReader(`{"unknown":"field"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.want {
				raw, _ := io.ReadAll(response.Body)
				t.Fatalf("role check: %d %s", response.StatusCode, raw)
			}
		})
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: makeClient("spiffe://agp/edge/node/gateway", false)}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/v2/decisions", strings.NewReader(`{"gatewayId":"other"}`))
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("certificate selected another gateway: %d", response.StatusCode)
	}
	plain := identityHTTPRequest(t, s.EdgeHandler(), http.MethodPost, "login.test", "/auth/v2/decisions", struct{}{}, nil, map[string]string{"X-SSL-Client-Verify": "SUCCESS", "X-Client-Cert": "verified"})
	if plain.Code != http.StatusForbidden {
		t.Fatalf("HTTP certificate headers accepted: %d", plain.Code)
	}
	without := makeClient("spiffe://agp/edge/node/gateway", false)
	without.Certificates = nil
	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: without}, Timeout: 3 * time.Second}
	defer noCertClient.CloseIdleConnections()
	if response, err := noCertClient.Post(srv.URL+"/auth/v2/decisions", "application/json", strings.NewReader(`{}`)); err == nil {
		response.Body.Close()
		t.Fatalf("TLS accepted no client certificate: %d", response.StatusCode)
	}
}

func edgeHTTPTestPKI(t *testing.T, clientTTL ...time.Duration) (*tls.Config, func(string, bool) *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic HTTP edge CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	serial := int64(2)
	certificate := func(role string, extra bool) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		serial++
		if role == "" {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tpl.DNSNames = []string{"auth.test"}
		} else {
			if len(clientTTL) != 0 {
				tpl.NotAfter = now.Add(clientTTL[0])
			}
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			u, err := url.Parse(role)
			if err != nil {
				t.Fatal(err)
			}
			tpl.URIs = []*url.URL{u}
			if extra {
				another, _ := url.Parse("spiffe://agp/edge/other/gateway")
				tpl.URIs = append(tpl.URIs, another)
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	server := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{certificate("", false)}}
	return server, func(role string, extra bool) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "auth.test", RootCAs: roots, Certificates: []tls.Certificate{certificate(role, extra)}}
	}
}

func TestEdgeKeepAliveRejectsExpiredClientCertificate(t *testing.T) {
	serverTLS, clientTLS := edgeHTTPTestPKI(t, 3*time.Second)
	api := NewServer(config.Config{SecureProfile: true}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewUnstartedServer(api.EdgeHandler())
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	clientConfig := clientTLS("spiffe://agp/edge/node/gateway", false)
	leaf, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientConfig}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	request := func(want int, wantReuse bool) {
		t.Helper()
		reused := false
		req, err := http.NewRequest(http.MethodPost, server.URL+"/auth/v2/decisions", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != want || reused != wantReuse {
			t.Fatalf("status=%d reused=%v, want %d/%v", response.StatusCode, reused, want, wantReuse)
		}
	}
	// Valid identity reaches the unavailable identity runtime. The subsequent
	// request must be rejected by peer validation on that exact same connection.
	request(http.StatusServiceUnavailable, false)
	time.Sleep(max(0, time.Until(leaf.NotAfter)+100*time.Millisecond))
	request(http.StatusForbidden, true)
}
