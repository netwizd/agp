package edgeauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(upstream string) Config {
	return Config{NodeID: "node_one", GatewayID: "gw_one", Origin: "https://app.example", LoginOrigin: "https://login.example", CentralOrigin: "https://central.example", DeploymentGeneration: "dep_000017", Routes: []Route{{ID: "route_one", PathPrefix: "/", Upstream: upstream, ApplicationCookies: []string{"app_sid"}}}}
}
func testToken(t *testing.T) string {
	t.Helper()
	s, e := randomToken()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func testStore(t *testing.T) *StateStore {
	t.Helper()
	s, e := OpenStateStore(context.Background(), filepath.Join(privateTestDir(t), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func edgeRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, "https://app.example"+path, nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-AGP-Client-IP", "192.0.2.10")
	return r
}

type fakeCentral struct {
	decide func(context.Context, DecisionRequest) (Decision, error)
	redeem func(context.Context, RedeemRequest) (RedeemResponse, error)
	logout func(context.Context, string, string) error
}

func (f fakeCentral) Decide(c context.Context, r DecisionRequest) (Decision, error) {
	if f.decide == nil {
		return Decision{}, fmt.Errorf("not available")
	}
	return f.decide(c, r)
}
func (f fakeCentral) Redeem(c context.Context, r RedeemRequest) (RedeemResponse, error) {
	if f.redeem == nil {
		return RedeemResponse{}, fmt.Errorf("not available")
	}
	return f.redeem(c, r)
}
func (f fakeCentral) Logout(c context.Context, g, t string) error {
	if f.logout == nil {
		return fmt.Errorf("not available")
	}
	return f.logout(c, g, t)
}
func testServer(t *testing.T, c Config, f Central) *Server {
	t.Helper()
	s, e := NewServer(c, testStore(t), f)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}

func TestPendingStoreDurabilityAndAtomicConsume(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(privateTestDir(t), "state.db")
	s, e := OpenStateStore(ctx, filename)
	if e != nil {
		t.Fatal(e)
	}
	p := Pending{State: testToken(t), Binding: testToken(t), Verifier: testToken(t), ReturnPath: "/dashboard?tab=one", Profile: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Minute)}
	if e = s.Create(ctx, p); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenStateStore(ctx, filename)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Consume(ctx, p.State, testToken(t), p.Profile, time.Now()); e != ErrPending {
		t.Fatalf("wrong binding accepted: %v", e)
	}
	if _, e = s.Consume(ctx, p.State, p.Binding, strings.Repeat("b", 64), time.Now()); e != ErrPending {
		t.Fatalf("changed deployment accepted: %v", e)
	}
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, e := s.Consume(ctx, p.State, p.Binding, p.Profile, time.Now())
			if e == nil {
				successes.Add(1)
				if got.Verifier != p.Verifier || got.ReturnPath != p.ReturnPath {
					t.Error("pending state changed")
				}
			} else if e != ErrPending {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}
	p.State = testToken(t)
	if e = s.Create(ctx, p); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Consume(ctx, p.State, p.Binding, p.Profile, time.Now().Add(2*time.Minute)); e != ErrPending {
		t.Fatalf("expired state accepted: %v", e)
	}
}

func TestBrowserHandoffBindingPKCEAndReplay(t *testing.T) {
	var redemptions int
	var challenge string
	sessionToken := testToken(t)
	f := fakeCentral{redeem: func(_ context.Context, in RedeemRequest) (RedeemResponse, error) {
		redemptions++
		sum := sha256.Sum256([]byte(in.CodeVerifier))
		if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || in.GatewayID != "gw_one" || in.RedirectURI != "https://app.example"+CallbackPath {
			t.Errorf("unbound redemption: %+v", in)
		}
		return RedeemResponse{SessionToken: sessionToken, SessionID: "session_one", UserID: "usr_one", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}}
	s := testServer(t, testConfig("http://127.0.0.1:8081"), f)
	start := httptest.NewRecorder()
	s.Handler().ServeHTTP(start, edgeRequest("GET", StartPath+"?return=%2Fdashboard%3Ftab%3Done"))
	if start.Code != 303 {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	location, e := url.Parse(start.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	if location.Scheme+"://"+location.Host != "https://login.example" || location.Path != "/auth/v2/authorize" {
		t.Fatal(location)
	}
	q := location.Query()
	challenge = q.Get("codeChallenge")
	if q.Get("codeChallengeMethod") != "S256" || !validToken(q.Get("state")) {
		t.Fatal(q)
	}
	var binding *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == PendingCookie {
			binding = c
		}
	}
	if binding == nil || !binding.Secure || !binding.HttpOnly || binding.Path != "/" || binding.Domain != "" {
		t.Fatal("insecure binding cookie")
	}
	callback := CallbackPath + "?" + url.Values{"state": {q.Get("state")}, "code": {testToken(t)}}.Encode()
	bad := edgeRequest("GET", callback)
	bad.AddCookie(&http.Cookie{Name: PendingCookie, Value: testToken(t)})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, bad)
	if w.Code != 400 || redemptions != 0 {
		t.Fatal("foreign browser redeemed")
	}
	good := edgeRequest("GET", callback)
	good.AddCookie(binding)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, good)
	if w.Code != 303 || w.Header().Get("Location") != "/dashboard?tab=one" || redemptions != 1 {
		t.Fatalf("callback failed %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("callback can leak code")
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == GatewayCookie {
			found = c.Value == sessionToken && c.Secure && c.HttpOnly && c.Domain == "" && c.Path == "/"
		}
	}
	if !found {
		t.Fatal("missing host-only gateway session")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, good)
	if w.Code != 400 || redemptions != 1 {
		t.Fatal("callback replay accepted")
	}
	for _, returnPath := range []string{"//evil.example/", "/../admin", "/%2f%2fevil.example", "/\\evil", "/_agp/callback", "https://evil.example/"} {
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, edgeRequest("GET", StartPath+"?"+url.Values{"return": {returnPath}}.Encode()))
		if w.Code != 400 {
			t.Errorf("unsafe return path accepted %q: %d", returnPath, w.Code)
		}
	}
}

func TestDecisionStatusAdapterFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision Decision
		err      error
		want     int
	}{
		{"allow", Decision{Decision: "allow", ReasonCode: "allowed", SecuritySequence: 7, UserID: "usr_one", GroupIDs: []string{"grp_one"}}, nil, 204},
		{"auth", Decision{Decision: "deny", ReasonCode: "authentication_required", SecuritySequence: 7}, nil, 401},
		{"expired", Decision{Decision: "deny", ReasonCode: "session_expired", SecuritySequence: 7}, nil, 401},
		{"mfa", Decision{Decision: "deny", ReasonCode: "mfa_required", SecuritySequence: 7}, nil, 401},
		{"denied", Decision{Decision: "deny", ReasonCode: "access_denied", SecuritySequence: 7}, nil, 403},
		{"unknown", Decision{Decision: "deny", ReasonCode: "unknown", SecuritySequence: 7}, nil, 503},
		{"identity_injection", Decision{Decision: "allow", ReasonCode: "allowed", UserID: "usr_one\r\nInjected: yes", GroupIDs: []string{}}, nil, 503},
		{"dependency", Decision{}, fmt.Errorf("offline"), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fakeCentral{decide: func(_ context.Context, in DecisionRequest) (Decision, error) {
				if in.GatewayID != "gw_one" || in.RouteID != "route_one" || in.DeploymentGeneration != "dep_000017" || in.Method != "POST" || in.Path != "/data?one=two" {
					t.Errorf("incorrect deployment context: %+v", in)
				}
				return tc.decision, tc.err
			}}
			s := testServer(t, testConfig("http://127.0.0.1:8081"), f)
			r := edgeRequest("GET", AuthorizePath)
			r.Header.Set("X-AGP-Original-URI", "/data?one=two")
			r.Header.Set("X-AGP-Original-Method", "POST")
			r.AddCookie(&http.Cookie{Name: GatewayCookie, Value: testToken(t)})
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want%d", w.Code, tc.want)
			}
			if tc.want != 204 && w.Header().Get("X-AGP-User-ID") != "" {
				t.Fatal("identity emitted for deny")
			}
		})
	}
}

func TestProxyFiltersCredentialsAndResponseCookies(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AGP-User-ID") != "usr_checked" || r.Header.Get("X-AGP-Groups") != "grp_checked" || r.Header.Get("X-AGP-User") != "" || r.Header.Get("X-AGP-Evil") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Errorf("spoofed headers reached upstream: %v", r.Header)
		}
		if got := r.Header.Get("Cookie"); got != "app_sid=app_value" {
			t.Errorf("credential cookie leak: %s", got)
		}
		for _, c := range []string{"app_sid=good; Path=/; Secure; HttpOnly", "app_sid=parent; Domain=example; Path=/", "__Host-agp_gateway=stolen; Path=/; Secure; HttpOnly", "agp_session=stolen; Path=/", "unknown=blocked; Path=/"} {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Set("X-AGP-User-ID", "usr_injected")
		_, _ = io.WriteString(w, "ok")
	}))
	defer app.Close()
	f := fakeCentral{decide: func(context.Context, DecisionRequest) (Decision, error) {
		return Decision{Decision: "allow", ReasonCode: "allowed", UserID: "usr_checked", GroupIDs: []string{"grp_checked"}, SecuritySequence: 2}, nil
	}}
	s := testServer(t, testConfig(app.URL), f)
	r := edgeRequest("GET", "/dashboard")
	r.AddCookie(&http.Cookie{Name: GatewayCookie, Value: testToken(t)})
	r.AddCookie(&http.Cookie{Name: "__Host-agp_management", Value: "management_secret"})
	r.AddCookie(&http.Cookie{Name: "agp_session", Value: "legacy_secret"})
	r.AddCookie(&http.Cookie{Name: "app_sid", Value: "app_value"})
	r.AddCookie(&http.Cookie{Name: "unknown", Value: "blocked"})
	r.Header.Set("X-AGP-User", "spoofed")
	r.Header.Set("X-AGP-User-ID", "usr_spoofed")
	r.Header.Set("X-AGP-Evil", "injected")
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("proxy failed: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "app_sid" || cookies[0].Value != "good" || cookies[0].Domain != "" {
		t.Fatalf("upstream can replace AGP/parent cookies: %v", w.Header().Values("Set-Cookie"))
	}
	if w.Header().Get("X-AGP-User-ID") != "" {
		t.Fatal("untrusted response identity leaked")
	}
}

func TestLogoutRequiresOriginAndAuthoritativeRevoke(t *testing.T) {
	var calls int
	token := testToken(t)
	f := fakeCentral{logout: func(_ context.Context, g, got string) error {
		calls++
		if g != "gw_one" || got != token {
			t.Fatal("wrong revoke binding")
		}
		return nil
	}}
	s := testServer(t, testConfig("http://127.0.0.1:8081"), f)
	for _, origin := range []string{"", "https://evil.example", "https://app.example"} {
		r := edgeRequest("POST", LogoutPath)
		r.Header.Set("Origin", origin)
		r.AddCookie(&http.Cookie{Name: GatewayCookie, Value: token})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		want := 403
		if origin == "https://app.example" {
			want = 204
		}
		if w.Code != want {
			t.Fatalf("logout origin %q status%d", origin, w.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("revoke called%d", calls)
	}
}

func TestUnauthenticatedPOSTRedirectNeverReplaysBody(t *testing.T) {
	var upstreamRequests atomic.Int32
	app := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamRequests.Add(1) }))
	defer app.Close()
	f := fakeCentral{decide: func(context.Context, DecisionRequest) (Decision, error) {
		return Decision{Decision: "deny", ReasonCode: "authentication_required", SecuritySequence: 3}, nil
	}}
	s := testServer(t, testConfig(app.URL), f)
	r := edgeRequest("POST", "/transfer?tab=one")
	r.Body = io.NopCloser(strings.NewReader("sensitive=never-replayed"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || upstreamRequests.Load() != 0 {
		t.Fatal("unauthenticated mutation was proxied or redirected with method preservation")
	}
	location, e := url.Parse(w.Header().Get("Location"))
	if e != nil || location.Path != StartPath || location.Query().Get("return") != "/transfer?tab=one" || strings.Contains(location.String(), "sensitive") {
		t.Fatal("request body entered handoff")
	}
}

func TestLoginOriginUsesDifferentHostname(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:8081")
	cfg.LoginOrigin = "https://app.example:8443"
	if cfg.Validate() == nil {
		t.Fatal("login accepted on app hostname with a different port")
	}
}

func TestDecisionClosedUnion(t *testing.T) {
	valid := `{"decision":"allow","reasonCode":"allowed","userId":"usr_one","groupIds":[],"securitySequence":"0"}`
	var d Decision
	if e := json.Unmarshal([]byte(valid), &d); e != nil {
		t.Fatal(e)
	}
	for _, input := range []string{`{"decision":"allow","reasonCode":"allowed","userId":"usr_one","securitySequence":"0"}`, `{"decision":"deny","reasonCode":"access_denied","securitySequence":"0","userId":""}`, `{"decision":"deny","reasonCode":"access_denied","securitySequence":"00"}`, `{"decision":"deny","reasonCode":"access_denied","securitySequence":0}`, `{"decision":"deny","reasonCode":"access_denied","securitySequence":"9223372036854775808"}`, `{"decision":"deny","decision":"allow","reasonCode":"allowed","userId":"usr_one","groupIds":[],"securitySequence":"0"}`, strings.TrimSuffix(valid, "}") + `,"unknown":true}`} {
		if e := json.Unmarshal([]byte(input), &d); e == nil {
			t.Errorf("malformed decision accepted: %s", input)
		}
	}
}

func TestWebSocketMaximumLife(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	stream := newBoundedStream(a, 20*time.Millisecond)
	defer stream.Close()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := b.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("stream did not close at maximum life: %v", e)
	}
}
