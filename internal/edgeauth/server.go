package edgeauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg               Config
	routes            []Route
	state             PendingStore
	central           Central
	proxies           map[string]*httputil.ReverseProxy
	webSocketLifetime time.Duration
}
type decisionKey struct{}

func NewServer(cfg Config, state PendingStore, central Central) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if state == nil || central == nil {
		return nil, fmt.Errorf("pending store and central authority are required")
	}
	s := &Server{cfg: cfg, routes: sortedRoutes(cfg.Routes), state: state, central: central, proxies: map[string]*httputil.ReverseProxy{}, webSocketLifetime: 5 * time.Minute}
	for _, route := range s.routes {
		route := route
		target, _ := url.Parse(route.Upstream)
		proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			stripIdentity(pr.Out.Header)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			filterRequestCookies(pr.Out, route.ApplicationCookies)
			d := pr.In.Context().Value(decisionKey{}).(Decision)
			pr.Out.Header.Set("X-AGP-User-ID", d.UserID)
			pr.Out.Header.Set("X-AGP-Groups", strings.Join(d.GroupIDs, ","))
		}, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "application unavailable", http.StatusServiceUnavailable)
		}, ModifyResponse: func(resp *http.Response) error {
			filterResponseCookies(resp, route.ApplicationCookies)
			stripIdentity(resp.Header)
			if resp.StatusCode == http.StatusSwitchingProtocols {
				rw, ok := resp.Body.(io.ReadWriteCloser)
				if !ok {
					return fmt.Errorf("invalid upgrade response")
				}
				resp.Body = newBoundedStream(rw, s.webSocketLifetime)
			}
			return nil
		}}
		s.proxies[route.ID] = proxy
	}
	return s, nil
}

func (s *Server) Close() {
	for _, p := range s.proxies {
		if t, ok := p.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}

// Handler must be served only through the provisioned Unix socket. Nginx owns
// TLS and overwrites the transport metadata below; clients cannot access the
// adapter location or choose an upstream or deployment identity.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(s.cfg.Origin)
	if r.Host != u.Host || r.Header.Get("X-Forwarded-Proto") != "https" || net.ParseIP(r.Header.Get("X-AGP-Client-IP")) == nil {
		http.Error(w, "invalid gateway context", http.StatusMisdirectedRequest)
		return
	}
	if r.URL.Path == AuthorizePath {
		s.authorize(w, r)
		return
	}
	if r.Header.Get("X-AGP-Start") == "1" && !strings.HasPrefix(r.URL.Path, "/_agp") {
		s.startReturn(w, r, r.Header.Get("X-AGP-Original-URI"))
		return
	}
	switch r.URL.Path {
	case StartPath:
		s.start(w, r)
	case CallbackPath:
		s.callback(w, r)
	case LogoutPath:
		s.logout(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/_agp") {
			http.NotFound(w, r)
			return
		}
		route := matchRoute(s.routes, r.URL.RequestURI())
		if route == nil {
			http.NotFound(w, r)
			return
		}
		d, status := s.decision(r, route, r.Method, r.URL.RequestURI())
		if status == http.StatusUnauthorized {
			securityHeaders(w)
			http.Redirect(w, r, StartPath+"?"+url.Values{"return": {r.URL.RequestURI()}}.Encode(), http.StatusSeeOther)
			return
		}
		if status != http.StatusNoContent {
			http.Error(w, http.StatusText(status), status)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), decisionKey{}, d))
		s.proxies[route.ID].ServeHTTP(w, r)
	}
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	raw := r.Header.Get("X-AGP-Original-URI")
	method := r.Header.Get("X-AGP-Original-Method")
	if !validMethod(method) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	route := matchRoute(s.routes, raw)
	if route == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	d, status := s.decision(r, route, method, raw)
	if status == http.StatusNoContent {
		w.Header().Set("X-AGP-User-ID", d.UserID)
		w.Header().Set("X-AGP-Groups", strings.Join(d.GroupIDs, ","))
	}
	w.WriteHeader(status)
}
func (s *Server) decision(r *http.Request, route *Route, method, raw string) (Decision, int) {
	token, ok := oneCookie(r, GatewayCookie)
	if !ok {
		return Decision{}, http.StatusUnauthorized
	}
	if token != "" && !validToken(token) {
		return Decision{}, http.StatusUnauthorized
	}
	d, err := s.central.Decide(r.Context(), DecisionRequest{SessionToken: token, GatewayID: s.cfg.GatewayID, RouteID: route.ID, DeploymentGeneration: s.cfg.DeploymentGeneration, ClientIP: r.Header.Get("X-AGP-Client-IP"), Method: method, Path: raw})
	if err != nil || d.Validate() != nil {
		return Decision{}, http.StatusServiceUnavailable
	}
	if d.Decision == "allow" {
		if token == "" {
			return Decision{}, http.StatusServiceUnavailable
		}
		return d, http.StatusNoContent
	}
	if d.ReasonCode == "access_denied" {
		return Decision{}, http.StatusForbidden
	}
	return Decision{}, http.StatusUnauthorized
}
func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 1 || len(q["return"]) != 1 {
		http.Error(w, "invalid return path", http.StatusBadRequest)
		return
	}
	returnPath := q.Get("return")
	s.startReturn(w, r, returnPath)
}
func (s *Server) startReturn(w http.ResponseWriter, r *http.Request, returnPath string) {
	securityHeaders(w)
	if r.Method != http.MethodGet && r.Header.Get("X-AGP-Start") != "1" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if matchRoute(s.routes, returnPath) == nil {
		http.Error(w, "invalid return path", http.StatusBadRequest)
		return
	}
	state, err := randomToken()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	binding, err := randomToken()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	verifier, err := randomToken()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	p := Pending{State: state, Binding: binding, Verifier: verifier, ReturnPath: returnPath, Profile: s.cfg.fingerprint(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	if err = s.state.Create(r.Context(), p); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	setCookie(w, PendingCookie, binding, p.ExpiresAt)
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{"gatewayId": {s.cfg.GatewayID}, "redirectUri": {s.cfg.callbackURI()}, "state": {state}, "codeChallenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "codeChallengeMethod": {"S256"}}
	http.Redirect(w, r, s.cfg.LoginOrigin+"/auth/v2/authorize?"+query.Encode(), http.StatusSeeOther)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 2 || len(q["code"]) != 1 || len(q["state"]) != 1 || !validToken(q.Get("code")) || !validToken(q.Get("state")) {
		http.Error(w, "invalid handoff", http.StatusBadRequest)
		return
	}
	binding, ok := oneCookie(r, PendingCookie)
	if !ok || !validToken(binding) {
		http.Error(w, "invalid handoff binding", http.StatusBadRequest)
		return
	}
	p, err := s.state.Consume(r.Context(), q.Get("state"), binding, s.cfg.fingerprint(), time.Now().UTC())
	if err != nil {
		http.Error(w, "handoff expired or already consumed", http.StatusBadRequest)
		return
	}
	clearCookie(w, PendingCookie)
	if matchRoute(s.routes, p.ReturnPath) == nil {
		http.Error(w, "invalid return path", http.StatusBadRequest)
		return
	}
	response, err := s.central.Redeem(r.Context(), RedeemRequest{Code: q.Get("code"), CodeVerifier: p.Verifier, GatewayID: s.cfg.GatewayID, RedirectURI: s.cfg.callbackURI()})
	if err != nil || !validToken(response.SessionToken) || !opaqueID.MatchString(response.SessionID) || !opaqueID.MatchString(response.UserID) || !response.ExpiresAt.After(time.Now()) || response.ExpiresAt.After(time.Now().Add(30*24*time.Hour)) {
		http.Error(w, "handoff unavailable; start login again", http.StatusServiceUnavailable)
		return
	}
	setCookie(w, GatewayCookie, response.SessionToken, response.ExpiresAt)
	http.Redirect(w, r, p.ReturnPath, http.StatusSeeOther)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Origin") != s.cfg.Origin {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	token, ok := oneCookie(r, GatewayCookie)
	if !ok || token != "" && !validToken(token) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if token != "" {
		if err := s.central.Logout(r.Context(), s.cfg.GatewayID, token); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	clearCookie(w, GatewayCookie)
	clearCookie(w, PendingCookie)
	w.WriteHeader(http.StatusNoContent)
}
func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func oneCookie(r *http.Request, name string) (string, bool) {
	found := false
	value := ""
	for _, c := range r.Cookies() {
		if c.Name == name {
			if found {
				return "", false
			}
			found = true
			value = c.Value
		}
	}
	return value, true
}
func setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires.UTC(), MaxAge: max(1, int(time.Until(expires).Seconds()))})
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0).UTC(), MaxAge: -1})
}
func validMethod(v string) bool {
	switch v {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	default:
		return false
	}
}

type boundedStream struct {
	io.ReadWriteCloser
	timer  *time.Timer
	mu     sync.Mutex
	closed bool
}

func newBoundedStream(rw io.ReadWriteCloser, ttl time.Duration) *boundedStream {
	b := &boundedStream{ReadWriteCloser: rw}
	b.mu.Lock()
	b.timer = time.AfterFunc(ttl, func() { _ = b.Close() })
	b.mu.Unlock()
	return b
}
func (b *boundedStream) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	t := b.timer
	b.mu.Unlock()
	if t != nil {
		t.Stop()
	}
	return b.ReadWriteCloser.Close()
}
