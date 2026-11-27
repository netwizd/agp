package oidcclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

type fixtureSecrets struct{ ca []byte }

func (s fixtureSecrets) ResolveOIDCSecrets(context.Context, string, string) (Secrets, error) {
	return Secrets{ClientSecret: []byte("synthetic-client-secret-unique"), CACertificatesPEM: append([]byte{}, s.ca...)}, nil
}

type pendingCode struct {
	nonce, challenge string
	used             bool
}
type idpFixture struct {
	server                                               *httptest.Server
	connector                                            *Connector
	provider                                             *Provider
	config                                               Config
	browser                                              *http.Client
	ca                                                   []byte
	mu                                                   sync.Mutex
	key                                                  *rsa.PrivateKey
	keyID, mode                                          string
	codes                                                map[string]*pendingCode
	sequence                                             int
	tokenCalls, metadataCalls, keyCalls, active, maximum atomic.Int64
}

func newIdP(t *testing.T) *idpFixture {
	t.Helper()
	f := &idpFixture{keyID: "rsa-one", codes: map[string]*pendingCode{}}
	var e error
	f.key, e = rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture IdP CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	leafPub, leafKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"issuer.example.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.server.Config.ErrorLog = discardLogger()
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	_, port, e := net.SplitHostPort(f.server.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	issuer := "https://issuer.example.test:" + port + "/tenant"
	f.config = Config{Issuer: issuer, ClientID: "client_login", ClientSecretVersionID: "secret_client_1", CASecretVersionID: "secret_ca_1", Purpose: "login", RegisteredRedirectURIs: []string{"https://login.agp.test/oidc/callback"}}
	f.connector, e = New(NetworkPolicy{HTTPSOrigins: []string{strings.TrimSuffix(issuer, "/tenant")}, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Timeout: time.Second, MaximumConcurrent: 2}, fixtureSecrets{f.ca})
	if e != nil {
		t.Fatal(e)
	}
	f.connector.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(f.ca)
	f.browser = &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "issuer.example.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { f.browser.CloseIdleConnections() })
	f.provider, e = f.connector.Discover(context.Background(), f.config)
	if e != nil {
		t.Fatal("discovery", e)
	}
	return f
}
func (f *idpFixture) setMode(mode string) { f.mu.Lock(); f.mode = mode; f.mu.Unlock() }
func (f *idpFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	mode := f.mode
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/tenant/.well-known/openid-configuration":
		f.metadataCalls.Add(1)
		if mode == "metadata_redirect" {
			w.Header().Set("Location", "https://evil.example/steal")
			w.WriteHeader(302)
			return
		}
		metadata := discovery{Issuer: f.config.Issuer, AuthorizationEndpoint: f.config.Issuer + "/authorize", TokenEndpoint: f.config.Issuer + "/token", JWKSURI: f.config.Issuer + "/keys", ResponseTypes: []string{"code"}, Algorithms: []string{"RS256"}, TokenAuthMethods: []string{"client_secret_basic"}, PKCEMethods: []string{"S256"}, GrantTypes: []string{"authorization_code"}}
		if mode == "endpoint_ssrf" {
			metadata.TokenEndpoint = "https://evil.example/steal"
		}
		if mode == "issuer_discovery_alias" {
			metadata.Issuer += "/"
		}
		if mode == "metadata_oversize" {
			_, _ = w.Write([]byte(strings.Repeat(" ", 70<<10)))
			return
		}
		_ = json.NewEncoder(w).Encode(metadata)
	case "/tenant/authorize":
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("client_id") != f.config.ClientID || q.Get("redirect_uri") != f.config.RegisteredRedirectURIs[0] || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		f.sequence++
		code := fmt.Sprintf("fixture-code-%d", f.sequence)
		f.codes[code] = &pendingCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
		f.mu.Unlock()
		location := q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
		w.Header().Set("Location", location)
		w.WriteHeader(302)
	case "/tenant/keys":
		f.keyCalls.Add(1)
		if mode == "jwks_redirect" {
			w.Header().Set("Location", "https://evil.example/keys")
			w.WriteHeader(302)
			return
		}
		if mode == "jwks_oversize" {
			_, _ = w.Write([]byte(strings.Repeat(" ", 140<<10)))
			return
		}
		f.mu.Lock()
		key, kid := f.key, f.keyID
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}}})
	case "/tenant/token":
		f.tokenCalls.Add(1)
		active := f.active.Add(1)
		defer f.active.Add(-1)
		for {
			old := f.maximum.Load()
			if old >= active || f.maximum.CompareAndSwap(old, active) {
				break
			}
		}
		if mode == "token_redirect" {
			w.Header().Set("Location", "https://evil.example/steal")
			w.WriteHeader(307)
			return
		}
		if mode == "token_oversize" {
			_, _ = w.Write([]byte(strings.Repeat(" ", 270<<10)))
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != f.config.ClientID || password != "synthetic-client-secret-unique" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"synthetic-client-secret-unique"}`))
			return
		}
		if e := r.ParseForm(); e != nil || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != f.config.RegisteredRedirectURIs[0] || r.Form.Get("client_secret") != "" {
			w.WriteHeader(400)
			return
		}
		if mode == "hang" {
			<-r.Context().Done()
			return
		}
		f.mu.Lock()
		code := f.codes[r.Form.Get("code")]
		valid := code != nil && !code.used && code.challenge == oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier"))
		if valid {
			code.used = true
		}
		f.mu.Unlock()
		if !valid {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"synthetic-client-secret-unique fixture-code"}`))
			return
		}
		if mode == "lost_response" {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				_ = conn.Close()
			}
			return
		}
		f.mu.Lock()
		key, kid := f.key, f.keyID
		nonce := code.nonce
		f.mu.Unlock()
		now := time.Now().Unix()
		claims := map[string]any{"iss": f.config.Issuer, "sub": "immutable-subject", "aud": []string{f.config.ClientID}, "iat": now - 1, "exp": now + 300, "auth_time": now - 60, "nonce": nonce, "acr": "urn:fixture:password", "amr": []string{"pwd"}}
		access := "synthetic-access-token"
		sum := sha256.Sum256([]byte(access))
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(sum[:16])
		switch mode {
		case "nonce":
			claims["nonce"] = "wrong-nonce"
		case "issuer":
			claims["iss"] = f.config.Issuer + "/"
		case "audience":
			claims["aud"] = []string{"another-client"}
		case "multi_no_azp":
			claims["aud"] = []string{f.config.ClientID, "extra-client"}
		case "multi_bad_azp":
			claims["aud"] = []string{f.config.ClientID, "extra-client"}
			claims["azp"] = "extra-client"
		case "multi_good_azp":
			claims["aud"] = []string{f.config.ClientID, "extra-client"}
			claims["azp"] = f.config.ClientID
		case "single_bad_azp":
			claims["azp"] = "extra-client"
		case "expired":
			claims["exp"] = now - 10
		case "future_iat":
			claims["iat"] = now + 20
		case "old_iat":
			claims["iat"] = now - 600
		case "future_nbf":
			claims["nbf"] = now + 30
		case "future_auth_time":
			claims["auth_time"] = now + 30
		case "old_auth_time":
			claims["auth_time"] = now - 25*3600
		case "missing_auth_time":
			delete(claims, "auth_time")
		case "null_auth_time":
			claims["auth_time"] = nil
		case "string_iat":
			claims["iat"] = "123456"
		case "fractional_iat":
			claims["iat"] = float64(now) - 0.5
		case "at_hash":
			claims["at_hash"] = "wrong-hash"
		case "unknown_kid":
			kid = "unknown-key"
		}
		payload, _ := json.Marshal(claims)
		if mode == "duplicate_claim" {
			payload = []byte(strings.TrimSuffix(string(payload), "}") + `,"sub":"different-subject"}`)
		}
		algorithm := jose.RS256
		var signingKey any = key
		if mode == "HS256" {
			algorithm = jose.HS256
			signingKey = []byte(strings.Repeat("x", 32))
		}
		signer, e := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
		if e != nil {
			w.WriteHeader(500)
			return
		}
		signed, e := signer.Sign(payload)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		raw, e := signed.CompactSerialize()
		if e != nil {
			w.WriteHeader(500)
			return
		}
		if mode == "none" {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"rsa-one"}`))
			raw = header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
		}
		envelope, _ := json.Marshal(map[string]any{"token_type": "Bearer", "access_token": access, "refresh_token": "synthetic-refresh-token", "expires_in": 300, "id_token": raw})
		switch mode {
		case "envelope_duplicate":
			// Both values contain a valid proof; the envelope itself is ambiguous.
			duplicate, _ := json.Marshal(raw)
			envelope = append(envelope[:len(envelope)-1], []byte(`,"id_token":`+string(duplicate)+`}`)...)
		case "envelope_depth":
			envelope = append(envelope[:len(envelope)-1], []byte(`,"extension":`+strings.Repeat(`{"nested":`, 20)+`true`+strings.Repeat(`}`, 20)+`}`)...)
		case "envelope_utf8":
			envelope = append(envelope[:len(envelope)-1], []byte(",\"extension\":\"\xff\"}")...)
		case "envelope_media_type":
			w.Header().Set("Content-Type", "application/jsonp")
		}
		_, _ = w.Write(envelope)
	default:
		w.WriteHeader(404)
	}
}
func (f *idpFixture) request(t *testing.T) ExchangeRequest {
	t.Helper()
	input, e := NewAuthorizationRequest(f.config.RegisteredRedirectURIs[0])
	if e != nil {
		t.Fatal(e)
	}
	authURL, e := f.provider.AuthorizationURL(input)
	if e != nil {
		t.Fatal(e)
	}
	response, e := f.browser.Get(authURL)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal("authorize status", response.StatusCode)
	}
	callback, e := url.Parse(response.Header.Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	if callback.Query().Get("state") != input.State {
		t.Fatal("IdP lost state")
	}
	return ExchangeRequest{Code: callback.Query().Get("code"), Nonce: input.Nonce, Verifier: input.Verifier, RedirectURI: input.RedirectURI}
}
func TestOIDCCodePKCEAndKeyRotation(t *testing.T) {
	f := newIdP(t)
	for i := 0; i < 2; i++ {
		if i == 1 {
			key, e := rsa.GenerateKey(rand.Reader, 2048)
			if e != nil {
				t.Fatal(e)
			}
			f.mu.Lock()
			f.key = key
			f.keyID = "rsa-two"
			f.mu.Unlock()
		}
		result, e := f.provider.Exchange(context.Background(), f.request(t))
		if e != nil {
			t.Fatal(e)
		}
		claims, e := result.Claims()
		if e != nil || claims.Issuer != f.config.Issuer || claims.Subject != "immutable-subject" || len(claims.AMR) != 1 || claims.AMR[0] != "pwd" || claims.AuthenticationTime.IsZero() {
			t.Fatalf("verified claims %#v %v", claims, e)
		}
		claims.AMR[0] = "mfa"
		again, _ := result.Claims()
		if again.AMR[0] != "pwd" {
			t.Fatal("caller mutated verified evidence")
		}
	}
	if f.tokenCalls.Load() != 2 || f.keyCalls.Load() != 3 {
		t.Fatal("unexpected token retry or stale JWKS", f.tokenCalls.Load(), f.keyCalls.Load())
	}
	if _, e := new(VerifiedIdentity).Claims(); !errors.Is(e, ErrRejected) {
		t.Fatal("zero value forged evidence", e)
	}
}
func TestOIDCRejectedClaimsAndAlgorithms(t *testing.T) {
	for _, mode := range []string{"nonce", "issuer", "audience", "multi_no_azp", "multi_bad_azp", "single_bad_azp", "expired", "future_iat", "old_iat", "future_nbf", "future_auth_time", "old_auth_time", "at_hash", "unknown_kid", "duplicate_claim", "null_auth_time", "string_iat", "fractional_iat", "HS256", "none"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdP(t)
			f.setMode(mode)
			request := f.request(t)
			result, e := f.provider.Exchange(context.Background(), request)
			if !errors.Is(e, ErrRejected) || result != nil {
				t.Fatalf("invalid proof accepted %#v %v", result, e)
			}
			for _, secret := range []string{"synthetic-client-secret-unique", request.Code, request.Nonce, request.Verifier} {
				if strings.Contains(e.Error(), secret) {
					t.Fatal("sensitive diagnostic escaped")
				}
			}
		})
	}
	t.Run("multi_aud_correct_azp", func(t *testing.T) {
		f := newIdP(t)
		f.setMode("multi_good_azp")
		if _, e := f.provider.Exchange(context.Background(), f.request(t)); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("max_age_requires_auth_time", func(t *testing.T) {
		f := newIdP(t)
		f.config.MaximumAuthenticationAge = time.Hour
		var e error
		f.provider, e = f.connector.Discover(context.Background(), f.config)
		if e != nil {
			t.Fatal(e)
		}
		f.setMode("missing_auth_time")
		if _, e = f.provider.Exchange(context.Background(), f.request(t)); !errors.Is(e, ErrRejected) {
			t.Fatal(e)
		}
	})
}
func TestOIDCExchangeNoAutomaticRetryOrReplay(t *testing.T) {
	for _, mode := range []string{"success", "lost_response"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdP(t)
			request := f.request(t)
			if mode != "success" {
				f.setMode(mode)
			}
			_, e := f.provider.Exchange(context.Background(), request)
			if mode == "success" && e != nil {
				t.Fatal(e)
			}
			if mode == "lost_response" && !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			if f.tokenCalls.Load() != 1 {
				t.Fatal("ambiguous token request retried", f.tokenCalls.Load())
			}
			f.setMode("")
			if _, e = f.provider.Exchange(context.Background(), request); !errors.Is(e, ErrRejected) {
				t.Fatal("IdP code replay accepted", e)
			}
			if f.tokenCalls.Load() != 2 {
				t.Fatal("SDK authentication autodetection retried", f.tokenCalls.Load())
			}
		})
	}
}
func TestOIDCTokenEnvelopeStrictJSON(t *testing.T) {
	for _, mode := range []string{"envelope_duplicate", "envelope_depth", "envelope_utf8", "envelope_media_type"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdP(t)
			f.setMode(mode)
			request := f.request(t)
			result, e := f.provider.Exchange(context.Background(), request)
			if !errors.Is(e, ErrUnavailable) || result != nil {
				t.Fatalf("invalid token envelope accepted %#v %v", result, e)
			}
			if f.tokenCalls.Load() != 1 {
				t.Fatal("invalid token envelope retried", f.tokenCalls.Load())
			}
			for _, secret := range []string{"synthetic-client-secret-unique", request.Code, request.Nonce, request.Verifier} {
				if strings.Contains(e.Error(), secret) {
					t.Fatal("sensitive envelope diagnostic escaped")
				}
			}
		})
	}
}
func TestOIDCNetworkPolicyBoundsAndRedirects(t *testing.T) {
	for _, mode := range []string{"metadata_redirect", "endpoint_ssrf", "issuer_discovery_alias", "metadata_oversize", "jwks_oversize"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdP(t)
			f.setMode(mode)
			if _, e := f.connector.Discover(context.Background(), f.config); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
		})
	}
	for _, mode := range []string{"token_redirect", "jwks_redirect", "token_oversize", "jwks_oversize"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdP(t)
			f.setMode(mode)
			if _, e := f.provider.Exchange(context.Background(), f.request(t)); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
		})
	}
	t.Run("all_DNS_answers_must_be_allowed", func(t *testing.T) {
		f := newIdP(t)
		before := f.metadataCalls.Load()
		f.connector.lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, nil
		}
		if _, e := f.connector.Discover(context.Background(), f.config); !errors.Is(e, ErrUnavailable) {
			t.Fatal(e)
		}
		if f.metadataCalls.Load() != before {
			t.Fatal("untrusted mixed DNS reached IdP")
		}
	})
	t.Run("IP_pinned_across_token_and_JWKS", func(t *testing.T) {
		f := newIdP(t)
		request := f.request(t)
		var calls atomic.Int64
		f.connector.lookup = func(context.Context, string) ([]netip.Addr, error) {
			if calls.Add(1) > 1 {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		if _, e := f.provider.Exchange(context.Background(), request); e != nil {
			t.Fatal(e)
		}
		if calls.Load() != 1 {
			t.Fatal("DNS pin not retained", calls.Load())
		}
	})
	t.Run("CA_and_original_hostname_verified", func(t *testing.T) {
		f := newIdP(t)
		wrong := newIdP(t)
		f.connector.secrets = fixtureSecrets{wrong.ca}
		if _, e := f.connector.Discover(context.Background(), f.config); !errors.Is(e, ErrUnavailable) {
			t.Fatal("CA bypass", e)
		}
		f.connector.secrets = fixtureSecrets{f.ca}
		f.config.Issuer = strings.Replace(f.config.Issuer, "issuer.example.test", "wrong.example.test", 1)
		f.connector.origins[strings.TrimSuffix(f.config.Issuer, "/tenant")] = true
		if _, e := f.connector.Discover(context.Background(), f.config); !errors.Is(e, ErrUnavailable) {
			t.Fatal("original hostname bypass", e)
		}
	})
}
func TestOIDCDeadlineCancellationAndConcurrency(t *testing.T) {
	f := newIdP(t)
	requests := make([]ExchangeRequest, 4)
	for i := range requests {
		requests[i] = f.request(t)
	}
	f.setMode("hang")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 4)
	var workers sync.WaitGroup
	for _, request := range requests {
		workers.Add(1)
		go func() { defer workers.Done(); _, e := f.provider.Exchange(ctx, request); results <- e }()
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for f.active.Load() < 2 {
		select {
		case <-deadline.C:
			t.Fatal("requests never reached concurrency bound")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	workers.Wait()
	close(results)
	for e := range results {
		if !errors.Is(e, ErrUnavailable) {
			t.Fatal("cancellation returned proof", e)
		}
	}
	if f.maximum.Load() != 2 || len(f.connector.slots) != 0 {
		t.Fatal("worker/slot bound leaked", f.maximum.Load(), len(f.connector.slots))
	}
	// A caller without cancellation is still bounded by the installation timeout.
	start := time.Now()
	if _, e := f.provider.Exchange(context.Background(), f.request(t)); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("operation deadline ignored")
	}
}
func TestOIDCClosedInputs(t *testing.T) {
	f := newIdP(t)
	input, e := NewAuthorizationRequest(f.config.RegisteredRedirectURIs[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, redirect := range []string{"http://login.agp.test/oidc/callback", "https://login.agp.test/oidc/callback/", "https://login.agp.test/oidc/callback?next=evil", "https://evil.example/oidc/callback"} {
		input.RedirectURI = redirect
		if _, e = f.provider.AuthorizationURL(input); !errors.Is(e, ErrInvalid) {
			t.Fatal("redirect alias accepted", redirect, e)
		}
	}
	for _, issuer := range []string{"http://issuer.example.test", "https://user:secret@issuer.example.test", "https://issuer.example.test?query=1", "https://issuer.example.test/#fragment", "https://ISSUER.example.test", "https://issuer.example.test:443", "https://issuer.example.test/a/../b"} {
		config := f.config
		config.Issuer = issuer
		if _, e = f.connector.Discover(context.Background(), config); !errors.Is(e, ErrInvalid) {
			t.Fatal("issuer alias accepted", issuer, e)
		}
	}
	input.RedirectURI = f.config.RegisteredRedirectURIs[0]
	input.Verifier = "short"
	if _, e = f.provider.AuthorizationURL(input); !errors.Is(e, ErrInvalid) {
		t.Fatal("weak verifier accepted", e)
	}
}
func TestOIDCDiscoveryEndpointPins(t *testing.T) {
	f := newIdP(t)
	pins := EndpointPins{f.config.Issuer + "/authorize", f.config.Issuer + "/token", f.config.Issuer + "/keys"}
	f.config.EndpointPins = pins
	if _, e := f.connector.Discover(context.Background(), f.config); e != nil {
		t.Fatal("matching pins rejected", e)
	}
	for _, field := range []string{"authorization", "token", "jwks"} {
		t.Run(field, func(t *testing.T) {
			config := f.config
			switch field {
			case "authorization":
				config.EndpointPins.AuthorizationEndpoint += "/changed"
			case "token":
				config.EndpointPins.TokenEndpoint += "/changed"
			case "jwks":
				config.EndpointPins.JWKSURI += "/changed"
			}
			if p, e := f.connector.Discover(context.Background(), config); !errors.Is(e, ErrUnavailable) || p != nil {
				t.Fatal("discovery changed pinned endpoint", e)
			}
		})
	}
	f.config.EndpointPins.TokenEndpoint = ""
	if _, e := f.connector.Discover(context.Background(), f.config); !errors.Is(e, ErrInvalid) {
		t.Fatal("partial pins accepted", e)
	}
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
func TestOIDCPKCEVerifierEnforcedByIdP(t *testing.T) {
	f := newIdP(t)
	request := f.request(t)
	correct := request.Verifier
	request.Verifier = strings.Repeat("A", 43)
	if _, e := f.provider.Exchange(context.Background(), request); !errors.Is(e, ErrRejected) {
		t.Fatal("wrong PKCE verifier accepted", e)
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatal("failed PKCE exchange retried")
	}
	request.Verifier = correct
	if _, e := f.provider.Exchange(context.Background(), request); e != nil {
		t.Fatal("correct PKCE proof rejected", e)
	}
}
