package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"golang.org/x/oauth2"
)

type oidcFixtureSecrets struct {
	ca    []byte
	equal *atomic.Bool
}

func (s oidcFixtureSecrets) ResolveOIDCSecrets(_ context.Context, ref, _ string) (oidcclient.Secrets, error) {
	secret := "fixture-login-client-secret"
	if ref == "oidc_management_secret" && !s.equal.Load() {
		secret = "fixture-management-client-secret"
	}
	return oidcclient.Secrets{ClientSecret: []byte(secret), CACertificatesPEM: append([]byte{}, s.ca...)}, nil
}

type oidcFixtureCode struct {
	nonce, challenge, client, redirect string
	used                               bool
}
type oidcFixture struct {
	*directoryAuthFixture
	oidc              *OIDCService
	server            *httptest.Server
	browser           *http.Client
	key               *rsa.PrivateKey
	p                 *OIDCProviderView
	documentOIDC      OIDCProviderDocument
	directoryIdentity *DirectoryIdentityView
	link              *OIDCLinkView
	mu                sync.Mutex
	mode              string
	codes             map[string]*oidcFixtureCode
	tokenCalls        atomic.Int64
	equalSecrets      atomic.Bool
	authTime          atomic.Int64
	tokenHook         func() error
}

func newOIDCFixture(t *testing.T, pg bool) *oidcFixture {
	t.Helper()
	f := &oidcFixture{directoryAuthFixture: newDirectoryAuthFixture(t, pg, false), codes: map[string]*oidcFixtureCode{}}
	f.authTime.Store(f.now.Unix() - 60)
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(f.ctx, `UPDATE sessions SET primary_at=? WHERE audience='management'`, f.now)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	var e error
	f.key, e = rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OIDC integration fixture CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	leafPub, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serveOIDC))
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.Listener.Close()
	f.server.Listener, e = net.Listen("tcp", "[::]:0")
	if e != nil {
		t.Fatal(e)
	}
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	port := f.server.Listener.Addr().(*net.TCPAddr).Port
	issuer := "https://localhost:" + strconv.Itoa(port) + "/tenant"
	connector, e := oidcclient.New(oidcclient.NetworkPolicy{HTTPSOrigins: []string{strings.TrimSuffix(issuer, "/tenant")}, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, Timeout: time.Second, MaximumConcurrent: 2}, oidcFixtureSecrets{caPEM, &f.equalSecrets})
	if e != nil {
		t.Fatal(e)
	}
	f.oidc, e = NewOIDCService(f.s, connector)
	if e != nil {
		t.Fatal(e)
	}
	stateKey := make([]byte, 32)
	rand.Read(stateKey)
	keys, e := NewOIDCStateKeyring("oidc_state_1", map[string][]byte{"oidc_state_1": stateKey})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.oidc.WithStateKeys(keys); e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	f.browser = &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(f.browser.CloseIdleConnections)
	f.p, e = f.oidc.CreateProvider(f.ctx, f.author, OIDCProviderCreate{Name: "OIDC test issuer", Issuer: issuer})
	if e != nil {
		t.Fatal(e)
	}
	f.documentOIDC = OIDCProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "OIDCProvider", Metadata: DirectoryMetadata{ID: f.p.ID, VersionID: securitystate.ID("oidcver"), SecurityGuardID: f.p.SecurityGuardID, SecurityGuardVersion: 1}, Spec: OIDCSpec{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/keys", CASecretVersionID: "oidc_ca_1", ResponseType: "code", Scope: "openid", TokenEndpointAuthMethod: "client_secret_basic", PKCEMethod: "S256", AllowedSigningAlgorithms: []string{"RS256"}, MFAClaimMode: "none", IdentityBinding: "approved_directory_link", Clients: []OIDCClient{{Purpose: "login", ClientID: "fixture_login", ClientSecretVersionID: "oidc_login_secret", RedirectURI: f.s.Profile.LoginOrigin + "/auth/v2/oidc/providers/" + f.p.ID + "/callback", MaximumAuthenticationAgeSeconds: 300}, {Purpose: "management", ClientID: "fixture_management", ClientSecretVersionID: "oidc_management_secret", RedirectURI: f.s.Profile.ManagementOrigin + "/auth/v2/oidc/providers/" + f.p.ID + "/callback", MaximumAuthenticationAgeSeconds: 300}}}}
	return f
}
func (f *oidcFixture) setOIDCMode(mode string) { f.mu.Lock(); f.mode = mode; f.mu.Unlock() }
func (f *oidcFixture) serveOIDC(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	mode := f.mode
	hook := f.tokenHook
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	issuer := f.documentOIDC.Spec.Issuer
	switch r.URL.Path {
	case "/tenant/.well-known/openid-configuration":
		token := issuer + "/token"
		if mode == "metadata_drift" {
			token += "/changed"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": token, "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}})
	case "/tenant/keys":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "fixture_key", Algorithm: "RS256", Use: "sig"}}})
	case "/tenant/authorize":
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("max_age") != "300" {
			w.WriteHeader(400)
			return
		}
		code, _, _ := auth.NewToken()
		f.mu.Lock()
		f.codes[code] = &oidcFixtureCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), client: q.Get("client_id"), redirect: q.Get("redirect_uri")}
		f.mu.Unlock()
		w.Header().Set("Location", q.Get("redirect_uri")+"?"+url.Values{"state": {q.Get("state")}, "code": {code}}.Encode())
		w.WriteHeader(302)
	case "/tenant/token":
		f.tokenCalls.Add(1)
		user, password, ok := r.BasicAuth()
		if e := r.ParseForm(); e != nil || !ok {
			w.WriteHeader(400)
			return
		}
		expected := "fixture-login-client-secret"
		if user == "fixture_management" {
			expected = "fixture-management-client-secret"
		}
		f.mu.Lock()
		code := f.codes[r.Form.Get("code")]
		valid := code != nil && !code.used && code.client == user && password == expected && code.redirect == r.Form.Get("redirect_uri") && code.challenge == oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier"))
		if valid {
			code.used = true
		}
		f.mu.Unlock()
		if !valid {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		if mode == "lost_response" {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				_ = conn.Close()
			}
			return
		}
		if mode == "hang" {
			<-r.Context().Done()
			return
		}
		if hook != nil {
			if e := hook(); e != nil {
				w.WriteHeader(503)
				return
			}
		}
		claims := map[string]any{"iss": issuer, "sub": "CaseSensitiveSubject_1", "aud": []string{user}, "iat": f.authTime.Load() + 59, "exp": time.Now().Unix() + 300, "auth_time": f.authTime.Load(), "nonce": code.nonce, "acr": "unqualified-mfa", "amr": []string{"mfa"}}
		if mode == "wrong_subject" {
			claims["sub"] = "casesensitivesubject_1"
		}
		if mode == "short_expiry" {
			claims["exp"] = time.Now().Unix() + 5
		}
		if mode == "missing_auth_time" {
			delete(claims, "auth_time")
		}
		if mode == "nonce" {
			claims["nonce"] = "wrong"
		}
		signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture_key"))
		if e != nil {
			w.WriteHeader(500)
			return
		}
		payload, _ := json.Marshal(claims)
		signed, e := signer.Sign(payload)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		token, e := signed.CompactSerialize()
		if e != nil {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": "synthetic-access-token", "id_token": token})
	default:
		w.WriteHeader(404)
	}
}
func (f *oidcFixture) activateOIDC(t *testing.T) {
	t.Helper()
	if _, e := f.oidc.ProposeVersion(f.ctx, f.author, f.p.ID, f.p.Revision, f.documentOIDC); e != nil {
		t.Fatal(e)
	}
	f.p.Revision++
	tested, e := f.oidc.TestProvider(f.ctx, f.author, f.p.ID, f.documentOIDC.Metadata.VersionID)
	if e != nil || tested.State != "passed" {
		t.Fatal("OIDC test", tested, e)
	}
	op, e := f.oidc.PlanActivationAtRevision(f.ctx, f.author, f.p.ID, securitystate.ID("req"), f.p.Revision, DirectoryActivation{VersionID: f.documentOIDC.Metadata.VersionID, Enabled: true, Reason: "reviewed exact issuer clients"})
	if e != nil {
		t.Fatal(e)
	}
	f.approveOIDC(t, op)
	if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, op.ID, securitystate.ID("req"), op.RequestDigest, "activate reviewed issuer"); e != nil {
		t.Fatal(e)
	}
	f.p, e = f.oidc.GetProvider(f.ctx, f.author, f.p.ID)
	if e != nil || !f.p.Enabled {
		t.Fatal("not enabled", e)
	}
}
func (f *oidcFixture) approveOIDC(t *testing.T, o *OIDCSecurityOperation) {
	t.Helper()
	if _, e := f.oidc.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, securitystate.ID("req"), o.RequestDigest, "independent exact target review"); e != nil {
		t.Fatal(e)
	}
}
func (f *oidcFixture) linkOIDC(t *testing.T) {
	t.Helper()
	f.directoryIdentity = f.provision(t)
	op, e := f.oidc.PlanLink(f.ctx, f.author, f.p.ID, securitystate.ID("req"), OIDCLinkCreate{Subject: "CaseSensitiveSubject_1", DirectoryIdentityID: f.directoryIdentity.ID, ExpiresAt: f.now.Add(4 * time.Minute), Reason: "verified immutable subject to directory GUID"})
	if e != nil {
		t.Fatal(e)
	}
	f.approveOIDC(t, op)
	if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, op.ID, securitystate.ID("req"), op.RequestDigest, "enable independently approved link"); e != nil {
		t.Fatal(e)
	}
	f.link, e = f.oidc.GetLink(f.ctx, f.author, f.p.ID, op.SubjectID)
	if e != nil || !f.link.Enabled {
		t.Fatal("link", f.link, e)
	}
}
func (f *oidcFixture) beginOIDC(t *testing.T, a FlowAuth) (state, code string) {
	t.Helper()
	view, e := f.oidc.BeginAuthorization(f.ctx, a, f.p.ID, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	response, e := f.browser.Get(view.AuthorizationURL)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal(response.StatusCode)
	}
	u, e := url.Parse(response.Header.Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	return u.Query().Get("state"), u.Query().Get("code")
}
func (f *oidcFixture) primaryOIDC(t *testing.T, a FlowAuth) FlowAuth {
	t.Helper()
	state, code := f.beginOIDC(t, a)
	result, e := f.oidc.Callback(f.ctx, a, f.p.ID, state, code, "", "")
	if e != nil || result.Terminal {
		t.Fatal("callback", result.Terminal, e, "token posts", f.tokenCalls.Load())
	}
	if result.Transition.View.State != "pending_mfa" || result.Transition.View.MFASatisfied {
		t.Fatal("OIDC external claim bypassed TOTP")
	}
	a.ID = result.Transition.View.ID
	a.Binding = result.Transition.Binding
	return a
}
func TestOIDCIdentitySQLite(t *testing.T)   { testOIDCIdentity(t, false) }
func TestOIDCIdentityPostgres(t *testing.T) { testOIDCIdentity(t, true) }
func testOIDCIdentity(t *testing.T, pg bool) {
	t.Run("HTTPS_AD_TOTP_session_and_link_revoke", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		a := f.primaryOIDC(t, f.startDirectory(t, "login"))
		if _, e := f.s.Complete(f.ctx, a, "", "test"); !errors.Is(e, ErrProof) {
			t.Fatal("OIDC-only session", e)
		}
		f.enroll(t, a)
		completed, e := f.s.Complete(f.ctx, a, "127.0.0.1", "HTTPS OIDC + AD + TOTP fixture")
		if e != nil {
			t.Fatal(e)
		}
		hash := auth.TokenHash(completed.SessionToken)
		session, e := f.s.Session(f.ctx, hash, "login", f.s.Profile.LoginOrigin)
		if e != nil || session.User.ID != f.directoryIdentity.PrincipalID || session.User.IsAdmin || session.Session.PrimaryAt == nil || !session.Session.PrimaryAt.Equal(f.now.Add(-60*time.Second)) {
			t.Fatal("session context", session, e)
		}
		f.wire.disabled.Store(true)
		if _, e = f.s.Session(f.ctx, hash, "login", f.s.Profile.LoginOrigin); !errors.Is(e, ErrProof) {
			t.Fatal("disabled AD allowed", e)
		}
		f.wire.disabled.Store(false)
		op, e := f.oidc.PlanLinkChange(f.ctx, f.author, f.p.ID, f.link.ID, securitystate.ID("req"), f.link.Revision, OIDCLinkSuccessor{DirectoryIdentityID: f.directoryIdentity.ID, Enabled: false, ExpiresAt: f.now.Add(4 * time.Minute), Reason: "revoke the external login binding"})
		if e != nil {
			t.Fatal(e)
		}
		f.wire.rejectTLS.Store(true)
		f.approveOIDC(t, op)
		if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, op.ID, securitystate.ID("req"), op.RequestDigest, "disable while AD unavailable"); e != nil {
			t.Fatal(e)
		}
		f.wire.rejectTLS.Store(false)
		if _, e = f.s.Session(f.ctx, hash, "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("revoked link kept allow")
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE oidc_links SET enabled=TRUE,active_version_id=?,guard_version=1,row_version=1 WHERE id=?`, f.link.Configuration.ID, f.link.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Session(f.ctx, hash, "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("restored old positive link bypassed floor")
		}
	})
	t.Run("second_person_config_author_and_idempotency", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		if _, e := f.oidc.ProposeVersion(f.ctx, f.author, f.p.ID, f.p.Revision, f.documentOIDC); e != nil {
			t.Fatal(e)
		}
		f.p.Revision++
		if _, e := f.oidc.TestProvider(f.ctx, f.author, f.p.ID, f.documentOIDC.Metadata.VersionID); e != nil {
			t.Fatal(e)
		}
		key := securitystate.ID("req")
		op, e := f.oidc.PlanActivationAtRevision(f.ctx, f.reviewer, f.p.ID, key, f.p.Revision, DirectoryActivation{VersionID: f.documentOIDC.Metadata.VersionID, Enabled: true, Reason: "B requests config authored by A"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.oidc.ApproveOperationRequest(f.ctx, f.author, op.ID, securitystate.ID("req"), op.RequestDigest, "A cannot approve own config"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("version author approved", e)
		}
		if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.reviewer, op.ID, securitystate.ID("req"), op.RequestDigest, "unapproved operation"); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal(e)
		}
		if _, e = f.oidc.PlanActivationAtRevision(f.ctx, f.reviewer, f.p.ID, key, f.p.Revision, DirectoryActivation{VersionID: f.documentOIDC.Metadata.VersionID, Enabled: false, Reason: "different payload"}); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("key reused", e)
		}
	})
	t.Run("clients_require_distinct_secret_contents_and_endpoint_pins", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		if _, e := f.oidc.ProposeVersion(f.ctx, f.author, f.p.ID, f.p.Revision, f.documentOIDC); e != nil {
			t.Fatal(e)
		}
		f.equalSecrets.Store(true)
		tested, e := f.oidc.TestProvider(f.ctx, f.author, f.p.ID, f.documentOIDC.Metadata.VersionID)
		if e != nil || tested.State != "failed" {
			t.Fatal("same secret contents accepted", tested, e)
		}
		f.equalSecrets.Store(false)
		f.setOIDCMode("metadata_drift")
		tested, e = f.oidc.TestProvider(f.ctx, f.author, f.p.ID, f.documentOIDC.Metadata.VersionID)
		if e != nil || tested.State != "failed" {
			t.Fatal("endpoint drift accepted", tested, e)
		}
	})
	for _, mode := range []string{"wrong_subject", "missing_auth_time", "nonce", "lost_response", "AD_disabled", "AD_outage"} {
		t.Run(mode, func(t *testing.T) {
			f := newOIDCFixture(t, pg)
			f.activateOIDC(t)
			f.linkOIDC(t)
			a := f.startDirectory(t, "login")
			state, code := f.beginOIDC(t, a)
			f.setOIDCMode(mode)
			if mode == "AD_disabled" {
				f.wire.disabled.Store(true)
			}
			if mode == "AD_outage" {
				f.wire.rejectTLS.Store(true)
			}
			if _, e := f.oidc.Callback(f.ctx, a, f.p.ID, state, code, "", ""); e == nil {
				t.Fatal("invalid callback succeeded")
			}
			if f.tokenCalls.Load() != 1 {
				t.Fatal("callback retried token")
			}
			f.setOIDCMode("")
			f.wire.disabled.Store(false)
			f.wire.rejectTLS.Store(false)
			if result, e := f.oidc.Callback(f.ctx, a, f.p.ID, state, code, "", ""); e != nil || !result.Terminal {
				t.Fatal("terminal callback", result.Terminal, e)
			}
			if f.tokenCalls.Load() != 1 {
				t.Fatal("terminal callback exchanged again")
			}
		})
	}
	t.Run("browser_provider_purpose_binding_and_parallel_consume", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		a := f.startDirectory(t, "login")
		state, code := f.beginOIDC(t, a)
		other := f.startDirectory(t, "login")
		for _, foreign := range []FlowAuth{other, {ID: a.ID, Binding: a.Binding, CSRF: a.CSRF, Origin: f.s.Profile.ManagementOrigin}} {
			if _, e := f.oidc.Callback(f.ctx, foreign, f.p.ID, state, code, "", ""); !errors.Is(e, ErrProof) {
				t.Fatal("foreign callback", e)
			}
		}
		if _, e := f.oidc.Callback(f.ctx, a, "oidc_other_provider", state, code, "", ""); !errors.Is(e, ErrProof) {
			t.Fatal("mixup accepted", e)
		}
		if f.tokenCalls.Load() != 0 {
			t.Fatal("binding failure sent code to IdP")
		}
		var wg sync.WaitGroup
		results := make(chan OIDCCallbackResult, 2)
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, e := f.oidc.Callback(f.ctx, a, f.p.ID, state, code, "", "")
				results <- r
				errs <- e
			}()
		}
		wg.Wait()
		close(results)
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		success := 0
		for r := range results {
			if !r.Terminal {
				success++
			}
		}
		if success != 1 || f.tokenCalls.Load() != 1 {
			t.Fatal("parallel callback duplication", success, f.tokenCalls.Load())
		}
	})
}
