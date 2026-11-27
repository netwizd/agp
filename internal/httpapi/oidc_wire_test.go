package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type oidcHTTPWireFixture struct {
	server  *Server
	browser *http.Client
	base    storage.Store
	ldap    *oidcHTTPWireLDAPPeer
	idp     *oidcHTTPWireIdP
}

func oidcHTTPWireStore(t *testing.T, pg bool) storage.Store {
	t.Helper()
	ctx := context.Background()
	var base storage.Store
	if pg {
		dsn := os.Getenv("AGP_TEST_OIDC_HTTP_DSN")
		if dsn == "" {
			dsn = os.Getenv("AGP_TEST_IDENTITY_DSN")
		}
		if dsn == "" {
			dsn = os.Getenv("AGP_TEST_POSTGRES_DSN")
		}
		if dsn == "" {
			t.Skip("AGP_TEST_IDENTITY_DSN / AGP_TEST_POSTGRES_DSN not set")
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal("open synthetic PG admin pool", err)
		}
		schema := strings.ToLower(strings.ReplaceAll(securitystate.ID("oidchttp"), "-", "_"))
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err = pool.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
			pool.Close()
			t.Fatal("create isolated OIDC HTTP schema", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); pool.Close() })
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal("parse fixture DSN")
			}
			query := u.Query()
			query.Set("search_path", schema)
			u.RawQuery = query.Encode()
			dsn = u.String()
		} else {
			dsn += " search_path=" + schema
		}
		base, err = postgres.Open(ctx, dsn)
		if err != nil {
			t.Fatal("open isolated OIDC HTTP store", err)
		}
	} else {
		var err error
		base, err = sqlite.Open(t.TempDir() + "/oidc-http.db")
		if err != nil {
			t.Fatal("open SQLite OIDC HTTP store", err)
		}
	}
	t.Cleanup(func() { _ = base.Close() })
	if err := base.Migrate(ctx); err != nil {
		t.Fatal("migrate OIDC HTTP store", err)
	}
	if pg {
		release, err := base.(interface {
			AcquireIdentityLease(context.Context) (func(), error)
		}).AcquireIdentityLease(ctx)
		if err != nil {
			t.Fatal("acquire isolated PG identity lease", err)
		}
		t.Cleanup(release)
	}
	return base
}

func newOIDCHTTPWireFixture(t *testing.T, pg bool) *oidcHTTPWireFixture {
	t.Helper()
	base := oidcHTTPWireStore(t, pg)
	ldap := newOIDCHTTPWireLDAPPeer(t)
	idp := newOIDCHTTPWireIdP(t)
	cfg := config.Config{DatabaseDriver: "postgres", SecureProfile: true, PortalHost: "portal.test", LoginOrigin: "https://login.test", ManagementOrigin: "https://management.test", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour, LoginRateLimitMax: 30, LoginRateLimitWind: time.Minute, MFAKeyFile: "/synthetic-keyring", AuthMTLSAddr: "127.0.0.1:0", AuthMTLSCertFile: "/synthetic-cert", AuthMTLSKeyFile: "/synthetic-key", AuthMTLSClientCAFile: "/synthetic-ca"}
	directory := identity.DirectoryProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "DirectoryProvider", Metadata: identity.DirectoryMetadata{ID: "oidc_wire_directory", VersionID: "oidc_wire_directory_v1", SecurityGuardID: "oidc_wire_directory_guard", SecurityGuardVersion: 1}, Spec: identity.DirectorySpec{ForestGUID: "00112233-4455-6677-8899-aabbccddeeff", DomainDNS: "corp.test", Transport: "ldaps", Endpoints: []identity.DirectoryEndpoint{{Host: oidcHTTPWireLDAPHost, Port: ldap.listener.Addr().(*net.TCPAddr).Port}}, UserBaseDNs: []string{"OU=People,DC=corp,DC=test"}, GroupBaseDNs: []string{"OU=Groups,DC=corp,DC=test"}, BindDN: "CN=reader,OU=People,DC=corp,DC=test", BindSecretVersionID: "oidc_wire_bind", CASecretVersionID: "oidc_wire_directory_ca", LoginAttribute: "userPrincipalName", Provisioning: "preprovisioned", GroupResolution: "token_groups_security", AccountCheck: "live_each_allow", OperationTimeoutSeconds: 2, MaximumGroups: 128, GroupMappings: []identity.DirectoryGroupMapping{}}}
	directoryBytes, _ := json.Marshal(directory)
	parsedDirectory, err := identity.ParseDirectoryProvider(bytes.NewReader(directoryBytes))
	if err != nil {
		t.Fatal("parse fixture directory", err)
	}
	directory = *parsedDirectory
	directoryCanonical, err := configmodel.CanonicalJSON(directory)
	if err != nil {
		t.Fatal("directory canonical", err)
	}
	directoryDigest, err := configmodel.Digest(directory)
	if err != nil {
		t.Fatal("directory digest", err)
	}
	provider := identity.OIDCProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "OIDCProvider", Metadata: identity.DirectoryMetadata{ID: "oidc_wire_provider", VersionID: "oidc_wire_provider_v1", SecurityGuardID: "oidc_wire_provider_guard", SecurityGuardVersion: 1}, Spec: identity.OIDCSpec{Issuer: idp.issuer, AuthorizationEndpoint: idp.issuer + "/authorize", TokenEndpoint: idp.issuer + "/token", JWKSURI: idp.issuer + "/keys", CASecretVersionID: "oidc_wire_ca", ResponseType: "code", Scope: "openid", TokenEndpointAuthMethod: "client_secret_basic", PKCEMethod: "S256", AllowedSigningAlgorithms: []string{"RS256"}, MFAClaimMode: "none", IdentityBinding: "approved_directory_link", Clients: []identity.OIDCClient{{Purpose: "login", ClientID: "wire_login", ClientSecretVersionID: "oidc_wire_login_secret", RedirectURI: cfg.LoginOrigin + "/auth/v2/oidc/providers/oidc_wire_provider/callback", MaximumAuthenticationAgeSeconds: 300}, {Purpose: "management", ClientID: "wire_management", ClientSecretVersionID: "oidc_wire_management_secret", RedirectURI: cfg.ManagementOrigin + "/auth/v2/oidc/providers/oidc_wire_provider/callback", MaximumAuthenticationAgeSeconds: 300}}}}
	providerBytes, _ := json.Marshal(provider)
	parsedProvider, err := identity.ParseOIDCProvider(bytes.NewReader(providerBytes))
	if err != nil {
		t.Fatal("parse fixture OIDC provider", err)
	}
	provider = *parsedProvider
	providerCanonical, err := configmodel.CanonicalJSON(provider)
	if err != nil {
		t.Fatal("provider canonical", err)
	}
	providerDigest, err := configmodel.Digest(provider)
	if err != nil {
		t.Fatal("provider digest", err)
	}
	link := identity.OIDCLinkVersion{ID: "oidc_wire_link_v1", LinkID: "oidc_wire_link", SecurityGuardVersion: 1, DirectoryIdentityID: "oidc_wire_directory_identity", PrincipalID: "oidc_wire_user"}
	link.ContentDigest, err = configmodel.Digest(link)
	if err != nil {
		t.Fatal("link digest", err)
	}
	linkCanonical, err := configmodel.CanonicalJSON(link)
	if err != nil {
		t.Fatal("link canonical", err)
	}
	now := time.Now().UTC()
	// Explicit trusted bootstrap seed: provider activation/link review lifecycle
	// is not the target of this HTTP composition test. All subsequent protocol,
	// MFA and session/current guards execute production code without proof hooks.
	err = base.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		queries := []struct {
			q    string
			args []any
		}{
			{`INSERT INTO users(id,username,password_hash,is_admin,identity_kind) VALUES('oidc_wire_user','oidc_wire_user','',FALSE,'directory')`, nil},
			{`INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES('cgrant_oidc_wire_read','oidc_wire_user','config.read','global','',1,?)`, []any{now}},
			{`INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES(?,?,?,?,1,1,TRUE,?,?)`, []any{directory.Metadata.ID, "Synthetic wire AD", directory.Spec.ForestGUID, directory.Metadata.SecurityGuardID, directory.Metadata.VersionID, now}},
			{`INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,1,?,?,?,?,?)`, []any{directory.Metadata.VersionID, directory.Metadata.ID, directoryDigest, string(directoryCanonical), "synthetic_bootstrap", "fixture-explicit-bootstrap", now}},
			{`INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,created_at) VALUES('oidc_wire_directory_identity','oidc_wire_user',?,?,?,1,?)`, []any{directory.Metadata.ID, directory.Spec.ForestGUID, "20112233-4455-6677-8899-aabbccddeeff", now}},
			{`INSERT INTO oidc_providers(id,name,issuer,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES(?,?,?,?,1,1,TRUE,?,?)`, []any{provider.Metadata.ID, "Synthetic corporate OIDC", provider.Spec.Issuer, provider.Metadata.SecurityGuardID, provider.Metadata.VersionID, now}},
			{`INSERT INTO oidc_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,1,?,?,?,?,?)`, []any{provider.Metadata.VersionID, provider.Metadata.ID, providerDigest, string(providerCanonical), "synthetic_bootstrap", "fixture-explicit-bootstrap", now}},
			{`INSERT INTO oidc_links(id,provider_id,subject,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES('oidc_wire_link',?,'CaseSensitiveWireSubject','oidc_wire_link_guard',1,1,TRUE,?,?)`, []any{provider.Metadata.ID, link.ID, now}},
			{`INSERT INTO oidc_link_versions(id,link_id,guard_version,directory_identity_id,principal_id,content_digest,canonical_json) VALUES(?,?,1,?,?,?,?)`, []any{link.ID, link.LinkID, link.DirectoryIdentityID, link.PrincipalID, link.ContentDigest, string(linkCanonical)}},
		}
		for index, query := range queries {
			if _, err := tx.Exec(context.Background(), query.q, query.args...); err != nil {
				return fmt.Errorf("fixture statement %d: %w", index, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("trusted fixture provider/link/grants seed", err)
	}
	coordinator := securitystate.New(base, newOIDCHTTPWireJournal())
	profile := cfg.SessionProfile()
	if err = coordinator.ActivateProfile(context.Background(), &profile); err != nil {
		t.Fatal("activate isolated secure profile", err)
	}
	protected := securitystate.ProtectStore(base, coordinator, profile)
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal("generate MFA key")
	}
	keys := &identity.Keyring{Active: "wire_mfa", Keys: map[string]string{"wire_mfa": base64.RawURLEncoding.EncodeToString(key)}}
	clear(key)
	authentication, err := identity.New(protected, coordinator, keys, profile)
	if err != nil {
		t.Fatal("construct identity", err)
	}
	ad, err := identity.NewADConnector(oidcHTTPWireLDAPSecrets{ldap.ca}, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal("construct LDAP transport", err)
	}
	directoryService := identity.NewDirectoryService(coordinator, cfg.ManagementOrigin, ad)
	authentication.WithDirectory(directoryService, ad)
	connector, err := oidcclient.New(oidcclient.NetworkPolicy{HTTPSOrigins: []string{strings.TrimSuffix(idp.issuer, "/tenant")}, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Timeout: 2 * time.Second, MaximumConcurrent: 2}, oidcHTTPWireSecrets{idp.ca})
	if err != nil {
		t.Fatal("construct OIDC connector", err)
	}
	federation, err := identity.NewOIDCService(authentication, connector)
	if err != nil {
		t.Fatal("construct OIDC identity", err)
	}
	stateKey := make([]byte, 32)
	if _, err = rand.Read(stateKey); err != nil {
		t.Fatal("generate standalone OIDC state key")
	}
	stateKeys, err := identity.NewOIDCStateKeyring("oidc_wire_state", map[string][]byte{"oidc_wire_state": stateKey})
	clear(stateKey)
	if err != nil {
		t.Fatal("construct OIDC state keys", err)
	}
	if _, err = federation.WithStateKeys(stateKeys); err != nil {
		t.Fatal("register distinct OIDC state key", err)
	}
	server := NewServer(cfg, protected, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetIdentity(authentication)
	server.SetDirectory(directoryService)
	server.SetOIDC(federation)
	return &oidcHTTPWireFixture{server: server, browser: newOIDCHTTPWireAPIBrowser(t, server.Handler()), base: base, ldap: ldap, idp: idp}
}

// The API leg is actual verified local HTTPS too. Only these three original
// browser hosts are mapped to its private listener; no host DNS or production
// configuration is changed, and redirects are returned to the test unchanged.
func newOIDCHTTPWireAPIBrowser(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic API certificate key")
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(13), DNSNames: []string{"login.test", "management.test", "portal.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, key)
	if err != nil {
		t.Fatal("sign synthetic API certificate")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse synthetic API certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ReadHeaderTimeout = 3 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" || (host != "login.test" && host != "management.test" && host != "portal.test") {
			return nil, fmt.Errorf("unsupported synthetic browser origin")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func (f *oidcHTTPWireFixture) httpRequest(t *testing.T, method, host, path string, body any, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal("encode synthetic HTTP request")
	}
	request, err := http.NewRequest(method, "https://"+host+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("construct synthetic HTTP request")
	}
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := f.browser.Do(request)
	if err != nil {
		t.Fatal("verified HTTPS API request failed")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || len(payload) >= 2<<20 {
		t.Fatal("API response read/bound failed")
	}
	recorder := httptest.NewRecorder()
	for name, values := range response.Header {
		recorder.Header()[name] = append([]string(nil), values...)
	}
	recorder.WriteHeader(response.StatusCode)
	_, _ = recorder.Write(payload)
	return recorder
}

type oidcHTTPWireBrowser struct {
	host, csrf string
	cookies    map[string]*http.Cookie
	flow       identity.FlowView
	callback   *url.URL
	oldBinding string
}

func (b *oidcHTTPWireBrowser) allCookies() []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookie := range b.cookies {
		cookies = append(cookies, cookie)
	}
	return cookies
}
func (b *oidcHTTPWireBrowser) remember(response *httptest.ResponseRecorder) {
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(b.cookies, cookie.Name)
		} else {
			b.cookies[cookie.Name] = cookie
		}
	}
}
func (b *oidcHTTPWireBrowser) headers() map[string]string {
	return map[string]string{"Origin": "https://" + b.host, "X-CSRF-Token": b.csrf}
}
func (f *oidcHTTPWireFixture) request(t *testing.T, b *oidcHTTPWireBrowser, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	response := f.httpRequest(t, method, b.host, path, body, b.allCookies(), b.headers())
	b.remember(response)
	return response
}
func (f *oidcHTTPWireFixture) begin(t *testing.T, audience string) *oidcHTTPWireBrowser {
	t.Helper()
	b := &oidcHTTPWireBrowser{host: audience + ".test", cookies: map[string]*http.Cookie{}}
	w := f.httpRequest(t, "GET", b.host, "/auth/v2/bootstrap", nil, nil, nil)
	if w.Code != 200 {
		t.Fatal("HTTP bootstrap failed", w.Code)
	}
	b.remember(w)
	b.csrf = cookieValue(w.Result().Cookies(), flowCSRFCookie)
	if !validFlowToken(b.csrf) {
		t.Fatal("bootstrap did not issue CSRF token")
	}
	w = f.request(t, b, "GET", "/auth/v2/oidc/providers", nil)
	var methods identity.OIDCLoginMethodList
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &methods) != nil || len(methods.Items) != 1 || methods.Items[0].ID != "oidc_wire_provider" {
		t.Fatal("HTTP public OIDC methods invalid", w.Code)
	}
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "issuer") {
		t.Fatal("public login methods leaked provider internals")
	}
	w = f.request(t, b, "POST", "/auth/v2/flows", map[string]string{"purpose": "login", "audience": audience})
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &b.flow) != nil || b.flow.State != "pending_primary" {
		t.Fatal("HTTP start flow failed", w.Code)
	}
	b.oldBinding = b.cookies[flowBindingCookie].Value
	w = f.request(t, b, "POST", "/auth/v2/flows/"+b.flow.ID+"/oidc-authorizations", map[string]string{"providerId": "oidc_wire_provider"})
	var authorization identity.OIDCAuthorizationView
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &authorization) != nil {
		t.Fatal("HTTP OIDC authorization failed", w.Code)
	}
	response, err := f.idp.browser.Get(authorization.AuthorizationURL)
	if err != nil {
		t.Fatal("verified HTTPS authorization request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal("IdP rejected actual authorization request", response.StatusCode)
	}
	b.callback, err = url.Parse(response.Header.Get("Location"))
	if err != nil || b.callback.Host != b.host {
		t.Fatal("IdP callback target changed")
	}
	return b
}

func (f *oidcHTTPWireFixture) currentCount(t *testing.T, q string, args ...any) int64 {
	t.Helper()
	var count int64
	err := f.base.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		return securitystate.One(context.Background(), tx, q, args, func(r storage.IdentityRows) error { return r.Scan(&count) })
	})
	if err != nil {
		t.Fatal("read HTTP wire fixture state", err)
	}
	return count
}

func (f *oidcHTTPWireFixture) complete(t *testing.T, b *oidcHTTPWireBrowser, boundaries bool) {
	t.Helper()
	originalID := b.flow.ID
	if boundaries {
		for _, test := range []struct {
			name, host, path string
			cookies          []*http.Cookie
		}{
			{"foreign_origin", "management.test", b.callback.RequestURI(), b.allCookies()},
			{"missing_browser", b.host, b.callback.RequestURI(), nil},
			{"foreign_browser", b.host, b.callback.RequestURI(), []*http.Cookie{{Name: flowBindingCookie, Value: strings.Repeat("A", 43)}}},
			{"duplicate_binding", b.host, b.callback.RequestURI(), append(b.allCookies(), &http.Cookie{Name: flowBindingCookie, Value: strings.Repeat("A", 43)})},
			{"foreign_provider", b.host, strings.Replace(b.callback.RequestURI(), "/oidc_wire_provider/", "/oidc_wire_other/", 1), b.allCookies()},
		} {
			w := f.httpRequest(t, "GET", test.host, test.path, nil, test.cookies, nil)
			if w.Code != 401 || f.idp.tokens.Load() != 0 {
				t.Fatal("callback boundary reached token endpoint", test.name, w.Code)
			}
		}
		wrongIssuer := *b.callback
		query := wrongIssuer.Query()
		query.Set("iss", "https://foreign.issuer.test")
		wrongIssuer.RawQuery = query.Encode()
		w := f.httpRequest(t, "GET", b.host, wrongIssuer.RequestURI(), nil, b.allCookies(), nil)
		if w.Code != 401 || f.idp.tokens.Load() != 0 {
			t.Fatal("issuer mismatch reached token endpoint", w.Code)
		}
	}
	w := f.httpRequest(t, "GET", b.host, b.callback.RequestURI(), nil, b.allCookies(), nil)
	if w.Code != 303 || f.idp.tokens.Load() != 1 || f.idp.pkce.Load() != 1 || f.idp.jwks.Load() == 0 || !f.idp.sni.Load() || f.ldap.binds.Load() == 0 || f.ldap.groups.Load() == 0 || f.ldap.guid.Load() == 0 {
		t.Fatal("actual OIDC→LDAP callback failed", w.Code)
	}
	newBinding := cookieValue(w.Result().Cookies(), flowBindingCookie)
	if !validFlowToken(newBinding) || newBinding == b.oldBinding {
		t.Fatal("callback did not rotate cookie binding")
	}
	for _, cookie := range w.Result().Cookies() {
		if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("callback binding cookie scope invalid")
		}
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Path != "/auth-ui/" || location.Query().Get("flow") == originalID {
		t.Fatal("callback redirect did not rotate flow")
	}
	b.remember(w)
	b.flow.ID = location.Query().Get("flow")
	w = f.request(t, b, "GET", "/auth/v2/flows/"+b.flow.ID, nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &b.flow) != nil || b.flow.State != "pending_mfa" || b.flow.NextStep != "totp_enrollment" || b.flow.MFASatisfied {
		t.Fatal("OIDC issuer's unqualified MFA claim bypassed AGP TOTP", w.Code)
	}
	w = f.httpRequest(t, "GET", b.host, "/auth/v2/flows/"+originalID, nil, []*http.Cookie{{Name: flowBindingCookie, Value: b.oldBinding}}, nil)
	if w.Code != 401 {
		t.Fatal("old pending flow binding remained valid", w.Code)
	}
	w = f.httpRequest(t, "GET", b.host, b.callback.RequestURI(), nil, []*http.Cookie{{Name: flowBindingCookie, Value: b.oldBinding}}, nil)
	if w.Code != 303 || f.idp.tokens.Load() != 1 || cookieValue(w.Result().Cookies(), flowBindingCookie) != "" {
		t.Fatal("callback replay repeated token exchange or issued a new binding", w.Code)
	}
	if f.currentCount(t, `SELECT COUNT(*) FROM sessions WHERE user_id='oidc_wire_user'`) != 0 {
		t.Fatal("primary OIDC callback issued a session")
	}
	w = f.request(t, b, "POST", "/auth/v2/flows/"+b.flow.ID+"/completions", struct{}{})
	if w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatal("HTTP completion accepted OIDC without TOTP", w.Code)
	}
	// Check current AD state at the MFA boundary, then recover the same pending
	// transaction. These flags simulate DC behavior, not persisted proof data.
	f.ldap.disabled.Store(true)
	w = f.request(t, b, "POST", "/auth/v2/flows/"+b.flow.ID+"/totp-enrollments", struct{}{})
	if w.Code != 401 {
		t.Fatal("disabled AD account started enrollment", w.Code)
	}
	f.ldap.disabled.Store(false)
	w = f.request(t, b, "POST", "/auth/v2/flows/"+b.flow.ID+"/totp-enrollments", struct{}{})
	var enrollment identity.Enrollment
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &enrollment) != nil {
		t.Fatal("actual HTTP TOTP enrollment failed", w.Code)
	}
	provisioning, err := url.Parse(enrollment.ProvisioningURI)
	if err != nil {
		t.Fatal("parse synthetic provisioning URI")
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(provisioning.Query().Get("secret"))
	if err != nil {
		t.Fatal("decode synthetic TOTP seed")
	}
	defer clear(seed)
	w = f.request(t, b, "POST", "/auth/v2/flows/"+b.flow.ID+"/totp-enrollments/"+enrollment.EnrollmentID+"/confirmations", map[string]string{"code": identity.TOTP(seed, time.Now().Unix()/30)})
	var confirmed identity.EnrollmentResult
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &confirmed) != nil || !confirmed.Flow.MFASatisfied {
		t.Fatal("actual TOTP confirmation/journal completion failed", w.Code)
	}
	w = f.request(t, b, "POST", "/auth/v2/flows/"+b.flow.ID+"/completions", struct{}{})
	if w.Code != 200 {
		t.Fatal("HTTP post-MFA completion failed", w.Code)
	}
	name := domain.LoginSessionCookieName
	foreign := domain.ManagementSessionCookieName
	if b.host == "management.test" {
		name, foreign = foreign, name
	}
	if b.cookies[name] == nil || !validFlowToken(b.cookies[name].Value) || b.cookies[foreign] != nil || b.cookies[flowBindingCookie] != nil {
		t.Fatal("audience session/flow cookies invalid")
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Value != "" && (!cookie.Secure || cookie.Domain != "" || cookie.Path != "/") {
			t.Fatal("authenticated cookie scope invalid")
		}
	}
	w = f.request(t, b, "GET", "/api/v1/me", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"oidc_wire_user"`) {
		t.Fatal("completed real OIDC/AD/TOTP session failed current HTTP guard", w.Code)
	}
	if f.currentCount(t, `SELECT COUNT(*) FROM sessions WHERE user_id='oidc_wire_user' AND audience=? AND oidc_authentication=TRUE AND directory_identity_id='oidc_wire_directory_identity'`, strings.TrimSuffix(b.host, ".test")) != 1 {
		t.Fatal("completion lost typed OIDC/directory session pins")
	}
}

func TestOIDCHTTPWireSQLite(t *testing.T)   { testOIDCHTTPWire(t, false) }
func TestOIDCHTTPWirePostgres(t *testing.T) { testOIDCHTTPWire(t, true) }
func testOIDCHTTPWire(t *testing.T, pg bool) {
	// No t.Parallel: Resolver replacement affects only this test process and is
	// restored after every IdP/LDAP connection and worker has been stopped.
	oidcHTTPWireDNS(t)
	for _, audience := range []string{"login", "management"} {
		t.Run(audience+"_full_flow_and_current_revocation", func(t *testing.T) {
			f := newOIDCHTTPWireFixture(t, pg)
			b := f.begin(t, audience)
			f.complete(t, b, audience == "login")
			before := f.ldap.binds.Load()
			f.ldap.disabled.Store(true)
			w := f.request(t, b, "GET", "/api/v1/me", nil)
			if w.Code != 401 || f.ldap.binds.Load() <= before {
				t.Fatal("current HTTP session used stale AD state", w.Code)
			}
			f.ldap.disabled.Store(false)
			f.ldap.outage.Store(true)
			w = f.request(t, b, "GET", "/api/v1/me", nil)
			if w.Code != 503 || !strings.Contains(w.Body.String(), "identity_provider_unavailable") {
				t.Fatal("LDAP TLS outage lost HTTP503 classification", w.Code)
			}
			f.ldap.outage.Store(false)
			w = f.request(t, b, "GET", "/api/v1/me", nil)
			if w.Code != 200 {
				t.Fatal("temporary AD outage permanently consumed session", w.Code)
			}
			guard := "oidc_wire_provider_guard"
			if audience == "management" {
				guard = "oidc_wire_link_guard"
			}
			if err := f.base.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
				_, err := tx.Exec(context.Background(), `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES(?,?,2)`, guard, guard)
				return err
			}); err != nil {
				t.Fatal("seed restrictive independent floor", err)
			}
			w = f.request(t, b, "GET", "/api/v1/me", nil)
			if w.Code != 401 {
				t.Fatal("current HTTP session survived restored OIDC provider/link below floor", w.Code)
			}
			if f.idp.tokens.Load() != 1 {
				t.Fatal("session checks or callback replay repeated token exchange")
			}
		})
	}
	t.Run("signed_wrong_nonce_rejected_before_directory_or_session", func(t *testing.T) {
		f := newOIDCHTTPWireFixture(t, pg)
		b := f.begin(t, "login")
		f.idp.mu.Lock()
		f.idp.badNonce = true
		f.idp.mu.Unlock()
		w := f.httpRequest(t, "GET", b.host, b.callback.RequestURI(), nil, b.allCookies(), nil)
		if w.Code != 401 || f.idp.tokens.Load() != 1 || f.ldap.binds.Load() != 0 || f.currentCount(t, `SELECT COUNT(*) FROM sessions WHERE user_id='oidc_wire_user'`) != 0 {
			t.Fatal("signed JWT nonce mismatch reached directory/session", w.Code)
		}
		w = f.httpRequest(t, "GET", b.host, b.callback.RequestURI(), nil, b.allCookies(), nil)
		if f.idp.tokens.Load() != 1 || cookieValue(w.Result().Cookies(), flowBindingCookie) != "" {
			t.Fatal("rejected callback replay re-exchanged code or minted proof", w.Code)
		}
	})
}
