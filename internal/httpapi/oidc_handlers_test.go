package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/storage"
)

func oidcHTTPFixture(t *testing.T) (*Server, []*http.Cookie, map[string]string) {
	t.Helper()
	s, cookies, headers := directoryHTTPFixture(t)
	s.identity.WithDirectory(s.directory, nil)
	service, e := identity.NewOIDCService(s.identity, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.SetOIDC(service)
	if e = s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, e := tx.Exec(context.Background(), `UPDATE sessions SET primary_at=? WHERE id='directory_http_session'`, time.Now().UTC())
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return s, cookies, headers
}
func oidcHTTPDocument(p identity.OIDCProviderView) identity.OIDCProviderDocument {
	return identity.OIDCProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "OIDCProvider", Metadata: identity.DirectoryMetadata{ID: p.ID, VersionID: "oidc_http_version_1", SecurityGuardID: p.SecurityGuardID, SecurityGuardVersion: 1}, Spec: identity.OIDCSpec{Issuer: p.Issuer, AuthorizationEndpoint: p.Issuer + "/authorize", TokenEndpoint: p.Issuer + "/token", JWKSURI: p.Issuer + "/keys", CASecretVersionID: "oidc_ca_http", ResponseType: "code", Scope: "openid", TokenEndpointAuthMethod: "client_secret_basic", PKCEMethod: "S256", AllowedSigningAlgorithms: []string{"RS256"}, MFAClaimMode: "none", IdentityBinding: "approved_directory_link", Clients: []identity.OIDCClient{{Purpose: "login", ClientID: "http-login", ClientSecretVersionID: "oidc_login_secret", RedirectURI: "https://login.test/auth/v2/oidc/providers/" + p.ID + "/callback", MaximumAuthenticationAgeSeconds: 300}, {Purpose: "management", ClientID: "http-management", ClientSecretVersionID: "oidc_management_secret", RedirectURI: "https://management.test/auth/v2/oidc/providers/" + p.ID + "/callback", MaximumAuthenticationAgeSeconds: 300}}}}
}
func TestOIDCManagementHTTPContractAndBoundaries(t *testing.T) {
	s, cookies, headers := oidcHTTPFixture(t)
	h := s.Handler()
	base := "/api/v2/identity-providers"
	for _, host := range []string{"portal.test", "login.test"} {
		if w := identityHTTPRequest(t, h, "GET", host, base, nil, cookies, nil); w.Code != 403 {
			t.Fatal("cross origin providers", host, w.Code)
		}
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", base, identity.OIDCProviderCreate{Name: "Corporate", Issuer: "https://idp.test"}, cookies, map[string]string{"Origin": "https://management.test"}); w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", base, map[string]any{"name": "Corporate", "issuer": "https://idp.test", "enabled": true}, cookies, headers); w.Code != 400 {
		t.Fatal("caller activation", w.Code)
	}
	w := identityHTTPRequest(t, h, "POST", "management.test", base, identity.OIDCProviderCreate{Name: "Corporate", Issuer: "https://idp.test"}, cookies, headers)
	if w.Code != 201 || w.Header().Get("ETag") != `"1"` {
		t.Fatal("create", w.Code, w.Body.String())
	}
	var p identity.OIDCProviderView
	if e := json.Unmarshal(w.Body.Bytes(), &p); e != nil {
		t.Fatal(e)
	}
	if p.Enabled || p.Configuration != nil {
		t.Fatal("registration enabled")
	}
	for _, query := range []string{"?limit=201", "?limit=1&limit=2", "?cursor=a&cursor=b", "?cursor=%ZZ", "?unknown=true"} {
		if w := identityHTTPRequest(t, h, "GET", "management.test", base+query, nil, cookies, nil); w.Code != 400 {
			t.Fatal("invalid query", query, w.Code)
		}
	}
	doc := oidcHTTPDocument(p)
	if w := identityHTTPRequest(t, h, "PUT", "management.test", base+"/"+p.ID, doc, cookies, headers); w.Code != 428 {
		t.Fatal("CAS omitted", w.Code)
	}
	headers["If-Match"] = `"1"`
	w = identityHTTPRequest(t, h, "PUT", "management.test", base+"/"+p.ID, doc, cookies, headers)
	if w.Code != 201 || w.Header().Get("ETag") != `"2"` || !strings.Contains(w.Body.String(), `"kind":"OIDCProvider"`) {
		t.Fatal("propose", w.Code, w.Body.String())
	}
	doc.Metadata.VersionID = "oidc_http_version_2"
	doc.Metadata.SecurityGuardVersion = 2
	if w := identityHTTPRequest(t, h, "PUT", "management.test", base+"/"+p.ID, doc, cookies, headers); w.Code != 412 {
		t.Fatal("stale CAS", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", base+"/"+p.ID+"/versions/oidc_http_version_1", nil, cookies, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"contentDigest":"sha256:`) {
		t.Fatal("immutable review", w.Code, w.Body.String())
	}
	w = identityHTTPRequest(t, h, "POST", "management.test", base+"/"+p.ID+"/tests", map[string]string{"versionId": "oidc_http_version_1"}, cookies, headers)
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"state":"failed"`) {
		t.Fatal("unconfigured test falsely passed", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/security/operations/oidcop_unknown", nil, cookies, nil); w.Code != 404 {
		t.Fatal("operation namespace", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "login.test", "/auth/v2/oidc/providers", nil, nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("disabled public methods", w.Code, w.Body.String())
	}
	if e := s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, e := tx.Exec(context.Background(), `UPDATE sessions SET primary_at=? WHERE id='directory_http_session'`, time.Now().Add(-6*time.Minute))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", base, identity.OIDCProviderCreate{Name: "Requires fresh primary", Issuer: "https://next-idp.test"}, cookies, headers); w.Code != 403 || !strings.Contains(w.Body.String(), "step_up_required") {
		t.Fatal("stale primary did not request reauthentication", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", base, nil, cookies, nil); w.Code != 200 {
		t.Fatal("ordinary provider read required fresh primary", w.Code, w.Body.String())
	}
}
func TestOIDCCallbackHTTPRejectsUnboundOrAmbiguousBeforeProvider(t *testing.T) {
	s, _, _ := oidcHTTPFixture(t)
	h := s.Handler()
	state := strings.Repeat("A", 43)
	base := "/auth/v2/oidc/providers/oidc_http/callback"
	for _, query := range []string{"?code=secret", "?state=" + state + "&code=a&code=b", "?state=" + state + "&code=a&error=access_denied", "?state=" + state + "&code=a&unknown=x", "?state=" + state + "&code=a&error_description=secret", "?state=" + state + "&code=a&session_state=bad+space"} {
		w := identityHTTPRequest(t, h, "GET", "login.test", base+query, nil, nil, nil)
		if w.Code != 400 || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("unbound callback", w.Code, w.Body.String())
		}
	}
	w := identityHTTPRequest(t, h, "GET", "login.test", base+"?state="+state+"&code=secret&session_state=opaque.valid", nil, nil, nil)
	if w.Code != 401 || strings.Contains(w.Body.String(), "secret") || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("binding required", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "portal.test", base+"?state="+state+"&code=secret", nil, nil, nil); w.Code != 403 {
		t.Fatal("portal callback", w.Code)
	}
}
