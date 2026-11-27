package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/storage"
)

func directoryHTTPFixture(t *testing.T) (*Server, []*http.Cookie, map[string]string) {
	t.Helper()
	s := secureHTTPFixture(t)
	s.identity.Coordinator.Authority = planHTTPAuthority{}
	s.SetDirectory(identity.NewDirectoryService(s.identity.Coordinator, s.cfg.ManagementOrigin, nil))
	user, err := s.store.FindUserByUsername(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	csrf := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	now := time.Now().UTC()
	if err := s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		return identity.InsertSession(context.Background(), tx, domain.Session{ID: "directory_http_session", UserID: user.ID, TokenHash: auth.TokenHash(token), CSRFHash: auth.TokenHash(csrf), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: domain.SessionAudienceManagement, AudienceOrigin: s.cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, MFAAt: &now, LastSeenAt: &now})
	}); err != nil {
		t.Fatal(err)
	}
	return s, []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}, map[string]string{"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": csrf, "Idempotency-Key": "directory_http_request_0001"}
}

func TestDirectoryManagementHTTPContractAndBoundaries(t *testing.T) {
	s, cookies, headers := directoryHTTPFixture(t)
	h := s.Handler()
	path := "/api/v2/directory-providers"
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/directory-access", nil, cookies, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"manage":true`) || !strings.Contains(w.Body.String(), `"approve":false`) {
		t.Fatalf("access must not imply approve for admin: %d %s", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, nil, nil); w.Code != 401 {
		t.Fatal("anonymous list", w.Code)
	}
	for _, host := range []string{"portal.test", "login.test"} {
		if w := identityHTTPRequest(t, h, "GET", host, path, nil, cookies, nil); w.Code != 403 {
			t.Fatal("other origin list", host, w.Code)
		}
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path, identity.DirectoryCreate{Name: "Directory", ForestGUID: "00000000-0000-0000-0000-000000000001"}, cookies, map[string]string{"Origin": s.cfg.ManagementOrigin}); w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path, map[string]any{"name": "Directory", "forestGuid": "00000000-0000-0000-0000-000000000001", "enabled": true}, cookies, headers); w.Code != 400 {
		t.Fatal("caller enabled provider", w.Code)
	}
	w := identityHTTPRequest(t, h, "POST", "management.test", path, identity.DirectoryCreate{Name: "Directory", ForestGUID: "00000000-0000-0000-0000-000000000001"}, cookies, headers)
	if w.Code != 201 || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var p identity.DirectoryProviderView
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Enabled || p.Configuration != nil {
		t.Fatal("new registration activated")
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", path+"?limit=201", nil, cookies, nil); w.Code != 400 {
		t.Fatal("unbounded page", w.Code)
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", path+"?cursor=a&cursor=b", nil, cookies, nil); w.Code != 400 {
		t.Fatal("duplicate query", w.Code)
	}
	doc := identity.DirectoryProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "DirectoryProvider", Metadata: identity.DirectoryMetadata{ID: p.ID, VersionID: "directory_version_http_1", SecurityGuardID: p.SecurityGuardID, SecurityGuardVersion: 1}, Spec: identity.DirectorySpec{ForestGUID: p.ForestGUID, DomainDNS: "corp.example.net", Transport: "ldaps", Endpoints: []identity.DirectoryEndpoint{{Host: "dc.corp.example.net", Port: 636}}, UserBaseDNs: []string{"OU=People,DC=corp,DC=example,DC=net"}, GroupBaseDNs: []string{"OU=Groups,DC=corp,DC=example,DC=net"}, BindDN: "CN=reader,DC=corp,DC=example,DC=net", BindSecretVersionID: "bind_secret_v1", CASecretVersionID: "ca_secret_v1", LoginAttribute: "userPrincipalName", Provisioning: "preprovisioned", GroupResolution: "token_groups_security", AccountCheck: "live_each_allow", OperationTimeoutSeconds: 3, MaximumGroups: 2048, GroupMappings: []identity.DirectoryGroupMapping{}}}
	if w := identityHTTPRequest(t, h, "PUT", "management.test", path+"/"+p.ID, doc, cookies, headers); w.Code != 428 {
		t.Fatal("CAS omitted", w.Code, w.Body.String())
	}
	headers["If-Match"] = `"1"`
	w = identityHTTPRequest(t, h, "PUT", "management.test", path+"/"+p.ID, doc, cookies, headers)
	if w.Code != 201 || w.Header().Get("ETag") != `"2"` {
		t.Fatalf("immutable version: %d %s", w.Code, w.Body.String())
	}
	doc.Metadata.VersionID = "directory_version_http_2"
	doc.Metadata.SecurityGuardVersion = 2
	if w := identityHTTPRequest(t, h, "PUT", "management.test", path+"/"+p.ID, doc, cookies, headers); w.Code != 412 {
		t.Fatal("stale CAS", w.Code, w.Body.String())
	}
	version := "directory_version_http_1"
	if w := identityHTTPRequest(t, h, "GET", "management.test", path+"/"+p.ID+"/versions/"+version, nil, cookies, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"contentDigest":"sha256:`) {
		t.Fatal("immutable review content", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path+"/"+p.ID+"/tests", map[string]string{"versionId": version}, cookies, headers); w.Code != 503 || !strings.Contains(w.Body.String(), "identity_provider_unavailable") {
		t.Fatal("missing real connector did not fail closed", w.Code, w.Body.String())
	}
	headers["If-Match"] = `"2"`
	if w := identityHTTPRequest(t, h, "POST", "management.test", path+"/"+p.ID+"/activations", identity.DirectoryActivation{VersionID: version, Enabled: true, Reason: "Enable"}, cookies, headers); w.Code != 503 {
		t.Fatal("enable without connector", w.Code, w.Body.String())
	}
	w = identityHTTPRequest(t, h, "POST", "management.test", path+"/"+p.ID+"/activations", identity.DirectoryActivation{VersionID: version, Enabled: false, Reason: "Keep disabled"}, cookies, headers)
	if w.Code != 202 {
		t.Fatalf("disable plan without network: %d %s", w.Code, w.Body.String())
	}
	var op identity.ProviderSecurityOperation
	if err := json.Unmarshal(w.Body.Bytes(), &op); err != nil {
		t.Fatal(err)
	}
	if op.State != "pending" || op.ApprovalStatus != "pending" || op.ProviderChange.Enabled {
		t.Fatal("plan activated provider")
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/security/operations/"+op.ID+"/approvals", map[string]string{"requestDigest": op.RequestDigest, "reason": "Self review"}, cookies, headers); w.Code != 403 {
		t.Fatal("admin implicit approve", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/security/operations/"+op.ID+"/executions", map[string]string{"requestDigest": op.RequestDigest, "reason": "Not approved"}, cookies, headers); w.Code < 400 {
		t.Fatal("unapproved execution")
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", path+"/"+p.ID, nil, cookies, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatal("failed operation changed active state", w.Code, w.Body.String())
	}
	// Revoked MFA cannot authorize a new mutation even with matching CSRF/CAS.
	if err := s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, err := tx.Exec(context.Background(), `UPDATE sessions SET mfa_at=? WHERE id=?`, time.Now().Add(-6*time.Minute), "directory_http_session")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path, identity.DirectoryCreate{Name: "Stale MFA", ForestGUID: "00000000-0000-0000-0000-000000000002"}, cookies, headers); w.Code != 403 {
		t.Fatal("stale MFA mutation", w.Code, w.Body.String())
	}
}

func TestDirectoryConsoleOriginBoundary(t *testing.T) {
	s, cookies, _ := directoryHTTPFixture(t)
	for _, tc := range []struct {
		host string
		want int
	}{{"management.test", 200}, {"portal.test", 403}, {"login.test", 403}} {
		w := identityHTTPRequest(t, s.Handler(), "GET", tc.host, "/directory-ui/", nil, cookies, nil)
		if w.Code != tc.want {
			t.Fatalf("console origin %s: %d", tc.host, w.Code)
		}
	}
	for _, host := range []string{"portal.test", "login.test"} {
		for _, path := range []string{"/directory-ui", "/directory-ui/missing.js", "/directory-ui/deep/link"} {
			w := identityHTTPRequest(t, s.Handler(), "HEAD", host, path, nil, cookies, nil)
			if w.Code != 403 {
				t.Fatalf("asset origin %s %s: %d", host, path, w.Code)
			}
		}
	}
}
