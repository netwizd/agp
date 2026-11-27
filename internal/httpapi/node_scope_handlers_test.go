package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nodeidentity"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func nodeScopeHTTPFixture(t *testing.T, pg bool) (*Server, func(string, string, string, string) ([]*http.Cookie, map[string]string)) {
	t.Helper()
	ctx := context.Background()
	base := oidcHTTPWireStore(t, pg)
	cfg := config.Config{DatabaseDriver: "postgres", SecureProfile: true, ConfigurationEnabled: true, NodeIdentityConfig: "/synthetic-node-identity", PortalHost: "portal.test", LoginOrigin: "https://login.test", ManagementOrigin: "https://management.test", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour, LoginRateLimitMax: 30, LoginRateLimitWind: time.Minute, MFAKeyFile: "/synthetic-keyring", AuthMTLSAddr: "127.0.0.1:0", AuthMTLSCertFile: "/synthetic-cert", AuthMTLSKeyFile: "/synthetic-key", AuthMTLSClientCAFile: "/synthetic-ca"}
	graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "node_http_scopes", Sites: []rolescope.Site{{ID: "site_one"}, {ID: "site_other"}}, NodeGroups: []rolescope.NodeGroup{}, Nodes: []rolescope.Node{{ID: "node_one", SiteID: "site_one", GroupIDs: []string{}}, {ID: "node_other", SiteID: "site_other", GroupIDs: []string{}}}, Resources: []rolescope.Resource{}, ResourceRoutes: []rolescope.ResourceRoute{}}
	now := time.Now().UTC()
	err := base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		if e := rolescope.BootstrapTx(ctx, tx, 1, graph); e != nil {
			return e
		}
		for _, n := range graph.Nodes {
			raw, _ := json.Marshal(nodeidentity.Node{ID: n.ID, SiteID: n.SiteID, Name: n.ID, Labels: map[string]string{}, GroupIDs: n.GroupIDs, CreatedAt: now})
			if _, e := tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, n.ID, n.SiteID, string(raw), now); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := securitystate.New(base, httpIdentityAuthority{})
	profile := cfg.SessionProfile()
	if err = coordinator.ActivateProfile(ctx, &profile); err != nil {
		t.Fatal(err)
	}
	protected := securitystate.ProtectStore(base, coordinator, profile)
	keys := &identity.Keyring{Active: "test", Keys: map[string]string{"test": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32))}}
	identities, err := identity.New(protected, coordinator, keys, profile)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, protected, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetIdentity(identities)
	// Real independently stored issuing CA. Synthetic certificates only; the
	// path protection and durable issuer are the production implementation.
	dir, err := os.MkdirTemp("/tmp", "agp-node-http-issuer.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-node-http-root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour)}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "issuer.pem"), filepath.Join(dir, "issuer.key")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err = os.WriteFile(certPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	issuer, err := nodeidentity.OpenIssuer(ctx, nodeidentity.IssuerConfig{LedgerFile: filepath.Join(dir, "issuer.db"), IssuingCertificateFile: certPath, IssuingKeyFile: keyPath, CertificateLifetimeSeconds: 3600}, coordinator.Authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	agents, err := inventory.NewWithRegistry(coordinator, coordinator.Authority, issuer)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := nodeidentity.New(coordinator, issuer, agents, cfg.ManagementOrigin)
	if err != nil {
		t.Fatal(err)
	}
	s.SetInventory(agents)
	s.SetNodeIdentity(nodes)
	actor := func(id, permission, kind, scope string) ([]*http.Cookie, map[string]string) {
		t.Helper()
		token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(len(id))}, 32))
		csrf := "node_csrf_" + id
		err := coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "synthetic-test-password"); e != nil {
				return e
			}
			if e := identity.InsertSession(ctx, tx, domain.Session{ID: "session_" + id, UserID: id, TokenHash: auth.TokenHash(token), CSRFHash: auth.TokenHash(csrf), Audience: "management", AudienceOrigin: cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now}); e != nil {
				return e
			}
			if e := securitystate.EnsureBuiltinRolesTx(ctx, tx); e != nil {
				return e
			}
			role, e := securitystate.ReadRoleDefinitionTx(ctx, tx, "role_"+strings.ReplaceAll(permission, ".", "_"))
			if e != nil {
				return e
			}
			return securitystate.PublishRoleBindingTx(ctx, tx, h, securitystate.RoleBinding{ID: "rbinding_" + id, PrincipalID: id, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: kind, ScopeID: scope, AuthorityEpoch: 1, Revision: 1, CreatedAt: h.RecordedAt})
		})
		if err != nil {
			t.Fatal(err)
		}
		return []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}, map[string]string{"Origin": cfg.ManagementOrigin, "X-CSRF-Token": csrf, "Idempotency-Key": "node_http_" + id}
	}
	operator, _ := actor("global_enroller", "nodes.enroll", "global", "")
	a := nodeidentity.Actor{TokenHash: auth.TokenHash(operator[0].Value), Origin: cfg.ManagementOrigin}
	for _, id := range []string{"node_one", "node_other"} {
		en, e := nodes.CreateEnrollment(ctx, a, id, "seed_"+id, nodeidentity.EnrollmentRequest{Role: "agent"})
		if e != nil {
			t.Fatal(e)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			t.Fatal(e)
		}
		in := nodeidentity.EnrollmentSubmission{NodeID: id, EnrollmentToken: en.EnrollmentToken, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
		pending, e := nodes.RequestEnrollment(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = nodes.ApproveEnrollment(ctx, a, id, en.ID, "approve_"+id, nodeidentity.ApprovalRequest{ExpectedPublicKeyDigest: pending.PublicKeyDigest, RequestDigest: pending.RequestDigest}); e != nil {
			t.Fatal(e)
		}
		if _, e = nodes.Enroll(ctx, in); e != nil {
			t.Fatal(e)
		}
	}
	return s, actor
}

func TestNodeScopedHTTPActualServicesSQLite(t *testing.T) { testNodeScopedHTTPActualServices(t, false) }
func TestNodeScopedHTTPActualServicesPostgres(t *testing.T) {
	testNodeScopedHTTPActualServices(t, true)
}
func testNodeScopedHTTPActualServices(t *testing.T, pg bool) {
	s, actor := nodeScopeHTTPFixture(t, pg)
	reader, _ := actor("site_reader", "nodes.read", "site", "site_one")
	enroller, headers := actor("site_enroller", "nodes.enroll", "site", "site_one")
	unrelated, unrelatedHeaders := actor("other_permission", "users.read", "global", "")
	h := s.Handler()
	for _, path := range []string{"/api/v2/nodes", "/api/v2/nodes/node_one", "/api/v2/agent-inventory", "/api/v2/node-identity-profile"} {
		w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, reader, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "node_other") {
			t.Fatal("scoped HTTP read", path, w.Code, w.Body.String())
		}
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/nodes/node_other", nil, reader, nil); w.Code != 404 {
		t.Fatal("sibling HTTP read", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/v2/nodes", "/api/v2/agent-inventory"} {
		if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, unrelated, nil); w.Code != 403 {
			t.Fatal("unrelated permission became node access", w.Code, w.Body.String())
		}
		if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, nil, nil); w.Code != 401 {
			t.Fatal("anonymous nodes", w.Code)
		}
		if w := identityHTTPRequest(t, h, "GET", "login.test", path, nil, reader, nil); w.Code < 400 {
			t.Fatal("wrong origin", w.Code)
		}
	}
	for _, tc := range []struct {
		name    string
		cookies []*http.Cookie
		headers map[string]string
		node    string
	}{{"missing_csrf", enroller, map[string]string{"Origin": s.cfg.ManagementOrigin, "Idempotency-Key": "missing_csrf_node"}, "node_one"}, {"wrong_origin", enroller, map[string]string{"Origin": "https://other.test", "X-CSRF-Token": headers["X-CSRF-Token"], "Idempotency-Key": "wrong_origin_node"}, "node_one"}, {"out_of_scope", enroller, headers, "node_other"}, {"no_permission", unrelated, unrelatedHeaders, "node_one"}} {
		w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/nodes/"+tc.node+"/enrollments", nodeidentity.EnrollmentRequest{Role: "agent"}, tc.cookies, tc.headers)
		if w.Code != 403 {
			t.Fatal(tc.name, w.Code, w.Body.String())
		}
	}
	headers["Idempotency-Key"] = "node_scoped_actual_enrollment"
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/nodes/node_one/enrollments", nodeidentity.EnrollmentRequest{Role: "agent"}, enroller, headers); w.Code != 201 {
		t.Fatal("nonadmin enrollment", w.Code, w.Body.String())
	}
	creator, creationHeaders := actor("creation_operator", "nodes.enroll", "global", "")
	body := map[string]any{"id": "node_created", "siteId": "site_one", "name": "frozen creation", "labels": map[string]string{}}
	created := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/nodes", body, creator, creationHeaders)
	if created.Code != 201 {
		t.Fatal("enroll-only creation", created.Code, created.Body.String())
	}
	err := s.identity.Coordinator.Store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		var raw string
		if e := securitystate.One(context.Background(), tx, `SELECT node_json FROM managed_nodes WHERE id='node_created'`, nil, func(rows storage.IdentityRows) error { return rows.Scan(&raw) }); e != nil {
			return e
		}
		var n nodeidentity.Node
		if e := json.Unmarshal([]byte(raw), &n); e != nil {
			return e
		}
		n.Name = "sensitive current metadata"
		b, _ := json.Marshal(n)
		_, e := tx.Exec(context.Background(), `UPDATE managed_nodes SET node_json=? WHERE id='node_created'`, string(b))
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	replay := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/nodes", body, creator, creationHeaders)
	if replay.Code != 201 || replay.Body.String() != created.Body.String() || strings.Contains(replay.Body.String(), "sensitive") {
		t.Fatal("creation key became current read authority", replay.Code, replay.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/nodes/node_created", nil, creator, nil); w.Code != 403 {
		t.Fatal("enroll implied read", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/nodes/node_created", nil, reader, nil); w.Code != 404 {
		t.Fatal("input site became sealed ownership", w.Code, w.Body.String())
	}
	if err = s.identity.Coordinator.Store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, e := tx.Exec(context.Background(), `UPDATE sessions SET mfa_at=? WHERE id='session_site_enroller'`, time.Now().Add(-6*time.Minute))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/nodes/node_one/enrollments", nodeidentity.EnrollmentRequest{Role: "agent"}, enroller, headers); w.Code != 403 || !strings.Contains(w.Body.String(), "step_up_required") {
		t.Fatal("stale MFA", w.Code, w.Body.String())
	}
	if err = s.identity.Coordinator.Store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, e := tx.Exec(context.Background(), `UPDATE sessions SET revoked_at=? WHERE id='session_site_reader'`, time.Now())
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/nodes", nil, reader, nil); w.Code != 401 {
		t.Fatal("revoked session", w.Code, w.Body.String())
	}
}
