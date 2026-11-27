package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type gatewayHTTPGrant struct{ permission, kind, scope string }

type gatewayHTTPActor struct {
	cookies []*http.Cookie
	headers map[string]string
}

type gatewayHTTPFixture struct {
	server        *Server
	base          storage.Store
	configuration configmodel.Configuration
	revision      *configuration.Revision
	actor         func(string, ...gatewayHTTPGrant) gatewayHTTPActor
	admin         configuration.Actor
	adminHTTP     gatewayHTTPActor
}

func newGatewayScopeHTTPFixture(t *testing.T, pg bool) *gatewayHTTPFixture {
	t.Helper()
	ctx := context.Background()
	base := oidcHTTPWireStore(t, pg)
	cfg := config.Config{DatabaseDriver: "postgres", SecureProfile: true, ConfigurationEnabled: true, PortalHost: "portal.test", LoginOrigin: "https://login.test", ManagementOrigin: "https://management.test", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour, LoginRateLimitMax: 30, LoginRateLimitWind: time.Minute, MFAKeyFile: "/synthetic-keyring", AuthMTLSAddr: "127.0.0.1:0", AuthMTLSCertFile: "/synthetic-cert", AuthMTLSKeyFile: "/synthetic-key", AuthMTLSClientCAFile: "/synthetic-ca"}
	raw, err := os.ReadFile("../../docs/v2/examples/configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	var document configmodel.Configuration
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(document.Gateways[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []struct{ id, site, node string }{
		{"gw_aaa_other", "site_other", "node_other"},
		{"gw_second", "site_msk", "node_msk02"},
		{"gw_shared", "site_msk", "node_msk01"},
		{"gw_visible", "site_msk", "node_msk01"},
	} {
		var gateway configmodel.Gateway
		if err = json.Unmarshal(original, &gateway); err != nil {
			t.Fatal(err)
		}
		gateway.Metadata.ID, gateway.Metadata.SiteID, gateway.Metadata.Name = extra.id, extra.site, "Private metadata of "+extra.id
		gateway.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{extra.node}}
		if extra.id == "gw_shared" {
			gateway.Spec.NodeSelector.NodeIDs = []string{"node_msk01", "node_msk02"}
		}
		gateway.Spec.Routes[0].ID, gateway.Spec.Routes[0].Hostname = "route_"+extra.id, strings.ReplaceAll(extra.id[3:], "_", "-")+".example.net"
		document.Gateways = append(document.Gateways, gateway)
	}
	graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "gateway_http_scopes", Sites: []rolescope.Site{{ID: "site_msk"}, {ID: "site_other"}}, NodeGroups: []rolescope.NodeGroup{{ID: "ng_front", SiteID: "site_msk"}, {ID: "ng_back", SiteID: "site_msk"}}, Nodes: []rolescope.Node{{ID: "node_msk01", SiteID: "site_msk", GroupIDs: []string{"ng_front"}}, {ID: "node_msk02", SiteID: "site_msk", GroupIDs: []string{"ng_back"}}, {ID: "node_other", SiteID: "site_other", GroupIDs: []string{}}}, Resources: []rolescope.Resource{}, ResourceRoutes: []rolescope.ResourceRoute{}}
	now := time.Now().UTC()
	err = base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES('gateway_http_admin','gateway_http_admin','synthetic-test-password',TRUE)`); e != nil {
			return e
		}
		for _, gateway := range document.Gateways {
			if _, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,?)`, gateway.Metadata.ID, gateway.Metadata.SiteID); e != nil {
				return e
			}
		}
		if e := rolescope.BootstrapTx(ctx, tx, 1, graph); e != nil {
			return e
		}
		for _, node := range graph.Nodes {
			fact, e := json.Marshal(map[string]any{"id": node.ID, "siteId": node.SiteID, "name": node.ID, "groupIds": node.GroupIDs, "labels": map[string]string{"environment": "pilot"}, "createdAt": now})
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, node.ID, node.SiteID, string(fact), now); e != nil {
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
	server := NewServer(cfg, protected, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetIdentity(identities)
	service := configuration.New(coordinator, cfg.ManagementOrigin, compiler.Options{})
	server.SetConfiguration(service)
	f := &gatewayHTTPFixture{server: server, base: base, configuration: document}
	f.actor = func(id string, grants ...gatewayHTTPGrant) gatewayHTTPActor {
		t.Helper()
		token, tokenHash, e := auth.NewToken()
		if e != nil {
			t.Fatal(e)
		}
		csrf := "gateway_csrf_" + id
		e = coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			if id != "gateway_http_admin" {
				if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "synthetic-test-password"); e != nil {
					return e
				}
			}
			if e := identity.InsertSession(ctx, tx, domain.Session{ID: "session_" + id, UserID: id, TokenHash: tokenHash, CSRFHash: auth.TokenHash(csrf), Audience: "management", AudienceOrigin: cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now}); e != nil {
				return e
			}
			// Trusted fixture publication supplies existing roles to the actual
			// authorizer; it is not a test of the separate approval workflow.
			if e := securitystate.EnsureBuiltinRolesTx(ctx, tx); e != nil {
				return e
			}
			for _, grant := range grants {
				role, e := securitystate.ReadRoleDefinitionTx(ctx, tx, "role_"+strings.ReplaceAll(grant.permission, ".", "_"))
				if e != nil {
					return e
				}
				binding := securitystate.RoleBinding{ID: securitystate.ID("rbinding"), PrincipalID: id, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: grant.kind, ScopeID: grant.scope, AuthorityEpoch: h.Epoch, Revision: 1, CreatedAt: h.RecordedAt}
				if e = securitystate.PublishRoleBindingTx(ctx, tx, h, binding); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		return gatewayHTTPActor{cookies: []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}, headers: map[string]string{"Origin": cfg.ManagementOrigin, "X-CSRF-Token": csrf, "Idempotency-Key": "gateway_http_" + id}}
	}
	admin := f.actor("gateway_http_admin")
	f.adminHTTP = admin
	f.admin = configuration.Actor{TokenHash: auth.TokenHash(admin.cookies[0].Value), Origin: cfg.ManagementOrigin}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	f.revision, err = service.CreateRevision(ctx, f.admin, "gateway_http_seed_revision", configuration.CreateRevision{Content: content})
	if err != nil {
		t.Fatal("seed full configuration through actual service", err)
	}
	return f
}

type gatewayHTTPWriteState struct {
	revisions, requests, drafts, audits, version int64
	head                                         string
}

func (f *gatewayHTTPFixture) writeState(t *testing.T) gatewayHTTPWriteState {
	t.Helper()
	var out gatewayHTTPWriteState
	err := f.base.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		return securitystate.One(context.Background(), tx, `SELECT (SELECT COUNT(*) FROM config_revisions),(SELECT COUNT(*) FROM config_requests),(SELECT COUNT(*) FROM config_drafts),(SELECT COUNT(*) FROM audit_events WHERE event_type LIKE 'config.%'),row_version,revision_id FROM config_head WHERE id=1`, nil, func(rows storage.IdentityRows) error {
			return rows.Scan(&out.revisions, &out.requests, &out.drafts, &out.audits, &out.version, &out.head)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGatewayScopedHTTPActualServicesSQLite(t *testing.T) {
	testGatewayScopedHTTPActualServices(t, false)
}

func TestGatewayScopedHTTPActualServicesPostgres(t *testing.T) {
	testGatewayScopedHTTPActualServices(t, true)
}

func testGatewayScopedHTTPActualServices(t *testing.T, pg bool) {
	f := newGatewayScopeHTTPFixture(t, pg)
	h := f.server.Handler()
	reader := f.actor("gateway_node_reader", gatewayHTTPGrant{"config.read", "node", "node_msk01"})
	group := f.actor("gateway_group_reader", gatewayHTTPGrant{"config.read", "node_group", "ng_front"})
	editor := f.actor("gateway_union_editor", gatewayHTTPGrant{"config.edit", "node", "node_msk01"}, gatewayHTTPGrant{"config.edit", "node_group", "ng_back"})
	noConfig := f.actor("gateway_other_permission", gatewayHTTPGrant{"users.read", "global", ""})
	for _, tc := range []struct {
		actor gatewayHTTPActor
		edit  bool
	}{{reader, false}, {group, false}, {editor, true}} {
		w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/config/access", nil, tc.actor.cookies, nil)
		var access configuration.Access
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &access) != nil || !access.GatewayRead || access.GatewayEdit != tc.edit || access.GlobalRead || access.GlobalEdit || access.GlobalApprove || len(access.Sites) != 0 {
			t.Fatal("Gateway capability was flattened into global/Site authority", w.Code, w.Body.String())
		}
	}

	first := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/gateways?limit=1", nil, reader.cookies, nil)
	var page configuration.GatewayPage
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &page) != nil || page.RevisionID != f.revision.ID || len(page.Items) != 1 || page.Items[0].ID != "gw_portal" || page.NextCursor != "gw_portal" || !page.Items[0].Access.Read || page.Items[0].Access.Edit {
		t.Fatal("authorized filtering must precede pagination and cursor calculation", first.Code, first.Body.String())
	}
	secondPath := "/api/v2/gateways?limit=1&revisionId=" + url.QueryEscape(page.RevisionID) + "&cursor=" + url.QueryEscape(page.NextCursor)
	second := identityHTTPRequest(t, h, "GET", "management.test", secondPath, nil, reader.cookies, nil)
	page = configuration.GatewayPage{}
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != "gw_visible" || page.NextCursor != "" {
		t.Fatal("hidden Gateways changed page boundaries/count", second.Code, second.Body.String())
	}
	for _, response := range []string{first.Body.String(), second.Body.String()} {
		for _, hidden := range []string{"gw_aaa_other", "gw_second", "gw_shared", "Private metadata of gw_aaa_other"} {
			if strings.Contains(response, hidden) {
				t.Fatal("hidden Gateway metadata leaked into list", response)
			}
		}
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/gateways?limit=1&revisionId="+f.revision.ID+"&cursor=gw_aaa_other", nil, reader.cookies, nil); w.Code != 404 {
		t.Fatal("hidden Gateway became a usable cursor", w.Code, w.Body.String())
	}
	viewPath := "/api/v2/config/revisions/" + f.revision.ID + "?gatewayId=gw_portal"
	for _, tc := range []struct {
		actor gatewayHTTPActor
		edit  bool
	}{{reader, false}, {group, false}, {editor, true}} {
		w := identityHTTPRequest(t, h, "GET", "management.test", viewPath, nil, tc.actor.cookies, nil)
		var view configuration.Revision
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.ViewScope != "gateway" || len(view.Content) != 0 || view.GatewayView == nil || view.GatewayView.Metadata.ID != "gw_portal" || view.GatewayAccess == nil || !view.GatewayAccess.Read || view.GatewayAccess.Edit != tc.edit || w.Header().Get("ETag") == "" {
			t.Fatal("object revision lost exact access projection or leaked full content", w.Code, w.Body.String())
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		if _, exists := fields["content"]; exists {
			t.Fatal("scoped revision serialized full content", w.Body.String())
		}
	}
	for _, hidden := range []string{"gw_aaa_other", "gw_shared", "gw_second"} {
		if w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/config/revisions/"+f.revision.ID+"?gatewayId="+hidden, nil, reader.cookies, nil); w.Code != 404 {
			t.Fatal("incomplete receiving scope was exposed", hidden, w.Code, w.Body.String())
		}
	}

	initialState := f.writeState(t)
	for _, request := range []struct{ method, path string }{
		{"GET", "/api/v2/config/revisions/" + f.revision.ID},
		{"GET", "/api/v2/config/revisions"},
		{"GET", "/api/v2/config/catalog-snapshots"},
		{"GET", "/api/v2/config/drafts/draft_hidden"},
		{"POST", "/api/v2/config/drafts"},
		{"POST", "/api/v2/config/catalog-snapshots"},
	} {
		if w := identityHTTPRequest(t, h, request.method, "management.test", request.path, map[string]any{}, editor.cookies, editor.headers); w.Code != 403 {
			t.Fatal("Gateway scope admitted full authoring workflow", request.path, w.Code, w.Body.String())
		}
	}
	snapshot, err := json.Marshal(f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	fullChange := configuration.CreateRevision{BaseRevisionID: f.revision.ID, Content: snapshot}
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", fullChange, editor.cookies, editor.headers); w.Code != 403 {
		t.Fatal("Gateway authoring capability admitted a full snapshot mutation", w.Code, w.Body.String())
	}
	if after := f.writeState(t); after != initialState {
		t.Fatalf("denied full workflows left side effects: before=%+v after=%+v", initialState, after)
	}
	for _, tc := range []struct {
		host    string
		cookies []*http.Cookie
		status  int
	}{{"management.test", nil, 401}, {"management.test", noConfig.cookies, 403}, {"login.test", reader.cookies, 403}} {
		if w := identityHTTPRequest(t, h, "GET", tc.host, "/api/v2/gateways", nil, tc.cookies, nil); w.Code != tc.status {
			t.Fatal("management/session capability boundary", tc.host, w.Code, w.Body.String())
		}
	}

	var shared configmodel.Gateway
	for _, gateway := range f.configuration.Gateways {
		if gateway.Metadata.ID == "gw_shared" {
			shared = gateway
		}
	}
	shared.Metadata.Name = "HTTP authorized mixed receiving closure"
	sharedRaw, err := json.Marshal(shared)
	if err != nil {
		t.Fatal(err)
	}
	command := configuration.CreateRevision{BaseRevisionID: f.revision.ID, GatewayChange: &configuration.GatewayChange{GatewayID: "gw_shared", Content: sharedRaw}}
	for _, tc := range []struct {
		name    string
		actor   gatewayHTTPActor
		headers map[string]string
	}{{"read_only", reader, reader.headers}, {"missing_csrf", editor, map[string]string{"Origin": f.server.cfg.ManagementOrigin, "Idempotency-Key": "gateway_http_missing_csrf"}}, {"wrong_origin", editor, map[string]string{"Origin": "https://other.test", "X-CSRF-Token": editor.headers["X-CSRF-Token"], "Idempotency-Key": "gateway_http_wrong_origin"}}} {
		w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, tc.actor.cookies, tc.headers)
		if w.Code != 403 {
			t.Fatal(tc.name, w.Code, w.Body.String())
		}
		if after := f.writeState(t); after != initialState {
			t.Fatalf("%s mutation had side effects: before=%+v after=%+v", tc.name, initialState, after)
		}
	}
	created := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, editor.cookies, editor.headers)
	var changed configuration.Revision
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &changed) != nil || changed.ID == f.revision.ID || changed.BaseRevisionID != f.revision.ID || changed.GatewayAccess == nil || !changed.GatewayAccess.Edit || changed.GatewayView == nil || changed.GatewayView.Metadata.Name != shared.Metadata.Name || len(changed.Content) != 0 {
		t.Fatal("scoped mixed-node/group authoring did not survive own CAS", created.Code, created.Body.String())
	}
	committed := f.writeState(t)
	if committed.head != changed.ID || committed.version != initialState.version+1 || committed.revisions != initialState.revisions+1 || committed.requests != initialState.requests+1 || committed.audits != initialState.audits+1 {
		t.Fatalf("scoped authoring did not commit exactly one revision/request/audit: %+v -> %+v", initialState, committed)
	}
	replay := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, editor.cookies, editor.headers)
	if replay.Code != 201 || replay.Body.String() != created.Body.String() || f.writeState(t) != committed {
		t.Fatal("exact HTTP retry changed receipt or repeated side effects", replay.Code, replay.Body.String())
	}
	full, err := f.server.configuration.GetRevision(context.Background(), f.admin, changed.ID)
	if err != nil {
		t.Fatal(err)
	}
	var fullDocument configmodel.Configuration
	if err = json.Unmarshal(full.Content, &fullDocument); err != nil {
		t.Fatal(err)
	}
	if len(fullDocument.Gateways) != len(f.configuration.Gateways) {
		t.Fatal("authorized Gateway edit removed hidden neighbors")
	}
	neighborFound := false
	for _, gateway := range fullDocument.Gateways {
		if gateway.Metadata.ID == "gw_aaa_other" {
			neighborFound = true
			if gateway.Metadata.Name != "Private metadata of gw_aaa_other" {
				t.Fatal("authorized Gateway edit overwrote hidden neighbor")
			}
		}
	}
	if !neighborFound {
		t.Fatal("authorized Gateway edit removed hidden neighbor")
	}
	// The same object command has a scoped receipt even when its caller has
	// global authority; it must not switch to a full-snapshot response.
	shared.Metadata.Name = "HTTP administrator Gateway receipt"
	sharedRaw, err = json.Marshal(shared)
	if err != nil {
		t.Fatal(err)
	}
	adminCommand := configuration.CreateRevision{BaseRevisionID: changed.ID, GatewayChange: &configuration.GatewayChange{GatewayID: "gw_shared", Content: sharedRaw}}
	adminCreated := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", adminCommand, f.adminHTTP.cookies, f.adminHTTP.headers)
	var adminReceipt configuration.Revision
	if adminCreated.Code != 201 || json.Unmarshal(adminCreated.Body.Bytes(), &adminReceipt) != nil || adminReceipt.BaseRevisionID != changed.ID || adminReceipt.ViewScope != "gateway" || len(adminReceipt.Content) != 0 || adminReceipt.GatewayView == nil || adminReceipt.GatewayView.Metadata.Name != shared.Metadata.Name || adminReceipt.GatewayAccess == nil || !adminReceipt.GatewayAccess.Edit {
		t.Fatal("global caller's object mutation lost scoped receipt", adminCreated.Code, adminCreated.Body.String())
	}
	adminCommitted := f.writeState(t)
	if adminCommitted.head != adminReceipt.ID || adminCommitted.version != committed.version+1 || adminCommitted.revisions != committed.revisions+1 || adminCommitted.requests != committed.requests+1 || adminCommitted.audits != committed.audits+1 {
		t.Fatalf("global object command did not commit exactly once: %+v -> %+v", committed, adminCommitted)
	}
	committed = adminCommitted
	// An independently observed pending node needs no certificate. Loss of its
	// current-epoch metadata is a source failure, not a concealed access denial.
	err = f.base.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, e := tx.Exec(context.Background(), `UPDATE managed_nodes SET authority_epoch=2 WHERE id='node_msk01'`)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v2/gateways", viewPath} {
		w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, reader.cookies, nil)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "security_state_unavailable") || strings.Contains(w.Body.String(), "Private metadata") {
			t.Fatal("lost authoritative source became 404/partial metadata", path, w.Code, w.Body.String())
		}
	}
	if after := f.writeState(t); !reflect.DeepEqual(after, committed) {
		t.Fatalf("unavailable reads changed authoring state: %+v -> %+v", committed, after)
	}
}
