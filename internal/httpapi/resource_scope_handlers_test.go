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

// This fixture shares only the lightweight HTTP actor/container helpers with
// the Gateway tests. Resource ownership is sealed here before activation;
// neither an issuing CA nor the positive role-approval workflow is simulated.
func newResourceScopeHTTPFixture(t *testing.T, pg bool) *gatewayHTTPFixture {
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
	first := &document.Gateways[0]
	first.Metadata.Name = "GatewayMetadataSecret"
	first.Spec.Routes[0].Name = "Owned route first"
	secondRaw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	hidden := first.Spec.Routes[0]
	hidden.ID, hidden.Name, hidden.Path = "route_hidden", "HiddenRouteNameSecret", "/hidden"
	first.Spec.Routes = append(first.Spec.Routes, hidden)
	var second configmodel.Gateway
	if err = json.Unmarshal(secondRaw, &second); err != nil {
		t.Fatal(err)
	}
	second.Metadata.ID, second.Metadata.Name = "gw_second", "SecondGatewayMetadataSecret"
	second.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{"node_msk02"}}
	second.Spec.Routes[0].ID, second.Spec.Routes[0].Name, second.Spec.Routes[0].Hostname = "route_second", "Owned route second", "second.example.net"
	document.Gateways = append(document.Gateways, second)
	graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "resource_http_scopes", Sites: []rolescope.Site{{ID: "site_msk"}}, NodeGroups: []rolescope.NodeGroup{}, Nodes: []rolescope.Node{{ID: "node_msk01", SiteID: "site_msk", GroupIDs: []string{}}, {ID: "node_msk02", SiteID: "site_msk", GroupIDs: []string{}}}, Resources: []rolescope.Resource{{ID: "resource_owned"}, {ID: "resource_aaa_hidden"}}, ResourceRoutes: []rolescope.ResourceRoute{{ResourceID: "resource_owned", GatewayID: "gw_portal", RouteID: "route_portal"}, {ResourceID: "resource_owned", GatewayID: "gw_second", RouteID: "route_second"}, {ResourceID: "resource_aaa_hidden", GatewayID: "gw_portal", RouteID: "route_hidden"}}}
	now := time.Now().UTC()
	err = base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES('resource_http_admin','resource_http_admin','synthetic-test-password',TRUE)`); e != nil {
			return e
		}
		for _, gateway := range document.Gateways {
			if _, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,?)`, gateway.Metadata.ID, gateway.Metadata.SiteID); e != nil {
				return e
			}
		}
		for _, resource := range []struct {
			id, name string
			enabled  bool
		}{{"resource_owned", "Owned disabled resource", false}, {"resource_aaa_hidden", "HiddenResourceNameSecret", true}} {
			if _, e := tx.Exec(ctx, `INSERT INTO resources(id,name,internal_url,public_host,enabled) VALUES(?,?,?,?,?)`, resource.id, resource.name, "https://backend.example.net", strings.ReplaceAll(resource.id, "_", "-")+".test", resource.enabled); e != nil {
				return e
			}
		}
		if e := rolescope.BootstrapTx(ctx, tx, 1, graph); e != nil {
			return e
		}
		for _, node := range graph.Nodes {
			fact, e := json.Marshal(map[string]any{"id": node.ID, "siteId": node.SiteID, "name": node.ID, "groupIds": node.GroupIDs, "labels": map[string]string{}, "createdAt": now})
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
	server.SetConfiguration(configuration.New(coordinator, cfg.ManagementOrigin, compiler.Options{}))
	f := &gatewayHTTPFixture{server: server, base: base, configuration: document}
	f.actor = func(id string, grants ...gatewayHTTPGrant) gatewayHTTPActor {
		t.Helper()
		token, tokenHash, e := auth.NewToken()
		if e != nil {
			t.Fatal(e)
		}
		csrf := "resource_csrf_" + id
		e = coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			if id != "resource_http_admin" {
				if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "synthetic-test-password"); e != nil {
					return e
				}
			}
			if e := identity.InsertSession(ctx, tx, domain.Session{ID: "session_" + id, UserID: id, TokenHash: tokenHash, CSRFHash: auth.TokenHash(csrf), Audience: "management", AudienceOrigin: cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now}); e != nil {
				return e
			}
			// Trusted test setup supplies existing grants to real authorization.
			if e := securitystate.EnsureBuiltinRolesTx(ctx, tx); e != nil {
				return e
			}
			for _, grant := range grants {
				role, e := securitystate.ReadRoleDefinitionTx(ctx, tx, "role_"+strings.ReplaceAll(grant.permission, ".", "_"))
				if e != nil {
					return e
				}
				binding := securitystate.RoleBinding{ID: "rbinding_" + id + "_" + strings.ReplaceAll(grant.permission, ".", "_"), PrincipalID: id, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: grant.kind, ScopeID: grant.scope, AuthorityEpoch: h.Epoch, Revision: 1, CreatedAt: h.RecordedAt}
				if e = securitystate.PublishRoleBindingTx(ctx, tx, h, binding); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		return gatewayHTTPActor{cookies: []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}, headers: map[string]string{"Origin": cfg.ManagementOrigin, "X-CSRF-Token": csrf, "Idempotency-Key": "resource_http_" + id}}
	}
	admin := f.actor("resource_http_admin")
	f.admin = configuration.Actor{TokenHash: auth.TokenHash(admin.cookies[0].Value), Origin: cfg.ManagementOrigin}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	f.revision, err = server.configuration.CreateRevision(ctx, f.admin, "resource_http_seed_revision", configuration.CreateRevision{Content: content})
	if err != nil {
		t.Fatal("seed resource configuration through actual service", err)
	}
	return f
}

func TestResourceScopedHTTPActualServicesSQLite(t *testing.T) {
	testResourceScopedHTTPActualServices(t, false)
}

func TestResourceScopedHTTPActualServicesPostgres(t *testing.T) {
	testResourceScopedHTTPActualServices(t, true)
}

func testResourceScopedHTTPActualServices(t *testing.T, pg bool) {
	f := newResourceScopeHTTPFixture(t, pg)
	h := f.server.Handler()
	reader := f.actor("resource_http_reader", gatewayHTTPGrant{"config.read", "resource", "resource_owned"})
	editor := f.actor("resource_http_editor", gatewayHTTPGrant{"config.read", "resource", "resource_owned"}, gatewayHTTPGrant{"config.edit", "resource", "resource_owned"})
	for _, tc := range []struct {
		actor gatewayHTTPActor
		edit  bool
	}{{reader, false}, {editor, true}} {
		w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/config/access", nil, tc.actor.cookies, nil)
		var access configuration.Access
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &access) != nil || !access.ResourceRead || access.ResourceEdit != tc.edit || access.GatewayRead || access.GatewayEdit || access.GlobalRead || access.GlobalEdit || len(access.Sites) != 0 {
			t.Fatal("pure resource binding widened configuration authority", w.Code, w.Body.String())
		}
	}
	first := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/config/resources?limit=1", nil, reader.cookies, nil)
	var page configuration.ResourceRoutePage
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &page) != nil || page.RevisionID != f.revision.ID || len(page.Items) != 1 || page.Items[0].ResourceID != "resource_owned" || page.Items[0].GatewayID != "gw_portal" || page.Items[0].RouteID != "route_portal" || page.Items[0].ResourceName != "Owned disabled resource" || !page.Items[0].Access.Read || page.Items[0].Access.Edit || page.NextCursor == "" {
		t.Fatal("resource filtering did not precede pagination", first.Code, first.Body.String())
	}
	secondPath := "/api/v2/config/resources?limit=1&revisionId=" + url.QueryEscape(page.RevisionID) + "&cursor=" + url.QueryEscape(page.NextCursor)
	second := identityHTTPRequest(t, h, "GET", "management.test", secondPath, nil, reader.cookies, nil)
	page = configuration.ResourceRoutePage{}
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].GatewayID != "gw_second" || page.Items[0].RouteID != "route_second" || page.NextCursor != "" {
		t.Fatal("resource route pagination exposed hidden count/cursor", second.Code, second.Body.String())
	}
	viewPath := "/api/v2/config/resources/resource_owned/routes/gw_portal/route_portal?revisionId=" + f.revision.ID
	assertView := func(wBody []byte, canEdit bool) configuration.Revision {
		t.Helper()
		var view configuration.Revision
		if err := json.Unmarshal(wBody, &view); err != nil {
			t.Fatal(err)
		}
		if view.ViewScope != "resource" || view.ResourceView == nil || view.ResourceView.ResourceID != "resource_owned" || view.ResourceView.ResourceName != "Owned disabled resource" || view.ResourceView.GatewayID != "gw_portal" || view.ResourceView.Route.ID != "route_portal" || view.ResourceAccess == nil || !view.ResourceAccess.Read || view.ResourceAccess.Edit != canEdit || len(view.Content) != 0 || view.GatewayView != nil || view.GatewayAccess != nil {
			t.Fatalf("resource response widened authority or lost exact access: %s", wBody)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(wBody, &fields); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"content", "gatewayView", "gatewayAccess"} {
			if _, exists := fields[field]; exists {
				t.Fatal("scoped resource serialized full/Gateway view", field)
			}
		}
		for _, hidden := range []string{"resource_aaa_hidden", "HiddenResourceNameSecret", "HiddenRouteNameSecret", "GatewayMetadataSecret", "componentProfileRef", "certificateVersionId"} {
			if strings.Contains(string(wBody), hidden) {
				t.Fatal("scoped resource view leaked unrelated metadata", string(wBody))
			}
		}
		return view
	}
	for _, tc := range []struct {
		actor gatewayHTTPActor
		edit  bool
	}{{reader, false}, {editor, true}} {
		w := identityHTTPRequest(t, h, "GET", "management.test", viewPath, nil, tc.actor.cookies, nil)
		if w.Code != 200 || w.Header().Get("ETag") == "" {
			t.Fatal("resource exact view", w.Code, w.Body.String())
		}
		assertView(w.Body.Bytes(), tc.edit)
	}
	for _, response := range []string{first.Body.String(), second.Body.String()} {
		for _, hidden := range []string{"resource_aaa_hidden", "HiddenResourceNameSecret", "HiddenRouteNameSecret", "GatewayMetadataSecret", "componentProfileRef", "certificateVersionId"} {
			if strings.Contains(response, hidden) {
				t.Fatal("scoped resource list leaked unrelated metadata", response)
			}
		}
	}
	for _, path := range []string{
		"/api/v2/config/resources/resource_aaa_hidden/routes/gw_portal/route_hidden?revisionId=" + f.revision.ID,
		"/api/v2/config/resources/resource_owned/routes/gw_portal/route_hidden?revisionId=" + f.revision.ID,
	} {
		if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, editor.cookies, nil); w.Code != 404 {
			t.Fatal("unowned/forged route identity accepted", w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/v2/gateways", "/api/v2/config/revisions/" + f.revision.ID, "/api/v2/config/revisions/" + f.revision.ID + "?gatewayId=gw_portal", "/api/v2/config/catalog-snapshots"} {
		if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, editor.cookies, nil); w.Code != 403 {
			t.Fatal("resource binding admitted full or Gateway workflow", path, w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		host    string
		cookies []*http.Cookie
		status  int
	}{{"management.test", nil, http.StatusUnauthorized}, {"login.test", reader.cookies, http.StatusForbidden}} {
		if w := identityHTTPRequest(t, h, "GET", tc.host, viewPath, nil, tc.cookies, nil); w.Code != tc.status {
			t.Fatal("resource endpoint lost secure management audience", w.Code, w.Body.String())
		}
	}
	before := f.writeState(t)
	route := f.configuration.Gateways[0].Spec.Routes[0]
	route.Name = "Scoped resource HTTP update"
	route.Upstream.ReadTimeoutSeconds++
	routeRaw, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	command := configuration.CreateRevision{BaseRevisionID: f.revision.ID, ResourceChange: &configuration.ResourceChange{ResourceID: "resource_owned", GatewayID: "gw_portal", RouteID: "route_portal", Content: routeRaw}}
	for _, tc := range []struct {
		name    string
		actor   gatewayHTTPActor
		headers map[string]string
	}{{"read_only", reader, reader.headers}, {"missing_csrf", editor, map[string]string{"Origin": f.server.cfg.ManagementOrigin, "Idempotency-Key": "resource_http_missing_csrf"}}, {"wrong_origin", editor, map[string]string{"Origin": "https://other.test", "X-CSRF-Token": editor.headers["X-CSRF-Token"], "Idempotency-Key": "resource_http_wrong_origin"}}} {
		if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, tc.actor.cookies, tc.headers); w.Code != 403 {
			t.Fatal(tc.name, w.Code, w.Body.String())
		}
		if after := f.writeState(t); after != before {
			t.Fatalf("denied %s left authoring side effects: %+v -> %+v", tc.name, before, after)
		}
	}
	full, err := json.Marshal(f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := json.Marshal(f.configuration.Gateways[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, mixed := range []configuration.CreateRevision{
		{BaseRevisionID: f.revision.ID, ResourceChange: command.ResourceChange, Content: full},
		{BaseRevisionID: f.revision.ID, ResourceChange: command.ResourceChange, GatewayChange: &configuration.GatewayChange{GatewayID: "gw_portal", Content: gateway}},
	} {
		if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", mixed, editor.cookies, editor.headers); w.Code != 400 {
			t.Fatal("mixed resource payload was not rejected as an invalid union", w.Code, w.Body.String())
		}
		if after := f.writeState(t); after != before {
			t.Fatalf("mixed payload left authoring side effects: %+v -> %+v", before, after)
		}
	}
	created := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, editor.cookies, editor.headers)
	if created.Code != 201 {
		t.Fatal("pure resource authoring did not survive own CAS", created.Code, created.Body.String())
	}
	changed := assertView(created.Body.Bytes(), true)
	if changed.ID == f.revision.ID || changed.BaseRevisionID != f.revision.ID || changed.ResourceView.Route.Name != route.Name {
		t.Fatal("resource mutation returned wrong immutable revision", created.Body.String())
	}
	committed := f.writeState(t)
	if committed.head != changed.ID || committed.version != before.version+1 || committed.revisions != before.revisions+1 || committed.requests != before.requests+1 || committed.audits != before.audits+1 {
		t.Fatalf("resource authoring did not commit exactly one revision/request/audit: %+v -> %+v", before, committed)
	}
	replay := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, editor.cookies, editor.headers)
	if replay.Code != 201 || replay.Body.String() != created.Body.String() || f.writeState(t) != committed {
		t.Fatal("exact resource retry changed receipt or repeated side effects", replay.Code, replay.Body.String())
	}
	adminView, err := f.server.configuration.GetRevision(context.Background(), f.admin, changed.ID)
	if err != nil {
		t.Fatal(err)
	}
	var merged configmodel.Configuration
	if err = json.Unmarshal(adminView.Content, &merged); err != nil {
		t.Fatal(err)
	}
	hiddenFound := false
	for _, gateway := range merged.Gateways {
		for _, current := range gateway.Spec.Routes {
			if current.ID == "route_hidden" {
				hiddenFound = current.Name == "HiddenRouteNameSecret" && current.Path == "/hidden"
			}
		}
	}
	if !hiddenFound {
		t.Fatal("resource edit changed or removed its hidden routing neighbor")
	}
	// Keep the separate read binding so this exercises current edit authority,
	// rather than merely invalidating the management session's admission.
	err = f.base.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		binding := "rbinding_resource_http_editor_config_edit"
		return securitystate.MaterializeEvent(context.Background(), tx, securityjournal.Event{ID: "event_resource_http_revoke", Epoch: 1, RecordedAt: time.Now().UTC(), Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", TargetType: "grant", TargetID: binding, Payload: securityjournal.Payload{GrantID: binding}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	deniedReplay := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/config/revisions", command, editor.cookies, editor.headers)
	if deniedReplay.Code != 403 || strings.Contains(deniedReplay.Body.String(), changed.ID) || f.writeState(t) != committed {
		t.Fatal("saved response outlived current resource grant", deniedReplay.Code, deniedReplay.Body.String())
	}
	readCurrent := identityHTTPRequest(t, h, "GET", "management.test", strings.Replace(viewPath, f.revision.ID, changed.ID, 1), nil, editor.cookies, nil)
	if readCurrent.Code != 200 {
		t.Fatal("edit revocation destroyed independently retained resource read", readCurrent.Code, readCurrent.Body.String())
	}
	assertView(readCurrent.Body.Bytes(), false)
}
