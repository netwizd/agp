package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func scopedFixture(t *testing.T, pg bool) *testFixture {
	t.Helper()
	return fixtureConfigured(t, pg, func(tx storage.IdentityTx) error {
		ctx := context.Background()
		now := time.Now().UTC()
		for _, id := range []string{"editor", "reviewer"} {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "hash"); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management','https://management.test',1,1,?,?)`, id, id, id+"_token", "csrf", "", "", now.Add(time.Hour), now, now, now); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES(?,?,'config.edit','site','site_msk',1,?)`, "cgrant_"+id, id, now); e != nil {
				return e
			}
		}
		_, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES('gw_portal','site_msk')`)
		return e
	})
}
func TestScopedAuthoringSQLite(t *testing.T)   { testScopedAuthoring(t, false) }
func TestScopedAuthoringPostgres(t *testing.T) { testScopedAuthoring(t, true) }
func testScopedAuthoring(t *testing.T, pg bool) {
	ctx := context.Background()
	f := scopedFixture(t, pg)
	editor := Actor{"editor_token", f.actor.Origin}
	var source configmodel.Configuration
	if e := json.Unmarshal(example(t), &source); e != nil {
		t.Fatal(e)
	}
	neighbor := source.Gateways[0]
	neighbor.Metadata.ID = "gw_neighbor"
	neighbor.Metadata.SiteID = "site_other"
	neighbor.Spec.Routes = append([]configmodel.Route{}, neighbor.Spec.Routes...)
	neighbor.Spec.Routes[0].Hostname = "neighbor.example.net"
	neighbor.Spec.Routes[0].ID = "route_neighbor"
	source.Gateways = append(source.Gateways, neighbor)
	body, _ := json.Marshal(source)
	r, e := f.service.CreateRevision(ctx, f.actor, "test_scoped_base_000", CreateRevision{Content: body})
	if e != nil {
		t.Fatal(e)
	}
	a, e := f.service.Access(ctx, editor)
	if e != nil || a.GlobalRead || len(a.Sites) != 1 || !a.Sites[0].Edit {
		t.Fatalf("access %#v %v", a, e)
	}
	if _, e = f.service.GetRevision(ctx, editor, r.ID); !errors.Is(e, storage.ErrPermissionDenied) {
		t.Fatalf("full snapshot leaked: %v", e)
	}
	view, e := f.service.GatewayRevision(ctx, editor, r.ID, "gw_portal")
	if e != nil || len(view.Content) > 0 || view.GatewayView == nil || view.ViewScope != "gateway" {
		t.Fatalf("bad scoped view %#v %v", view, e)
	}
	if _, e = f.service.GatewayRevision(ctx, editor, r.ID, "gw_neighbor"); !errors.Is(e, storage.ErrNotFound) {
		t.Fatalf("neighbor leaked %v", e)
	}
	next := source.Gateways[0]
	next.Metadata.Name = "Scoped change"
	raw, _ := json.Marshal(next)
	successfulPayload := append(json.RawMessage{}, raw...)
	command := CreateRevision{BaseRevisionID: r.ID, GatewayChange: &GatewayChange{GatewayID: next.Metadata.ID, Content: raw}}
	changed, e := f.service.ChangeGateway(ctx, editor, "test_scoped_change_000", command)
	if e != nil {
		t.Fatal(e)
	}
	if len(changed.Content) > 0 || changed.GatewayView.Metadata.Name != next.Metadata.Name {
		t.Fatal("bad response")
	}
	full, e := f.service.GetRevision(ctx, f.actor, changed.ID)
	if e != nil {
		t.Fatal(e)
	}
	unchanged, e := gatewayFrom(full, "gw_neighbor")
	if e != nil || unchanged.Metadata.Name != neighbor.Metadata.Name {
		t.Fatal("neighbor overwritten")
	}
	_, e = f.service.ChangeGateway(ctx, editor, "test_scoped_stale_000", command)
	if !errors.Is(e, ErrRevisionMismatch) {
		t.Fatalf("stale CAS %v", e)
	}
	collision := next
	collision.Spec.Routes = append([]configmodel.Route{}, next.Spec.Routes...)
	collision.Spec.Routes[0].Hostname = neighbor.Spec.Routes[0].Hostname
	if _, e = f.service.ChangeGateway(ctx, editor, "test_scope_collision01", CreateRevision{BaseRevisionID: changed.ID, GatewayChange: &GatewayChange{GatewayID: next.Metadata.ID, Content: mustJSON(t, collision)}}); !errors.Is(e, storage.ErrConflict) {
		t.Fatalf("neighbor collision detail escaped %T %v", e, e)
	}
	next.Metadata.SiteID = "site_other"
	raw, _ = json.Marshal(next)
	command.BaseRevisionID = changed.ID
	command.GatewayChange.Content = raw
	if _, e = f.service.ChangeGateway(ctx, editor, "test_scope_escape_000", command); e == nil {
		t.Fatal("Site move allowed")
	}
	if e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return securitystate.MaterializeEvent(ctx, tx, securityjournal.Event{Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", Payload: securityjournal.Payload{GrantID: "cgrant_editor"}}, RecordedAt: time.Now()})
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.GatewayRevision(ctx, editor, changed.ID, "gw_portal"); !errors.Is(e, storage.ErrNotFound) {
		t.Fatalf("revoke ignored %v", e)
	}
	command.BaseRevisionID = r.ID
	command.GatewayChange.Content = successfulPayload
	if _, e = f.service.ChangeGateway(ctx, editor, "test_scoped_change_000", command); e == nil {
		t.Fatal("idempotency replay bypassed revoke")
	}
	if e = BootstrapAccess(ctx, f.store, 1, BootstrapManifest{Grants: []ScopeGrant{{PrincipalID: "editor", Permission: "config.edit", ScopeType: "global"}}}); e == nil {
		t.Fatal("postactivation bootstrap allowed")
	}
	if !authz.IsPrivileged([]string{"config.edit"}) || !authz.IsPrivileged([]string{"config.approve"}) {
		t.Fatal("scoped editor not privileged")
	}
}
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
