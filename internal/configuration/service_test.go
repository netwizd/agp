package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type testAuthority struct{ unavailable atomic.Bool }

func (a *testAuthority) Head(context.Context) (securityjournal.Head, error) {
	if a.unavailable.Load() {
		return securityjournal.Head{}, securityjournal.ErrUnavailable
	}
	return securityjournal.Head{AuthorityID: "s1_test", Epoch: 1, Sequence: 0, Digest: strings.Repeat("0", 64), RecordedAt: time.Now().UTC()}, nil
}
func (*testAuthority) Append(context.Context, securityjournal.AppendRequest) (securityjournal.Event, error) {
	return securityjournal.Event{}, errors.New("unexpected journal append in authoring")
}
func (*testAuthority) Operation(context.Context, string) (securityjournal.Event, error) {
	return securityjournal.Event{}, storage.ErrNotFound
}
func (*testAuthority) Events(context.Context, securityjournal.UInt63, int) ([]securityjournal.Event, error) {
	return nil, nil
}

type testFixture struct {
	store     storage.Store
	service   *Service
	actor     Actor
	authority *testAuthority
}

type failedAuditCurrent struct{ underlying Current }
type failedAuditTx struct{ storage.IdentityTx }

func (c failedAuditCurrent) Head(ctx context.Context) (securityjournal.Head, error) {
	return c.underlying.Head(ctx)
}

func (t failedAuditTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	if strings.Contains(q, "INSERT INTO audit_events") && len(args) > 0 && args[0] == "config.revision.created" {
		return 0, errors.New("injected audit write failure")
	}
	return t.IdentityTx.Exec(ctx, q, args...)
}
func (c failedAuditCurrent) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return fn(failedAuditTx{tx}, h) })
}

func fixture(t *testing.T, pg bool) *testFixture { return fixtureConfigured(t, pg, nil) }
func fixtureConfigured(t *testing.T, pg bool, setup func(storage.IdentityTx) error) *testFixture {
	t.Helper()
	ctx := context.Background()
	var base storage.Store
	var err error
	if pg {
		dsn := os.Getenv("AGP_TEST_CONFIGURATION_DSN")
		if dsn == "" {
			dsn = os.Getenv("AGP_TEST_POSTGRES_DSN")
		}
		if dsn == "" {
			t.Skip("AGP_TEST_POSTGRES_DSN is not set")
		}
		admin, e := pgxpool.New(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		schema := strings.ToLower(securitystate.ID("s1"))
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, e = admin.Exec(ctx, `CREATE SCHEMA `+quoted); e != nil {
			admin.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = admin.Exec(ctx, `DROP SCHEMA `+quoted+` CASCADE`); admin.Close() })
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, e := url.Parse(dsn)
			if e != nil {
				t.Fatal(e)
			}
			q := u.Query()
			q.Set("search_path", schema)
			u.RawQuery = q.Encode()
			dsn = u.String()
		} else {
			dsn += " search_path=" + schema
		}
		p, e := postgres.Open(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		base = p
	} else {
		base, err = sqlite.Open(t.TempDir() + "/s1.db")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = base.Close() })
	if err = base.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if pg {
		release, e := base.(interface {
			AcquireIdentityLease(context.Context) (func(), error)
		}).AcquireIdentityLease(ctx)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	now := time.Now().UTC()
	err = base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		if setup != nil {
			if e := setup(tx); e != nil {
				return e
			}
		}
		for _, query := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO users(id,username,password_hash,is_admin) VALUES('s1_admin','s1_admin','hash',?)`, []any{true}},
			{`INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,'s1_test',1,0,?,?)`, []any{strings.Repeat("0", 64), true}},
			{`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES('s1_session','s1_admin','s1_token','s1_csrf','','',?,?,'management','https://management.test',1,1,?,?)`, []any{now.Add(time.Hour), now, now, now}},
		} {
			if _, e := tx.Exec(ctx, query.sql, query.args...); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := &testAuthority{}
	coordinator := securitystate.New(base, authority)
	return &testFixture{base, New(coordinator, "https://management.test", compiler.Options{Version: "s1-test", BuildDigest: "sha256:" + strings.Repeat("a", 64), MinimumWAFMode: "detection"}), Actor{TokenHash: "s1_token", Origin: "https://management.test"}, authority}
}
func example(t *testing.T) json.RawMessage {
	t.Helper()
	raw, e := os.ReadFile("../../docs/v2/examples/configuration.json")
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func mustDraft(t *testing.T, f *testFixture, key, base string) *Draft {
	t.Helper()
	d, e := f.service.CreateDraft(context.Background(), f.actor, key, CreateDraft{BaseRevisionID: base, Content: example(t)})
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func scalar(t *testing.T, f *testFixture, query string, args ...any) int64 {
	t.Helper()
	var out int64
	e := f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		return securitystate.One(context.Background(), tx, query, args, func(r storage.IdentityRows) error { return r.Scan(&out) })
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestConfigurationSQLite(t *testing.T)   { testConfiguration(t, false) }
func TestConfigurationPostgres(t *testing.T) { testConfiguration(t, true) }
func testConfiguration(t *testing.T, pg bool) {
	t.Run("durable_draft_CAS_and_exact_idempotent_response", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		d := mustDraft(t, f, "test_draft_create_0001", "")
		var c configmodel.Configuration
		if e := json.Unmarshal(d.Content, &c); e != nil {
			t.Fatal(e)
		}
		c.Metadata.Name = "Изменённое имя"
		body, _ := json.Marshal(c)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, key := range []string{"test_draft_update_0001", "test_draft_update_0002"} {
			wg.Add(1)
			go func(key string) {
				defer wg.Done()
				_, e := f.service.UpdateDraft(ctx, f.actor, d.ID, d.Revision, key, body)
				errs <- e
			}(key)
		}
		wg.Wait()
		close(errs)
		success, stale := 0, 0
		for e := range errs {
			if e == nil {
				success++
			} else if errors.Is(e, ErrRevisionMismatch) {
				stale++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || stale != 1 {
			t.Fatalf("lost update accepted: success=%d stale=%d", success, stale)
		}
		replayed, e := f.service.CreateDraft(ctx, f.actor, "test_draft_create_0001", CreateDraft{Content: example(t)})
		if e != nil {
			t.Fatal(e)
		}
		if replayed.Revision != "0" || replayed.ContentDigest != d.ContentDigest {
			t.Fatal("idempotency returned changed mutable draft instead of original response handle")
		}
		if _, e = f.service.CreateDraft(ctx, f.actor, "test_draft_create_0001", CreateDraft{Content: body}); !errors.Is(e, ErrIdempotencyConflict) {
			t.Fatalf("different payload accepted: %v", e)
		}
		current, e := f.service.GetDraft(ctx, f.actor, d.ID)
		if e != nil || current.Revision != "1" {
			t.Fatalf("draft CAS not persisted: %#v %v", current, e)
		}
	})
	t.Run("global_head_conflict_preserves_drafts_and_retry", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		a := mustDraft(t, f, "test_draft_first_0001", "")
		b := mustDraft(t, f, "test_draft_other_0001", "")
		r, e := f.service.SealDraft(ctx, f.actor, a.ID, a.Revision, "test_seal_first_0001")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.SealDraft(ctx, f.actor, b.ID, b.Revision, "test_seal_other_0001"); !errors.Is(e, ErrRevisionMismatch) {
			t.Fatalf("stale global base accepted: %v", e)
		}
		if _, e = f.service.GetDraft(ctx, f.actor, b.ID); e != nil {
			t.Fatal("conflict lost user's draft", e)
		}
		newDraft := mustDraft(t, f, "test_draft_second_001", r.ID)
		if _, e = f.service.SealDraft(ctx, f.actor, newDraft.ID, newDraft.Revision, "test_seal_second_001"); e != nil {
			t.Fatal(e)
		}
		again, e := f.service.SealDraft(ctx, f.actor, a.ID, a.Revision, "test_seal_first_0001")
		if e != nil || again.ID != r.ID {
			t.Fatalf("lost-response retry re-executed: %#v %v", again, e)
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_revisions`); n != 2 {
			t.Fatalf("duplicate revision: %d", n)
		}
	})
	t.Run("test_gateway_upsert_preserves_neighbours_and_canonical_projections", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		doc, e := parseContent(example(t))
		if e != nil {
			t.Fatal(e)
		}
		other := doc.Configuration.Gateways[0]
		other.Metadata.ID = "gw_other"
		other.Spec.Routes = append([]configmodel.Route(nil), other.Spec.Routes...)
		other.Spec.Routes[0].ID = "route_other"
		other.Spec.Routes[0].Hostname = "other.example.net"
		doc.Configuration.Gateways = append(doc.Configuration.Gateways, other)
		body, _ := json.Marshal(doc.Configuration)
		base, e := f.service.CreateRevision(ctx, f.actor, "test_revision_base_001", CreateRevision{Content: body})
		if e != nil {
			t.Fatal(e)
		}
		gateway := doc.Configuration.Gateways[0]
		gateway.Metadata.Name = "Новое имя"
		gb, _ := json.Marshal(gateway)
		in := CreateRevision{BaseRevisionID: base.ID, GatewayChange: &GatewayChange{GatewayID: gateway.Metadata.ID, Content: gb}}
		r, e := f.service.CreateRevision(ctx, f.actor, "test_gateway_upsert_001", in)
		if e != nil {
			t.Fatal(e)
		}
		next, e := parseContent(r.Content)
		if e != nil {
			t.Fatal(e)
		}
		if len(next.Configuration.Gateways) != 2 {
			t.Fatal("upsert dropped neighbouring gateway")
		}
		// Equivalent JSON key order and whitespace retry the normalized command.
		var pretty any
		_ = json.Unmarshal(gb, &pretty)
		in.GatewayChange.Content, _ = json.MarshalIndent(pretty, "", "  ")
		again, e := f.service.CreateRevision(ctx, f.actor, "test_gateway_upsert_001", in)
		if e != nil || again.ID != r.ID {
			t.Fatalf("normalized retry conflict: %v", e)
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_routes WHERE revision_id=?`, r.ID); n != 2 {
			t.Fatal("route projection mismatch")
		}
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `INSERT INTO config_gateway_nodes(revision_id,gateway_id,node_id) VALUES(?,?,?)`, r.ID, gateway.Metadata.ID, "node_appended_late")
			return e
		})
		if e == nil {
			t.Fatal("sealed closure allowed late append")
		}
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE config_revisions SET canonical_json='{}' WHERE id=?`, r.ID)
			return e
		})
		if e == nil {
			t.Fatal("immutable body changed")
		}
	})
	t.Run("admission_rechecks_admin_MFA_pending_and_journal", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		d := mustDraft(t, f, "test_draft_admission01", "")
		r, e := f.service.SealDraft(ctx, f.actor, d.ID, d.Revision, "test_seal_admission_01")
		if e != nil {
			t.Fatal(e)
		}
		f.authority.unavailable.Store(true)
		if _, e = f.service.GetRevision(ctx, f.actor, r.ID); !errors.Is(e, securitystate.ErrUnavailable) {
			t.Fatalf("journal outage did not close read: %v", e)
		}
		f.authority.unavailable.Store(false)
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `INSERT INTO security_operations(id,requests_json,intent_json,status,actor_id) VALUES('pending','[]','{}','pending','s1_admin')`)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if e = f.service.Activate(ctx); !errors.Is(e, securitystate.ErrBarrier) {
			t.Fatalf("activation crossed pending operation: %v", e)
		}
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `DELETE FROM security_operations WHERE id='pending'`)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE users SET is_admin=? WHERE id='s1_admin'`, false)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.GetRevision(ctx, f.actor, r.ID); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("cached admin rights survived revoke: %v", e)
		}
	})
	t.Run("explicit_cutover_fences_legacy_and_preserves_journal_disable", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		resource, e := f.store.CreateResource(ctx, domain.ResourceInput{Name: "Legacy", InternalURL: "http://127.0.0.1:8080", PublicHost: "legacy.test", PublicPath: "/", Enabled: true})
		if e != nil {
			t.Fatal(e)
		}
		d := mustDraft(t, f, "test_draft_cutover001", "")
		if _, e = f.service.SealDraft(ctx, f.actor, d.ID, d.Revision, "test_seal_cutover_001"); e != nil {
			t.Fatal(e)
		}
		if e = f.service.Activate(ctx); e != nil {
			t.Fatal(e)
		}
		if e = CheckProfile(ctx, f.store, false); e == nil {
			t.Fatal("environment downgrade accepted")
		}
		if _, e = f.store.CreateResource(ctx, domain.ResourceInput{Name: "Bypass", InternalURL: "http://127.0.0.1", PublicHost: "bypass.test", PublicPath: "/", Enabled: true}); !errors.Is(e, storage.ErrConfigurationReadOnly) {
			t.Fatalf("legacy SQL writer bypassed persisted fence: %v", e)
		}
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE resources SET enabled=?,updated_at=? WHERE id=?`, false, time.Now().UTC(), resource.ID)
			return e
		})
		if e != nil {
			t.Fatal("restrictive journal disable was blocked", e)
		}
		e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE resources SET enabled=? WHERE id=?`, true, resource.ID)
			return e
		})
		if !errors.Is(e, storage.ErrConfigurationReadOnly) {
			t.Fatalf("legacy positive grant bypass: %v", e)
		}
	})
	t.Run("durable_validation_reports_never_claim_deployability", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		d := mustDraft(t, f, "test_draft_report_001", "")
		report, e := f.service.PreviewDraft(ctx, f.actor, d.ID, "", "test_preview_report01")
		if e != nil {
			t.Fatal(e)
		}
		if report.Deployable || report.AuthoringValid || len(report.Issues) != 1 || report.Issues[0].Code != "catalog_required" {
			t.Fatalf("missing references pretended validated: %#v", report)
		}
		r, e := f.service.SealDraft(ctx, f.actor, d.ID, d.Revision, "test_seal_report_0001")
		if e != nil {
			t.Fatal(e)
		}
		accepted, e := f.service.ValidateRevision(ctx, f.actor, r.ID, "test_validate_report1")
		if e != nil {
			t.Fatal(e)
		}
		saved, e := f.service.GetReport(ctx, f.actor, accepted.ResourceID)
		if e != nil || saved.ID == "" || saved.Deployable {
			t.Fatalf("report not durable: %#v %v", saved, e)
		}
		op, e := f.service.GetOperation(ctx, f.actor, accepted.OperationID)
		if e != nil || op.State != "succeeded" {
			t.Fatalf("operation execution not durable: %#v %v", op, e)
		}
	})
	t.Run("catalog_snapshot_pins_complete_proposal_without_qualification", func(t *testing.T) {
		f := fixture(t, pg)
		ctx := context.Background()
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `INSERT INTO groups(id,name) VALUES('grp_AbCdEf123','S1 catalog group')`)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		catalog := configmodel.Catalog{APIVersion: "agp.catalog/v1alpha1", ID: "catalog_test_1", SourceKind: "operator_declared", SourceRef: "S1 test declared authoring inventory", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Sites: []configmodel.CatalogSite{{ID: "site_msk"}}, Nodes: []configmodel.CatalogNode{{ID: "node_msk01", SiteID: "site_msk", Labels: configmodel.Labels{}, NodeGroupIDs: []string{}}}, Groups: []string{"grp_AbCdEf123"}, Inputs: []configmodel.CatalogInput{
			{Kind: "component_profile", ID: "profile_nginx_waf_001", Digest: "sha256:" + strings.Repeat("a", 64), SiteID: "site_msk", State: "published"},
			{Kind: "certificate", ID: "cert_portal_v1", Digest: "sha256:" + strings.Repeat("b", 64), SiteID: "site_msk", State: "published"},
			{Kind: "waf_policy", ID: "waf_balanced_v1", Digest: "sha256:" + strings.Repeat("c", 64), SiteID: "site_msk", State: "published"},
		}}
		raw, _ := json.Marshal(catalog)
		snapshot, e := f.service.ImportCatalog(ctx, f.actor, "test_catalog_import01", raw, configmodel.JSON)
		if e != nil {
			t.Fatal(e)
		}
		d := mustDraft(t, f, "test_draft_catalog_01", "")
		report, e := f.service.PreviewDraft(ctx, f.actor, d.ID, snapshot.ID, "test_preview_catalog1")
		if e != nil {
			t.Fatal(e)
		}
		if !report.AuthoringValid || report.Deployable || report.CatalogDigest != snapshot.ContentDigest || report.Preview == nil || len(report.Preview.Bundles) != 1 {
			t.Fatalf("reference validation/proposal lost pins: %#v", report)
		}
		bundle := report.Preview.Bundles[0]
		if bundle.NodeID != "node_msk01" || len(bundle.Routes) != 1 || len(bundle.Artifacts) == 0 || bundle.Deployable {
			t.Fatalf("proposal not complete: %#v", bundle)
		}
		catalog.SourceRef = "changed under the same immutable ID"
		raw, _ = json.Marshal(catalog)
		if _, e = f.service.ImportCatalog(ctx, f.actor, "test_catalog_import02", raw, configmodel.JSON); !errors.Is(e, storage.ErrConflict) {
			t.Fatalf("catalog ID overwrite accepted: %v", e)
		}
		again, e := f.service.PreviewDraft(ctx, f.actor, d.ID, snapshot.ID, "test_preview_catalog1")
		if e != nil || again.ID != report.ID || again.CatalogDigest != snapshot.ContentDigest {
			t.Fatalf("report retry re-resolved mutable inputs: %v", e)
		}
	})
	t.Run("audit_failure_rolls_back_revision_projection_seal_and_head", func(t *testing.T) {
		f := fixture(t, pg)
		service := New(failedAuditCurrent{f.service.current}, "https://management.test", f.service.compiler)
		if _, e := service.CreateRevision(context.Background(), f.actor, "test_revision_fault01", CreateRevision{Content: example(t)}); e == nil {
			t.Fatal("fault injection was ignored")
		}
		for _, table := range []string{"config_revisions", "config_gateways", "config_routes", "config_revision_seals", "config_requests"} {
			if n := scalar(t, f, `SELECT COUNT(*) FROM `+table); n != 0 {
				t.Fatalf("failed transaction leaked %s: %d", table, n)
			}
		}
		if n := scalar(t, f, `SELECT row_version FROM config_head WHERE id=1`); n != 0 {
			t.Fatal("failed transaction advanced head")
		}
	})
}
