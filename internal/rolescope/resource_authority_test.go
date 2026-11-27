package rolescope

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/storage"
)

type resourceAuthorityProbeTx struct {
	storage.IdentityTx
	queries int
	fail    error
	rowFail error
}

func (tx *resourceAuthorityProbeTx) Query(ctx context.Context, query string, args ...any) (storage.IdentityRows, error) {
	tx.queries++
	if strings.Contains(query, "FROM resources") && tx.fail != nil {
		err := tx.fail
		tx.fail = nil
		return nil, err
	}
	rows, err := tx.IdentityTx.Query(ctx, query, args...)
	if err == nil && strings.Contains(query, "FROM resources") && tx.rowFail != nil {
		rows = resourceAuthorityFailedRows{IdentityRows: rows, failure: tx.rowFail}
		tx.rowFail = nil
	}
	return rows, err
}

type resourceAuthorityFailedRows struct {
	storage.IdentityRows
	failure error
}

func (rows resourceAuthorityFailedRows) Err() error { return rows.failure }

func TestResourceAuthoritySQLite(t *testing.T)   { testResourceAuthority(t, false) }
func TestResourceAuthorityPostgres(t *testing.T) { testResourceAuthority(t, true) }

func testResourceAuthority(t *testing.T, pg bool) {
	f := newGraphFixture(t, pg)
	rollback := errors.New("resource authority fixture rollback")
	within := func(t *testing.T, fn func(storage.IdentityTx)) {
		t.Helper()
		err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			fn(tx)
			return rollback
		})
		if !errors.Is(err, rollback) {
			t.Fatal(err)
		}
	}
	resolver := func(t *testing.T, tx storage.IdentityTx) *ResourceAuthorityResolver {
		t.Helper()
		r, err := NewResourceAuthorityResolver(f.ctx, tx, f.head)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	resolve := func(t *testing.T, r *ResourceAuthorityResolver, id string) ResourceAuthority {
		t.Helper()
		out, err := r.Resolve(id)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	t.Run("sealed_resource_and_exact_Gateway_route_ownership_are_separate_namespaces", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			r := resolver(t, tx)
			ids, err := r.ResourceIDs()
			if err != nil || !reflect.DeepEqual(ids, []string{"resource_portal", "resource_shared"}) {
				t.Fatal("sealed IDs", ids, err)
			}
			shared := resolve(t, r, "resource_shared")
			want := []ResourceRoute{{ResourceID: "resource_shared", GatewayID: "gw_portal", RouteID: "route_shared_a"}, {ResourceID: "resource_shared", GatewayID: "gw_second", RouteID: "route_shared_b"}}
			if shared.ResourceID != "resource_shared" || shared.Name != "resource_shared" || !reflect.DeepEqual(shared.Placements, want) || shared.Digest == "" || len(shared.Sources) != 2 {
				t.Fatalf("resource projection: %+v", shared)
			}
			for _, source := range shared.Sources {
				if source.Kind != "resource_metadata" && source.Kind != "scope_graph" {
					t.Fatalf("resource acquired node/Gateway/configuration authority: %+v", source)
				}
			}
			for _, tc := range []struct{ gateway, route, resource string }{
				{"gw_portal", "route_portal", "resource_portal"},
				{"gw_portal", "route_shared_a", "resource_shared"},
				{"gw_second", "route_shared_b", "resource_shared"},
				{"gw_second", "route_shared_a", ""},
				{"gw_portal", "resource_portal", ""},
			} {
				id, err := r.LookupRoute(tc.gateway, tc.route)
				if err != nil || id != tc.resource {
					t.Fatalf("route identity guessed or crossed Gateway boundary: %+v got=%s err=%v", tc, id, err)
				}
			}
			if out, err := r.Resolve("route_portal"); !errors.Is(err, storage.ErrNotFound) || !reflect.DeepEqual(out, ResourceAuthority{}) {
				t.Fatalf("route ID became resource identity: %+v %v", out, err)
			}
		})
	})
	t.Run("lazy_snapshot_is_shared_and_returned_collections_cannot_modify_it", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			probe := &resourceAuthorityProbeTx{IdentityTx: tx}
			r := resolver(t, probe)
			if probe.queries != 0 {
				t.Fatal("constructor eagerly loaded authority")
			}
			before := resolve(t, r, "resource_shared")
			ids, err := r.ResourceIDs()
			if err != nil {
				t.Fatal(err)
			}
			ids[0] = "caller_supplied_resource"
			before.Placements[0].GatewayID = "caller_supplied_gateway"
			before.Sources[0].Digest = "caller_supplied_digest"
			again := resolve(t, r, "resource_shared")
			ids, err = r.ResourceIDs()
			if err != nil || probe.queries != 2 || ids[0] != "resource_portal" || again.Placements[0].GatewayID != "gw_portal" || again.Sources[0].Digest == "caller_supplied_digest" || again.Digest != before.Digest {
				t.Fatalf("detached collections or single SQL snapshot lost: %+v ids=%v queries=%d err=%v", again, ids, probe.queries, err)
			}
		})
	})
	t.Run("configuration_CAS_and_node_metadata_are_not_resource_authority_sources", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			before := resolve(t, resolver(t, tx), "resource_shared")
			if err := f.insertConfiguration(tx, f.configuration, "revision_resource_own_cas", 2); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(f.ctx, `UPDATE managed_nodes SET authority_epoch=2`); err != nil {
				t.Fatal(err)
			}
			if after := resolve(t, resolver(t, tx), "resource_shared"); !reflect.DeepEqual(before, after) {
				t.Fatalf("resource projection depended on own config CAS or node management fallback: %+v -> %+v", before, after)
			}
		})
	})
	t.Run("disabled_resource_remains_draft_editable_and_all_live_metadata_is_pinned", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			r := resolver(t, tx)
			before := resolve(t, r, "resource_portal")
			if _, err := tx.Exec(f.ctx, `UPDATE resources SET enabled=FALSE WHERE id='resource_portal'`); err != nil {
				t.Fatal(err)
			}
			disabled := resolve(t, resolver(t, tx), "resource_portal")
			if disabled.Digest == before.Digest || !reflect.DeepEqual(disabled.Placements, before.Placements) {
				t.Fatal("disabled resource disappeared or enabled status was not pinned")
			}
			if _, err := tx.Exec(f.ctx, `UPDATE resources SET name='Changed administrative name' WHERE id='resource_portal'`); err != nil {
				t.Fatal(err)
			}
			renamed := resolve(t, resolver(t, tx), "resource_portal")
			if renamed.Name != "Changed administrative name" || renamed.Digest == disabled.Digest {
				t.Fatal("resource name was not included in evidence")
			}
			if _, err := tx.Exec(f.ctx, `UPDATE resources SET updated_at=? WHERE id='resource_portal'`, f.head.RecordedAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			updated := resolve(t, resolver(t, tx), "resource_portal")
			if updated.Digest == renamed.Digest || resolve(t, r, "resource_portal").Digest != before.Digest {
				t.Fatal("new final resolver did not detect updatedAt drift or old snapshot refreshed itself")
			}
		})
	})
	t.Run("missing_live_declared_resource_is_not_pruned_or_turned_into_unowned_route", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			if _, err := tx.Exec(f.ctx, `DELETE FROM resources WHERE id='resource_portal'`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(f.ctx, `INSERT INTO resources(id,name,internal_url,public_host) VALUES('resource_unsealed','Unsealed','https://unsealed.test','unsealed.test')`); err != nil {
				t.Fatal(err)
			}
			r := resolver(t, tx)
			ids, err := r.ResourceIDs()
			if err != nil || !reflect.DeepEqual(ids, []string{"resource_portal", "resource_shared"}) {
				t.Fatal("missing declared resource pruned or unsealed row became authority", ids, err)
			}
			if id, err := r.LookupRoute("gw_portal", "route_portal"); err != nil || id != "resource_portal" {
				t.Fatal("missing metadata turned mapped route into unowned neighbor", id, err)
			}
			if out, err := r.Resolve("resource_portal"); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(out, ResourceAuthority{}) {
				t.Fatalf("missing current resource returned partial metadata: %+v %v", out, err)
			}
			if _, err := r.Resolve("resource_unsealed"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatal("unsealed resource became administrative route authority", err)
			}
			resolve(t, r, "resource_shared")
		})
	})
	for _, stage := range []string{"query", "iteration"} {
		t.Run("source_"+stage+"_failure_is_memoized_across_every_lookup", func(t *testing.T) {
			within(t, func(tx storage.IdentityTx) {
				failure := errors.New("resource SQL source unavailable")
				probe := &resourceAuthorityProbeTx{IdentityTx: tx}
				if stage == "query" {
					probe.fail = failure
				} else {
					probe.rowFail = failure
				}
				r := resolver(t, probe)
				for i := 0; i < 2; i++ {
					out, err := r.Resolve("resource_portal")
					if !errors.Is(err, failure) || !reflect.DeepEqual(out, ResourceAuthority{}) {
						t.Fatalf("source failure became allow: %+v %v", out, err)
					}
					if ids, err := r.ResourceIDs(); !errors.Is(err, failure) || ids != nil {
						t.Fatal("source failure bypassed via IDs", ids, err)
					}
					if id, err := r.LookupRoute("gw_portal", "route_portal"); !errors.Is(err, failure) || id != "" {
						t.Fatal("source failure bypassed via route lookup", id, err)
					}
					if probe.queries != 2 {
						t.Fatal("failed snapshot retried a healthy fallback", probe.queries)
					}
				}
			})
		})
	}
	t.Run("epoch_mismatch_and_cancellation_do_not_reuse_a_snapshot", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			head := f.head
			head.Epoch++
			r, err := NewResourceAuthorityResolver(f.ctx, tx, head)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.Resolve("resource_portal"); !errors.Is(err, ErrUnavailable) {
				t.Fatal("resource graph crossed authority epoch", err)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			r, err = NewResourceAuthorityResolver(ctx, tx, f.head)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			resolve(t, r, "resource_portal")
			cancel()
			if _, err = r.ResourceIDs(); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled callback retained usable authority", err)
			}
		})
	})
}
