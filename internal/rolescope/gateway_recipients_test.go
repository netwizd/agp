package rolescope

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/storage"
)

func TestGatewayRecipientsSQLite(t *testing.T)   { testGatewayRecipients(t, false) }
func TestGatewayRecipientsPostgres(t *testing.T) { testGatewayRecipients(t, true) }

type gatewayProbeTx struct {
	storage.IdentityTx
	queries int
	fail    error
}

func (tx *gatewayProbeTx) Query(ctx context.Context, query string, args ...any) (storage.IdentityRows, error) {
	tx.queries++
	if tx.fail != nil && strings.Contains(query, "FROM managed_nodes") {
		err := tx.fail
		tx.fail = nil
		return nil, err
	}
	return tx.IdentityTx.Query(ctx, query, args...)
}

func gatewayLabels(g configmodel.Gateway, labels configmodel.Labels) configmodel.Gateway {
	g.Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &labels}
	return g
}

func putGatewayFact(ctx context.Context, tx storage.IdentityTx, n nodeFact) error {
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE managed_nodes SET site_id=?,node_json=? WHERE id=?`, n.SiteID, string(raw), n.ID)
	return err
}

func testGatewayRecipients(t *testing.T, pg bool) {
	f := newGraphFixture(t, pg)
	base := f.configuration.Gateways[0]
	rollback := errors.New("rollback gateway recipient fixture")
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
	resolve := func(t *testing.T, tx storage.IdentityTx, g configmodel.Gateway) GatewayRecipients {
		t.Helper()
		out, err := ResolveGatewayRecipients(f.ctx, tx, f.head, g)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	deny := func(t *testing.T, tx storage.IdentityTx, g configmodel.Gateway) {
		t.Helper()
		out, err := ResolveGatewayRecipients(f.ctx, tx, f.head, g)
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(out, GatewayRecipients{}) {
			t.Fatalf("accepted unavailable authority or returned partial recipients: %+v %v", out, err)
		}
	}
	fact := func(id string) nodeFact {
		return nodeFact{ID: id, SiteID: "site_msk", Name: id, Labels: map[string]string{"environment": "pilot"}, GroupIDs: []string{"ng_msk"}, CreatedAt: f.head.RecordedAt}
	}

	t.Run("sorted_pending_receivers_detached_from_caller_and_resource_placements", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			g := base
			g.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{"node_msk02", "node_msk01"}}
			before := resolve(t, tx, g)
			if len(before.Nodes) != 2 || before.Nodes[0].NodeID != "node_msk01" || before.Nodes[1].NodeID != "node_msk02" || !reflect.DeepEqual(before.Nodes[0].GroupIDs, []string{"ng_msk"}) || before.SiteID != "site_msk" {
				t.Fatalf("incomplete receiving closure: %+v", before)
			}
			if g.Spec.NodeSelector.NodeIDs[0] != "node_msk02" {
				t.Fatal("resolver normalized caller-owned selector")
			}
			for _, s := range before.Sources {
				if s.Kind != "scope_graph" && s.Kind != "gateway_ownership" && s.Kind != "managed_node" {
					t.Fatalf("explicit gateway inferred resource/configuration authority: %+v", s)
				}
			}
			if err := f.insertConfiguration(tx, f.configuration, "revision_gateway_self_cas", 2); err != nil {
				t.Fatal(err)
			}
			after := resolve(t, tx, g)
			if before.Digest != after.Digest {
				t.Fatal("own configuration CAS invalidated external gateway evidence")
			}
			g.Spec.Routes = append([]configmodel.Route{}, g.Spec.Routes...)
			g.Spec.Routes[0].Upstream.ReadTimeoutSeconds++
			candidate := resolve(t, tx, g)
			if candidate.Digest != before.Digest || !reflect.DeepEqual(candidate.Sources, before.Sources) {
				t.Fatal("non-scope candidate field changed gateway authority evidence")
			}
			g.Spec.NodeSelector.NodeIDs = []string{"node_msk01"}
			if resolve(t, tx, g).Digest == before.Digest {
				t.Fatal("changed receiving selector was omitted from authority digest")
			}
		})
	})

	t.Run("one_snapshot_per_callback_and_new_final_resolver_reads_current_facts", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			probe := &gatewayProbeTx{IdentityTx: tx}
			r, err := NewGatewayRecipientResolver(f.ctx, probe, f.head)
			if err != nil || probe.queries != 0 {
				t.Fatalf("snapshot was not lazy: %v, queries=%d", err, probe.queries)
			}
			before, err := r.Resolve(base)
			if err != nil || probe.queries != 3 {
				t.Fatalf("authority snapshot queries=%d: %v", probe.queries, err)
			}
			before.Nodes[0].GroupIDs[0] = "caller_modified_group"
			again, err := r.Resolve(base)
			if err != nil || again.Nodes[0].GroupIDs[0] != "ng_msk" || again.Digest != before.Digest || probe.queries != 3 {
				t.Fatalf("caller modified cache or sources reloaded: %+v %v", again, err)
			}
			changed := fact("node_msk01")
			changed.Labels["environment"] = "changed"
			if err = putGatewayFact(f.ctx, tx, changed); err != nil {
				t.Fatal(err)
			}
			fresh := resolve(t, tx, base)
			if fresh.Digest == before.Digest {
				t.Fatal("new final resolver failed to detect source drift")
			}
		})
	})

	t.Run("snapshot_sql_failure_is_latched_even_when_next_query_would_succeed", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			failure := errors.New("managed node SQL unavailable")
			probe := &gatewayProbeTx{IdentityTx: tx, fail: failure}
			r, err := NewGatewayRecipientResolver(f.ctx, probe, f.head)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				out, err := r.Resolve(base)
				if !errors.Is(err, failure) || !reflect.DeepEqual(out, GatewayRecipients{}) || probe.queries != 2 {
					t.Fatalf("snapshot error hidden by healthy retry: %+v %v queries=%d", out, err, probe.queries)
				}
			}
		})
	})

	t.Run("label_universe_includes_pending_and_does_not_prune_revoked_matches", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			g := gatewayLabels(base, configmodel.Labels{"environment": "pilot"})
			out := resolve(t, tx, g)
			if len(out.Nodes) != 2 {
				t.Fatalf("pending receivers were pruned: %+v", out)
			}
			if _, err := tx.Exec(f.ctx, `INSERT INTO security_node_revocations(node_id,event_id) VALUES('node_msk02','event_gateway_revoke')`); err != nil {
				t.Fatal(err)
			}
			deny(t, tx, g)
			g.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{"node_msk02"}}
			deny(t, tx, g)
		})
	})

	t.Run("nonmatching_revoked_fact_is_retained_in_universe_evidence", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			other := fact("node_msk02")
			other.Labels["environment"] = "outside"
			if err := putGatewayFact(f.ctx, tx, other); err != nil {
				t.Fatal(err)
			}
			g := gatewayLabels(base, configmodel.Labels{"environment": "pilot"})
			before := resolve(t, tx, g)
			if _, err := tx.Exec(f.ctx, `INSERT INTO security_node_revocations(node_id,event_id) VALUES('node_msk02','event_gateway_nonmatch')`); err != nil {
				t.Fatal(err)
			}
			after := resolve(t, tx, g)
			if len(after.Nodes) != 1 || after.Digest == before.Digest {
				t.Fatal("nonmatching revoked fact disappeared from full universe evidence")
			}
			if resolve(t, tx, base).Nodes[0].NodeID != "node_msk01" {
				t.Fatal("unrelated revocation changed explicit selector")
			}
		})
	})

	for _, change := range []string{"missing", "old_epoch", "site_drift", "group_drift"} {
		t.Run("declared_"+change+"_cannot_shrink_label_universe", func(t *testing.T) {
			within(t, func(tx storage.IdentityTx) {
				var err error
				switch change {
				case "missing":
					_, err = tx.Exec(f.ctx, `DELETE FROM managed_nodes WHERE id='node_msk02'`)
				case "old_epoch":
					_, err = tx.Exec(f.ctx, `UPDATE managed_nodes SET authority_epoch=2 WHERE id='node_msk02'`)
				case "site_drift":
					n := fact("node_msk02")
					n.SiteID, n.GroupIDs = "site_other", []string{}
					err = putGatewayFact(f.ctx, tx, n)
				case "group_drift":
					n := fact("node_msk02")
					n.GroupIDs = []string{}
					err = putGatewayFact(f.ctx, tx, n)
				}
				if err != nil {
					t.Fatal(err)
				}
				deny(t, tx, gatewayLabels(base, configmodel.Labels{"environment": "pilot"}))
				// A complete explicit receiver's facts remain sufficient without
				// pretending that a different node matched a label selector.
				resolve(t, tx, base)
				g := base
				g.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{"node_msk02"}}
				deny(t, tx, g)
			})
		})
	}

	t.Run("actual_unknown_nodes_never_become_implicit_installation_owned_mapping", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			g := gatewayLabels(base, configmodel.Labels{"environment": "pilot"})
			before := resolve(t, tx, g)
			n := fact("node_unknown")
			n.GroupIDs, n.Labels["environment"] = []string{}, "outside"
			raw, _ := json.Marshal(n)
			if _, err := tx.Exec(f.ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,1,?)`, n.ID, n.SiteID, string(raw), n.CreatedAt); err != nil {
				t.Fatal(err)
			}
			after := resolve(t, tx, g)
			if len(after.Nodes) != 2 || before.Digest == after.Digest {
				t.Fatal("actual unknown nonmatch was silently omitted from source universe")
			}
			n.Labels["environment"] = "pilot"
			if err := putGatewayFact(f.ctx, tx, n); err != nil {
				t.Fatal(err)
			}
			deny(t, tx, g)
			explicit := base
			explicit.Spec.NodeSelector = configmodel.NodeSelector{NodeIDs: []string{n.ID}}
			deny(t, tx, explicit)
		})
	})

	t.Run("gateway_site_and_unknown_ownership_are_not_browser_authority", func(t *testing.T) {
		within(t, func(tx storage.IdentityTx) {
			g := base
			g.Metadata.SiteID = "site_other"
			deny(t, tx, g)
			g = base
			g.Metadata.ID = "gateway_unowned"
			deny(t, tx, g)
			empty := resolve(t, tx, gatewayLabels(base, configmodel.Labels{"environment": "no_matches"}))
			if empty.Nodes == nil || len(empty.Nodes) != 0 || empty.Digest == "" || len(empty.Sources) != 3 {
				t.Fatalf("complete empty selector became unavailable or lost evidence: %+v", empty)
			}
			out, err := ResolveGatewayRecipients(f.ctx, tx, f.head, configmodel.Gateway{})
			if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(out, GatewayRecipients{}) {
				t.Fatalf("accepted malformed gateway: %+v %v", out, err)
			}
			head := f.head
			head.Epoch++
			if _, err = ResolveGatewayRecipients(f.ctx, tx, head, base); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("accepted sealed graph from another epoch: %v", err)
			}
		})
	})
}

func TestGatewayRecipientsSiteIsolationSQLite(t *testing.T) {
	testGatewayRecipientsSiteIsolation(t, false)
}

func TestGatewayRecipientsSiteIsolationPostgres(t *testing.T) {
	testGatewayRecipientsSiteIsolation(t, true)
}

func testGatewayRecipientsSiteIsolation(t *testing.T, pg bool) {
	f := newGraphFixture(t, pg, Node{ID: "node_other", SiteID: "site_other", GroupIDs: []string{"ng_other"}})
	g := gatewayLabels(f.configuration.Gateways[0], configmodel.Labels{"environment": "pilot"})
	err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		before, err := ResolveGatewayRecipients(f.ctx, tx, f.head, g)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(f.ctx, `DELETE FROM managed_nodes WHERE id='node_other'`); err != nil {
			return err
		}
		r, err := NewGatewayRecipientResolver(f.ctx, tx, f.head)
		if err != nil {
			return err
		}
		after, err := r.Resolve(g)
		if err != nil || !reflect.DeepEqual(before.Nodes, after.Nodes) || after.Digest == before.Digest {
			t.Fatalf("unrelated site's missing node changed receivers or disappeared from universe evidence: %+v %v", after, err)
		}
		if err = r.checkDeclaredUniverse("site_other"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("missing declared node's own site was accepted: %v", err)
		}
		again, err := r.Resolve(g)
		if err != nil || again.Digest != after.Digest {
			t.Fatalf("other site's memoized failure poisoned complete local site: %+v %v", again, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
