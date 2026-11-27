package configuration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/storage"
)

type selectorResolverSpy struct{ calls int }

func (s *selectorResolverSpy) WithCurrentHistoricalSubjects(ctx context.Context, _ []string, fn func(context.Context) error) error {
	s.calls++
	return fn(ctx)
}

func selectorSubjects(t *testing.T, f *testFixture, a Actor, selection directorySubjectSelection) []string {
	t.Helper()
	var out []string
	err := f.service.transactScoped(context.Background(), a, false, func(tx storage.IdentityTx, p *Principal) error {
		var e error
		out, e = collectDirectorySubjects(context.Background(), tx, p, &selection)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDirectorySubjectCollectorsSQLite(t *testing.T)   { testDirectorySubjectCollectors(t, false) }
func TestDirectorySubjectCollectorsPostgres(t *testing.T) { testDirectorySubjectCollectors(t, true) }

func testDirectorySubjectCollectors(t *testing.T, pg bool) {
	t.Run("latest_32_before_expiry_filter", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		r := createWaf(t, f)
		validateWaf(t, f, r)
		approval := approveWaf(t, f, r)
		var baseTime time.Time
		if err := f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
			rows, err := tx.Query(context.Background(), "SELECT created_at FROM config_waf_policy_approvals WHERE id=?", approval.ApprovalID)
			if err != nil {
				return err
			}
			if !rows.Next() {
				rows.Close()
				return storage.ErrNotFound
			}
			err = rows.Scan(&baseTime)
			rows.Close()
			if err != nil {
				return err
			}
			for i := 0; i < 32; i++ {
				created := baseTime.Add(time.Duration(i+1) * time.Second)
				_, err = tx.Exec(context.Background(), `INSERT INTO config_waf_policy_approvals(id,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) SELECT ?,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,?,authority_epoch,author_fingerprint,approver_fingerprint,?,?,?,reason FROM config_waf_policy_approvals WHERE id=?`, fmt.Sprintf("selector_approval_%02d", i), fmt.Sprintf("selector_reviewer_%02d", i), created, created.Add(time.Second), created, approval.ApprovalID)
				if err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// The newest 32 are expired at this deterministic observation time.
		// The older, still-live original must not expand the actual candidate set.
		err := f.service.transactScoped(context.Background(), f.actor, false, func(tx storage.IdentityTx, p *Principal) error {
			c := &directorySubjectCollector{ctx: context.Background(), tx: tx, p: p, now: baseTime.Add(time.Minute), subjects: map[string]bool{}, visited: map[string]bool{}}
			if err := c.policy(r.ID, "policy_publish"); err != nil {
				return err
			}
			if len(c.subjects) != 1 || !c.subjects["waf_author"] {
				t.Fatalf("selector reached candidates outside latest 32: %v", c.subjects)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("published_metadata_and_exact_owner_dependency", func(t *testing.T) {
		f, _, _, policy, _ := trustedZoneFixture(t, pg)
		body := zoneBody("selector_published", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		body.Metadata.OwnerID = "waf_reader"
		body.Spec.PolicyRevisionID = policy.ID
		z, err := f.service.CreateZoneRevision(context.Background(), wafActor(f, "waf_author"), "selector_zone_create01", ZoneCreate{Content: mustJSON(t, body)})
		if err != nil {
			t.Fatal(err)
		}
		publishTrustedZone(t, f, z)
		spy := &selectorResolverSpy{}
		f.service.WithDirectorySubjects(spy)
		if _, err = f.service.GetWafPolicyRevision(context.Background(), f.actor, policy.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.service.GetZoneRevision(context.Background(), f.actor, z.ID); err != nil {
			t.Fatal(err)
		}
		if spy.calls != 0 {
			t.Fatal("historical published metadata requested live credentials")
		}
		ids := selectorSubjects(t, f, f.actor, directorySubjectSelection{Kind: "published_zone", ID: z.ID, SiteID: "site_msk"})
		if !reflect.DeepEqual(ids, []string{"waf_reader"}) {
			t.Fatalf("published consumption selected author/reviewer rather than owner: %v", ids)
		}
	})
	t.Run("site_closure_contains_sealed_source_and_target_only", func(t *testing.T) {
		f, _, _, policy, base := trustedZoneFixture(t, pg)
		old := publishTrustedZone(t, f, createTrustedZone(t, f, policy.ID, "selector_source", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}}))
		resolution := resolveTrustedZone(t, f, old, base)
		assigned, err := f.service.MaterializeZone(context.Background(), f.actor, "selector_materialize01", trustedChange(base, old, resolution))
		if err != nil {
			t.Fatal(err)
		}
		body := zoneBody("selector_target", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
		body.Metadata.OwnerID = "waf_reader"
		body.Spec.PolicyRevisionID = policy.ID
		target, err := f.service.CreateZoneRevision(context.Background(), wafActor(f, "waf_author"), "selector_target_create1", ZoneCreate{Content: mustJSON(t, body)})
		if err != nil {
			t.Fatal(err)
		}
		foreign := zoneBody("selector_foreign", configmodel.ZoneMembership{MatchLabels: &configmodel.Labels{"environment": "other"}})
		foreign.Metadata.SiteID = "site_other"
		foreign.Metadata.OwnerID = "waf_foreign"
		foreign.Spec.PolicyRevisionID = policy.ID
		other, err := f.service.CreateZoneRevision(context.Background(), wafActor(f, "waf_foreign"), "selector_foreign_create", ZoneCreate{Content: mustJSON(t, foreign)})
		if err != nil {
			t.Fatal(err)
		}
		ids := selectorSubjects(t, f, f.actor, directorySubjectSelection{Kind: "closure", RevisionID: assigned.ID, SiteID: "site_msk", ZoneRevisionIDs: []string{target.ID}})
		if !reflect.DeepEqual(ids, []string{"waf_author", "waf_reader"}) {
			t.Fatalf("missing sealed source or selected unrelated Site: %v", ids)
		}
		err = f.service.transactScoped(context.Background(), f.actor, false, func(tx storage.IdentityTx, p *Principal) error {
			_, err := collectDirectorySubjects(context.Background(), tx, p, &directorySubjectSelection{Kind: "closure", RevisionID: assigned.ID, SiteID: "site_msk", ZoneRevisionIDs: []string{other.ID}})
			return err
		})
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatal("cross-Site replacement selected a directory subject", err)
		}
	})
	t.Run("two_hundred_reviews_and_distinct_author", func(t *testing.T) {
		f, _, _, revision := planFixture(t, pg)
		proposal := mustProposal(t, f, revision)
		if err := f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
			for i := 0; i < 200; i++ {
				_, err := tx.Exec(context.Background(), `INSERT INTO config_plan_proposal_reviews(id,proposal_id,reviewer_id,reviewer_fingerprint,review_digest,review_json,created_at) VALUES(?,?,?,'fixture','fixture','{}',?)`, fmt.Sprintf("selector_review_%03d", i), proposal.ID, fmt.Sprintf("selector_reviewer_%03d", i), time.Now().UTC())
				if err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		ids := selectorSubjects(t, f, f.actor, directorySubjectSelection{Kind: "plan_reviews", ID: proposal.ID})
		if len(ids) != 201 || !sort.StringsAreSorted(ids) {
			t.Fatalf("valid 200-review page lost participants: %d", len(ids))
		}
		if i := sort.SearchStrings(ids, proposal.AuthorID); i >= len(ids) || ids[i] != proposal.AuthorID {
			t.Fatal("proposal author omitted")
		}
	})
	t.Run("wrong_site_never_calls_network_resolver", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		policy := createWaf(t, f)
		spy := &selectorResolverSpy{}
		f.service.WithDirectorySubjects(spy)
		ctx, err := f.service.directorySubjectContext(context.Background(), wafActor(f, "waf_foreign"), false, directorySubjectSelection{Kind: "policy_write", ID: policy.ID})
		if !errors.Is(err, storage.ErrNotFound) || ctx != nil || spy.calls != 0 {
			t.Fatalf("unauthorized root requested live subjects: context=%v error=%v calls=%d", ctx, err, spy.calls)
		}
	})
}
