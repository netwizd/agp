package configuration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// An independent journal-clock adapter for the service fixture. Native
// qualification remains a boundary double, including its injected clock.
type planClockCurrent struct {
	underlying Current
	offset     time.Duration
	after      func()
}

type planZeroHeadCurrent struct{ underlying Current }

func (c planZeroHeadCurrent) Head(ctx context.Context) (securityjournal.Head, error) {
	h, err := c.underlying.Head(ctx)
	h.RecordedAt = time.Time{}
	return h, err
}

func (c planZeroHeadCurrent) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		h.RecordedAt = time.Time{}
		return fn(tx, h)
	})
}

func (c planClockCurrent) Head(ctx context.Context) (securityjournal.Head, error) {
	h, err := c.underlying.Head(ctx)
	if err == nil {
		h.RecordedAt = time.Now().UTC().Add(c.offset)
	}
	return h, err
}

type planInventoryFailure struct{ err error }

func (v planInventoryFailure) Current(context.Context, storage.IdentityTx, securityjournal.UInt63, string, []WAFQualification) (*TrustedInventorySnapshot, error) {
	return nil, v.err
}

func (c planClockCurrent) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		h.RecordedAt = time.Now().UTC().Add(c.offset)
		e := fn(tx, h)
		if c.after != nil {
			c.after()
		}
		return e
	})
}

type planChangedCapabilities struct{ TrustedInventory }

func (v planChangedCapabilities) Current(ctx context.Context, tx storage.IdentityTx, epoch securityjournal.UInt63, site string, proofs []WAFQualification) (*TrustedInventorySnapshot, error) {
	observed, e := v.TrustedInventory.Current(ctx, tx, epoch, site, proofs)
	if e != nil {
		return nil, e
	}
	observed.Nodes = append([]configmodel.CatalogNode{}, observed.Nodes...)
	observed.Nodes[0].CapabilityDigest = "sha256:" + strings.Repeat("7", 64)
	return observed, nil
}
func planFixture(t *testing.T, pg bool) (*testFixture, *testWafQualifier, *testTrustedInventory, *Revision) {
	t.Helper()
	ctx := context.Background()
	f := fixtureConfigured(t, pg, func(tx storage.IdentityTx) error {
		now := time.Now().UTC()
		if _, e := tx.Exec(ctx, `INSERT INTO groups(id,name) VALUES('grp_AbCdEf123','Plan fixture group')`); e != nil {
			return e
		}
		for _, id := range []string{"waf_author", "waf_approver", "waf_foreign", "waf_reader"} {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "hash"); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management','https://management.test',1,1,?,?)`, id, id, id+"_token", "csrf", "", "", now.Add(time.Hour), now, now, now); e != nil {
				return e
			}
		}
		for _, g := range []struct{ id, user, permission, scope, site string }{{"plan_author_edit", "waf_author", "config.edit", "global", ""}, {"plan_author_approve", "waf_author", "config.approve", "global", ""}, {"plan_approver_read", "waf_approver", "config.read", "global", ""}, {"plan_approver_approve", "waf_approver", "config.approve", "global", ""}, {"plan_reader_read", "waf_reader", "config.read", "global", ""}, {"plan_foreign", "waf_foreign", "config.edit", "site", "site_other"}} {
			if _, e := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES(?,?,?,?,?,1,?)`, "cgrant_"+g.id, g.user, g.permission, g.scope, g.site, now); e != nil {
				return e
			}
		}
		for _, id := range []string{"gw_portal", "gw_second"} {
			if _, e := tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,'site_msk')`, id); e != nil {
				return e
			}
		}
		return nil
	})
	q := &testWafQualifier{}
	source := &testTrustedInventory{source: "8"}
	f.service.WithWAFQualifier(q).WithTrustedInventory(source)
	policy := createWaf(t, f)
	validateWaf(t, f, policy)
	approveWaf(t, f, policy)
	if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), policy.ID, "plan_policy_publish01", WafPolicyPublicationRequest{policy.ContentDigest}); e != nil {
		t.Fatal(e)
	}
	var c configmodel.Configuration
	if e := json.Unmarshal(example(t), &c); e != nil {
		t.Fatal(e)
	}
	c.Gateways[0].Spec.WAF.PolicyRevisionID = policy.ID
	c.Gateways[0].Spec.ComponentProfileRef = configmodel.Reference{ID: "native_profile", Digest: "sha256:" + strings.Repeat("2", 64)}
	revision, e := f.service.CreateRevision(ctx, f.actor, "plan_fixture_revision01", CreateRevision{Content: mustJSON(t, c)})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../docs/v2/examples/catalog-authoring-pilot.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.ImportCatalog(ctx, f.actor, "plan_fixture_catalog01", raw, configmodel.JSON); e != nil {
		t.Fatal(e)
	}
	f.service.current = planClockCurrent{underlying: f.service.current}
	return f, q, source, revision
}
func planRequest(r *Revision) PlanProposalCreate {
	return PlanProposalCreate{RevisionID: r.ID, SiteID: "site_msk", TargetNodeIDs: []string{"node_msk01"}, RolloutPolicy: deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{"node_msk01"}, MaxParallel: 1, MaxUnavailable: 0, ObservationSeconds: 30, FailureAction: "pause"}, Reason: "Review the full pinned node configuration"}
}
func mustProposal(t *testing.T, f *testFixture, r *Revision) *PlanProposal {
	t.Helper()
	p, e := f.service.CreatePlanProposal(context.Background(), wafActor(f, "waf_author"), "plan_create_request_0001", planRequest(r))
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func mustPlanReview(t *testing.T, f *testFixture, p *PlanProposal) *PlanProposalReview {
	t.Helper()
	r, e := f.service.ReviewPlanProposal(context.Background(), wafActor(f, "waf_approver"), p.ID, "plan_review_request_0001", PlanProposalReviewRequest{p.ProposalDigest, "Independent review of planning proposal"})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestPlanProposalsSQLite(t *testing.T)   { testPlanProposals(t, false) }
func TestPlanProposalsPostgres(t *testing.T) { testPlanProposals(t, true) }
func testPlanProposals(t *testing.T, pg bool) {
	ctx := context.Background()
	t.Run("persisted_full_review_no_execution_and_exact_replay", func(t *testing.T) {
		f, _, _, r := planFixture(t, pg)
		p := mustProposal(t, f, r)
		if p.Deployable || !p.NoExecution || p.Purpose != "planning_review" || len(p.Targets) != 1 || len(p.Targets[0].GatewayIDs) != 1 || len(p.Blockers) < 4 || p.Targets[0].CapabilityDigest != "sha256:"+strings.Repeat("9", 64) {
			t.Fatalf("unsafe proposal: %#v", p)
		}
		before := scalar(t, f, `SELECT row_version FROM config_head WHERE id=1`)
		retry, e := f.service.CreatePlanProposal(ctx, wafActor(f, "waf_author"), "plan_create_request_0001", planRequest(r))
		if e != nil || retry.ProposalDigest != p.ProposalDigest || retry.ID != p.ID {
			t.Fatalf("retry %#v %v", retry, e)
		}
		view, e := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), p.ID)
		if e != nil || !view.Current {
			t.Fatalf("read-only current %#v %v", view, e)
		}
		page, e := f.service.ListPlanProposals(ctx, wafActor(f, "waf_reader"), 1, "")
		if e != nil || len(page.Items) != 1 || !page.Items[0].Current {
			t.Fatalf("page %#v %v", page, e)
		}
		review := mustPlanReview(t, f, p)
		again, e := f.service.ReviewPlanProposal(ctx, wafActor(f, "waf_approver"), p.ID, "plan_review_request_0001", PlanProposalReviewRequest{p.ProposalDigest, review.Reason})
		if e != nil || again.ID != review.ID {
			t.Fatalf("review replay %#v %v", again, e)
		}
		reviews, e := f.service.PlanProposalReviews(ctx, wafActor(f, "waf_reader"), p.ID)
		if e != nil || len(reviews) != 1 || !reviews[0].Current {
			t.Fatalf("reviews %#v %v", reviews, e)
		}
		if scalar(t, f, `SELECT row_version FROM config_head WHERE id=1`) != before {
			t.Fatal("review changed configuration head")
		}
	})
	t.Run("list_cache_is_one_fenced_snapshot_and_never_cross_request", func(t *testing.T) {
		f, _, source, r := planFixture(t, pg)
		first := mustProposal(t, f, r)
		in := planRequest(r)
		in.Reason = "A separate immutable planning discussion"
		second, e := f.service.CreatePlanProposal(ctx, wafActor(f, "waf_author"), "plan_create_second_0001", in)
		if e != nil {
			t.Fatal(e)
		}
		source.mu.Lock()
		before := source.calls
		source.mu.Unlock()
		page, e := f.service.ListPlanProposals(ctx, wafActor(f, "waf_reader"), 50, "")
		if e != nil || len(page.Items) != 2 {
			t.Fatalf("list %#v %v", page, e)
		}
		source.mu.Lock()
		calls := source.calls - before
		source.source = "7"
		source.mu.Unlock()
		if calls != 1 {
			t.Fatalf("expected one transaction-local observation, got %d", calls)
		}
		for _, p := range []*PlanProposal{first, second} {
			view, e := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), p.ID)
			if e != nil || view.Current {
				t.Fatalf("cross-request stale cache %#v %v", view, e)
			}
		}
		page, e = f.service.ListPlanProposals(ctx, wafActor(f, "waf_reader"), 1, "")
		if e != nil || len(page.Items) != 1 || page.NextCursor == "" {
			t.Fatalf("first page %#v %v", page, e)
		}
		next, e := f.service.ListPlanProposals(ctx, wafActor(f, "waf_reader"), 1, page.NextCursor)
		if e != nil || len(next.Items) != 1 || next.Items[0].Proposal.ID == page.Items[0].Proposal.ID {
			t.Fatalf("cursor %#v %v", next, e)
		}
	})
	t.Run("target_subset_contains_complete_node_gateway_tree", func(t *testing.T) {
		f, _, _, r := planFixture(t, pg)
		var c configmodel.Configuration
		if e := json.Unmarshal(r.Content, &c); e != nil {
			t.Fatal(e)
		}
		second := c.Gateways[0]
		second.Metadata.ID = "gw_second"
		second.Spec.Routes = append([]configmodel.Route{}, second.Spec.Routes...)
		second.Spec.Routes[0].ID = "route_second"
		second.Spec.Routes[0].Hostname = "second.example.net"
		c.Gateways = append(c.Gateways, second)
		revised, e := f.service.CreateRevision(ctx, f.actor, "plan_full_tree_config01", CreateRevision{BaseRevisionID: r.ID, Content: mustJSON(t, c)})
		if e != nil {
			t.Fatal(e)
		}
		p := mustProposal(t, f, revised)
		if len(p.Targets) != 1 || len(p.Targets[0].GatewayIDs) != 2 || p.Targets[0].GatewayIDs[0] != "gw_portal" || p.Targets[0].GatewayIDs[1] != "gw_second" {
			t.Fatalf("node tree shrank %#v", p.Targets)
		}
	})
	t.Run("identity_deletion_preserves_history_and_invalidates_review", func(t *testing.T) {
		for _, deleted := range []string{"waf_author", "waf_approver"} {
			t.Run(deleted, func(t *testing.T) {
				f, _, _, r := planFixture(t, pg)
				p := mustProposal(t, f, r)
				review := mustPlanReview(t, f, p)
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				if e := f.service.WithPlanReviewSigningKey("plan_key", key); e != nil {
					t.Fatal(e)
				}
				signed, e := f.service.SignPlanProposalReview(ctx, wafActor(f, "waf_approver"), p.ID, review.ID, "plan_delete_sign_0001")
				if e != nil || signed == nil {
					t.Fatalf("initial signature %#v %v", signed, e)
				}
				// The normal fenced administrator admission exercises the physical DELETE
				// used by identity storage; immutable audit artifacts keep opaque subject IDs.
				e = f.service.transactPlan(ctx, f.actor, true, "config.edit", func(tx storage.IdentityTx, _ *Principal, _ time.Time) error {
					_, e := tx.Exec(ctx, `DELETE FROM users WHERE id=?`, deleted)
					return e
				})
				if e != nil {
					t.Fatalf("identity deletion blocked by history: %v", e)
				}
				view, e := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), p.ID)
				if e != nil || view.Proposal.AuthorID != p.AuthorID {
					t.Fatalf("lost proposal history %#v %v", view, e)
				}
				if deleted == "waf_author" && view.Current {
					t.Fatal("deleted author remained current")
				}
				reviews, e := f.service.PlanProposalReviews(ctx, wafActor(f, "waf_reader"), p.ID)
				if e != nil || len(reviews) != 1 || reviews[0].Current {
					t.Fatalf("lost/still-current review %#v %v", reviews, e)
				}
				if out, e := f.service.SignPlanProposalReview(ctx, wafActor(f, "waf_approver"), p.ID, review.ID, "plan_delete_sign_0001"); e == nil || out != nil {
					t.Fatalf("deleted identity signed again %#v %v", out, e)
				}
				for _, table := range []string{"config_plan_proposals", "config_plan_proposal_reviews", "config_plan_proposal_signatures"} {
					if scalar(t, f, `SELECT COUNT(*) FROM `+table) != 1 {
						t.Fatalf("history disappeared: %s", table)
					}
				}
			})
		}
	})
	t.Run("scope_independence_digest_and_closed_fields", func(t *testing.T) {
		f, _, _, r := planFixture(t, pg)
		p := mustProposal(t, f, r)
		request := PlanProposalReviewRequest{p.ProposalDigest, "Review must use explicit global approve"}
		for _, actor := range []Actor{wafActor(f, "waf_author"), f.actor, wafActor(f, "waf_foreign"), wafActor(f, "waf_reader")} {
			if out, e := f.service.ReviewPlanProposal(ctx, actor, p.ID, "plan_forbidden_review01", request); e == nil || out != nil {
				t.Fatalf("forbidden review %#v %v", out, e)
			}
		}
		if out, e := f.service.GetPlanProposal(ctx, wafActor(f, "waf_foreign"), p.ID); e == nil || out != nil {
			t.Fatalf("site-only reader got full node %#v %v", out, e)
		}
		request.ProposalDigest = "sha256:" + strings.Repeat("0", 64)
		if out, e := f.service.ReviewPlanProposal(ctx, wafActor(f, "waf_approver"), p.ID, "plan_wrong_digest_0001", request); e == nil || out != nil {
			t.Fatalf("wrong digest %#v %v", out, e)
		}
		in := planRequest(r)
		in.TargetNodeIDs = []string{"node_other"}
		if out, e := f.service.CreatePlanProposal(ctx, wafActor(f, "waf_author"), "plan_foreign_target_01", in); e == nil || out != nil {
			t.Fatalf("foreign target %#v %v", out, e)
		}
		in = planRequest(r)
		in.RolloutPolicy.CanaryNodeIDs = []string{"node_other"}
		if _, e := f.service.CreatePlanProposal(ctx, wafActor(f, "waf_author"), "plan_bad_canary_00001", in); !errors.Is(e, ErrInvalidRequest) {
			t.Fatalf("canary: %v", e)
		}
	})
	t.Run("review_signing_distinct_domain_durable_and_optional", func(t *testing.T) {
		f, _, _, r := planFixture(t, pg)
		p := mustProposal(t, f, r)
		review := mustPlanReview(t, f, p)
		actor := wafActor(f, "waf_approver")
		if out, e := f.service.SignPlanProposalReview(ctx, actor, p.ID, review.ID, "plan_sign_request_0001"); !errors.Is(e, ErrUnavailable) || out != nil {
			t.Fatalf("missing signer %#v %v", out, e)
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		original := append(ed25519.PrivateKey(nil), key...)
		if e = f.service.WithPlanReviewSigningKey("plan_review_key", key); e != nil {
			t.Fatal(e)
		}
		key[0] ^= 1
		if e = f.service.WithPlanReviewSigningKey("other", original); !errors.Is(e, storage.ErrConflict) {
			t.Fatalf("signer replacement: %v", e)
		}
		envelope, e := f.service.SignPlanProposalReview(ctx, actor, p.ID, review.ID, "plan_sign_request_0001")
		if e != nil {
			t.Fatal(e)
		}
		message, e := planReviewMessage(*envelope)
		if e != nil {
			t.Fatal(e)
		}
		signature, e := base64.StdEncoding.DecodeString(envelope.SignatureBase64)
		if e != nil || !ed25519.Verify(pub, message, signature) {
			t.Fatal("signature does not verify")
		}
		if ed25519.Verify(pub, append([]byte("AGP-PLAN-v1\n"), message...), signature) || envelope.Deployable || !envelope.NoExecution {
			t.Fatal("review promoted to execution")
		}
		retry, e := f.service.SignPlanProposalReview(ctx, actor, p.ID, review.ID, "plan_sign_request_0001")
		if e != nil || retry.SignatureBase64 != envelope.SignatureBase64 {
			t.Fatalf("signed retry %#v %v", retry, e)
		}
		// A restarted service must use the configured server key, not stored bytes.
		fresh := New(f.service.current, f.service.origin, f.service.compiler).WithWAFQualifier(f.service.wafQualifier).WithTrustedInventory(f.service.trustedInventory)
		if e = fresh.WithPlanReviewSigningKey("plan_review_key", original); e != nil {
			t.Fatal(e)
		}
		retry, e = fresh.SignPlanProposalReview(ctx, actor, p.ID, review.ID, "plan_sign_request_0001")
		if e != nil || retry.SignatureBase64 != envelope.SignatureBase64 {
			t.Fatalf("restart %#v %v", retry, e)
		}
		changed := *envelope
		changed.Proposal.Reason = "tampered planning reason"
		message, _ = planReviewMessage(changed)
		if ed25519.Verify(pub, message, signature) {
			t.Fatal("full proposal not signed")
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_plan_proposal_signatures`) != 1 {
			t.Fatal("duplicate immutable signature")
		}
		for _, q := range []string{`UPDATE config_plan_proposal_signatures SET envelope_json='{}'`, `DELETE FROM config_plan_proposal_signatures`} {
			if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q); return e }); e == nil {
				t.Fatalf("mutable signature: %s", q)
			}
		}

	})
	t.Run("immutable_database_and_error_never_returns_artifact", func(t *testing.T) {
		f, _, _, r := planFixture(t, pg)
		p := mustProposal(t, f, r)
		review := mustPlanReview(t, f, p)
		for _, q := range []string{`UPDATE config_plan_proposals SET proposal_json='{}'`, `DELETE FROM config_plan_proposals`, `UPDATE config_plan_proposal_reviews SET review_json='{}'`, `DELETE FROM config_plan_proposal_reviews`} {
			if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q); return e }); e == nil {
				t.Fatalf("mutable: %s", q)
			}
		}
		underlying := f.service.current
		f.service.current = planClockCurrent{underlying: underlying, after: func() { f.authority.unavailable.Store(true) }}
		if out, e := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), p.ID); e == nil || out != nil {
			t.Fatalf("post-head read leak %#v %v", out, e)
		}
		f.authority.unavailable.Store(false)
		if out, e := f.service.ReviewPlanProposal(ctx, wafActor(f, "waf_approver"), p.ID, "plan_review_request_0001", PlanProposalReviewRequest{p.ProposalDigest, review.Reason}); e == nil || out != nil {
			t.Fatalf("post-head review leak %#v %v", out, e)
		}
		f.authority.unavailable.Store(false)
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		if e := f.service.WithPlanReviewSigningKey("plan_key", key); e != nil {
			t.Fatal(e)
		}
		if out, e := f.service.SignPlanProposalReview(ctx, wafActor(f, "waf_approver"), p.ID, review.ID, "plan_posthead_sign_001"); e == nil || out != nil {
			t.Fatalf("post-head signed output leak %#v %v", out, e)
		}
		f.authority.unavailable.Store(false)
		if scalar(t, f, `SELECT COUNT(*) FROM config_plan_proposal_signatures`) != 0 {
			t.Fatal("failed fenced signature committed")
		}
	})
	t.Run("every_retry_rechecks_full_inventory_and_qualifications", func(t *testing.T) {
		for _, kind := range []string{"inventory", "capabilities", "qualification", "compiler", "catalog", "author", "reviewer", "head", "expiry"} {
			t.Run(kind, func(t *testing.T) {
				f, q, source, r := planFixture(t, pg)
				p := mustProposal(t, f, r)
				review := mustPlanReview(t, f, p)
				switch kind {
				case "inventory":
					source.mu.Lock()
					source.source = "7"
					source.mu.Unlock()
				case "capabilities":
					f.service.WithTrustedInventory(planChangedCapabilities{source})
				case "qualification":
					q.revoked.Store(true)
				case "compiler":
					f.service.compiler.Version = "changed"
				case "catalog":
					catalog, e := f.service.ListCatalogs(ctx, f.actor)
					if e != nil {
						t.Fatal(e)
					}
					var d *configmodel.CatalogDocument
					e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
						var er error
						d, er = loadCatalog(ctx, tx, catalog[0].ID)
						return er
					})
					if e != nil {
						t.Fatal(e)
					}
					d.Catalog.ID = "new_catalog"
					if _, e = f.service.ImportCatalog(ctx, f.actor, "plan_new_catalog_0001", mustJSON(t, d.Catalog), configmodel.JSON); e != nil {
						t.Fatal(e)
					}
				case "author", "reviewer":
					id := "cgrant_plan_author_edit"
					if kind == "reviewer" {
						id = "cgrant_plan_approver_approve"
					}
					if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
						_, e := tx.Exec(ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id=?`, id)
						return e
					}); e != nil {
						t.Fatal(e)
					}
				case "head":
					if _, e := f.service.CreateRevision(ctx, f.actor, "plan_successor_000001", CreateRevision{BaseRevisionID: r.ID, Content: example(t)}); e != nil {
						t.Fatal(e)
					}
				case "expiry":
					f.service.current = planClockCurrent{underlying: f.service.current, offset: 31 * time.Minute}
					if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
						_, e := tx.Exec(ctx, `UPDATE sessions SET last_seen_at=?,mfa_at=?`, time.Now().Add(31*time.Minute), time.Now().Add(31*time.Minute))
						return e
					}); e != nil {
						t.Fatal(e)
					}
				}
				view, e := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), p.ID)
				if e != nil {
					t.Fatal(e)
				}
				if kind != "reviewer" && view.Current {
					t.Fatal("drift remained current")
				}
				if out, e := f.service.ReviewPlanProposal(ctx, wafActor(f, "waf_approver"), p.ID, "plan_review_request_0001", PlanProposalReviewRequest{p.ProposalDigest, review.Reason}); e == nil || out != nil {
					t.Fatalf("stale review replay %#v %v", out, e)
				}
				if kind != "reviewer" {
					if out, e := f.service.CreatePlanProposal(ctx, wafActor(f, "waf_author"), "plan_create_request_0001", planRequest(r)); e == nil || out != nil {
						t.Fatalf("stale create replay %#v %v", out, e)
					}
				}
			})
		}
	})
	t.Run("inventory_staleness_retains_history", func(t *testing.T) {
		f, _, _, revision := planFixture(t, pg)
		proposal := mustProposal(t, f, revision)
		review := mustPlanReview(t, f, proposal)
		for _, dependencyError := range []error{inventory.ErrNotFresh, inventory.ErrIdentity} {
			f.service.WithTrustedInventory(planInventoryFailure{dependencyError})
			view, err := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), proposal.ID)
			if err != nil || view == nil || view.Current || view.Proposal.ProposalDigest != proposal.ProposalDigest {
				t.Fatalf("stale inventory hid frozen proposal: %#v %v", view, err)
			}
			page, err := f.service.ListPlanProposals(ctx, wafActor(f, "waf_reader"), 20, "")
			if err != nil || page == nil || len(page.Items) != 1 || page.Items[0].Current {
				t.Fatalf("stale inventory broke historical list: %#v %v", page, err)
			}
			reviews, err := f.service.PlanProposalReviews(ctx, wafActor(f, "waf_reader"), proposal.ID)
			if err != nil || len(reviews) != 1 || reviews[0].ID != review.ID || reviews[0].Current {
				t.Fatalf("stale inventory hid historical review: %#v %v", reviews, err)
			}
			if replay, err := f.service.ReviewPlanProposal(ctx, wafActor(f, "waf_approver"), proposal.ID, "plan_review_request_0001", PlanProposalReviewRequest{proposal.ProposalDigest, review.Reason}); err == nil || replay != nil {
				t.Fatalf("stale review replay remained authorized: %#v %v", replay, err)
			}
		}
		f.service.WithTrustedInventory(planInventoryFailure{inventory.ErrUnavailable})
		if view, err := f.service.GetPlanProposal(ctx, wafActor(f, "waf_reader"), proposal.ID); !errors.Is(err, inventory.ErrUnavailable) || view != nil {
			t.Fatalf("dependency outage lost unavailable state: %#v %v", view, err)
		}
		if page, err := f.service.ListPlanProposals(ctx, wafActor(f, "waf_reader"), 20, ""); !errors.Is(err, inventory.ErrUnavailable) || page != nil {
			t.Fatalf("dependency outage became a historical page: %#v %v", page, err)
		}
		if reviews, err := f.service.PlanProposalReviews(ctx, wafActor(f, "waf_reader"), proposal.ID); !errors.Is(err, inventory.ErrUnavailable) || reviews != nil {
			t.Fatalf("dependency outage became historical reviews: %#v %v", reviews, err)
		}
	})
	t.Run("session_clock_source_and_floor_guards", func(t *testing.T) {
		for _, kind := range []string{"future_mfa", "future_seen", "stale_mfa", "source_revoked", "principal_floor", "password_floor", "zero_head"} {
			t.Run(kind, func(t *testing.T) {
				f, _, _, r := planFixture(t, pg)
				if kind == "zero_head" {
					f.service.current = planZeroHeadCurrent{underlying: f.service.current.(planClockCurrent).underlying}
				} else if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
					switch kind {
					case "future_mfa":
						_, e := tx.Exec(ctx, `UPDATE sessions SET mfa_at=? WHERE user_id='waf_author'`, time.Now().Add(time.Hour))
						return e
					case "future_seen":
						_, e := tx.Exec(ctx, `UPDATE sessions SET last_seen_at=? WHERE user_id='waf_author'`, time.Now().Add(time.Hour))
						return e
					case "stale_mfa":
						_, e := tx.Exec(ctx, `UPDATE sessions SET mfa_at=? WHERE user_id='waf_author'`, time.Now().Add(-6*time.Minute))
						return e
					case "source_revoked":
						now := time.Now().UTC()
						_, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,revoked_at) VALUES('plan_source','waf_author','plan_source_token','csrf','','',?,?,'management','https://management.test',1,1,?,?,?)`, now.Add(time.Hour), now, now, now, now)
						if e != nil {
							return e
						}
						_, e = tx.Exec(ctx, `UPDATE sessions SET source_session_id='plan_source' WHERE id='waf_author'`)
						return e
					default:
						authenticator := "principal_waf_author"
						if kind == "password_floor" {
							authenticator = "password_waf_author"
						}
						_, e := tx.Exec(ctx, `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES('waf_author',?,2)`, authenticator)
						return e
					}
				}); e != nil {
					t.Fatal(e)
				}
				if out, e := f.service.CreatePlanProposal(ctx, wafActor(f, "waf_author"), "plan_invalid_actor_001", planRequest(r)); e == nil || out != nil {
					t.Fatalf("guard %s %#v %v", kind, out, e)
				}
			})
		}
	})
}
