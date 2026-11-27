package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type testWafQualifier struct {
	revoked    atomic.Bool
	calls      atomic.Int64
	badDigest  bool
	onValidate func()
}

type wafAuditFailCurrent struct {
	underlying Current
	event      string
}
type wafAuditFailTx struct {
	storage.IdentityTx
	event string
}

func (t wafAuditFailTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	if strings.Contains(q, "INSERT INTO audit_events") && len(args) > 0 && args[0] == t.event {
		return 0, errors.New("injected WAF audit failure")
	}
	return t.IdentityTx.Exec(ctx, q, args...)
}
func (c wafAuditFailCurrent) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return fn(wafAuditFailTx{tx, c.event}, h) })
}

func (c wafAuditFailCurrent) Head(ctx context.Context) (securityjournal.Head, error) {
	return c.underlying.Head(ctx)
}

func (q *testWafQualifier) ValidatePolicy(ctx context.Context, p configmodel.WafPolicy) (*WAFQualification, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q.calls.Add(1)
	if q.onValidate != nil {
		q.onValidate()
	}
	d, _ := configmodel.Digest(p)
	if q.badDigest {
		d = "sha256:" + strings.Repeat("0", 64)
	}
	return &WAFQualification{ID: securitystate.ID("qualification"), ContentDigest: d, RulesetVersionID: p.Spec.RulesetVersionID, RulesetDigest: "sha256:" + strings.Repeat("1", 64), ManifestDigest: "sha256:" + strings.Repeat("6", 64), ReleaseSequence: "1", ProfileID: "native_profile", ProfileDigest: "sha256:" + strings.Repeat("2", 64), TupleDigest: "sha256:" + strings.Repeat("3", 64), EvidenceDigest: "sha256:" + strings.Repeat("4", 64), CompilerDigest: "sha256:" + strings.Repeat("5", 64), ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
}
func (q *testWafQualifier) Current(ctx context.Context, proof *WAFQualification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if q.revoked.Load() || !time.Now().Before(proof.ExpiresAt) {
		return storage.ErrConflict
	}
	return nil
}
func wafFixture(t *testing.T, pg bool) (*testFixture, *testWafQualifier) {
	t.Helper()
	f := fixtureConfigured(t, pg, func(tx storage.IdentityTx) error {
		ctx, now := context.Background(), time.Now().UTC()
		for _, id := range []string{"waf_author", "waf_approver", "waf_foreign", "waf_approveonly"} {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,FALSE)`, id, id, "hash"); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management','https://management.test',1,1,?,?)`, id, id, id+"_token", "csrf", "", "", now.Add(time.Hour), now, now, now); e != nil {
				return e
			}
		}
		for _, grant := range []struct{ id, user, permission, site string }{
			{"author_edit", "waf_author", "config.edit", "site_msk"},
			{"author_approve", "waf_author", "config.approve", "site_msk"},
			{"approver_read", "waf_approver", "config.read", "site_msk"},
			{"approver_approve", "waf_approver", "config.approve", "site_msk"},
			{"foreign_edit", "waf_foreign", "config.edit", "site_other"},
			{"foreign_approve", "waf_foreign", "config.approve", "site_other"},
			{"approveonly_approve", "waf_approveonly", "config.approve", "site_msk"},
		} {
			if _, e := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES(?,?,?,'site',?,1,?)`, "cgrant_"+grant.id, grant.user, grant.permission, grant.site, now); e != nil {
				return e
			}
		}
		return nil
	})
	q := &testWafQualifier{}
	f.service.wafQualifier = q
	return f, q
}
func wafActor(f *testFixture, id string) Actor {
	return Actor{TokenHash: id + "_token", Origin: f.actor.Origin}
}
func baseWafPolicy(t *testing.T) json.RawMessage {
	t.Helper()
	raw, e := os.ReadFile("../../docs/v2/examples/waf-policy.json")
	if e != nil {
		t.Fatal(e)
	}
	var p configmodel.WafPolicy
	if e = json.Unmarshal(raw, &p); e != nil {
		t.Fatal(e)
	}
	p.Spec.Exceptions = []configmodel.WafException{}
	return mustJSON(t, p)
}
func createWaf(t *testing.T, f *testFixture) *WafPolicyRevision {
	t.Helper()
	r, e := f.service.CreateWafPolicyRevision(context.Background(), wafActor(f, "waf_author"), "waf_create_00000001", WafPolicyCreate{Content: baseWafPolicy(t)})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func validateWaf(t *testing.T, f *testFixture, r *WafPolicyRevision) *AcceptedOperation {
	t.Helper()
	op, e := f.service.ValidateWafPolicyRevision(context.Background(), wafActor(f, "waf_author"), r.ID, "waf_validate_000001")
	if e != nil {
		t.Fatal(e)
	}
	return op
}
func approveWaf(t *testing.T, f *testFixture, r *WafPolicyRevision) *WafPolicyApproval {
	t.Helper()
	v, e := f.service.ApproveWafPolicyRevision(context.Background(), wafActor(f, "waf_approver"), r.ID, "waf_approve_0000001", WafPolicyApprovalRequest{ContentDigest: r.ContentDigest, Reason: "Проверены native qualification и digest"})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestWafPoliciesSQLite(t *testing.T)   { testWafPolicies(t, false) }
func TestWafPoliciesPostgres(t *testing.T) { testWafPolicies(t, true) }
func testWafPolicies(t *testing.T, pg bool) {
	ctx := context.Background()
	t.Run("approval_and_publication_require_current_read", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		r := createWaf(t, f)
		validateWaf(t, f, r)
		approvalRequest := WafPolicyApprovalRequest{r.ContentDigest, "Проверены native qualification и digest"}
		if _, e := f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_approveonly"), r.ID, "waf_approveonly_01", approvalRequest); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("approve-only grant approved unreadable content: %v", e)
		}
		approval := approveWaf(t, f, r)
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approveonly"), r.ID, "waf_publishonly_01", WafPolicyPublicationRequest{r.ContentDigest}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("approve-only grant published unreadable content: %v", e)
		}
		// The author has current edit/read and explicit approve. Publish through
		// that independent actor so the retry below exercises the historical
		// approver's read grant, rather than only the caller's admission check.
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_readrevoke_pub1", WafPolicyPublicationRequest{r.ContentDigest}); e != nil {
			t.Fatal(e)
		}
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id='cgrant_approver_read'`)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_approve_0000001", approvalRequest); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("approval retry survived own read revocation: %v", e)
		}
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_readrevoke_pub2", WafPolicyPublicationRequest{r.ContentDigest}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("publication survived own read revocation: %v", e)
		}
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_readrevoke_pub1", WafPolicyPublicationRequest{r.ContentDigest}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("publication retry survived historical approver read revocation: %v", e)
		}
		if e := f.service.transactScoped(ctx, wafActor(f, "waf_author"), false, func(tx storage.IdentityTx, p *Principal) error {
			record, e := readWafPolicyRecord(ctx, tx, r.ID)
			if e != nil {
				return e
			}
			if _, e = f.service.currentWafApproval(ctx, tx, p, record, approval.ApprovalID); !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatalf("historical approval survived approver read revocation: %v", e)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("concurrent_successors_require_exact_head", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		r := createWaf(t, f)
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, key := range []string{"waf_cas_writer_001", "waf_cas_writer_002"} {
			wg.Add(1)
			go func(key string) {
				defer wg.Done()
				_, e := f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), key, WafPolicyCreate{BaseRevisionID: r.ID, Content: r.Content})
				results <- e
			}(key)
		}
		wg.Wait()
		close(results)
		success, conflict := 0, 0
		for e := range results {
			if e == nil {
				success++
			} else if errors.Is(e, ErrRevisionMismatch) {
				conflict++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || conflict != 1 || scalar(t, f, `SELECT COUNT(*) FROM config_waf_policy_revisions`) != 2 {
			t.Fatalf("lost update success=%d conflict=%d", success, conflict)
		}
	})
	t.Run("qualified_independent_approval_and_publication", func(t *testing.T) {
		f, q := wafFixture(t, pg)
		r := createWaf(t, f)
		if r.State != "draft" || r.Revision != "1" {
			t.Fatalf("initial state %#v", r)
		}
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_unapproved_0001", WafPolicyPublicationRequest{r.ContentDigest}); e == nil {
			t.Fatal("unapproved publication allowed")
		}
		op := validateWaf(t, f, r)
		if op.StatusURL != "/api/v2/operations/"+op.OperationID {
			t.Fatalf("bad operation %#v", op)
		}
		operation, e := f.service.GetWafPolicyOperation(ctx, wafActor(f, "waf_approver"), op.OperationID)
		if e != nil || operation.ResourceID != op.ResourceID || operation.State != "succeeded" {
			t.Fatalf("operation %#v %v", operation, e)
		}
		report, e := f.service.GetWafPolicyValidation(ctx, wafActor(f, "waf_approver"), op.ResourceID)
		if e != nil || !report.Valid || !report.Current || report.Deployable || report.QualificationDigest == "" {
			t.Fatalf("report %#v %v", report, e)
		}
		again, e := f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_validate_000001")
		if e != nil || again.OperationID != op.OperationID || q.calls.Load() != 1 {
			t.Fatalf("validation retry %#v %v calls=%d", again, e, q.calls.Load())
		}
		state, e := f.service.GetWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID)
		if e != nil || state.State != "validated" {
			t.Fatalf("validated state %#v %v", state, e)
		}
		request := WafPolicyApprovalRequest{r.ContentDigest, "Проверены native qualification и digest"}
		if _, e = f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_selfapprove_001", request); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("self approval %v", e)
		}
		if _, e = f.service.ApproveWafPolicyRevision(ctx, f.actor, r.ID, "waf_adminapprove_01", request); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("implicit admin approval %v", e)
		}
		approval := approveWaf(t, f, r)
		retry, e := f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_approve_0000001", request)
		if e != nil || retry.ApprovalID != approval.ApprovalID {
			t.Fatalf("approval retry %#v %v", retry, e)
		}
		if _, e = f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_approve_0000001", WafPolicyApprovalRequest{r.ContentDigest, "Другой reason with same request key"}); !errors.Is(e, ErrIdempotencyConflict) {
			t.Fatalf("approval fingerprint %v", e)
		}
		state, e = f.service.GetWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID)
		if e != nil || state.State != "approved" {
			t.Fatalf("approved state %#v %v", state, e)
		}
		published, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_publish_0000001", WafPolicyPublicationRequest{r.ContentDigest})
		if e != nil || published.State != "published" || string(published.Content) != string(r.Content) {
			t.Fatalf("publication %#v %v", published, e)
		}
		published, e = f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_publish_0000001", WafPolicyPublicationRequest{r.ContentDigest})
		if e != nil || published.State != "published" {
			t.Fatalf("publication retry %#v %v", published, e)
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_waf_policy_publications`) != 1 || scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 0 {
			t.Fatal("publication changed configuration or duplicated fact")
		}
		q.revoked.Store(true)
		if _, e = f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_publish_0000001", WafPolicyPublicationRequest{r.ContentDigest}); e == nil {
			t.Fatal("publication replay bypassed revoked native proof")
		}
		for _, table := range []string{"config_waf_policy_revisions", "config_waf_policy_validations", "config_waf_policy_operations", "config_waf_policy_approvals", "config_waf_policy_publications"} {
			if e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, `DELETE FROM `+table); return e }); e == nil {
				t.Fatalf("immutable %s allowed delete", table)
			}
		}
	})
	t.Run("scope_CAS_unsupported_and_unqualified", func(t *testing.T) {
		f, q := wafFixture(t, pg)
		r := createWaf(t, f)
		for _, read := range []func() error{
			func() error { _, e := f.service.GetWafPolicyRevision(ctx, wafActor(f, "waf_foreign"), r.ID); return e },
			func() error {
				_, e := f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_foreign"), r.ID, "waf_foreignval_001")
				return e
			},
		} {
			if e := read(); !errors.Is(e, storage.ErrNotFound) {
				t.Fatalf("foreign access %v", e)
			}
		}
		if _, e := f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), "waf_bad_derivation", WafPolicyCreate{Content: baseWafPolicy(t), Derivation: &WafPolicyDerivation{GatewayID: "gw_portal"}}); e == nil {
			t.Fatal("unimplemented derivation accepted")
		}
		raw, e := os.ReadFile("../../docs/v2/examples/waf-policy.json")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), "waf_bad_exceptions", WafPolicyCreate{Content: raw}); e == nil {
			t.Fatal("unsupported exceptions discarded")
		}
		if _, e = f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), "waf_stale_create01", WafPolicyCreate{Content: r.Content}); !errors.Is(e, ErrRevisionMismatch) {
			t.Fatalf("stale CAS %v", e)
		}
		f.service.wafQualifier = nil
		if _, e = f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_nil_qualifier1"); e == nil {
			t.Fatal("nil qualifier accepted")
		}
		f.service.wafQualifier = q
		q.badDigest = true
		if _, e = f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_bad_proofdige1"); e == nil {
			t.Fatal("wrong proof content digest accepted")
		}
		q.badDigest = false
		op := validateWaf(t, f, r)
		if _, e = f.service.GetWafPolicyValidation(ctx, wafActor(f, "waf_foreign"), op.ResourceID); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("foreign report %v", e)
		}
		if _, e = f.service.GetWafPolicyOperation(ctx, wafActor(f, "waf_foreign"), op.OperationID); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("foreign operation %v", e)
		}
		approveWaf(t, f, r)
		var body configmodel.WafPolicy
		json.Unmarshal(r.Content, &body)
		body.Metadata.Name = "Next body"
		next, e := f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), "waf_next_revision1", WafPolicyCreate{BaseRevisionID: r.ID, Content: mustJSON(t, body)})
		if e != nil || next.Revision != "2" {
			t.Fatalf("successor %#v %v", next, e)
		}
		if _, e = f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_stale_publish1", WafPolicyPublicationRequest{r.ContentDigest}); !errors.Is(e, ErrRevisionMismatch) {
			t.Fatalf("old head published %v", e)
		}
		report, e := f.service.GetWafPolicyValidation(ctx, wafActor(f, "waf_approver"), op.ResourceID)
		if e != nil || report.Current {
			t.Fatalf("stale report %#v %v", report, e)
		}
	})
	t.Run("revocations_invalidate_approval_and_retries", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		r := createWaf(t, f)
		validateWaf(t, f, r)
		approveWaf(t, f, r)
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			return securitystate.MaterializeEvent(ctx, tx, securityjournal.Event{Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", Payload: securityjournal.Payload{GrantID: "cgrant_author_edit"}}, RecordedAt: time.Now()})
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_revoke_publish1", WafPolicyPublicationRequest{r.ContentDigest}); e == nil {
			t.Fatal("revoked author still publishable")
		}
		if _, e := f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_approve_0000001", WafPolicyApprovalRequest{r.ContentDigest, "Проверены native qualification и digest"}); e == nil {
			t.Fatal("approval retry bypassed author revoke")
		}
	})
	t.Run("approver_revoke_and_fresh_MFA", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		r := createWaf(t, f)
		validateWaf(t, f, r)
		approveWaf(t, f, r)
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id='cgrant_approver_approve'`)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_revokedapp_001", WafPolicyPublicationRequest{r.ContentDigest}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("revoked approver %v", e)
		}
		if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(ctx, `UPDATE sessions SET mfa_at=? WHERE user_id='waf_author'`, time.Now().Add(-6*time.Minute))
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_stale_mfa_0001"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("stale MFA %v", e)
		}
	})
	t.Run("native_work_rechecks_author_rights_before_commit", func(t *testing.T) {
		f, q := wafFixture(t, pg)
		r := createWaf(t, f)
		q.onValidate = func() {
			if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				_, e := tx.Exec(ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id='cgrant_author_edit'`)
				return e
			}); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_mid_revoke_001"); e == nil {
			t.Fatal("revocation during native compilation ignored")
		}
		if scalar(t, f, `SELECT COUNT(*) FROM config_waf_policy_validations`) != 0 {
			t.Fatal("invalid validation persisted")
		}
	})
	t.Run("epoch_and_expiry_bound_facts", func(t *testing.T) {
		f, _ := wafFixture(t, pg)
		r := createWaf(t, f)
		op := validateWaf(t, f, r)
		approval := approveWaf(t, f, r)
		if e := f.service.transactScoped(ctx, wafActor(f, "waf_approver"), false, func(tx storage.IdentityTx, p *Principal) error {
			record, e := readWafPolicyRecord(ctx, tx, r.ID)
			if e != nil {
				return e
			}
			v, e := loadWafPolicyValidation(ctx, tx, op.ResourceID)
			if e != nil {
				return e
			}
			otherEpoch := *p
			otherEpoch.Epoch++
			if e = f.service.wafValidationCurrent(ctx, tx, &otherEpoch, record, v); e == nil {
				t.Fatal("validation survived changed verified epoch")
			}
			if _, e = f.service.currentWafApproval(ctx, tx, &otherEpoch, record, approval.ApprovalID); e == nil {
				t.Fatal("approval survived changed verified epoch")
			}
			v.report.ExpiresAt = time.Now().Add(-time.Minute)
			if e = f.service.wafValidationCurrent(ctx, tx, p, record, v); e == nil {
				t.Fatal("expired validation accepted")
			}
			var expires, created time.Time
			e = securitystate.One(ctx, tx, `SELECT created_at,expires_at FROM config_waf_policy_approvals WHERE id=?`, []any{approval.ApprovalID}, func(rows storage.IdentityRows) error { return rows.Scan(&created, &expires) })
			if e != nil {
				return e
			}
			if expires.Sub(created) > 30*time.Minute {
				t.Fatal("approval TTL exceeds 30 minutes")
			}
			pastCreated := time.Now().Add(-32 * time.Minute).UTC().Truncate(time.Microsecond)
			_, e = tx.Exec(ctx, `INSERT INTO config_waf_policy_approvals(id,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) SELECT 'expired_approval',policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,?,?,?,'Expired regression artifact' FROM config_waf_policy_approvals WHERE id=?`, pastCreated, pastCreated.Add(30*time.Minute), pastCreated, approval.ApprovalID)
			if e != nil {
				return e
			}
			if _, e = f.service.currentWafApproval(ctx, tx, p, record, "expired_approval"); e == nil {
				t.Fatal("expired approval accepted")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("audit_failure_rolls_back_facts_and_idempotency", func(t *testing.T) {
		for _, stage := range []string{"create", "validate", "approve", "publish"} {
			t.Run(stage, func(t *testing.T) {
				f, _ := wafFixture(t, pg)
				var r *WafPolicyRevision
				if stage != "create" {
					r = createWaf(t, f)
				}
				if stage == "approve" || stage == "publish" {
					validateWaf(t, f, r)
				}
				if stage == "publish" {
					approveWaf(t, f, r)
				}
				beforeRequests := scalar(t, f, `SELECT COUNT(*) FROM config_requests`)
				event := map[string]string{"create": "config.waf.policy.revision.created", "validate": "config.waf.policy.validation.completed", "approve": "config.waf.policy.approved", "publish": "config.waf.policy.published"}[stage]
				f.service.current = wafAuditFailCurrent{f.service.current, event}
				var e error
				switch stage {
				case "create":
					_, e = f.service.CreateWafPolicyRevision(ctx, wafActor(f, "waf_author"), "waf_audit_create01", WafPolicyCreate{Content: baseWafPolicy(t)})
				case "validate":
					_, e = f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "waf_audit_valid001")
				case "approve":
					_, e = f.service.ApproveWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_audit_approve1", WafPolicyApprovalRequest{r.ContentDigest, "Независимая проверка qualification"})
				case "publish":
					_, e = f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), r.ID, "waf_audit_publish1", WafPolicyPublicationRequest{r.ContentDigest})
				}
				if e == nil {
					t.Fatal("audit failure ignored")
				}
				if scalar(t, f, `SELECT COUNT(*) FROM config_requests`) != beforeRequests {
					t.Fatal("idempotency handle survived rollback")
				}
				table := map[string]string{"create": "config_waf_policy_revisions", "validate": "config_waf_policy_validations", "approve": "config_waf_policy_approvals", "publish": "config_waf_policy_publications"}[stage]
				if scalar(t, f, `SELECT COUNT(*) FROM `+table) != 0 {
					t.Fatal("fact survived failed atomic audit")
				}
			})
		}
	})
}
