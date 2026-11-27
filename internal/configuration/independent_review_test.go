package configuration

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func TestConfigurationIndependentReviewSQLite(t *testing.T) { configurationIndependentReview(t, false) }
func TestConfigurationIndependentReviewPostgres(t *testing.T) {
	configurationIndependentReview(t, true)
}

func configurationIndependentReview(t *testing.T, pg bool) {
	t.Run("AD_provider_alias_cannot_approve_or_reuse_stored_approval", func(t *testing.T) {
		directoryWireDNS(t)
		ctx := context.Background()
		f := directoryWafFixtureNew(t, pg, "waf_author")
		configurationAliasReviewer(t, f)
		policy := createWaf(t, f.testFixture)
		validation := validateWaf(t, f.testFixture, policy)
		actor := wafActor(f.testFixture, "waf_approver")
		_, err := f.service.ApproveWafPolicyRevision(ctx, actor, policy.ID, "same_person_review_001", WafPolicyApprovalRequest{ContentDigest: policy.ContentDigest, Reason: "review requires an independent directory person"})
		if !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("provider alias counted as independent: %v", err)
		}
		if n := scalar(t, f.testFixture, `SELECT COUNT(*) FROM config_waf_policy_approvals`); n != 0 {
			t.Fatal("denied review created approval")
		}

		// Exact trusted pre-upgrade approval metadata, with current fingerprints
		// and real live LDAP observations for both aliases. Publication must
		// reject the human quorum even when every stored fingerprint is valid.
		ctx, err = f.service.directorySubjectContext(ctx, actor, true, directorySubjectSelection{Kind: "policy_write", ID: policy.ID})
		if err != nil {
			t.Fatal(err)
		}
		err = f.service.transactScoped(ctx, actor, true, func(tx storage.IdentityTx, p *Principal) error {
			report, err := loadWafPolicyValidation(ctx, tx, validation.ResourceID)
			if err != nil {
				return err
			}
			author, err := subjectFingerprint(ctx, tx, "waf_author", p.head)
			if err != nil {
				return err
			}
			reviewer, err := subjectFingerprint(ctx, tx, "waf_approver", p.head)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			_, err = tx.Exec(ctx, `INSERT INTO config_waf_policy_approvals(id,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) VALUES('wapproval_preupgrade_alias',?,?,?,?,?,?,1,?,?,?,?,?,?)`, policy.ID, validation.ResourceID, policy.ContentDigest, report.report.QualificationDigest, "waf_author", "waf_approver", author, reviewer, now, report.report.ExpiresAt, p.MFAAt, "trusted pre-upgrade identity alias fixture")
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.service.PublishWafPolicyRevision(context.Background(), actor, policy.ID, "same_person_publish01", WafPolicyPublicationRequest{ContentDigest: policy.ContentDigest}); !errors.Is(err, storage.ErrConflict) {
			t.Fatalf("stored same-person approval published: %v", err)
		}
		if n := scalar(t, f.testFixture, `SELECT COUNT(*) FROM config_waf_policy_publications`); n != 0 {
			t.Fatal("invalid human quorum published policy")
		}
		if f.wire.binds.Load() == 0 || f.wire.guid.Load() == 0 {
			t.Fatal("actual TLS LDAP proof was not exercised")
		}
	})
	t.Run("historical_read_failure_cannot_hide_behind_another_valid_approval", func(t *testing.T) {
		ctx := context.Background()
		f, _ := wafFixture(t, pg)
		policy := createWaf(t, f)
		validateWaf(t, f, policy)
		approval := approveWaf(t, f, policy)
		err := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO config_waf_policy_approvals(id,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) SELECT 'wapproval_second_current',policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,?,expires_at,mfa_at,reason FROM config_waf_policy_approvals WHERE id=?`, time.Now().UTC(), approval.ApprovalID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		failure := errors.New("injected historical projection failure")
		current := &configurationHistoricalFailure{underlying: f.service.current, failure: failure}
		f.service.current = current
		_, err = f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_approver"), policy.ID, "historical_error_0001", WafPolicyPublicationRequest{ContentDigest: policy.ContentDigest})
		if !errors.Is(err, failure) {
			t.Fatalf("source failure became stale/success: %v", err)
		}
		if current.reads.Load() < 2 || current.publications.Load() != 1 {
			t.Fatalf("fallback/rollback was not exercised: reads=%d attempted publications=%d", current.reads.Load(), current.publications.Load())
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_waf_policy_publications`); n != 0 {
			t.Fatal("failed historical source committed publication")
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM audit_events WHERE event_type='config.waf.policy.published'`); n != 0 {
			t.Fatal("failed historical source committed audit")
		}
		if n := scalar(t, f, `SELECT COUNT(*) FROM config_requests WHERE request_key='historical_error_0001'`); n != 0 {
			t.Fatal("failed source left replayable success")
		}
	})
}

func configurationAliasReviewer(t *testing.T, f *directoryWafFixture) {
	t.Helper()
	doc := f.document
	doc.Metadata.ID, doc.Metadata.VersionID, doc.Metadata.SecurityGuardID = "dir_waf_alias", "dirver_waf_alias_1", "guard_waf_alias"
	raw, err := configmodel.CanonicalJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := configmodel.Digest(doc)
	if err != nil {
		t.Fatal(err)
	}
	err = f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		ctx, now := context.Background(), time.Now().UTC()
		for _, query := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES(?,?,?,?,1,1,TRUE,?,?)`, []any{doc.Metadata.ID, "Synthetic alias provider", doc.Spec.ForestGUID, doc.Metadata.SecurityGuardID, doc.Metadata.VersionID, now}},
			{`INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,1,?,?,?,?,?)`, []any{doc.Metadata.VersionID, doc.Metadata.ID, digest, string(raw), "s1_admin", "trusted alias fixture", now}},
			{`UPDATE users SET identity_kind='directory',password_hash='' WHERE id='waf_approver'`, nil},
			{`INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,created_at) VALUES('diridentity_waf_alias','waf_approver',?,?,?,1,?)`, []any{doc.Metadata.ID, doc.Spec.ForestGUID, "20112233-4455-6677-8899-aabbccddeeff", now}},
			{`UPDATE sessions SET directory_identity_id='diridentity_waf_alias',directory_identity_version=1,directory_provider_version_id=?,directory_provider_guard_version=1 WHERE user_id='waf_approver'`, []any{doc.Metadata.VersionID}},
		} {
			if _, err := tx.Exec(ctx, query.sql, query.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type configurationHistoricalFailure struct {
	underlying   Current
	failure      error
	reads        atomic.Int64
	publications atomic.Int64
}

func (c *configurationHistoricalFailure) Head(ctx context.Context) (securityjournal.Head, error) {
	return c.underlying.Head(ctx)
}
func (c *configurationHistoricalFailure) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		return fn(configurationHistoricalFailureTx{IdentityTx: tx, owner: c}, h)
	})
}

type configurationHistoricalFailureTx struct {
	storage.IdentityTx
	owner *configurationHistoricalFailure
}

func (tx configurationHistoricalFailureTx) Query(ctx context.Context, q string, args ...any) (storage.IdentityRows, error) {
	if strings.HasPrefix(q, "SELECT is_admin,security_version,password_version FROM users") && len(args) == 1 && args[0] == "waf_author" {
		if tx.owner.reads.Add(1) == 1 {
			return nil, tx.owner.failure
		}
	}
	return tx.IdentityTx.Query(ctx, q, args...)
}
func (tx configurationHistoricalFailureTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	n, err := tx.IdentityTx.Exec(ctx, q, args...)
	if err == nil && strings.Contains(q, "INSERT INTO config_waf_policy_publications") {
		tx.owner.publications.Add(1)
	}
	return n, err
}
