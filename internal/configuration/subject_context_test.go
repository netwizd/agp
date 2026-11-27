package configuration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type historicalResolverFunc func(context.Context, []string, func(context.Context) error) error

func (f historicalResolverFunc) WithCurrentHistoricalSubjects(ctx context.Context, ids []string, fn func(context.Context) error) error {
	return f(ctx, ids, fn)
}

func TestConfigurationHistoricalBoundarySQLite(t *testing.T) {
	testConfigurationHistoricalBoundary(t, false)
}
func TestConfigurationHistoricalBoundaryPostgres(t *testing.T) {
	testConfigurationHistoricalBoundary(t, true)
}
func testConfigurationHistoricalBoundary(t *testing.T, pg bool) {
	ctx := context.Background()
	t.Run("unavailable_is_not_stale_and_partial_writes_roll_back", func(t *testing.T) {
		f := fixture(t, pg)
		calls := 0
		err := f.service.transactScoped(ctx, f.actor, true, func(tx storage.IdentityTx, p *Principal) error {
			calls++
			if err := securitystate.Audit(ctx, tx, "subject.proof.test", p.ID, map[string]any{}); err != nil {
				return err
			}
			// Match lifecycle code that ignores a failed candidate or marks it stale.
			_ = subjectFailure(tx, identity.ErrDirectoryUnavailable)
			return nil
		})
		if !errors.Is(err, identity.ErrDirectoryUnavailable) || calls != 1 {
			t.Fatalf("error=%v callbacks=%d", err, calls)
		}
		if n := scalar(t, f, "SELECT COUNT(*) FROM audit_events WHERE event_type=?", "subject.proof.test"); n != 0 {
			t.Fatalf("partial audit committed: %d", n)
		}
	})
	t.Run("network_resolver_outside_writer_and_original_command_once", func(t *testing.T) {
		f, q := wafFixture(t, pg)
		r := createWaf(t, f)
		calls := 0
		f.service.WithDirectorySubjects(historicalResolverFunc(func(ctx context.Context, ids []string, fn func(context.Context) error) error {
			calls++
			if len(ids) != 1 || ids[0] != "waf_author" {
				t.Fatalf("wrong participants: %v", ids)
			}
			// A separate writer succeeds here: no fenced command TX spans live reads.
			bounded, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			if err := f.store.WriteIdentity(bounded, func(tx storage.IdentityTx) error {
				return securitystate.Audit(bounded, tx, "subject.resolver.test", "waf_author", map[string]any{})
			}); err != nil {
				return err
			}
			return fn(ctx)
		}))
		if _, err := f.service.ValidateWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "historical_validate_once_001"); err != nil {
			t.Fatal(err)
		}
		if calls != 2 || q.calls.Load() != 1 {
			t.Fatalf("pre/final refresh=%d native commands=%d", calls, q.calls.Load())
		}
		if n := scalar(t, f, "SELECT COUNT(*) FROM config_waf_policy_validations WHERE policy_revision_id=?", r.ID); n != 1 {
			t.Fatal("command repeated", n)
		}
	})
	t.Run("selection_has_no_positive_authority_after_final_change", func(t *testing.T) {
		f, q := wafFixture(t, pg)
		r := createWaf(t, f)
		f.service.WithDirectorySubjects(historicalResolverFunc(func(ctx context.Context, _ []string, fn func(context.Context) error) error {
			if err := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				_, err := tx.Exec(ctx, `UPDATE users SET identity_kind='directory' WHERE id='waf_author'`)
				return err
			}); err != nil {
				return err
			}
			return fn(ctx)
		}))
		// A different local editor holds config.edit, but the historical author no
		// longer has a valid typed link. A captured selection cannot authorize it.
		if _, err := f.service.ValidateWafPolicyRevision(ctx, f.actor, r.ID, "historical_changed_author_01"); err == nil {
			t.Fatal("changed typed author accepted")
		}
		if q.calls.Load() != 0 || scalar(t, f, "SELECT COUNT(*) FROM config_waf_policy_validations WHERE policy_revision_id=?", r.ID) != 0 {
			t.Fatal("invalid author reached compiler or committed")
		}
	})
	for _, change := range []string{"missing_directory_link", "principal_floor", "password_floor"} {
		t.Run("local_publisher_cannot_reuse_"+change, func(t *testing.T) {
			f, _ := wafFixture(t, pg)
			r := createWaf(t, f)
			validateWaf(t, f, r)
			approveWaf(t, f, r)
			if err := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				if change == "missing_directory_link" {
					_, err := tx.Exec(ctx, `UPDATE users SET identity_kind='directory' WHERE id='waf_approver'`)
					return err
				}
				prefix := "principal_"
				if change == "password_floor" {
					prefix = "password_"
				}
				_, err := tx.Exec(ctx, `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES('waf_approver',?,2)`, prefix+"waf_approver")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.PublishWafPolicyRevision(ctx, wafActor(f, "waf_author"), r.ID, "historical_deny_publish_001", WafPolicyPublicationRequest{r.ContentDigest}); err == nil {
				t.Fatal("invalid historical reviewer authorized publication")
			}
			if n := scalar(t, f, "SELECT COUNT(*) FROM config_waf_policy_publications WHERE policy_revision_id=?", r.ID); n != 0 {
				t.Fatal("publication committed", n)
			}
		})
	}
}
