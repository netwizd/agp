package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type directoryJournalClock struct {
	securityjournal.Authority
	now *time.Time
}

func (j directoryJournalClock) Head(ctx context.Context) (securityjournal.Head, error) {
	h, e := j.Authority.Head(ctx)
	h.RecordedAt = *j.now
	return h, e
}

type directoryValidatorTest struct {
	calls       atomic.Int64
	unavailable atomic.Bool
	wrongForest atomic.Bool
	partial     atomic.Bool
}

func (v *directoryValidatorTest) Validate(ctx context.Context, d DirectoryProviderDocument) (DirectoryValidation, error) {
	v.calls.Add(1)
	if v.unavailable.Load() {
		return DirectoryValidation{}, errors.New("LDAP diagnostic containing synthetic-password must never escape")
	}
	out := DirectoryValidation{ForestGUID: d.Spec.ForestGUID}
	for _, name := range directoryChecks {
		out.Checks = append(out.Checks, DirectoryTestCheck{Name: name, State: "passed", ReasonCode: "verified"})
	}
	if v.wrongForest.Load() {
		out.ForestGUID = "00000000-0000-0000-0000-000000000099"
	}
	if v.partial.Load() {
		out.Checks = out.Checks[:4]
	}
	return out, nil
}

type directoryFixture struct {
	*fixture
	directory        *DirectoryService
	validator        *directoryValidatorTest
	author, reviewer DirectoryActor
	provider         *DirectoryProviderView
	document         DirectoryProviderDocument
}

func newDirectoryFixture(t *testing.T, pg bool) *directoryFixture {
	t.Helper()
	f := newFixture(t, pg)
	f.s.Coordinator.Authority = directoryJournalClock{f.j, &f.now}
	validator := &directoryValidatorTest{}
	d := NewDirectoryService(f.s.Coordinator, f.s.Profile.ManagementOrigin, validator)
	out := &directoryFixture{fixture: f, directory: d, validator: validator}
	for i, u := range []domain.User{f.user, f.other} {
		token, hash, _ := auth.NewToken()
		a := DirectoryActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin}
		if i == 0 {
			out.author = a
		} else {
			out.reviewer = a
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return InsertSession(f.ctx, tx, domain.Session{ID: securitystate.ID("session"), UserID: u.ID, TokenHash: hash, CSRFHash: auth.TokenHash(token), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), Audience: "management", AudienceOrigin: a.Origin, AuthorityEpoch: 1, SecurityVersion: 1, MFAAt: &f.now, LastSeenAt: &f.now})
		}); e != nil {
			t.Fatal(e)
		}
	}
	p, e := d.CreateProvider(f.ctx, out.author, DirectoryCreate{Name: "Corporate directory", ForestGUID: "00000000-0000-0000-0000-000000000001"})
	if e != nil {
		t.Fatal(e)
	}
	out.provider = p
	out.document = DirectoryProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "DirectoryProvider", Metadata: DirectoryMetadata{ID: p.ID, VersionID: securitystate.ID("dirver"), SecurityGuardID: p.SecurityGuardID, SecurityGuardVersion: 1}, Spec: DirectorySpec{ForestGUID: p.ForestGUID, DomainDNS: "corp.example.net", Transport: "ldaps", Endpoints: []DirectoryEndpoint{{Host: "dc01.corp.example.net", Port: 636}}, UserBaseDNs: []string{"OU=People,DC=corp,DC=example,DC=net"}, GroupBaseDNs: []string{"OU=Groups,DC=corp,DC=example,DC=net"}, BindDN: "CN=reader,DC=corp,DC=example,DC=net", BindSecretVersionID: "sec_bind_1", CASecretVersionID: "sec_ca_1", LoginAttribute: "userPrincipalName", Provisioning: "preprovisioned", GroupResolution: "token_groups_security", AccountCheck: "live_each_allow", OperationTimeoutSeconds: 1, MaximumGroups: 2048, GroupMappings: []DirectoryGroupMapping{{GroupObjectGUID: "00000000-0000-0000-0000-000000000002", AccessGroupID: f.group.ID}}}}
	return out
}
func (f *directoryFixture) propose(t *testing.T) {
	t.Helper()
	_, e := f.directory.ProposeVersion(f.ctx, f.author, f.provider.ID, f.provider.Revision, f.document)
	if e != nil {
		t.Fatal(e)
	}
	f.provider.Revision++
}
func (f *directoryFixture) test(t *testing.T) {
	t.Helper()
	r, e := f.directory.TestProvider(f.ctx, f.author, f.provider.ID, f.document.Metadata.VersionID)
	if e != nil || r.State != "passed" {
		t.Fatalf("test: %#v %v", r, e)
	}
}
func (f *directoryFixture) plan(t *testing.T, enabled bool) *ProviderSecurityOperation {
	t.Helper()
	r, e := f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, securitystate.ID("request"), DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: enabled, Reason: "Use the reviewed corporate directory configuration"})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func (f *directoryFixture) approve(t *testing.T, o *ProviderSecurityOperation) {
	t.Helper()
	_, e := f.directory.ApproveOperation(f.ctx, f.reviewer, o.ID, o.RequestDigest, "Reviewed immutable provider config and target digest")
	if e != nil {
		t.Fatal(e)
	}
}
func TestDirectoryProvidersSQLite(t *testing.T)   { testDirectoryProviders(t, false) }
func TestDirectoryProvidersPostgres(t *testing.T) { testDirectoryProviders(t, true) }
func testDirectoryProviders(t *testing.T, pg bool) {
	t.Run("immutable_versions_independent_activation_and_restore_floor", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		if f.provider.Enabled || f.provider.Configuration != nil {
			t.Fatal("registration enabled provider")
		}
		f.propose(t)
		if p, e := f.directory.GetProvider(f.ctx, f.author, f.provider.ID); e != nil || p.Configuration != nil || p.Enabled {
			t.Fatalf("proposal activated: %#v %v", p, e)
		}
		if _, e := f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, "request_without_test_001", DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: true, Reason: "No caller claim can validate AD"}); !errors.Is(e, ErrDirectoryUnavailable) {
			t.Fatalf("untested enable: %v", e)
		}
		f.test(t)
		o := f.plan(t, true)
		if _, e := f.directory.ApproveOperation(f.ctx, f.author, o.ID, o.RequestDigest, "self approval prohibited"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("self approval: %v", e)
		}
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatalf("unreviewed execute: %v", e)
		}
		f.approve(t, o)
		r, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest)
		if e != nil || r.State != "applied" {
			t.Fatalf("execute %#v %v", r, e)
		}
		if f.validator.calls.Load() != 2 {
			t.Fatal("execution did not retest real connector")
		}
		if _, e = f.directory.CurrentProvider(f.ctx, f.provider.ID); e != nil {
			t.Fatal(e)
		}
		if _, e = f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e != nil {
			t.Fatal("exact applied retry", e)
		}
		if len(f.j.events) != 1 || f.j.events[0].Request.Payload.AuthenticatorID != f.provider.SecurityGuardID {
			t.Fatal("missing independent provider floor")
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE directory_providers SET guard_version=0 WHERE id=?`, f.provider.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.directory.CurrentProvider(f.ctx, f.provider.ID); e == nil {
			t.Fatal("restored provider below durable floor accepted")
		}
	})

	t.Run("version_author_cannot_approve_another_operators_activation", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		o, e := f.directory.PlanActivation(f.ctx, f.reviewer, f.provider.ID, "request_cross_author_001", DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: true, Reason: "Operator B requests config authored by A"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.directory.ApproveOperation(f.ctx, f.author, o.ID, o.RequestDigest, "Author A must not approve own config"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("version author approved: %v", e)
		}
		if len(f.j.events) != 0 {
			t.Fatal("rejected approval reached journal")
		}
	})
	t.Run("recovery_rechecks_reviewer_and_keeps_provider_closed", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		o := f.plan(t, true)
		f.approve(t, o)
		f.j.failAppend = true
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e == nil {
			t.Fatal("expected interrupted floor")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `DELETE FROM user_groups WHERE user_id=?`, f.other.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		f.j.failAppend = false
		RegisterDirectoryRecovery(f.s.Coordinator)
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal(e)
		}
		r, e := f.directory.GetOperation(f.ctx, f.author, o.ID)
		if e != nil || r.State != "recovery_required" {
			t.Fatalf("recovery status %#v %v", r, e)
		}
		if _, e = f.directory.CurrentProvider(f.ctx, f.provider.ID); e == nil {
			t.Fatal("recovery resurrected provider after reviewer lost rights")
		}
		if len(f.j.events) != 1 {
			t.Fatal("required restrictive floor absent")
		}
	})

	t.Run("recovery_expiry_uses_independent_journal_time", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		o := f.plan(t, true)
		f.approve(t, o)
		f.j.failAppend = true
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e == nil {
			t.Fatal("expected interrupted floor")
		}
		// The journal advances beyond approval expiry while the process wall clock
		// still precedes it. Recovery must obey the independently signed time.
		f.clock(f.now.Add(6 * time.Minute))
		f.j.failAppend = false
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal(e)
		}
		r, e := f.directory.GetOperation(f.ctx, f.author, o.ID)
		if e != nil || r.State != "recovery_required" {
			t.Fatalf("expired recovery %#v %v", r, e)
		}
		if _, e = f.directory.CurrentProvider(f.ctx, f.provider.ID); e == nil {
			t.Fatal("expired journal-time approval enabled provider")
		}
	})
	t.Run("version_author_rights_change_invalidates_pending_activation", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		o := f.plan(t, true)
		f.approve(t, o)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `DELETE FROM user_groups WHERE user_id=?`, f.user.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e == nil {
			t.Fatal("changed version author rights accepted")
		}
		if len(f.j.events) != 0 {
			t.Fatal("stale author reached journal")
		}
	})
	t.Run("server_validation_redacted_forest_bound_and_complete", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		for _, mode := range []string{"offline", "wrong_forest", "partial"} {
			f.validator.unavailable.Store(mode == "offline")
			f.validator.wrongForest.Store(mode == "wrong_forest")
			f.validator.partial.Store(mode == "partial")
			r, e := f.directory.TestProvider(f.ctx, f.author, f.provider.ID, f.document.Metadata.VersionID)
			if e != nil || r.State != "failed" {
				t.Fatalf("%s: %#v %v", mode, r, e)
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "synthetic-password") {
				t.Fatal("connector diagnostic escaped")
			}
		}
		if _, e := f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, "request_failed_test_001", DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: true, Reason: "Invalid validation must stay closed"}); !errors.Is(e, ErrDirectoryUnavailable) {
			t.Fatal(e)
		}
	})
	t.Run("revoked_approver_and_changed_head_reject_exact_retries", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		o := f.plan(t, true)
		f.approve(t, o)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `DELETE FROM user_groups WHERE user_id=?`, f.other.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.directory.ApproveOperation(f.ctx, f.reviewer, o.ID, o.RequestDigest, "retry after rights removed"); e == nil {
			t.Fatal("revoked review retry")
		}
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e == nil {
			t.Fatal("revoked reviewer executed")
		}
		if len(f.j.events) != 0 {
			t.Fatal("rejected operation wrote floor")
		}
	})
	t.Run("CAS_successor_and_disable_during_AD_outage", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		o := f.plan(t, true)
		f.approve(t, o)
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e != nil {
			t.Fatal(e)
		}
		f.provider.Revision++
		if _, e := f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, "request_toggle_old_001", DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: false, Reason: "Cannot toggle a previously activated version"}); !errors.Is(e, ErrDirectoryStale) {
			t.Fatalf("old toggle %v", e)
		}
		f.document.Metadata.VersionID = securitystate.ID("dirver")
		f.document.Metadata.SecurityGuardVersion = 2
		f.propose(t)
		f.validator.unavailable.Store(true)
		o = f.plan(t, false)
		f.approve(t, o)
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e != nil {
			t.Fatal(e)
		}
		if p, e := f.directory.GetProvider(f.ctx, f.author, f.provider.ID); e != nil || p.Enabled || p.Configuration.Metadata.SecurityGuardVersion != 2 {
			t.Fatalf("disable successor %#v %v", p, e)
		}
		if _, e := f.directory.CurrentProvider(f.ctx, f.provider.ID); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("disabled allow %v", e)
		}
	})
	t.Run("floor_barrier_crash_recovery_and_idempotent_plan", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		in := DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: true, Reason: "Durable activation test"}
		o, e := f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, "request_exact_retry_001", in)
		if e != nil {
			t.Fatal(e)
		}
		retry, e := f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, "request_exact_retry_001", in)
		if e != nil || retry.ID != o.ID {
			t.Fatal(e)
		}
		in.Enabled = false
		if _, e = f.directory.PlanActivation(f.ctx, f.author, f.provider.ID, "request_exact_retry_001", in); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("mutable intent retry", e)
		}
		f.approve(t, o)
		f.j.failAppend = true
		if _, e = f.directory.ExecuteOperation(f.ctx, f.author, o.ID, o.RequestDigest); e == nil {
			t.Fatal("journal failure")
		}
		if e = f.s.Coordinator.Ready(f.ctx); !errors.Is(e, securitystate.ErrBarrier) {
			t.Fatal("pending guard did not close global admission", e)
		}
		f.j.failAppend = false
		if e = f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal(e)
		}
		if p, e := f.directory.CurrentProvider(f.ctx, f.provider.ID); e != nil || p == nil {
			t.Fatal(e)
		}
		if len(f.j.events) != 1 {
			t.Fatal("floor replay duplicate")
		}
	})
	t.Run("future_MFA_stale_source_floors_and_configuration_immutability", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE directory_provider_versions SET canonical_json='{}' WHERE id=?`, f.document.Metadata.VersionID)
			return e
		}); e == nil {
			t.Fatal("immutable config update")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET mfa_at=? WHERE token_hash=?`, f.now.Add(time.Second), f.author.TokenHash)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.directory.GetProvider(f.ctx, f.author, f.provider.ID); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("future MFA accepted", e)
		}
	})

	t.Run("HTTP_CAS_and_action_request_keys_are_bound", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		f.propose(t)
		f.test(t)
		in := DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: true, Reason: "Review the exact provider successor"}
		if _, e := f.directory.PlanActivationAtRevision(f.ctx, f.author, f.provider.ID, "request_stale_CAS_001", 1, in); !errors.Is(e, ErrDirectoryStale) {
			t.Fatal("activation If-Match ignored", e)
		}
		o, e := f.directory.PlanActivationAtRevision(f.ctx, f.author, f.provider.ID, "request_correct_CAS_001", 2, in)
		if e != nil {
			t.Fatal(e)
		}
		reviewReason := "Independently reviewed exact configuration and digest"
		view, e := f.directory.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, "approval_exact_key_001", o.RequestDigest, reviewReason)
		if e != nil || view.ApprovalID == "" || view.ApprovedBy != f.other.ID {
			t.Fatalf("view %#v %v", view, e)
		}
		retry, e := f.directory.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, "approval_exact_key_001", o.RequestDigest, reviewReason)
		if e != nil || retry.ApprovalID != view.ApprovalID {
			t.Fatal("approval retry", e)
		}
		if _, e = f.directory.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, "approval_exact_key_001", o.RequestDigest, "Different reason for the same key"); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("approval key not bound", e)
		}
		executionReason := "Apply the reviewed directory security successor"
		if _, e = f.directory.ExecuteOperationRequest(f.ctx, f.author, o.ID, "execution_exact_key_001", o.RequestDigest, executionReason); e != nil {
			t.Fatal(e)
		}
		if _, e = f.directory.ExecuteOperationRequest(f.ctx, f.author, o.ID, "execution_exact_key_001", o.RequestDigest, executionReason); e != nil {
			t.Fatal("execution retry", e)
		}
		if _, e = f.directory.ExecuteOperationRequest(f.ctx, f.author, o.ID, "execution_exact_key_001", o.RequestDigest, "Changed execution reason"); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("execution key not bound", e)
		}
		if len(f.j.events) != 1 {
			t.Fatal("execution replay repeated provider floor")
		}
	})
	t.Run("large_page_budget_visits_every_provider_without_loss", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		for i := 0; i < 8; i++ {
			provider, e := f.directory.CreateProvider(f.ctx, f.author, DirectoryCreate{Name: fmt.Sprintf("Large directory %d", i), ForestGUID: f.provider.ForestGUID})
			if e != nil {
				t.Fatal(e)
			}
			doc := f.document
			doc.Metadata.ID = provider.ID
			doc.Metadata.VersionID = securitystate.ID("dirver")
			doc.Metadata.SecurityGuardID = provider.SecurityGuardID
			doc.Spec.GroupMappings = make([]DirectoryGroupMapping, 2000)
			for n := range doc.Spec.GroupMappings {
				doc.Spec.GroupMappings[n] = DirectoryGroupMapping{GroupObjectGUID: fmt.Sprintf("00000000-0000-0000-0000-%012x", n+1), AccessGroupID: f.group.ID}
			}
			if _, e = f.directory.ProposeVersion(f.ctx, f.author, provider.ID, 1, doc); e != nil {
				t.Fatal(e)
			}
			// Trusted fixture projection: this test exercises paginated reads,
			// while reviewed activation and floors have separate regressions.
			if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				_, e := tx.Exec(f.ctx, `UPDATE directory_providers SET active_version_id=?,guard_version=1 WHERE id=?`, doc.Metadata.VersionID, provider.ID)
				return e
			}); e != nil {
				t.Fatal(e)
			}
		}
		seen := map[string]bool{}
		cursor := ""
		pages := 0
		for {
			page, e := f.directory.ListProviders(f.ctx, f.author, 50, cursor)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(page)
			if e != nil || len(raw) > 3*(1<<19) {
				t.Fatalf("page exceeds server budget: %d %v", len(raw), e)
			}
			pages++
			for _, item := range page.Items {
				if seen[item.ID] || item.ID <= cursor {
					t.Fatal("duplicate or non-progressing cursor", item.ID, cursor)
				}
				seen[item.ID] = true
			}
			if page.NextCursor == "" {
				break
			}
			if len(page.Items) == 0 || page.NextCursor != page.Items[len(page.Items)-1].ID {
				t.Fatal("cursor skipped an unreturned provider")
			}
			cursor = page.NextCursor
		}
		if len(seen) != 9 || pages < 2 {
			t.Fatalf("missing providers or no byte pagination: count=%d pages=%d", len(seen), pages)
		}
	})

	t.Run("proposal_CAS_and_namespace_invariants", func(t *testing.T) {
		f := newDirectoryFixture(t, pg)
		bad := f.document
		bad.Metadata.SecurityGuardID = f.user.ID
		if _, e := f.directory.ProposeVersion(f.ctx, f.author, f.provider.ID, 1, bad); !errors.Is(e, ErrDirectoryStale) {
			t.Fatal("guard substitution", e)
		}
		f.propose(t)
		f.document.Metadata.VersionID = securitystate.ID("dirver")
		f.document.Metadata.SecurityGuardVersion = 2
		if _, e := f.directory.ProposeVersion(f.ctx, f.author, f.provider.ID, 1, f.document); !errors.Is(e, ErrDirectoryStale) {
			t.Fatal("CAS stale", e)
		}
	})
}
func TestDirectoryProviderClosedCodec(t *testing.T) {
	raw := []byte(`{"apiVersion":"agp.identity/v1alpha1","kind":"DirectoryProvider","metadata":{"id":"dir_corp","versionId":"dirver_1","securityGuardId":"guard_dir_1","securityGuardVersion":"1"},"spec":{"forestGuid":"00000000-0000-0000-0000-000000000001","domainDns":"corp.example.net","transport":"ldaps","endpoints":[{"host":"dc01.corp.example.net","port":636}],"userBaseDns":["DC=corp,DC=example,DC=net"],"groupBaseDns":["DC=corp,DC=example,DC=net"],"bindDn":"CN=reader,DC=corp,DC=example,DC=net","bindSecretVersionId":"sec_bind_1","caSecretVersionId":"sec_ca_1","loginAttribute":"userPrincipalName","provisioning":"preprovisioned","groupResolution":"token_groups_security","accountCheck":"live_each_allow","operationTimeoutSeconds":3,"maximumGroups":2048,"groupMappings":[]}}`)
	if _, e := ParseDirectoryProvider(bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"transport":"ldaps"`, `"transport":"ldap"`, 1) },
		func(s string) string { return strings.Replace(s, `"bindDn":`, `"skipVerify":true,"bindDn":`, 1) },
		func(s string) string { return strings.Replace(s, `"bindDn":`, `"bindPassword":"secret","bindDn":`, 1) },
		func(s string) string {
			return strings.Replace(s, `"securityGuardVersion":"1"`, `"securityGuardVersion":1`, 1)
		},
		func(s string) string { return strings.Replace(s, `"groupMappings":[]`, `"groupMappings":null`, 1) },
		func(s string) string {
			return strings.Replace(s, `"maximumGroups":2048`, `"maximumGroups":2048,"maximumGroups":2048`, 1)
		},
		func(s string) string { return strings.Replace(s, `"apiVersion":`, `"APIVersion":`, 1) },
	} {
		if _, e := ParseDirectoryProvider(strings.NewReader(mutate(string(raw)))); !errors.Is(e, ErrDirectoryInvalid) {
			t.Fatal("nonclosed codec", e)
		}
	}
}
