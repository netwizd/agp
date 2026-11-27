package identity

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// Real paired databases/coordinator with an explicit fault-injection journal
// and synthetic already-authenticated MG sessions. No corporate AD claim.
type roleFixture struct {
	*emailFixture
	roles                       *RoleBindingService
	creator, reviewer, executor LifecycleActor
	target, executorUser        domain.User
}

func newRoleFixture(t *testing.T, pg bool) *roleFixture {
	t.Helper()
	return newRoleFixtureSetup(t, pg, nil)
}
func newRoleFixtureSetup(t *testing.T, pg bool, setup func(context.Context, storage.Store, string) error) *roleFixture {
	t.Helper()
	var target, executor domain.User
	base := newFixtureSetup(t, pg, func(ctx context.Context, s storage.Store, author string) error {
		u, e := s.CreateUser(ctx, domain.UserInput{Username: "role-target", PasswordHash: "fixture-unused-hash"})
		if e != nil {
			return e
		}
		target = *u
		u, e = s.CreateUser(ctx, domain.UserInput{Username: "role-executor", PasswordHash: "fixture-unused-hash", IsAdmin: true})
		if e != nil {
			return e
		}
		executor = *u
		if setup != nil {
			return setup(ctx, s, author)
		}
		return nil
	})
	f := attachEmailFixture(t, base)
	review, _ := f.newActor(t, f.other.ID, "management")
	exec, _ := f.newActor(t, executor.ID, "management")
	return &roleFixture{emailFixture: f, roles: f.s.RoleBindingService(), creator: LifecycleActor{TokenHash: f.actor.TokenHash, Origin: f.actor.Origin}, reviewer: LifecycleActor{TokenHash: review.TokenHash, Origin: review.Origin}, executor: LifecycleActor{TokenHash: exec.TokenHash, Origin: exec.Origin}, target: target, executorUser: executor}
}
func (f *roleFixture) create(t *testing.T, key string) *RoleSecurityOperation {
	t.Helper()
	o, e := f.roles.Create(f.ctx, f.creator, key, RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global"})
	if e != nil {
		t.Fatal("plan", e)
	}
	return o
}
func (f *roleFixture) approve(t *testing.T, o *RoleSecurityOperation) {
	t.Helper()
	if _, e := f.roles.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, "workflow_role_approval", o.RequestDigest, "independent role intent review"); e != nil {
		t.Fatal("approve", e)
	}
}
func (f *roleFixture) execute(t *testing.T, o *RoleSecurityOperation) *RoleSecurityOperation {
	t.Helper()
	v, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "workflow_role_execution", o.RequestDigest, "execute exact reviewed grant")
	if e != nil {
		t.Fatal("execute", e)
	}
	return v
}
func (f *roleFixture) effective(t *testing.T) securitystate.EffectiveGrants {
	t.Helper()
	var out securitystate.EffectiveGrants
	if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var e error
		out, e = securitystate.ReadEffectiveGrants(f.ctx, tx, h, f.target.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *roleFixture) sql(t *testing.T, q string, args ...any) {
	t.Helper()
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(f.ctx, q, args...); return e }); e != nil {
		t.Fatal(e)
	}
}
func TestRoleWorkflowSQLite(t *testing.T)   { roleWorkflow(t, false) }
func TestRoleWorkflowPostgres(t *testing.T) { roleWorkflow(t, true) }
func roleWorkflow(t *testing.T, pg bool) {
	t.Run("independent_approval_atomic_positive_no_barrier_or_journal", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o := f.create(t, "workflow_role_create")
		if o.Family != "grant_role_binding" || o.State != "pending" || o.RoleGrantRequest == nil || o.RoleGrantRequest.GrantExpiresAt != nil {
			t.Fatal("intent shape")
		}
		if e := f.s.Coordinator.Ready(f.ctx); e != nil {
			t.Fatal("approval installed global barrier", e)
		}
		if len(f.effective(t).Global) != 0 {
			t.Fatal("pending role became effective")
		}
		if _, e := f.roles.ExecuteOperationRequest(f.ctx, f.creator, o.ID, "unapproved_execute", o.RequestDigest, "execution before approval"); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal("no independent approval", e)
		}
		if _, e := f.roles.ApproveOperationRequest(f.ctx, f.creator, o.ID, "workflow_self_review", o.RequestDigest, "creator attempts own approval"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("self review", e)
		}
		f.approve(t, o)
		if len(f.effective(t).Global) != 0 {
			t.Fatal("approval applied grant")
		}
		applied := f.execute(t, o)
		if applied.State != "applied" || !lifecycleHas(f.effective(t).Global, "config.read") {
			t.Fatal("atomic grant missing")
		}
		f.j.mu.Lock()
		n := len(f.j.events)
		f.j.mu.Unlock()
		if n != 0 {
			t.Fatal("positive grant appended journal", n)
		}
		again, e := f.roles.Create(f.ctx, f.creator, "workflow_role_create", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global"})
		if e != nil || again.ID != o.ID {
			t.Fatal("lost create response", e)
		}
		if _, e = f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "workflow_role_execution", o.RequestDigest, "execute exact reviewed grant"); e != nil {
			t.Fatal("lost execute response", e)
		}
		if _, e = f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "workflow_role_execution", o.RequestDigest, "changed retry content"); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("key changed body", e)
		}
		if _, e = f.roles.Create(f.ctx, f.creator, "workflow_role_create", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_edit", ScopeType: "global"}); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("key changed role", e)
		}
	})
	t.Run("approval_lost_response_and_concurrent_execution", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o := f.create(t, "workflow_concurrent_role")
		f.approve(t, o)
		if _, e := f.roles.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, "workflow_role_approval", o.RequestDigest, "independent role intent review"); e != nil {
			t.Fatal("approval replay", e)
		}
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				_, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "same_role_execution", o.RequestDigest, "same execution request")
				results <- e
			})
		}
		wg.Wait()
		close(results)
		for e := range results {
			if e != nil {
				t.Fatal("concurrent exact replay", e)
			}
		}
		if len(f.effective(t).Entries) != 1 {
			t.Fatal("duplicate incarnation")
		}
	})
	t.Run("audit_failure_rolls_back_binding_operation_and_retry_key", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o := f.create(t, "atomic_role_request")
		f.approve(t, o)
		if pg {
			f.sql(t, `CREATE FUNCTION test_role_audit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='identity.role_grant.applied' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`)
			f.sql(t, `CREATE TRIGGER test_role_audit_reject BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION test_role_audit_reject()`)
		} else {
			f.sql(t, `CREATE TRIGGER test_role_audit_reject BEFORE INSERT ON audit_events WHEN NEW.event_type='identity.role_grant.applied' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`)
		}
		if _, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "atomic_role_execution", o.RequestDigest, "execution with durable audit"); e == nil {
			t.Fatal("audit failure ignored")
		}
		if len(f.effective(t).Entries) != 0 {
			t.Fatal("positive binding survived transaction rollback")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var state string
			var keys int
			if e := securitystate.One(f.ctx, tx, `SELECT state FROM role_grant_operations WHERE id=?`, []any{o.ID}, func(row storage.IdentityRows) error { return row.Scan(&state) }); e != nil {
				return e
			}
			if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_grant_requests WHERE action=?`, []any{"execute:" + o.ID}, func(row storage.IdentityRows) error { return row.Scan(&keys) }); e != nil {
				return e
			}
			if state != "pending" || keys != 0 {
				t.Fatal("partial operation or replay key", state, keys)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		if pg {
			f.sql(t, `DROP TRIGGER test_role_audit_reject ON audit_events`)
		} else {
			f.sql(t, `DROP TRIGGER test_role_audit_reject`)
		}
		if _, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "atomic_role_execution", o.RequestDigest, "execution with durable audit"); e != nil {
			t.Fatal("atomic retry", e)
		}
	})
	t.Run("revoke_exact_incarnation_and_fresh_approval_for_regrant", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o := f.create(t, "workflow_first_role")
		f.approve(t, o)
		f.execute(t, o)
		b := o.RoleGrantRequest.BindingID
		if _, e := f.roles.Revoke(f.ctx, f.creator, b, "workflow_stale_revoke", 2, "withdraw role binding"); !errors.Is(e, ErrLifecycleStale) {
			t.Fatal("revoke ignored CAS", e)
		}
		r, e := f.roles.Revoke(f.ctx, f.creator, b, "workflow_revoke_role", 1, "withdraw role binding")
		if e != nil || r.State != "applied" {
			t.Fatal("revoke", e)
		}
		if len(f.effective(t).Entries) != 0 {
			t.Fatal("revoked grant effective")
		}
		again, e := f.roles.Revoke(f.ctx, f.creator, b, "workflow_revoke_role", 1, "withdraw role binding")
		if e != nil || again.ID != r.ID {
			t.Fatal("lost revoke response", e)
		}
		fresh := f.create(t, "workflow_second_role")
		if fresh.RoleGrantRequest.BindingID == b {
			t.Fatal("incarnation reused")
		}
		if _, e = f.roles.ExecuteOperationRequest(f.ctx, f.creator, fresh.ID, "workflow_new_unapproved", fresh.RequestDigest, "old approval cannot authorize"); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal("approval inherited", e)
		}
		f.approve(t, fresh)
		f.execute(t, fresh)
		if len(f.effective(t).Entries) != 1 {
			t.Fatal("regrant missing")
		}
		if _, e = f.roles.Revoke(f.ctx, f.creator, b, "workflow_revoke_role", 1, "withdraw role binding"); e != nil {
			t.Fatal("old replay", e)
		}
		if len(f.effective(t).Entries) != 1 {
			t.Fatal("old replay revoked new grant")
		}
	})
	t.Run("lost_journal_response_reconciles_tombstone", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o := f.create(t, "workflow_role_before_fault")
		f.approve(t, o)
		f.execute(t, o)
		f.j.mu.Lock()
		f.j.lostResponse = true
		f.j.mu.Unlock()
		_, e := f.roles.Revoke(f.ctx, f.creator, o.RoleGrantRequest.BindingID, "workflow_lost_revoke", 1, "withdraw exact incarnation")
		if e != nil {
			if e = f.s.Coordinator.Recover(f.ctx); e != nil {
				t.Fatal("recover restrictive receipt", e)
			}
		}
		if len(f.effective(t).Entries) != 0 {
			t.Fatal("lost response restored grant")
		}
		if e = f.s.Coordinator.Ready(f.ctx); e != nil {
			t.Fatal("barrier not retired", e)
		}
	})
	for _, scenario := range []string{"creator_drift", "reviewer_drift", "target_drift", "target_floor", "expiry", "epoch", "authority_outage", "creator_session_revoked", "reviewer_session_revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRoleFixture(t, pg)
			o := f.create(t, "workflow_role_drift")
			f.approve(t, o)
			switch scenario {
			case "creator_drift":
				f.sql(t, `UPDATE users SET display_name='Changed creator' WHERE id=?`, f.user.ID)
			case "reviewer_drift":
				f.sql(t, `UPDATE users SET display_name='Changed reviewer' WHERE id=?`, f.other.ID)
			case "target_drift":
				f.sql(t, `UPDATE users SET display_name='Changed target' WHERE id=?`, f.target.ID)
			case "target_floor":
				e := f.s.Coordinator.ExecuteDynamic(f.ctx, "logout", func(storage.IdentityTx, securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
					return json.RawMessage(`{}`), []securityjournal.AppendRequest{securitystate.FloorRequest(f.user.ID, f.target.ID, "principal_"+f.target.ID, 2)}, nil
				})
				if e != nil {
					t.Fatal(e)
				}
			case "expiry":
				f.j.mu.Lock()
				f.j.head.RecordedAt = f.now.Add(6 * time.Minute)
				f.j.mu.Unlock()
			case "epoch":
				f.j.mu.Lock()
				f.j.head.Epoch++
				f.j.mu.Unlock()
			case "authority_outage":
				f.j.mu.Lock()
				f.j.unavailable = true
				f.j.mu.Unlock()
			case "creator_session_revoked":
				f.sql(t, `UPDATE sessions SET revoked_at=? WHERE token_hash=?`, f.now, f.creator.TokenHash)
			case "reviewer_session_revoked":
				f.sql(t, `UPDATE sessions SET revoked_at=? WHERE token_hash=?`, f.now, f.reviewer.TokenHash)
			}
			if _, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "deny_drift_execution", o.RequestDigest, "authority must remain current"); e == nil {
				t.Fatal("stale grant applied")
			}
			var n int
			if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				return securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_bindings`, nil, func(row storage.IdentityRows) error { return row.Scan(&n) })
			}); e != nil || n != 0 {
				t.Fatal("partial positive write", n, e)
			}
		})
	}
	t.Run("target_pending_blocked_and_full_existing_ceiling", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		f.sql(t, `UPDATE users SET lifecycle_state='invited' WHERE id=?`, f.target.ID)
		if _, e := f.roles.Create(f.ctx, f.creator, "workflow_pending_target", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global"}); e == nil {
			t.Fatal("pending granted role")
		}
		f.sql(t, `UPDATE users SET lifecycle_state='active',blocked_at=? WHERE id=?`, f.now, f.target.ID)
		if _, e := f.roles.Create(f.ctx, f.creator, "workflow_blocked_target", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global"}); e == nil {
			t.Fatal("blocked granted role")
		}
	})
	t.Run("each_human_must_cover_complete_existing_target_authority", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		f.sql(t, `INSERT INTO groups(id,name) VALUES('role_target_audit','Target audit authority')`)
		f.sql(t, `INSERT INTO group_permissions(group_id,permission_id) VALUES('role_target_audit','audit.read')`)
		f.sql(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,'role_target_audit')`, f.target.ID)
		f.sql(t, `INSERT INTO groups(id,name) VALUES('role_narrow_operator','Narrow role operator')`)
		for _, p := range []string{authz.PermUsersSuperAdminManage, "config.read", "config.approve"} {
			f.sql(t, `INSERT INTO group_permissions(group_id,permission_id) VALUES('role_narrow_operator',?)`, p)
		}
		narrow := func(id string) {
			f.sql(t, `UPDATE users SET is_admin=FALSE WHERE id=?`, id)
			f.sql(t, `DELETE FROM user_groups WHERE user_id=?`, id)
			f.sql(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,'role_narrow_operator')`, id)
		}
		restore := func(id string, group bool) {
			f.sql(t, `UPDATE users SET is_admin=TRUE WHERE id=?`, id)
			f.sql(t, `DELETE FROM user_groups WHERE user_id=?`, id)
			if group {
				f.sql(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, id, f.group.ID)
			}
		}
		narrow(f.user.ID)
		if _, e := f.roles.Create(f.ctx, f.creator, "creator_target_ceiling_request", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("creator ignored target audit authority", e)
		}
		restore(f.user.ID, true)
		o := f.create(t, "complete_target_ceiling_request")
		narrow(f.other.ID)
		if _, e := f.roles.ApproveOperationRequest(f.ctx, f.reviewer, o.ID, "reviewer_target_ceiling_request", o.RequestDigest, "review complete target authority"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("reviewer ignored target audit authority", e)
		}
		restore(f.other.ID, true)
		f.approve(t, o)
		narrow(f.executorUser.ID)
		if _, e := f.roles.ExecuteOperationRequest(f.ctx, f.executor, o.ID, "executor_target_ceiling_request", o.RequestDigest, "execute complete target authority"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("executor ignored target audit authority", e)
		}
		restore(f.executorUser.ID, false)
		f.execute(t, o)
	})
	t.Run("admin_is_not_implicit_approval_and_target_cannot_review", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o := f.create(t, "workflow_review_rules")
		if _, e := f.roles.ApproveOperationRequest(f.ctx, f.executor, o.ID, "admin_no_explicit_approve", o.RequestDigest, "admin without approval permission"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("implicit admin approval", e)
		}
		a, _ := f.newActor(t, f.target.ID, "management")
		f.sql(t, `UPDATE users SET is_admin=TRUE WHERE id=?`, f.target.ID)
		f.sql(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, f.target.ID, f.group.ID)
		if _, e := f.roles.ApproveOperationRequest(f.ctx, LifecycleActor{TokenHash: a.TokenHash, Origin: a.Origin}, o.ID, "target_self_review", o.RequestDigest, "target attempts review"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("target reviewed own elevation", e)
		}
	})
	t.Run("redundant_self_binding_requires_distinct_reviewer_and_current_ceiling", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		o, e := f.roles.Create(f.ctx, f.creator, "redundant_self_binding_request", RoleBindingRequest{PrincipalID: f.user.ID, RoleID: "role_config_read", ScopeType: "global"})
		if e != nil {
			t.Fatal("existing own ceiling", e)
		}
		if _, e = f.roles.ApproveOperationRequest(f.ctx, f.creator, o.ID, "redundant_self_review_request", o.RequestDigest, "author cannot review own binding"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("self review", e)
		}
		f.approve(t, o)
		if out, e := f.roles.ExecuteOperationRequest(f.ctx, f.creator, o.ID, "redundant_self_execute_request", o.RequestDigest, "independently reviewed existing authority"); e != nil || out.State != "applied" {
			t.Fatal("redundant self binding", e)
		}
	})
	t.Run("scope_union_and_read_only_inventory", func(t *testing.T) {
		f := newRoleFixture(t, pg)
		for _, in := range []RoleBindingRequest{{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global", ScopeID: "site_x"}, {PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "site"}, {PrincipalID: f.target.ID, RoleID: "role_users_manage", ScopeType: "node", ScopeID: "node_x"}, {PrincipalID: f.target.ID, RoleID: "role_nodes_enroll", ScopeType: "node", ScopeID: "node_x"}, {PrincipalID: f.target.ID, RoleID: "role_nodes_read", ScopeType: "resource", ScopeID: "resource_x"}} {
			if _, e := f.roles.Create(f.ctx, f.creator, securitystate.ID("request"), in); e == nil {
				t.Fatal("invalid or unsupported role scope accepted", in)
			}
		}
		f.sql(t, `UPDATE users SET is_admin=FALSE WHERE id=?`, f.executorUser.ID)
		f.sql(t, `INSERT INTO groups(id,name,description) VALUES('role_readers','Role readers','')`)
		f.sql(t, `INSERT INTO group_permissions(group_id,permission_id) VALUES('role_readers',?)`, authz.PermUsersRead)
		f.sql(t, `INSERT INTO user_groups(user_id,group_id) VALUES(?,'role_readers')`, f.executorUser.ID)
		if _, e := f.roles.Catalog(f.ctx, f.executor); e != nil {
			t.Fatal("read-only role catalog", e)
		}
		if _, e := f.roles.Bindings(f.ctx, f.executor, 20, ""); e != nil {
			t.Fatal("read-only bindings", e)
		}
		if _, e := f.roles.Create(f.ctx, f.executor, "reader_cannot_write", RoleBindingRequest{PrincipalID: f.target.ID, RoleID: "role_config_read", ScopeType: "global"}); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("reader granted role", e)
		}
	})
}
