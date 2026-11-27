package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestRecoveryFaultSQLite(t *testing.T)   { recoveryFaultMatrix(t, false) }
func TestRecoveryFaultPostgres(t *testing.T) { recoveryFaultMatrix(t, true) }
func recoveryFaultMatrix(t *testing.T, pg bool) {
	t.Run("fourth_executor_current_authority", func(t *testing.T) {
		for _, revoke := range []bool{false, true} {
			name := "valid"
			if revoke {
				name = "revoked_after_journal"
			}
			t.Run(name, func(t *testing.T) {
				f := newRecoveryFixture(t, pg, true)
				op := f.plan(t, "reset_password")
				f.approve(t, op)
				actor, _ := f.newActor(t, f.executor.ID, "management")
				executor := LifecycleActor{TokenHash: actor.TokenHash, Origin: actor.Origin, SourceIP: actor.SourceIP}
				if revoke {
					f.s.Coordinator.Register("identity_recovery", func(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
						if _, e := tx.Exec(ctx, `UPDATE users SET blocked_at=? WHERE id=?`, f.now, f.executor.ID); e != nil {
							return e
						}
						return f.recovery.materializeOperation(ctx, tx, raw)
					})
				}
				out, e := f.recovery.ExecuteOperationRequest(f.ctx, executor, op.ID, securitystate.ID("request"), op.RequestDigest, "separate operator execution")
				if e != nil {
					t.Fatal("fourth executor", e)
				}
				expected := "applied"
				if revoke {
					expected = "recovery_required"
				}
				if out.State != expected {
					t.Fatal("executor current guard", out.State)
				}
				hash, sv, pv := f.password(t)
				if hash != "" || sv != 2 || pv != 2 {
					t.Fatal("restrictions lost")
				}
				if revoke {
					if _, e = f.recovery.IssueTicket(f.ctx, f.creator, op.ID); e == nil {
						t.Fatal("revoked executor published ticket")
					}
				}
			})
		}
	})

	t.Run("untouched_floor_drift_after_journal_denies_positive", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "reset_password")
		f.approve(t, op)
		f.s.Coordinator.Register("identity_recovery", func(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
			// Fault-inject an independent floor projection drift after our child
			// receipts, without changing any principal metadata fingerprint.
			if _, e := tx.Exec(ctx, `UPDATE authenticator_floors SET minimum_version=minimum_version+1 WHERE principal_id=? AND authenticator_id=?`, f.target.ID, ReplayID(f.target.ID)); e != nil {
				return e
			}
			return f.recovery.materializeOperation(ctx, tx, raw)
		})
		out, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "drift after exact planned restrictions")
		if e != nil || out.State != "recovery_required" {
			t.Fatal("unpinned floor accepted", e)
		}
		if _, e = f.recovery.IssueTicket(f.ctx, f.creator, op.ID); e == nil {
			t.Fatal("floor drift issued capability")
		}
		if e = f.s.Coordinator.Current(f.ctx, func(storage.IdentityTx, securityjournal.Head) error { return nil }); e != nil {
			t.Fatal("barrier retained", e)
		}
	})

	t.Run("legacy_restore_guard_stable_and_spent", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, false)
		a := f.startTarget(t, "recover", "setup")
		tr, e := f.s.Primary(f.ctx, a, f.target.Username, "existing target password", "192.0.2.61")
		if e != nil {
			t.Fatal(e)
		}
		a.ID = tr.View.ID
		a.Binding = tr.Binding
		if _, e = f.s.RecoveryProof(f.ctx, a, f.codes[0]); e != nil {
			t.Fatal(e)
		}
		var guard, oldOperation string
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			c, e := readRecoveryCapability(f.ctx, tx, a.ID)
			if e != nil {
				return e
			}
			guard = c.guardID
			ids, e := securitystate.Strings(f.ctx, tx, `SELECT id FROM security_operations`)
			if e != nil {
				return e
			}
			for _, id := range ids {
				var raw string
				if e = securitystate.One(f.ctx, tx, `SELECT intent_json FROM security_operations WHERE id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&raw) }); e != nil {
					return e
				}
				var in securitystate.Intent
				if e = json.Unmarshal([]byte(raw), &in); e != nil {
					return e
				}
				if in.Kind == "mfa_recovery" {
					var rec recoveryIntent
					if e = json.Unmarshal(in.Data, &rec); e != nil {
						return e
					}
					if rec.FlowID == a.ID {
						oldOperation = id
					}
				}
			}
			if oldOperation == "" {
				return storage.ErrNotFound
			}
			if _, e = tx.Exec(f.ctx, `DELETE FROM identity_recovery_capabilities WHERE flow_id=?`, a.ID); e != nil {
				return e
			}
			h, e := f.j.Head(f.ctx)
			if e != nil {
				return e
			}
			flow, e := loadFlow(f.ctx, tx, a.ID)
			if e != nil {
				return e
			}
			if e = f.recovery.AuthorizeLegacyMFAReplacementTx(f.ctx, tx, h, flow); e != nil {
				return e
			}
			c, e = readRecoveryCapability(f.ctx, tx, a.ID)
			if e != nil {
				return e
			}
			if c.guardID != guard {
				t.Fatal("materializer minted a different guard")
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.recovery.CancelRecovery(f.ctx, a); e != nil {
			t.Fatal(e)
		}
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `DELETE FROM identity_recovery_capabilities WHERE flow_id=?`, a.ID); e != nil {
				return e
			}
			if _, e := tx.Exec(f.ctx, `UPDATE identity_flows SET state='pending_mfa',next_step='totp_enrollment' WHERE id=?`, a.ID); e != nil {
				return e
			}
			_, e := tx.Exec(f.ctx, `UPDATE security_operations SET status='pending' WHERE id=?`, oldOperation)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if e = f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("core restore replay", e)
		}
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var state string
			if e := securitystate.One(f.ctx, tx, `SELECT status FROM security_operations WHERE id=?`, []any{oldOperation}, func(row storage.IdentityRows) error { return row.Scan(&state) }); e != nil {
				return e
			}
			if state != "aborted" {
				t.Fatal("foreign terminal guard did not abort old pending intent")
			}
			if _, e := readRecoveryCapability(f.ctx, tx, a.ID); !errors.Is(e, storage.ErrNotFound) {
				t.Fatal("core restore recreated cap", e)
			}
			// Defense in depth for direct idempotent handler re-entry: the spent
			// deterministic guard closes the flow and never produces a new capability.
			raw, e := json.Marshal(recoveryIntent{a.ID, f.target.ID})
			if e != nil {
				return e
			}
			if e = f.s.materializeRecovery(f.ctx, tx, raw); e != nil {
				return e
			}
			flow, e := loadFlow(f.ctx, tx, a.ID)
			if e != nil {
				return e
			}
			if flow.State != "cancelled" {
				t.Fatal("spent guard flow revived")
			}
			if _, e = readRecoveryCapability(f.ctx, tx, a.ID); !errors.Is(e, storage.ErrNotFound) {
				t.Fatal("spent guard recreated cap", e)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("lost_append_response_stable_recovery", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "replace_mfa")
		f.approve(t, op)
		f.j.mu.Lock()
		f.j.lostResponse = true
		f.j.mu.Unlock()
		_, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "injected lost append response")
		// ExecuteDynamic may resolve a lost response by exact Operation lookup in
		// the same call. Either path must use the persisted stable child receipt.
		f.j.mu.Lock()
		injected := !f.j.lostResponse
		f.j.mu.Unlock()
		if !injected {
			t.Fatal("fault was not injected")
		}
		if e = f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("recover", e)
		}
		result, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "retry after durable recovery")
		if e != nil || result.State != "applied" {
			t.Fatal("stable retry", e)
		}
		_, sv, pv := f.password(t)
		if sv != 2 || pv != 1 {
			t.Fatal("retry duplicated restrictions")
		}
		f.j.mu.Lock()
		count := 0
		for _, event := range f.j.events {
			if event.Request.Kind == "raise_security_floor" && event.Request.TargetID == f.target.ID {
				count++
			}
		}
		f.j.mu.Unlock()
		if count != 1 {
			t.Fatal("duplicate journal child")
		}
		_ = f.ticketFlow(t, op)
	})
	t.Run("abort_after_journal_retires_barrier_and_allows_new_plan", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "reset_password")
		f.approve(t, op)
		f.s.Coordinator.Register("identity_recovery", func(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
			f.clock(f.now.Add(4*time.Minute + time.Second))
			return f.recovery.materializeOperation(ctx, tx, raw)
		})
		out, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "expire after independent restrictions")
		if e != nil || out.State != "recovery_required" {
			t.Fatal("abort", e)
		}
		hash, sv, pv := f.password(t)
		if hash != "" || sv != 2 || pv != 2 {
			t.Fatal("restrictive-only projection")
		}
		if _, e = f.recovery.IssueTicket(f.ctx, f.creator, op.ID); e == nil {
			t.Fatal("abort issued ticket")
		}
		if e = f.s.Coordinator.Current(f.ctx, func(storage.IdentityTx, securityjournal.Head) error { return nil }); e != nil {
			t.Fatal("barrier retained", e)
		}
		f.s.Coordinator.Register("identity_recovery", f.recovery.materializeOperation)
		// The exact abort rebased only its own restrictions, so a fresh, separately
		// approved operation can repair the active account without a floor bypass.
		f.plan(t, "reset_password")
	})

	t.Run("password_final_abort_spends_guard_retains_only_restrictions", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "reset_password")
		f.approve(t, op)
		f.execute(t, op)
		a := f.ticketFlow(t, op)
		if _, e := f.recovery.SetResetPassword(f.ctx, a, "must remain unpublished password"); e != nil {
			t.Fatal(e)
		}
		f.s.Coordinator.Register("identity_recovery_complete", func(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
			f.clock(f.now.Add(4*time.Minute + time.Second))
			return f.recovery.materializeComplete(ctx, tx, raw)
		})
		if _, e := f.s.Complete(f.ctx, a, "192.0.2.61", "fixture"); e == nil {
			t.Fatal("stale final password published")
		}
		hash, sv, pv := f.password(t)
		if hash != "" || sv != 3 || pv != 3 {
			t.Fatal("final abort failed restrictive-only projection")
		}
		e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
			c, e := readRecoveryCapability(f.ctx, tx, a.ID)
			if e != nil {
				return e
			}
			if c.state != "cancelled" || c.password != "" {
				t.Fatal("staged password retained")
			}
			floor, e := securitystate.Floor(f.ctx, tx, c.guardID, c.guardID)
			if e != nil {
				return e
			}
			if floor != c.boundGuard+1 {
				t.Fatal("guard not irreversibly spent")
			}
			return nil
		})
		if e != nil {
			t.Fatal("barrier retained", e)
		}
		f.plan(t, "reset_password")
	})
	t.Run("restored_cancelled_capability_denied_by_journal", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "reset_password")
		f.approve(t, op)
		f.execute(t, op)
		a := f.ticketFlow(t, op)
		if _, e := f.recovery.CancelRecovery(f.ctx, a); e != nil {
			t.Fatal(e)
		}
		e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			// Simulate restoring mutable rows from a pre-cancel snapshot. The external
			// authority and its floor projection are deliberately not rolled back.
			q := `DROP TRIGGER identity_recovery_capability_terminal`
			if pg {
				q += ` ON identity_recovery_capabilities`
			}
			if _, e := tx.Exec(f.ctx, q); e != nil {
				return e
			}
			if _, e := tx.Exec(f.ctx, `UPDATE identity_recovery_capabilities SET state='pending' WHERE flow_id=?`, a.ID); e != nil {
				return e
			}
			_, e := tx.Exec(f.ctx, `UPDATE identity_flows SET state='pending_mfa',next_step='password_setup' WHERE id=?`, a.ID)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.recovery.SetResetPassword(f.ctx, a, "restored cap cannot publish"); e == nil {
			t.Fatal("restored cancelled cap revived")
		}
	})
	t.Run("anonymous_no_enumeration_no_human_restriction", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		hash, sv, pv := f.password(t)
		for _, in := range []PasswordResetRequest{{Username: "unknown", Email: "missing@corp.example"}, {Username: f.target.Username, Email: "missing@corp.example"}, {Username: "", Email: "bad"}} {
			if e := f.recovery.RequestPasswordReset(f.ctx, f.s.Profile.LoginOrigin, "192.0.2.73", in); e != nil {
				t.Fatal("target-dependent response", e)
			}
		}
		after, afterSV, afterPV := f.password(t)
		if hash != after || sv != afterSV || pv != afterPV || len(f.mail.snapshot()) != 0 {
			t.Fatal("anonymous issuance changed privileged target")
		}
		e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
			floor, e := securitystate.Floor(f.ctx, tx, f.target.ID, "principal_"+f.target.ID)
			if e != nil {
				return e
			}
			if floor > sv {
				t.Fatal("anonymous human floor")
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("restart_invited_below_floors_only", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		reviewer, _ := f.newActor(t, f.other.ID, "management")
		r := f.s.recovery.(*RecoveryService)
		e := f.s.Coordinator.Execute(f.ctx, securitystate.Intent{Kind: "logout", Data: json.RawMessage(`{}`)}, func(storage.IdentityTx, securityjournal.Head) ([]securityjournal.AppendRequest, error) {
			return []securityjournal.AppendRequest{securitystate.FloorRequest("fixture", f.pending.ID, "principal_"+f.pending.ID, 3), securitystate.FloorRequest("fixture", f.pending.ID, PasswordID(f.pending.ID), 4)}, nil
		})
		if e != nil {
			t.Fatal(e)
		}
		in := RecoveryPlanRequest{TargetPrincipalID: f.pending.ID, ExpectedSecurityVersion: f.pending.Revision, AllowedAction: "restart_activation", ExpiresAt: f.now.Add(4 * time.Minute), Reason: "repair failed initial activation"}
		op, e := r.Plan(f.ctx, f.admin, f.pending.ID, securitystate.ID("request"), in)
		if e != nil {
			t.Fatal("below-floor plan", e)
		}
		if uint64(op.RecoveryRequest.ObservedFloors.Principal) != 3 || uint64(op.RecoveryRequest.ObservedFloors.Password) != 4 {
			t.Fatal("observed floors not pinned")
		}
		actor := LifecycleActor{TokenHash: reviewer.TokenHash, Origin: reviewer.Origin, SourceIP: reviewer.SourceIP}
		if _, e = r.ApproveOperationRequest(f.ctx, actor, op.ID, securitystate.ID("request"), op.RequestDigest, "independent activation restart review"); e != nil {
			t.Fatal(e)
		}
		out, e := r.ExecuteOperationRequest(f.ctx, f.admin, op.ID, securitystate.ID("request"), op.RequestDigest, "execute initial activation repair")
		if e != nil || out.State != "applied" {
			t.Fatal(e)
		}
		if _, e = r.IssueTicket(f.ctx, f.admin, op.ID); e == nil {
			t.Fatal("restart produced ticket")
		}
		var state, hash string
		var sv, pv uint64
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return securitystate.One(f.ctx, tx, `SELECT lifecycle_state,password_hash,security_version,password_version FROM users WHERE id=?`, []any{f.pending.ID}, func(row storage.IdentityRows) error { return row.Scan(&state, &hash, &sv, &pv) })
		})
		if e != nil {
			t.Fatal(e)
		}
		if state != "invited" || hash != "" || sv != 4 || pv != 5 {
			t.Fatal("unsafe restart projection")
		}
		// A normal invitation is possible again at the new version, while no active
		// credential or session was published by the repair itself.
		_, e = f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, securitystate.ID("request"), securityjournal.UInt63(sv), InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300})
		if e != nil {
			t.Fatal("invite after repair", e)
		}
		active := RecoveryPlanRequest{TargetPrincipalID: f.user.ID, ExpectedSecurityVersion: 1, AllowedAction: "restart_activation", ExpiresAt: f.now.Add(time.Minute), Reason: "must reject active target"}
		if _, e = r.Plan(f.ctx, actor, f.user.ID, securitystate.ID("request"), active); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("active transitioned to invited", e)
		}
	})
}
