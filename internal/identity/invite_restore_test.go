package identity

import (
	"encoding/json"
	"testing"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestInvitationRestoreSQLite(t *testing.T)   { testInvitationRestore(t, false) }
func TestInvitationRestorePostgres(t *testing.T) { testInvitationRestore(t, true) }
func testInvitationRestore(t *testing.T, pg bool) {
	t.Run("terminal_stage_requires_erasure_and_cannot_refill", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		_, raw := f.invitation(t, "terminal")
		a := f.activation(t, raw)
		f.stageActivation(t, a)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE identity_activation_stages SET state='completed' WHERE flow_id=?`, a.ID)
			return e
		}); e == nil {
			t.Fatal("terminal transition retained staged credentials")
		}
		if _, e := f.invites.CancelActivation(f.ctx, a); e != nil {
			t.Fatal(e)
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE identity_activation_stages SET password_phc='forbidden' WHERE flow_id=?`, a.ID)
			return e
		}); e == nil {
			t.Fatal("terminal stage refilled")
		}
		f.assertPending(t)
	})
	t.Run("missing_issue_row_retires_positive_intent", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		f.s.Coordinator.Authority = &inviteFaultAuthority{Authority: f.j, remaining: 0}
		if _, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "missing_issue", f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300}); e == nil {
			t.Fatal("journal outage accepted")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `DELETE FROM identity_invite_outbox WHERE token_id IN (SELECT id FROM identity_one_time_tokens WHERE principal_id=?)`, f.pending.ID); e != nil {
				return e
			}
			if pg {
				if _, e := tx.Exec(f.ctx, `ALTER TABLE identity_one_time_tokens DISABLE TRIGGER identity_one_time_live_no_delete`); e != nil {
					return e
				}
			} else {
				if _, e := tx.Exec(f.ctx, `DROP TRIGGER identity_one_time_live_no_delete`); e != nil {
					return e
				}
			}
			_, e := tx.Exec(f.ctx, `DELETE FROM identity_one_time_tokens WHERE principal_id=?`, f.pending.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		f.s.Coordinator.Authority = f.j
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("partial restore left global barrier", e)
		}
		f.assertPending(t)
	})
	t.Run("missing_reserved_flow_does_not_resurrect_raw_token_or_block_global_recovery", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		_, raw := f.invitation(t, "missing_flow")
		tr, e := f.invites.StartActivate(f.ctx, "setup", f.s.Profile.LoginOrigin, "prelogin_csrf", "192.0.2.40")
		if e != nil {
			t.Fatal(e)
		}
		f.s.Coordinator.Authority = &inviteFaultAuthority{Authority: f.j, remaining: 0}
		if _, e = f.invites.BindInvitation(f.ctx, FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "prelogin_csrf", Origin: f.s.Profile.LoginOrigin}, raw, "192.0.2.40"); e == nil {
			t.Fatal("journal outage accepted")
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var intent string
			if e := securitystate.One(f.ctx, tx, `SELECT intent_json FROM security_operations WHERE status='pending'`, nil, func(r storage.IdentityRows) error { return r.Scan(&intent) }); e != nil {
				return e
			}
			var envelope securitystate.Intent
			if e := json.Unmarshal([]byte(intent), &envelope); e != nil {
				return e
			}
			var in inviteReservationIntent
			if e := json.Unmarshal(envelope.Data, &in); e != nil {
				return e
			}
			if _, e := tx.Exec(f.ctx, `DELETE FROM identity_activation_stages WHERE flow_id=?`, in.FlowID); e != nil {
				return e
			}
			_, e := tx.Exec(f.ctx, `DELETE FROM identity_flows WHERE id=?`, in.FlowID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		f.s.Coordinator.Authority = f.j
		if e = f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("missing setup row left barrier", e)
		}
		if e = f.activationAttempt(t, raw); e == nil {
			t.Fatal("raw token resurrected")
		}
		if e = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return nil }); e != nil {
			t.Fatal(e)
		}
		f.assertPending(t)
	})
}
