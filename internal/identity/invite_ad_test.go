package identity

import (
	"testing"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func newADInvitationFixture(t *testing.T, pg bool) (*inviteFixture, *directoryAuthFixture) {
	t.Helper()
	ad := newDirectoryAuthFixture(t, pg, false)
	_, actor := ad.managementDirectory(t)
	email := attachEmailFixture(t, ad.fixture)
	sender := &inviteTestSender{state: "accepted"}
	email.email.sender = sender
	inv := ad.s.InvitationService()
	if inv == nil {
		inv = NewInvitationService(ad.s)
	}
	t.Cleanup(inv.Close)
	f := &inviteFixture{emailFixture: email, invites: inv, mail: sender, admin: LifecycleActor{TokenHash: actor.TokenHash, Origin: actor.Origin, SourceIP: "192.0.2.45"}}
	pending, e := inv.CreatePending(f.ctx, f.admin, "AD_pending", PendingUserInput{ID: securitystate.ID("usr"), Username: "AD-invited-local", DisplayName: "Invited local", GroupIDs: []string{}})
	if e != nil {
		t.Fatal("AD inviter", e)
	}
	f.pending = pending
	return f, ad
}
func TestInvitationADIssuerSQLite(t *testing.T)   { testInvitationADIssuer(t, false) }
func TestInvitationADIssuerPostgres(t *testing.T) { testInvitationADIssuer(t, true) }
func testInvitationADIssuer(t *testing.T, pg bool) {
	t.Run("actual_TLS_LDAP_inviter_and_final_liveproof", func(t *testing.T) {
		f, _ := newADInvitationFixture(t, pg)
		_, raw := f.invitation(t, "AD_invite")
		a := f.activation(t, raw)
		f.stageActivation(t, a)
		completed, e := f.invites.CompleteActivation(f.ctx, a)
		if e != nil {
			t.Fatal("AD issuer finalization", e)
		}
		if completed.View.State != "completed" || completed.View.MFASatisfied || completed.SessionToken != "" {
			t.Fatal("unexpected AD inviter session authority")
		}
	})
	t.Run("disabled_historical_issuer_blocks_delivery_and_publication", func(t *testing.T) {
		f, ad := newADInvitationFixture(t, pg)
		_, raw := f.invitation(t, "AD_invite")
		a := f.activation(t, raw)
		f.stageActivation(t, a)
		ad.wire.disabled.Store(true)
		if _, e := f.invites.CompleteActivation(f.ctx, a); e == nil {
			t.Fatal("disabled issuer activated account")
		}
		f.assertPending(t)
	})
	t.Run("restart_without_volatile_issuer_proof_retires_partial_positive_intent", func(t *testing.T) {
		f, _ := newADInvitationFixture(t, pg)
		_, raw := f.invitation(t, "AD_invite")
		a := f.activation(t, raw)
		f.stageActivation(t, a)
		authority := f.s.Coordinator.Authority
		f.s.Coordinator.Authority = &inviteFaultAuthority{Authority: authority, remaining: 2}
		if _, e := f.invites.CompleteActivation(f.ctx, a); e == nil {
			t.Fatal("partial journal accepted")
		}
		f.s.Coordinator.Authority = authority
		// Recover uses the process/startup context, never the lost request's private
		// AD proof. It must keep restrictions and safely retire the positive intent.
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("missing private proof left global barrier", e)
		}
		f.assertPending(t)
		if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			var pending int
			if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM security_operations WHERE status='pending'`, nil, func(r storage.IdentityRows) error { return r.Scan(&pending) }); e != nil {
				return e
			}
			if pending != 0 {
				t.Fatal("global barrier retained")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	})
}
