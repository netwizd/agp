package identity

import (
	"context"
	"encoding/base32"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func inviteEnrollmentSeed(t *testing.T, uri string) []byte {
	t.Helper()
	u, e := url.Parse(uri)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if e != nil {
		t.Fatal(e)
	}
	return seed
}

type inviteFaultAuthority struct {
	securityjournal.Authority
	mu        sync.Mutex
	remaining int
}

func (a *inviteFaultAuthority) Append(ctx context.Context, r securityjournal.AppendRequest) (securityjournal.Event, error) {
	a.mu.Lock()
	if a.remaining == 0 {
		a.mu.Unlock()
		return securityjournal.Event{}, securityjournal.ErrUnavailable
	}
	a.remaining--
	a.mu.Unlock()
	return a.Authority.Append(ctx, r)
}
func TestInvitationBoundariesSQLite(t *testing.T)   { testInvitationBoundaries(t, false) }
func TestInvitationBoundariesPostgres(t *testing.T) { testInvitationBoundaries(t, true) }
func testInvitationBoundaries(t *testing.T, pg bool) {
	t.Run("partial_journal_no_partial_credentials_then_recover", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		v, raw := f.invitation(t, "partial")
		a := f.activation(t, raw)
		f.stageActivation(t, a)
		fault := &inviteFaultAuthority{Authority: f.j, remaining: 2}
		f.s.Coordinator.Authority = fault
		if _, e := f.invites.CompleteActivation(f.ctx, a); e == nil {
			t.Fatal("partial journal accepted")
		}
		f.assertPending(t)
		var consumed bool
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			tok, e := readLifecycleToken(f.ctx, tx, v.InviteID)
			if e == nil {
				consumed = tok.ConsumedAt != nil
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if consumed {
			t.Fatal("partial operation consumed token")
		}
		f.s.Coordinator.Authority = f.j
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("durable operation recovery", e)
		}
		if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			var state string
			if e := securitystate.One(f.ctx, tx, `SELECT lifecycle_state FROM users WHERE id=?`, []any{f.pending.ID}, func(r storage.IdentityRows) error { return r.Scan(&state) }); e != nil {
				return e
			}
			if state != "active" {
				t.Fatal("valid local recovery not materialized")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("expiry_after_partial_journal_retires_barrier_without_positive_publication", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		_, raw := f.invitation(t, "expire_partial")
		a := f.activation(t, raw)
		f.stageActivation(t, a)
		f.s.Coordinator.Authority = &inviteFaultAuthority{Authority: f.j, remaining: 1}
		if _, e := f.invites.CompleteActivation(f.ctx, a); e == nil {
			t.Fatal("partial journal accepted")
		}
		f.clockInvite(f.now.Add(6 * time.Minute))
		f.s.Coordinator.Authority = f.j
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal("expired intent left global barrier", e)
		}
		f.assertPending(t)
		if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			var pending int
			if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM security_operations WHERE status='pending'`, nil, func(r storage.IdentityRows) error { return r.Scan(&pending) }); e != nil {
				return e
			}
			if pending != 0 {
				t.Fatal("barrier not retired")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("restored_issued_row_cannot_reclaim_spent_guard", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		v, raw := f.invitation(t, "restore_claim")
		a := f.activation(t, raw)
		// Simulate CP snapshot rollback while independent guard receipts survive.
		// Dropping a migration guard is fixture-only; normal APIs cannot unreserve.
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if pg {
				if _, e := tx.Exec(f.ctx, `ALTER TABLE identity_one_time_tokens DISABLE TRIGGER identity_one_time_terminal`); e != nil {
					return e
				}
			} else {
				if _, e := tx.Exec(f.ctx, `DROP TRIGGER identity_one_time_terminal`); e != nil {
					return e
				}
			}
			_, e := tx.Exec(f.ctx, `UPDATE identity_one_time_tokens SET reserved_flow_id='',reserved_binding_hash='',reserved_at=NULL WHERE id=?`, v.InviteID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if e := f.activationAttempt(t, raw); e == nil {
			t.Fatal("snapshot rollback reopened spent raw token")
		}
		if _, e := f.invites.SetInitialPassword(f.ctx, a, "correct setup password"); e == nil {
			t.Fatal("inconsistent reservation accepted")
		}
	})
	t.Run("pending_principal_normal_paths_failclosed", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		_, hash, e := auth.NewToken()
		if e != nil {
			t.Fatal(e)
		}
		sessionID := securitystate.ID("session")
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return InsertSession(f.ctx, tx, domain.Session{ID: sessionID, UserID: f.pending.ID, TokenHash: hash, CSRFHash: auth.TokenHash("csrf"), Audience: "management", AudienceOrigin: f.s.Profile.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), MFAAt: &f.now, PrimaryAt: &f.now, LastSeenAt: &f.now})
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Session(f.ctx, hash, "management", f.s.Profile.ManagementOrigin); e == nil {
			t.Fatal("pending session authorized")
		}
		actor := LifecycleActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin, SourceIP: "192.0.2.90"}
		if _, e = f.invites.CreatePending(f.ctx, actor, "forbidden", PendingUserInput{ID: securitystate.ID("usr"), Username: "nested-invite", GroupIDs: []string{}}); e == nil {
			t.Fatal("pending actor obtained management authority")
		}
	})
	t.Run("fresh_actor_and_ifmatch_before_metadata_replay", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		in := InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300}
		v, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "metadata", f.pending.Revision, in)
		if e != nil {
			t.Fatal(e)
		}
		same, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "metadata", f.pending.Revision, in)
		if e != nil || same.InviteID != v.InviteID {
			t.Fatal("metadata replay", e)
		}
		if _, e = f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "metadata", f.pending.Revision+1, in); !errors.Is(e, ErrLifecycleStale) {
			t.Fatal("CAS after replay", e)
		}
		f.clockInvite(f.now.Add(6 * time.Minute))
		if _, e = f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "metadata", f.pending.Revision, in); !errors.Is(e, ErrLifecycleReauthRequired) {
			t.Fatal("stale actor replay", e)
		}
	})
	t.Run("concurrent_worker_single_claim_no_key_theft", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		released := make(chan struct{})
		started := make(chan struct{}, 1)
		f.mail.block = released
		f.mail.started = started
		if _, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "worker_race", f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300}); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { _, e := f.invites.ProcessDeliveryOne(f.ctx); done <- e }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("SMTP not reached")
		}
		if yes, e := f.invites.ProcessDeliveryOne(f.ctx); yes || e != nil {
			t.Fatal("sending row selected again")
		}
		close(released)
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if len(f.mail.snapshot()) != 1 {
			t.Fatal("multiple SMTP sends")
		}
	})
}
