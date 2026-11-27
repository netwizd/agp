package identity

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type inviteTestSender struct {
	mu       sync.Mutex
	messages []mailtransport.Message
	state    mailtransport.State
	err      error
	block    <-chan struct{}
	started  chan struct{}
}

func (s *inviteTestSender) Send(ctx context.Context, m mailtransport.Message) (mailtransport.Result, error) {
	s.mu.Lock()
	m.Text = append([]byte(nil), m.Text...)
	s.messages = append(s.messages, m)
	started := s.started
	block := s.block
	state, e := s.state, s.err
	s.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return mailtransport.Result{State: mailtransport.Unknown}, mailtransport.ErrUnknown
		}
	}
	return mailtransport.Result{State: state}, e
}
func (s *inviteTestSender) snapshot() []mailtransport.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mailtransport.Message(nil), s.messages...)
}

type inviteFixture struct {
	*emailFixture
	invites *InvitationService
	mail    *inviteTestSender
	admin   LifecycleActor
	pending *LifecycleUserView
}

func newInviteFixture(t *testing.T, pg bool) *inviteFixture {
	t.Helper()
	f := newEmailFixture(t, pg)
	f.j.mu.Lock()
	f.j.head.RecordedAt = f.now
	f.j.mu.Unlock()
	s := NewInvitationService(f.s)
	t.Cleanup(s.Close)
	sender := &inviteTestSender{state: mailtransport.Accepted}
	f.email.sender = sender
	out := &inviteFixture{emailFixture: f, invites: s, mail: sender, admin: LifecycleActor{TokenHash: f.actor.TokenHash, Origin: f.actor.Origin, SourceIP: f.actor.SourceIP}}
	p, e := s.CreatePending(f.ctx, out.admin, "pending_first", PendingUserInput{ID: securitystate.ID("usr"), Username: "new-user", DisplayName: "New User", GroupIDs: []string{}})
	if e != nil {
		t.Fatal("pending", e)
	}
	out.pending = p
	return out
}
func (f *inviteFixture) clockInvite(at time.Time) {
	f.clock(at)
	f.j.mu.Lock()
	f.j.head.RecordedAt = at
	f.j.mu.Unlock()
}
func (f *inviteFixture) invitation(t *testing.T, key string) (*InviteView, string) {
	t.Helper()
	v, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, key, f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 3600})
	if e != nil {
		t.Fatal("invite", e)
	}
	if ok, e := f.invites.ProcessDeliveryOne(f.ctx); !ok || e != nil {
		t.Fatal("invitation delivery", ok, e)
	}
	m := f.mail.snapshot()
	text := string(m[len(m)-1].Text)
	token := regexp.MustCompile(`#token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(text)
	if len(token) != 2 {
		t.Fatal("missing token fragment")
	}
	if !strings.Contains(text, f.s.Profile.LoginOrigin+"/auth-ui/activate#token=") || m[len(m)-1].To != "Recipient@corp.example" {
		t.Fatal("recipient or configured landing")
	}
	encoded, _ := json.Marshal(v)
	if strings.Contains(string(encoded), token[1]) {
		t.Fatal("API leaked capability")
	}
	return v, token[1]
}
func (f *inviteFixture) activation(t *testing.T, raw string) FlowAuth {
	t.Helper()
	tr, e := f.s.StartWithSource(f.ctx, "activate", "setup", f.s.Profile.LoginOrigin, "prelogin_csrf", "", "192.0.2.40")
	if e != nil {
		t.Fatal("start", e)
	}
	a := FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "prelogin_csrf", Origin: f.s.Profile.LoginOrigin}
	next, e := f.invites.BindInvitation(f.ctx, a, raw, "192.0.2.40")
	if e != nil {
		t.Fatal("bind", e)
	}
	if next.View.ID == a.ID || next.Binding == a.Binding || next.View.NextStep != "password_setup" || next.View.ContactID == "" || next.View.MFASatisfied {
		t.Fatal("unsafe invitation transition")
	}
	a.ID = next.View.ID
	a.Binding = next.Binding
	return a
}

// stageActivation uses public setup APIs and the actual mandatory email OTP;
// it never marks a stage ready with fixture SQL.
func (f *inviteFixture) stageActivation(t *testing.T, a FlowAuth) ([]byte, []string) {
	t.Helper()
	v, e := f.invites.SetInitialPassword(f.ctx, a, "  correct setup password  ")
	if e != nil {
		t.Fatal("password setup", e)
	}
	if v.NextStep != "email_code" || v.MFASatisfied || v.ContactID == "" {
		t.Fatal("email confirmation missing")
	}
	challenge, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "invite_confirmation", ContactID: v.ContactID}, "192.0.2.40")
	if e != nil {
		t.Fatal("OTP issue", e)
	}
	if ok, e := f.email.ProcessOne(f.ctx); !ok || e != nil {
		t.Fatal("OTP delivery", e)
	}
	msgs := f.mail.snapshot()
	code := regexp.MustCompile(`[0-9]{8}`).FindString(string(msgs[len(msgs)-1].Text))
	if len(code) != 8 {
		t.Fatal("OTP absent")
	}
	v, e = f.email.Verify(f.ctx, a, challenge.ID, code)
	if e != nil {
		t.Fatal("OTP verify", e)
	}
	if v.NextStep != "totp_enrollment" || v.MFASatisfied {
		t.Fatal("email proof expanded authority")
	}
	en, e := f.s.StartEnrollment(f.ctx, a)
	if e != nil {
		t.Fatal("initial TOTP", e)
	}
	u, e := url.Parse(en.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if e != nil {
		t.Fatal(e)
	}
	result, e := f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30))
	if e != nil {
		t.Fatal("TOTP confirmation", e)
	}
	if len(result.RecoveryCodes) != 10 || result.Flow.State != "ready" || result.Flow.MFASatisfied {
		t.Fatal("initial TOTP not staged")
	}
	if replay, e := f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); e == nil || len(replay.RecoveryCodes) != 0 {
		t.Fatal("recovery codes replayed")
	}
	return seed, result.RecoveryCodes
}
func (f *inviteFixture) assertPending(t *testing.T) {
	t.Helper()
	e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		var state, password string
		var n int
		if e := securitystate.One(f.ctx, tx, `SELECT lifecycle_state,password_hash FROM users WHERE id=?`, []any{f.pending.ID}, func(r storage.IdentityRows) error { return r.Scan(&state, &password) }); e != nil {
			return e
		}
		if state != "invited" || password != "" {
			t.Fatal("published pending password")
		}
		if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM mfa_factors WHERE principal_id=?`, []any{f.pending.ID}, func(r storage.IdentityRows) error { return r.Scan(&n) }); e != nil {
			return e
		}
		if n != 0 {
			t.Fatal("published initial factor early")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestInvitationsSQLite(t *testing.T)   { testInvitations(t, false) }
func TestInvitationsPostgres(t *testing.T) { testInvitations(t, true) }
func testInvitations(t *testing.T, pg bool) {
	t.Run("full_staged_setup_atomic_sessionless_activation", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		v, raw := f.invitation(t, "invite_first")
		a := f.activation(t, raw)
		f.assertPending(t)
		_, codes := f.stageActivation(t, a)
		f.assertPending(t)
		complete, e := f.s.Complete(f.ctx, a, "192.0.2.40", "invitation-test")
		if e != nil {
			t.Fatal("complete", e)
		}
		if complete.View.State != "completed" || complete.View.MFASatisfied || complete.SessionToken != "" || complete.CSRFToken != "" || complete.Session.ID != "" {
			t.Fatal("activation returned session authority")
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var state, phc string
			var sv, pv uint64
			var count int
			if e := securitystate.One(f.ctx, tx, `SELECT lifecycle_state,password_hash,security_version,password_version FROM users WHERE id=?`, []any{f.pending.ID}, func(r storage.IdentityRows) error { return r.Scan(&state, &phc, &sv, &pv) }); e != nil {
				return e
			}
			ok, e := auth.VerifyPassword("  correct setup password  ", phc)
			if e != nil || !ok || state != "active" || sv != 2 || pv != 2 {
				t.Fatal("atomic credentials absent", e)
			}
			if ok, _ := auth.VerifyPassword("correct setup password", phc); ok {
				t.Fatal("password silently trimmed")
			}
			if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM recovery_codes WHERE principal_id=? AND code_hash=?`, []any{f.pending.ID, auth.TokenHash(codes[0])}, func(r storage.IdentityRows) error { return r.Scan(&count) }); e != nil {
				return e
			}
			if count != 1 {
				t.Fatal("recovery hashes not installed")
			}
			if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, []any{f.pending.ID}, func(r storage.IdentityRows) error { return r.Scan(&count) }); e != nil {
				return e
			}
			if count != 0 {
				t.Fatal("session created")
			}
			tok, e := readLifecycleToken(f.ctx, tx, v.InviteID)
			if e != nil {
				return e
			}
			if tok.ConsumedAt == nil || tok.RevokedAt != nil {
				t.Fatal("token not atomically consumed")
			}
			st, e := readInviteStage(f.ctx, tx, a.ID)
			if e != nil {
				return e
			}
			if st.state != "completed" || st.passwordPHC != "" || st.sealed.Ciphertext != "" || st.codeHashes != "[]" {
				t.Fatal("staged secrets retained")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Complete(f.ctx, a, "192.0.2.40", "invitation-test"); e == nil {
			t.Fatal("completion replay granted")
		}
		_ = f.activationAttempt(t, raw)
	})
	t.Run("pending_metadata_idempotency_privilege_and_optional_transport", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		in := PendingUserInput{ID: f.pending.ID, Username: f.pending.Username, DisplayName: f.pending.DisplayName, GroupIDs: []string{}}
		replay, e := f.invites.CreatePending(f.ctx, f.admin, "pending_first", in)
		if e != nil || replay.ID != in.ID {
			t.Fatal("metadata retry", e)
		}
		in.DisplayName = "conflict"
		if _, e = f.invites.CreatePending(f.ctx, f.admin, "pending_first", in); !errors.Is(e, ErrLifecycleStale) {
			t.Fatal("different payload replay", e)
		}
		for _, id := range []string{"guard_setup_human", "other_prefix"} {
			if _, e = f.invites.CreatePending(f.ctx, f.admin, "bad_namespace", PendingUserInput{ID: id, Username: id, GroupIDs: []string{}}); e == nil {
				t.Fatal("service namespace accepted")
			}
		}
		if _, e = f.invites.CreatePending(f.ctx, f.admin, "group_grant", PendingUserInput{ID: securitystate.ID("usr"), Username: "no-admin", GroupIDs: []string{f.group.ID}}); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal("silent permission grant", e)
		}
		f.s.email = nil
		if _, e = f.invites.CreatePending(f.ctx, f.admin, "transport_optional", PendingUserInput{ID: securitystate.ID("usr"), Username: "no-transport", GroupIDs: []string{}}); e != nil {
			t.Fatal("pending CRUD needs SMTP", e)
		}
		if _, e = f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "delivery_unavailable", f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300}); !errors.Is(e, ErrLifecycleUnavailable) {
			t.Fatal("nil SMTP open", e)
		}
	})
	t.Run("claim_is_irreversible_and_browser_origin_csrf_bound", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		_, raw := f.invitation(t, "once")
		a := f.activation(t, raw)
		if e := f.activationAttempt(t, raw); e == nil {
			t.Fatal("mail capability exchanged twice")
		}
		for _, changed := range []FlowAuth{{ID: a.ID, Binding: "wrong", CSRF: a.CSRF, Origin: a.Origin}, {ID: a.ID, Binding: a.Binding, CSRF: "wrong", Origin: a.Origin}, {ID: a.ID, Binding: a.Binding, CSRF: a.CSRF, Origin: f.s.Profile.ManagementOrigin}} {
			if _, e := f.invites.SetInitialPassword(f.ctx, changed, "correct setup password"); e == nil {
				t.Fatal("unbound setup")
			}
		}
		if _, e := f.invites.SetInitialPassword(f.ctx, a, strings.Repeat("я", 513)); !errors.Is(e, ErrLifecycleInvalid) {
			t.Fatal("byte bound", e)
		}
		f.assertPending(t)
	})
	t.Run("cancel_expiry_reissue_and_restart_delivery", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		_, raw := f.invitation(t, "first")
		a := f.activation(t, raw)
		if _, e := f.invites.SetInitialPassword(f.ctx, a, "correct setup password"); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.Cancel(f.ctx, a); e != nil {
			t.Fatal("cancel", e)
		}
		if _, e := f.invites.SetInitialPassword(f.ctx, a, "correct setup password"); e == nil {
			t.Fatal("canceled reservation usable")
		}
		f.assertPending(t)
		_, raw = f.invitation(t, "second")
		a = f.activation(t, raw)
		_, newraw := f.invitation(t, "third")
		if _, e := f.invites.SetInitialPassword(f.ctx, a, "correct setup password"); e == nil {
			t.Fatal("reissue kept reserved predecessor")
		}
		b := f.activation(t, newraw)
		f.clockInvite(f.now.Add(6 * time.Minute))
		if _, e := f.invites.SetInitialPassword(f.ctx, b, "correct setup password"); e == nil {
			t.Fatal("expired reservation usable")
		}
		if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return f.invites.CleanupTx(f.ctx, tx, h) }); e != nil {
			t.Fatal(e)
		}
		f.assertPending(t)
	})
	t.Run("delivery_unknown_and_lost_volatile_key_never_retry", func(t *testing.T) {
		f := newInviteFixture(t, pg)
		f.mail.state = mailtransport.Unknown
		f.mail.err = mailtransport.ErrUnknown
		v, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "unknown", f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300})
		if e != nil {
			t.Fatal(e)
		}
		if yes, e := f.invites.ProcessDeliveryOne(f.ctx); !yes || e == nil {
			t.Fatal("unknown status missing")
		}
		if yes, e := f.invites.ProcessDeliveryOne(f.ctx); yes || e != nil {
			t.Fatal("automatic resend")
		}
		view, e := f.invites.GetDelivery(f.ctx, f.admin, v.DeliveryOperationID)
		if e != nil || view.State != "failed" {
			t.Fatal("unknown leaked as accepted", e)
		}
		v, e = f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "lostkey", f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 300})
		if e != nil {
			t.Fatal(e)
		}
		f.invites.vault.close()
		f.invites.vault = newEmailVault(1024)
		if yes, e := f.invites.ProcessDeliveryOne(f.ctx); !yes || e == nil {
			t.Fatal("lost key sent")
		}
		if len(f.mail.snapshot()) != 1 {
			t.Fatal("restart retried encrypted message")
		}
		view, e = f.invites.GetDelivery(f.ctx, f.admin, v.DeliveryOperationID)
		if e != nil || view.State != "failed" {
			t.Fatal("lostkey status", e)
		}
	})
}
func (f *inviteFixture) activationAttempt(t *testing.T, raw string) error {
	t.Helper()
	tr, e := f.invites.StartActivate(f.ctx, "setup", f.s.Profile.LoginOrigin, "attempt_csrf", "192.0.2.41")
	if e != nil {
		return e
	}
	_, e = f.invites.BindInvitation(f.ctx, FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "attempt_csrf", Origin: f.s.Profile.LoginOrigin}, raw, "192.0.2.41")
	return e
}
