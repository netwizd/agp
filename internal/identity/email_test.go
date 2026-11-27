package identity

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type emailTestSender struct {
	mu       sync.Mutex
	calls    int
	code, to string
	state    mailtransport.State
	err      error
}

func (s *emailTestSender) Send(_ context.Context, m mailtransport.Message) (mailtransport.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.to = m.To
	s.code = regexp.MustCompile(`[0-9]{8}`).FindString(string(m.Text))
	return mailtransport.Result{State: s.state}, s.err
}
func (s *emailTestSender) snapshot() (int, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.code, s.to
}

type emailFixture struct {
	*fixture
	email   *EmailService
	sender  *emailTestSender
	actor   EmailActor
	session string
}

func newEmailFixture(t *testing.T, pg bool) *emailFixture {
	t.Helper()
	return attachEmailFixture(t, newFixture(t, pg))
}
func attachEmailFixture(t *testing.T, f *fixture) *emailFixture {
	t.Helper()
	enc, mac := make([]byte, 32), make([]byte, 32)
	rand.Read(enc)
	rand.Read(mac)
	keys, e := NewEmailKeyring("contact_key_v1", "otp_pepper_v1", map[string][]byte{"contact_key_v1": enc}, map[string][]byte{"otp_pepper_v1": mac})
	if e != nil {
		t.Fatal(e)
	}
	clear(enc)
	clear(mac)
	sender := &emailTestSender{state: mailtransport.Accepted}
	email, e := NewEmailService(f.s, keys, sender)
	if e != nil {
		t.Fatal(e)
	}
	f.s.WithEmail(email)
	t.Cleanup(email.Close)
	out := &emailFixture{fixture: f, email: email, sender: sender}
	out.actor, out.session = out.newActor(t, f.user.ID, "management")
	return out
}
func (f *emailFixture) newActor(t *testing.T, principal, audience string) (EmailActor, string) {
	t.Helper()
	_, hash, e := auth.NewToken()
	if e != nil {
		t.Fatal(e)
	}
	id := securitystate.ID("session")
	origin := f.s.Profile.ManagementOrigin
	if audience == "login" {
		origin = f.s.Profile.LoginOrigin
	}
	e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return InsertSession(f.ctx, tx, domain.Session{ID: id, UserID: principal, TokenHash: hash, CSRFHash: auth.TokenHash("synthetic_csrf"), Audience: audience, AudienceOrigin: origin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), MFAAt: &f.now, PrimaryAt: &f.now, LastSeenAt: &f.now})
	})
	if e != nil {
		t.Fatal(e)
	}
	return EmailActor{TokenHash: hash, Audience: audience, Origin: origin, SourceIP: "192.0.2.14"}, id
}
func (f *emailFixture) contact(t *testing.T, address string) ContactView {
	t.Helper()
	c, e := f.email.CreateContact(f.ctx, f.actor, address)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func (f *emailFixture) flow(t *testing.T) FlowAuth {
	t.Helper()
	tr, e := f.email.StartFlow(f.ctx, f.actor.Audience, f.actor.Origin, "synthetic_csrf", f.actor.TokenHash, f.actor.SourceIP)
	if e != nil {
		t.Fatal(e)
	}
	if tr.View.State != "pending_mfa" || tr.View.NextStep != "email_code" || tr.View.MFASatisfied {
		t.Fatal("flow contract changed")
	}
	return FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "synthetic_csrf", Origin: f.actor.Origin}
}
func (f *emailFixture) issue(t *testing.T, a FlowAuth, c ContactView) ChallengeView {
	t.Helper()
	v, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "verify_email", ContactID: c.ID}, f.actor.SourceIP)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *emailFixture) deliver(t *testing.T) (string, string) {
	t.Helper()
	yes, e := f.email.ProcessOne(f.ctx)
	if !yes || e != nil {
		t.Fatal("send failed", e)
	}
	_, code, to := f.sender.snapshot()
	if len(code) != 8 {
		t.Fatal("transport lacked code")
	}
	return code, to
}
func emailRun(t *testing.T, pg bool) {
	t.Run("encrypted_contact_confirm_no_session_and_one_consume", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "Recipient@corp.example")
		if c.Verified || c.MaskedAddress != "R***@corp.example" {
			t.Fatal("unsafe contact view")
		}
		a := f.flow(t)
		v := f.issue(t, a, c)
		var raw string
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return securitystate.One(f.ctx, tx, `SELECT ciphertext FROM identity_contacts WHERE id=?`, []any{c.ID}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
		}); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(raw, "Recipient") {
			t.Fatal("address plaintext stored")
		}
		again, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "verify_email", ContactID: c.ID}, f.actor.SourceIP)
		if e != nil || again.ID != v.ID {
			t.Fatal("lost issue response duplicated challenge", e)
		}
		code, to := f.deliver(t)
		if to != "Recipient@corp.example" {
			t.Fatal("recipient not from contact")
		}
		get, e := f.email.Get(f.ctx, a, v.ID)
		if e != nil || get.DeliveryState != "accepted" {
			t.Fatal("accepted state", e)
		}
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				view, e := f.email.Verify(f.ctx, a, v.ID, code)
				if e == nil && view.MFASatisfied {
					t.Error("email became MFA")
				}
				results <- e
			})
		}
		wg.Wait()
		close(results)
		success := 0
		for e := range results {
			if e == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatal("consume was not single use")
		}
		completion, e := f.email.CompleteFlow(f.ctx, a)
		if e != nil || completion.View.State != "completed" || completion.View.MFASatisfied || completion.SessionToken != "" || completion.CSRFToken != "" || completion.Session.ID != "" {
			t.Fatal("email completion minted credential", e)
		}
		list, e := f.email.Contacts(f.ctx, f.actor)
		if e != nil || len(list.Items) != 1 || !list.Items[0].Verified || list.Items[0].Revision != 2 {
			t.Fatal("contact verification not atomic", e)
		}
		if _, e = f.email.CompleteFlow(f.ctx, a); e == nil {
			t.Fatal("completion replay allowed")
		}
		f.email.vault.mu.Lock()
		n := len(f.email.vault.entries)
		f.email.vault.mu.Unlock()
		if n != 0 {
			t.Fatal("consumed DEK retained")
		}
	})
	t.Run("bad_codes_commit_joint_limit", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		v := f.issue(t, a, c)
		for i := 0; i < 5; i++ {
			if _, e := f.email.Verify(f.ctx, a, v.ID, "bad-code"); !errors.Is(e, ErrProof) {
				t.Fatalf("wrong attempt %d did not fail uniformly: %v", i, e)
			}
		}
		var attempts, challengeAttempts int
		e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return securitystate.One(f.ctx, tx, `SELECT f.attempts,c.attempts FROM identity_flows f JOIN identity_email_challenges c ON c.flow_id=f.id WHERE c.id=?`, []any{v.ID}, func(r storage.IdentityRows) error { return r.Scan(&attempts, &challengeAttempts) })
		})
		if e != nil || attempts != 5 || challengeAttempts != 5 {
			t.Fatal("bad-code increments rolled back", attempts, challengeAttempts, e)
		}
		if _, e = f.email.Verify(f.ctx, a, v.ID, "12345678"); !errors.Is(e, ErrLimited) {
			t.Fatal("joint limit bypassed", e)
		}
	})
	t.Run("resend_race_cancels_generation_preserves_expiry_and_budget", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		old := f.issue(t, a, c)
		oldCode, _ := f.deliver(t)
		f.clock(f.now.Add(time.Minute))
		var wg sync.WaitGroup
		views := make(chan ChallengeView, 2)
		errs := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				v, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "verify_email", ContactID: c.ID}, f.actor.SourceIP)
				views <- v
				errs <- e
			})
		}
		wg.Wait()
		close(views)
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		id := ""
		for v := range views {
			if id != "" && id != v.ID {
				t.Fatal("parallel resend created two generations")
			}
			id = v.ID
			if v.Generation != 2 || !v.ExpiresAt.Equal(old.ExpiresAt) {
				t.Fatal("resend extended lifetime")
			}
		}
		if _, e := f.email.Verify(f.ctx, a, old.ID, oldCode); e == nil {
			t.Fatal("cancelled generation accepted")
		}
		newCode, _ := f.deliver(t)
		if _, e := f.email.Verify(f.ctx, a, id, newCode); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("target_budget_across_new_flow_contact_and_case", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		for i := 0; i < 5; i++ {
			c := f.contact(t, "SameTarget@corp.example")
			f.issue(t, f.flow(t), c)
		}
		c := f.contact(t, "sametarget@corp.example")
		if _, e := f.email.Issue(f.ctx, f.flow(t), EmailIssue{Purpose: "verify_email", ContactID: c.ID}, "192.0.2.99"); !errors.Is(e, ErrLimited) {
			t.Fatal("new contact/flow/case reset target budget", e)
		}
	})
	t.Run("recent_primary_separate_from_mfa_and_masked_read", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		f.contact(t, "target@corp.example")
		e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET primary_at=NULL WHERE id=?`, f.session)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.email.CreateContact(f.ctx, f.actor, "second@corp.example"); !errors.Is(e, ErrEmailReauthRequired) {
			t.Fatal("NULL primary inferred from MFA", e)
		}
		if list, e := f.email.Contacts(f.ctx, f.actor); e != nil || len(list.Items) != 1 {
			t.Fatal("masked GET required recent primary", e)
		}
		if _, e = f.email.StartFlow(f.ctx, f.actor.Audience, f.actor.Origin, "csrf", f.actor.TokenHash, f.actor.SourceIP); !errors.Is(e, ErrEmailReauthRequired) {
			t.Fatal("unknown primary start did not request reauth", e)
		}
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET primary_at=? WHERE id=?`, f.now.Add(-6*time.Minute), f.session)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.email.CreateContact(f.ctx, f.actor, "second@corp.example"); !errors.Is(e, ErrEmailReauthRequired) {
			t.Fatal("stale primary accepted", e)
		}
	})
	t.Run("replace_floor_cancel_restore_and_exact_CAS", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "old@corp.example")
		a := f.flow(t)
		v := f.issue(t, a, c)
		var original emailContact
		e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			x, e := f.email.readContact(f.ctx, tx, c.ID, f.user.ID)
			if e == nil {
				original = *x
			}
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.email.ReplaceContact(f.ctx, f.actor, c.ID, 2, "new@corp.example"); !errors.Is(e, ErrContactStale) {
			t.Fatal("stale contact CAS accepted", e)
		}
		updated, e := f.email.ReplaceContact(f.ctx, f.actor, c.ID, 1, "new@corp.example")
		if e != nil || updated.AuthenticatorVersion != 2 || updated.Revision != 2 || updated.Verified {
			t.Fatal("replace failed", e)
		}
		if _, e = f.email.Verify(f.ctx, a, v.ID, "12345678"); e == nil {
			t.Fatal("old contact challenge remained valid")
		}
		f.email.vault.mu.Lock()
		n := len(f.email.vault.entries)
		f.email.vault.mu.Unlock()
		if n != 0 {
			t.Fatal("replaced contact key retained")
		}
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE identity_contacts SET authenticator_version=1,revision=1,key_id=?,nonce=?,ciphertext=? WHERE id=?`, original.keyID, original.nonce, original.ciphertext, c.ID)
			if e != nil {
				return e
			}
			_, e = tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=NULL WHERE id=?`, f.session)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.email.Contacts(f.ctx, f.actor); e == nil {
			t.Fatal("restored old contact below independent floor allowed")
		}
	})
	t.Run("outbox_unknown_terminal_and_restart_loses_keys", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		v := f.issue(t, a, c)
		f.sender.state = mailtransport.Unknown
		f.sender.err = mailtransport.ErrUnknown
		if _, e := f.email.ProcessOne(f.ctx); !errors.Is(e, ErrEmailUnavailable) {
			t.Fatal("SMTP unknown not redacted", e)
		}
		get, e := f.email.Get(f.ctx, a, v.ID)
		if e != nil || get.DeliveryState != "failed" {
			t.Fatal("SMTP unknown public state", e)
		}
		if yes, e := f.email.ProcessOne(f.ctx); e != nil || yes {
			t.Fatal("unknown automatically retried", e)
		}
		calls, _, _ := f.sender.snapshot()
		if calls != 1 {
			t.Fatal("multiple SMTP calls")
		}
		f.clock(f.now.Add(time.Minute))
		newChallenge := f.issue(t, a, c)
		replacement, e := NewEmailService(f.s, f.email.keys, f.sender)
		if e != nil {
			t.Fatal(e)
		}
		defer replacement.Close()
		if e = replacement.Cleanup(f.ctx); e != nil {
			t.Fatal(e)
		}
		get, e = replacement.Get(f.ctx, a, newChallenge.ID)
		if e != nil || get.DeliveryState != "failed" {
			t.Fatal("restart resurrected outbox", e)
		}
		if yes, e := replacement.ProcessOne(f.ctx); e != nil || yes {
			t.Fatal("restart resent code", e)
		}
	})
	t.Run("purpose_contact_browser_epoch_and_source_denied", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		if _, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "invite_confirmation", ContactID: c.ID}, f.actor.SourceIP); e == nil {
			t.Fatal("missing invite authorization allowed")
		}
		if _, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "recovery_confirmation", ContactID: c.ID}, f.actor.SourceIP); e == nil {
			t.Fatal("purpose mismatch allowed")
		}
		v := f.issue(t, a, c)
		code, _ := f.deliver(t)
		wrong := a
		wrong.Binding = "foreign"
		if _, e := f.email.Verify(f.ctx, wrong, v.ID, code); e == nil {
			t.Fatal("browser mismatch allowed")
		}
		other := f.flow(t)
		if _, e := f.email.Verify(f.ctx, other, v.ID, code); e == nil {
			t.Fatal("cross-flow code allowed")
		}
		e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=? WHERE id=?`, f.now, f.session)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.email.Verify(f.ctx, a, v.ID, code); e == nil {
			t.Fatal("revoked source allowed")
		}
	})
}
func TestEmailIdentitySQLite(t *testing.T)   { emailRun(t, false) }
func TestEmailIdentityPostgres(t *testing.T) { emailRun(t, true) }
func TestEmailMACAndVault(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	f := &flow{FlowView: FlowView{ID: "flow_1", Purpose: "verify_email", Audience: "login"}, PrincipalID: "principal_1"}
	c := &emailChallenge{ChallengeView: ChallengeView{ID: "challenge_1", Purpose: "verify_email"}, contact: "contact_1", contactVersion: 2, epoch: 3}
	baseline := emailChallengeMAC(key, c, f, "00123456")
	for _, change := range []func(){func() { c.ID = "challenge_2" }, func() { f.ID = "flow_2" }, func() { c.Purpose = "recovery_confirmation" }, func() { f.Audience = "management" }, func() { f.PrincipalID = "principal_2" }, func() { c.contact = "contact_2" }, func() { c.contactVersion++ }, func() { c.epoch++ }} {
		change()
		if emailChallengeMAC(key, c, f, "00123456") == baseline {
			t.Fatal("MAC omitted binding")
		}
		baseline = emailChallengeMAC(key, c, f, "00123456")
	}
	if emailMAC(key, "ab", "c") == emailMAC(key, "a", "bc") {
		t.Fatal("ambiguous MAC encoding")
	}
	now := time.Now()
	v := newEmailVault(1)
	defer v.close()
	ref, k, e := v.put(now, now.Add(30*time.Millisecond))
	if e != nil {
		t.Fatal(e)
	}
	clear(k)
	if _, _, e = v.put(now, now.Add(time.Minute)); e == nil {
		t.Fatal("vault capacity unbounded")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		v.mu.Lock()
		n := len(v.entries)
		v.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	v.mu.Lock()
	n := len(v.entries)
	v.mu.Unlock()
	if n != 0 || v.has(ref, now) {
		t.Fatal("TTL required caller cleanup")
	}
}
func TestEmailAddressAndKeySeparation(t *testing.T) {
	for _, bad := range []string{"Name <a@corp.example>", "a@corp.example\r\nBcc:x@corp.example", "тест@corp.example", " a@corp.example", "a@localhost", "a..b@corp.example", "a@127.0.0.1", "a@[127.0.0.1]", "a@corp_.example"} {
		if _, e := emailAddress(bad); e == nil {
			t.Fatal("unsupported address allowed")
		}
	}
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	rand.Read(b)
	if _, e := NewEmailKeyring("enc", "mac", map[string][]byte{"enc": a}, map[string][]byte{"mac": a}); e == nil {
		t.Fatal("same contact/MAC keys reused")
	}
	keys, e := NewEmailKeyring("enc", "mac", map[string][]byte{"enc": a}, map[string][]byte{"mac": b})
	if e != nil {
		t.Fatal(e)
	}
	clear(a)
	if len(keys.encryption["enc"]) != 32 || emailEqual(string(keys.encryption["enc"]), string(a)) {
		t.Fatal("keyring retained mutable caller buffer")
	}
	view := ContactView{ID: "contact_1", MaskedAddress: "a***@corp.example", Revision: securityjournal.UInt63(1), AuthenticatorVersion: 1}
	raw, e := json.Marshal(view)
	if e != nil || strings.Contains(string(raw), "ciphertext") {
		t.Fatal("contact serialized secret")
	}
}

func TestEmailLifecycleRacesSQLite(t *testing.T)   { testEmailLifecycleRaces(t, false) }
func TestEmailLifecycleRacesPostgres(t *testing.T) { testEmailLifecycleRaces(t, true) }
func testEmailLifecycleRaces(t *testing.T, pg bool) {
	t.Run("parallel_worker_one_send_and_missing_pepper_no_attempt", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		v := f.issue(t, a, c)
		var id string
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return securitystate.One(f.ctx, tx, `SELECT id FROM identity_email_outbox WHERE challenge_id=?`, []any{v.ID}, func(r storage.IdentityRows) error { return r.Scan(&id) })
		}); e != nil {
			t.Fatal(e)
		}
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { _ = f.email.SendQueued(f.ctx, id) })
		}
		wg.Wait()
		calls, code, _ := f.sender.snapshot()
		if calls != 1 {
			t.Fatal("parallel worker duplicated SMTP transaction", calls)
		}
		key := f.email.keys.peppers[f.email.keys.activePepper]
		delete(f.email.keys.peppers, f.email.keys.activePepper)
		if _, e := f.email.Verify(f.ctx, a, v.ID, code); !errors.Is(e, ErrEmailUnavailable) {
			t.Fatal("missing pepper was not infrastructure error", e)
		}
		f.email.keys.peppers[f.email.keys.activePepper] = key
		if _, e := f.email.Verify(f.ctx, a, v.ID, code); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("cancel_expiry_and_epoch_delete_volatile_keys", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		v := f.issue(t, a, c)
		if e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
			if _, e := tx.Exec(f.ctx, `UPDATE identity_flows SET state='cancelled' WHERE id=?`, a.ID); e != nil {
				return e
			}
			return f.email.CancelFlow(f.ctx, tx, a.ID)
		}); e != nil {
			t.Fatal(e)
		}
		f.email.vault.mu.Lock()
		n := len(f.email.vault.entries)
		f.email.vault.mu.Unlock()
		if n != 0 {
			t.Fatal("cancel retained DEK")
		}
		if _, e := f.email.Verify(f.ctx, a, v.ID, "12345678"); e == nil {
			t.Fatal("cancelled flow verified")
		}
		b := f.flow(t)
		w := f.issue(t, b, c)
		f.clock(f.now.Add(6 * time.Minute))
		if e := f.email.Cleanup(f.ctx); e != nil {
			t.Fatal(e)
		}
		f.email.vault.mu.Lock()
		n = len(f.email.vault.entries)
		f.email.vault.mu.Unlock()
		if n != 0 {
			t.Fatal("expiry retained DEK")
		}
		if _, e := f.email.Verify(f.ctx, b, w.ID, "12345678"); e == nil {
			t.Fatal("expired flow verified")
		}
		// A mismatched live authority epoch closes the transaction before any code
		// compare; the restored database cannot manufacture the missing RAM keys.
		f.j.mu.Lock()
		f.j.head.Epoch = 2
		f.j.mu.Unlock()
		if _, e := f.email.Get(f.ctx, b, w.ID); e == nil {
			t.Fatal("authority epoch mismatch accepted")
		}
	})
	t.Run("issue_three_per_flow_and_cross_contact_principal_denied", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		f.issue(t, a, c)
		for range 2 {
			f.clock(f.now.Add(time.Minute))
			f.issue(t, a, c)
		}
		f.clock(f.now.Add(time.Minute))
		if _, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "verify_email", ContactID: c.ID}, f.actor.SourceIP); !errors.Is(e, ErrLimited) {
			t.Fatal("flow issue budget reset", e)
		}
		other, _ := f.newActor(t, f.other.ID, "login")
		foreign, e := f.email.CreateContact(f.ctx, other, "foreign@corp.example")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.email.Issue(f.ctx, f.flow(t), EmailIssue{Purpose: "verify_email", ContactID: foreign.ID}, f.actor.SourceIP); e == nil {
			t.Fatal("foreign contact accepted")
		}
	})
	t.Run("invalid_first_job_terminal_does_not_starve_next", func(t *testing.T) {
		f := newEmailFixture(t, pg)
		c := f.contact(t, "target@corp.example")
		a := f.flow(t)
		f.issue(t, a, c)
		second, _ := f.newActor(t, f.other.ID, "login")
		d, e := f.email.CreateContact(f.ctx, second, "second@corp.example")
		if e != nil {
			t.Fatal(e)
		}
		tr, e := f.email.StartFlow(f.ctx, "login", second.Origin, "csrf_2", second.TokenHash, "192.0.2.99")
		if e != nil {
			t.Fatal(e)
		}
		b := FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "csrf_2", Origin: second.Origin}
		if _, e = f.email.Issue(f.ctx, b, EmailIssue{Purpose: "verify_email", ContactID: d.ID}, "192.0.2.99"); e != nil {
			t.Fatal(e)
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=? WHERE id=?`, f.now, f.session)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		// IDs order tie may select either job first, so process both and assert only
		// the live recipient was passed to transport and no queued job remains.
		for range 2 {
			_, _ = f.email.ProcessOne(f.ctx)
		}
		calls, _, to := f.sender.snapshot()
		if calls != 1 || to != "second@corp.example" {
			t.Fatal("invalid job sent or live job starved", calls)
		}
		if yes, e := f.email.ProcessOne(f.ctx); yes || e != nil {
			t.Fatal("invalid job was requeued", e)
		}
	})
}
func TestEmailDirectorySourceSQLite(t *testing.T)   { testEmailDirectorySource(t, false) }
func TestEmailDirectorySourcePostgres(t *testing.T) { testEmailDirectorySource(t, true) }
func testEmailDirectorySource(t *testing.T, pg bool) {
	f := newDirectoryAuthFixture(t, pg, false)
	f.provision(t)
	login := f.login(t, "login")
	ef := attachEmailFixture(t, f.fixture)
	ef.actor = EmailActor{TokenHash: auth.TokenHash(login.SessionToken), Audience: "login", Origin: f.s.Profile.LoginOrigin, SourceIP: "192.0.2.14"}
	ef.session = login.Session.ID
	c := ef.contact(t, "directory-contact@corp.example")
	a := ef.flow(t)
	v := ef.issue(t, a, c)
	code, _ := ef.deliver(t)
	f.wire.disabled.Store(true)
	if _, e := ef.email.Verify(f.ctx, a, v.ID, code); e == nil {
		t.Fatal("disabled AD source confirmed email")
	}
	if _, e := ef.email.Contacts(f.ctx, ef.actor); e == nil {
		t.Fatal("disabled AD source read contacts")
	}
	f.wire.disabled.Store(false)
	if _, e := ef.email.Verify(f.ctx, a, v.ID, code); e != nil {
		t.Fatal(e)
	}
	// An external direct service call cannot mint the private session proof used
	// by contact mutations; it must perform the real DC read in withActor.
	f.wire.missingGroups.Store(true)
	if _, e := ef.email.CreateContact(f.ctx, ef.actor, "another@corp.example"); e == nil {
		t.Fatal("incomplete AD membership allowed contact mutation")
	}
}

func TestEmailRecoveryConfirmationSQLite(t *testing.T)   { testEmailRecoveryConfirmation(t, false) }
func TestEmailRecoveryConfirmationPostgres(t *testing.T) { testEmailRecoveryConfirmation(t, true) }
func testEmailRecoveryConfirmation(t *testing.T, pg bool) {
	f := newEmailFixture(t, pg)
	contact := f.contact(t, "verified@corp.example")
	verifyFlow := f.flow(t)
	challenge := f.issue(t, verifyFlow, contact)
	code, _ := f.deliver(t)
	if _, e := f.email.Verify(f.ctx, verifyFlow, challenge.ID, code); e != nil {
		t.Fatal(e)
	}
	primary := f.primary(t, f.start(t, "login", ""), "test-initial-password")
	_, recoveryCodes := f.enroll(t, primary)
	recovery := f.primary(t, f.start(t, "recover", ""), "test-initial-password")
	in := EmailIssue{Purpose: "recovery_confirmation", ContactID: contact.ID}
	if _, e := f.email.Issue(f.ctx, recovery, in, f.actor.SourceIP); e == nil {
		t.Fatal("email authorized recovery before independent recovery proof")
	}
	if _, e := f.s.RecoveryProof(f.ctx, recovery, recoveryCodes[0]); e != nil {
		t.Fatal(e)
	}
	issued, e := f.email.Issue(f.ctx, recovery, in, f.actor.SourceIP)
	if e != nil {
		t.Fatal(e)
	}
	confirmation, _ := f.deliver(t)
	view, e := f.email.Verify(f.ctx, recovery, issued.ID, confirmation)
	if e != nil || view.MFASatisfied || view.State != "pending_mfa" || view.NextStep != "totp_enrollment" {
		t.Fatal("email changed recovery permission/MFA state", e)
	}
	if _, e = f.s.Complete(f.ctx, recovery, "192.0.2.14", "email recovery fixture"); e == nil {
		t.Fatal("email completed recovery before factor replacement")
	}
	if _, e = f.email.Issue(f.ctx, recovery, in, f.actor.SourceIP); e == nil {
		t.Fatal("consumed recovery confirmation was resent")
	}
}
