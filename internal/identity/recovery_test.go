package identity

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// The database and lifecycle APIs are real. The independent journal and SMTP
// sender are explicit deterministic doubles; this is not corporate acceptance.
type recoveryFixture struct {
	*emailFixture
	recovery          *RecoveryService
	creator, reviewer LifecycleActor
	target            domain.User
	executor          domain.User
	seed              []byte
	codes             []string
	mail              *inviteTestSender
}

func newRecoveryFixture(t *testing.T, pg bool, privileged bool) *recoveryFixture {
	t.Helper()
	var target, executor domain.User
	base := newFixtureSetup(t, pg, func(ctx context.Context, s storage.Store, _ string) error {
		phc, e := auth.HashPassword("existing target password", auth.Argon2idParams{Memory: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
		if e != nil {
			return e
		}
		v, e := s.CreateUser(ctx, domain.UserInput{Username: "recovery-target", PasswordHash: phc, IsAdmin: privileged})
		if e != nil {
			return e
		}
		target = *v
		exec, e := s.CreateUser(ctx, domain.UserInput{Username: "fourth-operator", PasswordHash: phc, IsAdmin: true})
		if e != nil {
			return e
		}
		executor = *exec
		return nil
	})
	email := attachEmailFixture(t, base)
	reviewer, _ := email.newActor(t, base.other.ID, "management")
	mail := &inviteTestSender{state: mailtransport.Accepted}
	email.email.sender = mail
	inv := base.s.invitations.(*InvitationService)
	t.Cleanup(inv.Close)
	f := &recoveryFixture{emailFixture: email, recovery: base.s.recovery.(*RecoveryService), creator: LifecycleActor{email.actor.TokenHash, email.actor.Origin, email.actor.SourceIP}, reviewer: LifecycleActor{reviewer.TokenHash, reviewer.Origin, reviewer.SourceIP}, target: target, executor: executor, mail: mail}
	a := f.startTarget(t, "login", "login")
	en, e := f.s.StartEnrollment(f.ctx, a)
	if e != nil {
		t.Fatal("target enrollment", e)
	}
	u, e := url.Parse(en.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if e != nil {
		t.Fatal(e)
	}
	proof, e := f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30))
	if e != nil {
		t.Fatal("target enrollment proof", e)
	}
	f.seed = seed
	f.codes = proof.RecoveryCodes
	f.clock(f.now.Add(30 * time.Second))
	return f
}
func (f *recoveryFixture) startTarget(t *testing.T, purpose, audience string) FlowAuth {
	t.Helper()
	origin := f.s.Profile.ManagementOrigin
	if audience == "setup" || audience == "login" {
		origin = f.s.Profile.LoginOrigin
	}
	tr, e := f.s.StartWithSource(f.ctx, purpose, audience, origin, "recovery_csrf", "", "192.0.2.61")
	if e != nil {
		t.Fatal("start", e)
	}
	a := FlowAuth{tr.View.ID, tr.Binding, "recovery_csrf", origin}
	if audience != "setup" {
		tr, e = f.s.Primary(f.ctx, a, f.target.Username, "existing target password", "192.0.2.61")
		if e != nil {
			t.Fatal("primary", e)
		}
		a.ID = tr.View.ID
		a.Binding = tr.Binding
	}
	return a
}
func (f *recoveryFixture) plan(t *testing.T, action string) *RecoverySecurityOperation {
	t.Helper()
	var sv uint64
	e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(f.ctx, tx, `SELECT security_version FROM users WHERE id=?`, []any{f.target.ID}, func(row storage.IdentityRows) error { return row.Scan(&sv) })
	})
	if e != nil {
		t.Fatal(e)
	}
	op, e := f.recovery.Plan(f.ctx, f.creator, f.target.ID, securitystate.ID("request"), RecoveryPlanRequest{TargetPrincipalID: f.target.ID, ExpectedSecurityVersion: securityjournal.UInt63(sv), AllowedAction: action, ExpiresAt: f.now.Add(4 * time.Minute), Reason: "owner requested exact recovery"})
	if e != nil {
		t.Fatal("plan", e)
	}
	if op.Family != "identity_recovery" || op.RecoveryRequest.ObservedFloors == nil || op.RecoveryRequest.CustodianPrincipalID != f.user.ID {
		t.Fatal("missing frozen authority")
	}
	digest, e := configDigest(op.RecoveryRequest)
	if e != nil || digest != op.RequestDigest {
		t.Fatal("intent digest")
	}
	return op
}
func configDigest(v any) (string, error) { return configmodel.Digest(v) }
func (f *recoveryFixture) approve(t *testing.T, op *RecoverySecurityOperation) {
	t.Helper()
	_, e := f.recovery.ApproveOperationRequest(f.ctx, f.reviewer, op.ID, securitystate.ID("request"), op.RequestDigest, "independent full intent review")
	if e != nil {
		t.Fatal("approve", e)
	}
}
func (f *recoveryFixture) execute(t *testing.T, op *RecoverySecurityOperation) *RecoverySecurityOperation {
	t.Helper()
	out, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "execute reviewed exact action")
	if e != nil {
		t.Fatal("execute", e)
	}
	if out.State != "applied" {
		t.Fatal("not applied", out.State)
	}
	return out
}
func (f *recoveryFixture) ticketFlow(t *testing.T, op *RecoverySecurityOperation) FlowAuth {
	t.Helper()
	ticket, e := f.recovery.IssueTicket(f.ctx, f.creator, op.ID)
	if e != nil {
		t.Fatal("ticket", e)
	}
	if !validLifecycleSecret(ticket.Ticket) {
		t.Fatal("ticket entropy/encoding")
	}
	if _, e = f.recovery.IssueTicket(f.ctx, f.creator, op.ID); !errors.Is(e, storage.ErrConflict) {
		t.Fatal("raw ticket replay", e)
	}
	a := f.startTarget(t, "recover", "setup")
	tr, e := f.recovery.ConsumeSupervisedTicket(f.ctx, a, ticket.Ticket, "192.0.2.61")
	if e != nil {
		t.Fatal("ticket consume", e)
	}
	if tr.View.ID == a.ID || tr.Binding == a.Binding || tr.View.MFASatisfied {
		t.Fatal("ticket did not rotate setup")
	}
	if _, e = f.recovery.ConsumeSupervisedTicket(f.ctx, a, ticket.Ticket, "192.0.2.61"); e == nil {
		t.Fatal("ticket reused")
	}
	a.ID = tr.View.ID
	a.Binding = tr.Binding
	return a
}
func (f *recoveryFixture) password(t *testing.T) (string, uint64, uint64) {
	t.Helper()
	var hash string
	var sv, pv uint64
	e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(f.ctx, tx, `SELECT password_hash,security_version,password_version FROM users WHERE id=?`, []any{f.target.ID}, func(row storage.IdentityRows) error { return row.Scan(&hash, &sv, &pv) })
	})
	if e != nil {
		t.Fatal(e)
	}
	return hash, sv, pv
}
func (f *recoveryFixture) factor(t *testing.T) (uint64, bool, string) {
	t.Helper()
	var v uint64
	var revoked bool
	var ciphertext string
	e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(f.ctx, tx, `SELECT version,revoked,ciphertext FROM mfa_factors WHERE principal_id=?`, []any{f.target.ID}, func(row storage.IdentityRows) error { return row.Scan(&v, &revoked, &ciphertext) })
	})
	if e != nil {
		t.Fatal(e)
	}
	return v, revoked, ciphertext
}
func (f *recoveryFixture) seedVerifiedContact(t *testing.T) {
	t.Helper()
	// An ordinary account manages its own contact through the login audience.
	// It must not acquire management admission just to prepare a reset fixture.
	actor, _ := f.newActor(t, f.target.ID, "login")
	c, e := f.email.CreateContact(f.ctx, actor, "Reset.Recipient@corp.example")
	if e != nil {
		t.Fatal("contact", e)
	}
	// Trusted fixture bootstrap of an already verified saved contact. Encryption,
	// target MAC limits, volatile outbox and delivery remain actual production code.
	e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(f.ctx, `UPDATE identity_contacts SET verified=TRUE WHERE id=?`, c.ID)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}
func (f *recoveryFixture) resetToken(t *testing.T) string {
	t.Helper()
	e := f.recovery.RequestPasswordReset(f.ctx, f.s.Profile.LoginOrigin, "192.0.2.62", PasswordResetRequest{Username: f.target.Username, Email: "Reset.Recipient@corp.example"})
	if e != nil {
		t.Fatal(e)
	}
	yes, e := f.s.invitations.(*InvitationService).ProcessDeliveryOne(f.ctx)
	if !yes || e != nil {
		t.Fatal("reset delivery", yes, e)
	}
	messages := f.mail.snapshot()
	if len(messages) != 1 {
		t.Fatal("unexpected message count")
	}
	parts := regexp.MustCompile(`#token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(string(messages[0].Text))
	if len(parts) != 2 || messages[0].To != "Reset.Recipient@corp.example" {
		t.Fatal("reset message missing saved contact")
	}
	return parts[1]
}
func TestRecoveryLifecycleSQLite(t *testing.T)   { recoveryLifecycleMatrix(t, false) }
func TestRecoveryLifecyclePostgres(t *testing.T) { recoveryLifecycleMatrix(t, true) }
func recoveryLifecycleMatrix(t *testing.T, pg bool) {
	t.Run("supervised_password_only", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		fv, _, cipher := f.factor(t)
		op := f.plan(t, "reset_password")
		f.approve(t, op)
		f.execute(t, op)
		hash, sv, pv := f.password(t)
		if hash != "" || sv != 2 || pv != 2 {
			t.Fatal("old password was not restricted")
		}
		a := f.ticketFlow(t, op)
		if _, e := f.s.StartEnrollment(f.ctx, a); e == nil {
			t.Fatal("reset ticket authorized MFA")
		}
		v, e := f.recovery.SetResetPassword(f.ctx, a, "  replacement target password  ")
		if e != nil || v.State != "ready" || v.NextStep != "complete" {
			t.Fatal("stage", e)
		}
		done, e := f.s.Complete(f.ctx, a, "192.0.2.61", "fixture")
		if e != nil || done.View.State != "completed" || done.SessionToken != "" || done.CSRFToken != "" {
			t.Fatal("reset completed as session", e)
		}
		hash, sv, pv = f.password(t)
		ok, _ := auth.VerifyPassword("  replacement target password  ", hash)
		if !ok || sv != 3 || pv != 3 {
			t.Fatal("replacement password not atomically published")
		}
		after, revoked, afterCipher := f.factor(t)
		if after != fv || revoked || afterCipher != cipher {
			t.Fatal("reset changed MFA")
		}
		if _, e = f.s.Complete(f.ctx, a, "192.0.2.61", "fixture"); e == nil {
			t.Fatal("completion replay")
		}
	})
	t.Run("supervised_mfa_only", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		before, _, oldPV := f.password(t)
		op := f.plan(t, "replace_mfa")
		f.approve(t, op)
		f.execute(t, op)
		a := f.ticketFlow(t, op)
		if _, e := f.recovery.SetResetPassword(f.ctx, a, "forbidden replacement password"); e == nil {
			t.Fatal("MFA ticket authorized password")
		}
		en, e := f.s.StartEnrollment(f.ctx, a)
		if e != nil {
			t.Fatal("new MFA", e)
		}
		u, _ := url.Parse(en.ProvisioningURI)
		seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		if e != nil {
			t.Fatal(e)
		}
		res, e := f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30))
		if e != nil || len(res.RecoveryCodes) != 10 || res.Flow.MFASatisfied {
			t.Fatal("MFA enrollment", e)
		}
		done, e := f.s.Complete(f.ctx, a, "192.0.2.61", "fixture")
		if e != nil || done.View.State != "completed" || done.SessionToken != "" {
			t.Fatal("MFA completion", e)
		}
		after, sv, pv := f.password(t)
		if before != after || oldPV != pv || sv != 2 {
			t.Fatal("MFA recovery changed password")
		}
	})
	t.Run("ordinary_email_requires_current_totp", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, false)
		f.seedVerifiedContact(t)
		before, sv, pv := f.password(t)
		factor, _, cipher := f.factor(t)
		raw := f.resetToken(t)
		after, afterSV, afterPV := f.password(t)
		if after != before || afterSV != sv || afterPV != pv {
			t.Fatal("anonymous issuance restricted target")
		}
		a := f.startTarget(t, "recover", "setup")
		old := a
		tr, e := f.recovery.BindResetInvitation(f.ctx, a, raw, "192.0.2.62")
		if e != nil || tr.View.NextStep != "totp" {
			t.Fatal("email bind", e)
		}
		a.ID = tr.View.ID
		a.Binding = tr.Binding
		if _, e = f.recovery.BindResetInvitation(f.ctx, old, raw, "192.0.2.62"); e == nil {
			t.Fatal("email token rebound")
		}
		if _, e = f.recovery.SetResetPassword(f.ctx, a, "too early replacement password"); e == nil {
			t.Fatal("reset omitted current TOTP")
		}
		if _, e = f.s.TOTPProof(f.ctx, a, "invalid"); !errors.Is(e, ErrProof) {
			t.Fatal("bad TOTP", e)
		}
		v, e := f.s.TOTPProof(f.ctx, a, TOTP(f.seed, f.now.Unix()/30))
		if e != nil || v.NextStep != "password_setup" {
			t.Fatal("reset TOTP", e)
		}
		if _, e = f.recovery.SetResetPassword(f.ctx, a, "ordinary replacement password"); e != nil {
			t.Fatal(e)
		}
		done, e := f.s.Complete(f.ctx, a, "192.0.2.62", "fixture")
		if e != nil || done.SessionToken != "" {
			t.Fatal("reset complete", e)
		}
		got, sv, pv := f.password(t)
		ok, _ := auth.VerifyPassword("ordinary replacement password", got)
		if !ok || sv != 2 || pv != 2 {
			t.Fatal("reset publication")
		}
		vFactor, revoked, newCipher := f.factor(t)
		if factor != vFactor || revoked || cipher != newCipher {
			t.Fatal("email reset changed factor")
		}
	})

	t.Run("ordinary_totp_factor_rotation_invalidates_reset", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, false)
		f.seedVerifiedContact(t)
		raw := f.resetToken(t)
		reset := f.startTarget(t, "recover", "setup")
		tr, e := f.recovery.BindResetInvitation(f.ctx, reset, raw, "192.0.2.62")
		if e != nil {
			t.Fatal(e)
		}
		reset.ID = tr.View.ID
		reset.Binding = tr.Binding
		if _, e = f.s.TOTPProof(f.ctx, reset, TOTP(f.seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		if _, e = f.recovery.SetResetPassword(f.ctx, reset, "stale factor must not reset password"); e != nil {
			t.Fatal(e)
		}
		// A genuine separate legacy MFA replacement preserves password/SV, so the
		// reset must pin the actual factor that supplied its current-TOTP proof.
		legacy := f.startTarget(t, "recover", "setup")
		tr, e = f.s.Primary(f.ctx, legacy, f.target.Username, "existing target password", "192.0.2.61")
		if e != nil {
			t.Fatal(e)
		}
		legacy.ID = tr.View.ID
		legacy.Binding = tr.Binding
		if _, e = f.s.RecoveryProof(f.ctx, legacy, f.codes[0]); e != nil {
			t.Fatal(e)
		}
		en, e := f.s.StartEnrollment(f.ctx, legacy)
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(en.ProvisioningURI)
		seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		if e != nil {
			t.Fatal(e)
		}
		f.clock(f.now.Add(30 * time.Second))
		if _, e = f.s.ConfirmEnrollment(f.ctx, legacy, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Complete(f.ctx, reset, "192.0.2.62", "fixture"); e == nil {
			t.Fatal("old-factor TOTP authorized reset")
		}
		hash, sv, pv := f.password(t)
		valid, _ := auth.VerifyPassword("existing target password", hash)
		if !valid || sv != 1 || pv != 1 {
			t.Fatal("denied reset changed password")
		}
	})
	t.Run("quorum_and_digest", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "replace_mfa")
		if _, e := f.recovery.ApproveOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "self approval blocked"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal("creator approved", e)
		}
		if _, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), op.RequestDigest, "unapproved execution"); !errors.Is(e, storage.ErrApprovalRequired) {
			t.Fatal("missing quorum", e)
		}
		f.approve(t, op)
		if _, e := f.recovery.ExecuteOperationRequest(f.ctx, f.creator, op.ID, securitystate.ID("request"), strings.Repeat("a", 64), "different digest blocked"); e == nil {
			t.Fatal("changed digest")
		}
		f.execute(t, op)
		blob, _ := json.Marshal(op)
		if strings.Contains(string(blob), "ticket") {
			t.Fatal("operation exposed secret")
		}
	})
	t.Run("historical_reviewer_revocation", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, true)
		op := f.plan(t, "reset_password")
		f.approve(t, op)
		f.execute(t, op)
		a := f.ticketFlow(t, op)
		if _, e := f.recovery.SetResetPassword(f.ctx, a, "must never become password"); e != nil {
			t.Fatal(e)
		}
		e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET blocked_at=? WHERE id=?`, f.now, f.other.ID)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Complete(f.ctx, a, "192.0.2.61", "fixture"); e == nil {
			t.Fatal("stale reviewer authorized password")
		}
		hash, _, _ := f.password(t)
		if hash != "" {
			t.Fatal("stale reviewer password published")
		}
	})
	t.Run("legacy_recovery_is_only_mfa", func(t *testing.T) {
		f := newRecoveryFixture(t, pg, false)
		before, _, pv := f.password(t)
		a := f.startTarget(t, "recover", "setup")
		// Legacy requires actual primary proof, unlike an unbound email reset flow.
		tr, e := f.s.Primary(f.ctx, a, f.target.Username, "existing target password", "192.0.2.61")
		if e != nil {
			t.Fatal(e)
		}
		a.ID = tr.View.ID
		a.Binding = tr.Binding
		if _, e = f.s.RecoveryProof(f.ctx, a, f.codes[0]); e != nil {
			t.Fatal("legacy recovery", e)
		}
		if _, e = f.recovery.SetResetPassword(f.ctx, a, "legacy cannot change password"); e == nil {
			t.Fatal("legacy granted password")
		}
		en, e := f.s.StartEnrollment(f.ctx, a)
		if e != nil {
			t.Fatal("legacy MFA", e)
		}
		u, _ := url.Parse(en.ProvisioningURI)
		seed, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		if _, e = f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		done, e := f.s.Complete(f.ctx, a, "192.0.2.61", "fixture")
		if e != nil || done.SessionToken != "" {
			t.Fatal("legacy completion", e)
		}
		after, _, newPV := f.password(t)
		if before != after || pv != newPV {
			t.Fatal("legacy changed password")
		}
	})
}
