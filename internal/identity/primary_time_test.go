package identity

import (
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/storage"
)

func TestPrimaryAuthenticationTimeSQLite(t *testing.T)   { testPrimaryAuthenticationTime(t, false) }
func TestPrimaryAuthenticationTimePostgres(t *testing.T) { testPrimaryAuthenticationTime(t, true) }
func testPrimaryAuthenticationTime(t *testing.T, pg bool) {
	t.Run("primary_time_survives_delayed_mfa_session_and_step_up", func(t *testing.T) {
		f := newFixture(t, pg)
		first := f.now
		a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
		f.clock(first.Add(90 * time.Second))
		seed, _ := f.enroll(t, a)
		c, err := f.s.Complete(f.ctx, a, "127.0.0.1", "primary-time fixture")
		if err != nil {
			t.Fatal(err)
		}
		if c.Session.PrimaryAt == nil || !c.Session.PrimaryAt.Equal(first) || c.Session.MFAAt == nil || !c.Session.MFAAt.Equal(f.now) {
			t.Fatalf("timestamps conflated: primary=%v mfa=%v", c.Session.PrimaryAt, c.Session.MFAAt)
		}
		session, err := f.s.Session(f.ctx, auth.TokenHash(c.SessionToken), "management", f.s.Profile.ManagementOrigin)
		if err != nil || session.PrimaryAt == nil || !session.PrimaryAt.Equal(first) {
			t.Fatal("primary timestamp not loaded", err)
		}
		second := f.now.Add(time.Minute)
		f.clock(second)
		step := f.primary(t, f.start(t, "step_up", auth.TokenHash(c.SessionToken)), "test-initial-password")
		f.clock(second.Add(30 * time.Second))
		if _, err = f.s.TOTPProof(f.ctx, step, TOTP(seed, f.now.Unix()/30)); err != nil {
			t.Fatal(err)
		}
		replacement, err := f.s.Complete(f.ctx, step, "127.0.0.1", "primary-time step-up")
		if err != nil {
			t.Fatal(err)
		}
		if replacement.Session.PrimaryAt == nil || !replacement.Session.PrimaryAt.Equal(second) {
			t.Fatal("step-up inherited old primary timestamp")
		}
		// Existing sessions remain usable for their previous rights, but their MFA or
		// creation time never fills an unknown historical primary authentication time.
		if err = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, err := tx.Exec(f.ctx, `UPDATE sessions SET primary_at=NULL WHERE id=?`, replacement.Session.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		historical, err := f.s.Session(f.ctx, auth.TokenHash(replacement.SessionToken), "management", f.s.Profile.ManagementOrigin)
		if err != nil || historical.PrimaryAt != nil || historical.MFAAt == nil {
			t.Fatal("unknown primary was inferred from MFA/creation", err)
		}
	})
	t.Run("directory_primary_time_is_not_totp_completion_time", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		f.provision(t)
		first := f.now
		a := f.primaryDirectory(t, f.startDirectory(t, "login"))
		f.clock(first.Add(90 * time.Second))
		f.enroll(t, a)
		c, err := f.s.Complete(f.ctx, a, "127.0.0.1", "directory primary-time fixture")
		if err != nil {
			t.Fatal(err)
		}
		if c.Session.PrimaryAt == nil || !c.Session.PrimaryAt.Equal(first) || c.Session.MFAAt == nil || !c.Session.MFAAt.Equal(f.now) {
			t.Fatal("directory primary was inferred from MFA")
		}
	})
}
