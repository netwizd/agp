package identity

import (
	"context"
	"encoding/base32"
	"errors"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestLifecycleEphemeralCleanupSQLite(t *testing.T)   { testLifecycleEphemeralCleanup(t, false) }
func TestLifecycleEphemeralCleanupPostgres(t *testing.T) { testLifecycleEphemeralCleanup(t, true) }
func testLifecycleEphemeralCleanup(t *testing.T, pg bool) {
	for _, viaStart := range []bool{true, false} {
		t.Run(map[bool]string{true: "new_anonymous_activation", false: "runtime_sweep"}[viaStart], func(t *testing.T) {
			f := newFixture(t, pg)
			csrf, _, _ := auth.NewToken()
			tr, e := f.s.Start(f.ctx, "activate", "setup", f.s.Profile.LoginOrigin, csrf, "")
			if e != nil {
				t.Fatal(e)
			}
			f.clock(f.now.Add(6 * time.Minute))
			if viaStart {
				_, e = f.s.Start(f.ctx, "activate", "setup", f.s.Profile.LoginOrigin, csrf, "")
			} else {
				e = f.s.CleanupLifecycle(f.ctx)
			}
			if e != nil {
				t.Fatal(e)
			}
			e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				var count int
				e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM identity_flows WHERE id=?`, []any{tr.View.ID}, func(r storage.IdentityRows) error { return r.Scan(&count) })
				if e == nil && count != 0 {
					t.Fatal("expired anonymous setup flow retained without a stage")
				}
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestLifecyclePendingUsernameSQLite(t *testing.T)   { testLifecyclePendingUsername(t, false) }
func TestLifecyclePendingUsernamePostgres(t *testing.T) { testLifecyclePendingUsername(t, true) }
func testLifecyclePendingUsername(t *testing.T, pg bool) {
	f := newInviteFixture(t, pg)
	for i, names := range [][2]string{{"New_Pending", "new_pending"}, {"ΟΣ", "οσ"}, {"İ", "i"}} {
		input := PendingUserInput{ID: securitystate.ID("usr"), Username: names[0], GroupIDs: []string{}}
		key := "canonical_pending_" + strconv.Itoa(i)
		created, e := f.invites.CreatePending(f.ctx, f.admin, key, input)
		if e != nil || created.Username != names[1] {
			t.Fatal("pending username differs from local-primary canonicalization", created, e)
		}
		input.Username = names[1]
		replay, e := f.invites.CreatePending(f.ctx, f.admin, key, input)
		if e != nil || replay.ID != created.ID || replay.Username != created.Username {
			t.Fatal("canonical retry changed metadata or failed idempotency", replay, e)
		}
	}
	_, e := f.invites.CreatePending(f.ctx, f.admin, "invalid_utf8_pending", PendingUserInput{ID: securitystate.ID("usr"), Username: string([]byte{0xff, 'A'}), GroupIDs: []string{}})
	if !errors.Is(e, ErrLifecycleInvalid) {
		t.Fatal("invalid UTF-8 was normalized into an accepted username", e)
	}
}

type finalEnrollmentClockAuthority struct {
	*memoryJournal
	principal string
	after     func()
	fired     bool
}

func (a *finalEnrollmentClockAuthority) Append(ctx context.Context, r securityjournal.AppendRequest) (securityjournal.Event, error) {
	event, e := a.memoryJournal.Append(ctx, r)
	if e == nil && !a.fired && r.Payload.PrincipalID == a.principal && r.Payload.AuthenticatorID == ReplayID(a.principal) {
		a.fired = true
		a.after()
	}
	return event, e
}
func TestEnrollmentFinalDeadlineSQLite(t *testing.T)   { testEnrollmentFinalDeadline(t, false) }
func TestEnrollmentFinalDeadlinePostgres(t *testing.T) { testEnrollmentFinalDeadline(t, true) }
func testEnrollmentFinalDeadline(t *testing.T, pg bool) {
	f := newFixture(t, pg)
	a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
	enrollment, e := f.s.StartEnrollment(f.ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	uri, e := url.Parse(enrollment.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(uri.Query().Get("secret"))
	if e != nil {
		t.Fatal(e)
	}
	authority := &finalEnrollmentClockAuthority{memoryJournal: f.j, principal: f.user.ID, after: func() { f.clock(f.now.Add(6 * time.Minute)) }}
	f.s.Coordinator.Authority = authority
	result, e := f.s.ConfirmEnrollment(f.ctx, a, enrollment.EnrollmentID, TOTP(seed, f.now.Unix()/30))
	if e == nil || len(result.RecoveryCodes) != 0 || !authority.fired {
		t.Fatal("expired final publication succeeded or leaked uninstalled recovery codes")
	}
	if e = f.s.Coordinator.Ready(f.ctx); e != nil {
		t.Fatal("expired positive publication retained global barrier", e)
	}
	e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		for _, q := range []string{`SELECT COUNT(*) FROM mfa_factors WHERE principal_id=?`, `SELECT COUNT(*) FROM mfa_enrollments WHERE principal_id=?`, `SELECT COUNT(*) FROM recovery_codes WHERE principal_id=?`} {
			var n int
			if e := securitystate.One(f.ctx, tx, q, []any{f.user.ID}, func(rows storage.IdentityRows) error { return rows.Scan(&n) }); e != nil {
				return e
			}
			if n != 0 {
				t.Fatal("aborted publication retained live/staged credentials")
			}
		}
		floor, e := securitystate.Floor(f.ctx, tx, f.user.ID, FactorID(f.user.ID))
		if e != nil {
			return e
		}
		if floor == 0 {
			t.Fatal("restrictive receipt was rolled back")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// A password-only login cannot turn a spent factor floor into an implicit
	// MFA replacement. Repair uses the separately approved typed recovery flow.
	fresh := f.start(t, "login", "")
	tr, e := f.s.Primary(f.ctx, fresh, "admin", "test-initial-password", "127.0.0.1")
	if e != nil {
		if !errors.Is(e, ErrProof) {
			t.Fatal("unexpected primary failure after aborted enrollment", e)
		}
	} else {
		fresh.ID, fresh.Binding = tr.View.ID, tr.Binding
		if _, e = f.s.StartEnrollment(f.ctx, fresh); !errors.Is(e, ErrProof) {
			t.Fatal("ordinary login did not reject implicit replacement at the spent MFA floor", e)
		}
	}

}
