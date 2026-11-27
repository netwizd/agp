package identity

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestRecoveryDirectoryWireSQLite(t *testing.T)   { recoveryDirectoryWire(t, false) }
func TestRecoveryDirectoryWirePostgres(t *testing.T) { recoveryDirectoryWire(t, true) }

// Actual verified TLS and LDAP BER account/GUID/tokenGroups exchanges exercise
// the production connector. Provider activation/provisioning use public APIs;
// fresh local operator sessions are trusted fixture bootstrap, not real AD DS
// or corporate SMTP qualification. The journal remains a deterministic double.
func recoveryDirectoryWire(t *testing.T, pg bool) {
	for _, mode := range []string{"success", "disabled_target", "tls_unavailable", "local_reviewer_revoked", "proof_expires_after_journal_retry"} {
		t.Run(mode, func(t *testing.T) {
			f := newDirectoryAuthFixture(t, pg, false)
			link := f.provision(t)
			f.login(t, "login") // Initial live AD primary + actual TOTP enrollment/session.
			f.clock(f.now.Add(30 * time.Second))
			// Older directory fixtures predate mandatory primary timestamps. These are
			// their two already authenticated local management sessions, not AD claims.
			e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				_, e := tx.Exec(f.ctx, `UPDATE sessions SET primary_at=?,mfa_at=?,last_seen_at=? WHERE token_hash IN (?,?)`, f.now, f.now, f.now, f.author.TokenHash, f.reviewer.TokenHash)
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			creator := LifecycleActor{TokenHash: f.author.TokenHash, Origin: f.author.Origin, SourceIP: "192.0.2.91"}
			reviewer := LifecycleActor{TokenHash: f.reviewer.TokenHash, Origin: f.reviewer.Origin, SourceIP: "192.0.2.92"}
			r := f.s.recovery.(*RecoveryService)
			before := f.wire.serviceBinds.Load()
			op, e := r.Plan(f.ctx, creator, link.PrincipalID, securitystate.ID("request"), RecoveryPlanRequest{TargetPrincipalID: link.PrincipalID, ExpectedSecurityVersion: 1, AllowedAction: "replace_mfa", ExpiresAt: f.now.Add(4 * time.Minute), Reason: "wire-qualified typed AD MFA replacement"})
			if e != nil {
				t.Fatal("AD plan", e)
			}
			if _, e = r.ApproveOperationRequest(f.ctx, reviewer, op.ID, securitystate.ID("request"), op.RequestDigest, "independent local review of AD recovery"); e != nil {
				t.Fatal("AD approve", e)
			}
			executed, e := r.ExecuteOperationRequest(f.ctx, creator, op.ID, securitystate.ID("request"), op.RequestDigest, "execute exact AD MFA replacement")
			if e != nil || executed.State != "applied" {
				t.Fatal("AD execute", e)
			}
			ticket, e := r.IssueTicket(f.ctx, creator, op.ID)
			if e != nil {
				t.Fatal("AD ticket", e)
			}
			tr, e := f.s.StartWithSource(f.ctx, "recover", "setup", f.s.Profile.LoginOrigin, "ad_recovery_csrf", "", "192.0.2.93")
			if e != nil {
				t.Fatal(e)
			}
			a := FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "ad_recovery_csrf", Origin: f.s.Profile.LoginOrigin}
			tr, e = r.ConsumeSupervisedTicket(f.ctx, a, ticket.Ticket, "192.0.2.93")
			if e != nil {
				t.Fatal("AD ticket bind", e)
			}
			a.ID = tr.View.ID
			a.Binding = tr.Binding
			if tr.View.NextStep != "totp_enrollment" || tr.View.MFASatisfied {
				t.Fatal("AD ticket granted session authority")
			}
			e = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				pin, e := directoryAuthPin(f.ctx, tx, h, link.PrincipalID)
				if e != nil {
					return e
				}
				if pin == nil {
					t.Fatal("lost AD identity")
				}
				stored, e := directoryStoredContext(f.ctx, tx, "identity_flows", a.ID)
				if e != nil {
					return e
				}
				if stored != pin.context || stored.IdentityID != link.ID || stored.ProviderVersionID != f.document.Metadata.VersionID {
					t.Fatal("ticket flow did not pin exact provider/link/GUID context")
				}
				var live int
				if e = securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL`, []any{link.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&live) }); e != nil {
					return e
				}
				if live != 0 {
					t.Fatal("old AD session survived recovery restrictions")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			en, e := f.s.StartEnrollment(f.ctx, a)
			if e != nil {
				t.Fatal("AD replacement seed", e)
			}
			u, _ := url.Parse(en.ProvisioningURI)
			seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "disabled_target":
				f.wire.disabled.Store(true)
			case "tls_unavailable":
				f.wire.rejectTLS.Store(true)
			case "local_reviewer_revoked":
				e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					_, e := tx.Exec(f.ctx, `UPDATE users SET blocked_at=? WHERE id=?`, f.now, f.other.ID)
					return e
				})
				if e != nil {
					t.Fatal(e)
				}
			case "proof_expires_after_journal_retry":
				// Advancing only trusted authority/fixture time expires the real observed
				// LDAP proof after the journal has already raised factor/replay floors.
				f.s.Coordinator.Register("mfa_enrollment", func(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
					f.clock(f.now.Add(11 * time.Second))
					return f.s.materializeEnrollment(ctx, tx, raw)
				})
			}
			result, e := f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30))
			if mode == "disabled_target" || mode == "tls_unavailable" || mode == "local_reviewer_revoked" {
				if mode == "tls_unavailable" {
					if !errors.Is(e, ErrDirectoryUnavailable) {
						t.Fatal("TLS failure was not unavailable", e)
					}
				} else if e == nil {
					t.Fatal("revoked live authority published MFA")
				}
				if len(result.RecoveryCodes) != 0 {
					t.Fatal("denied request returned recovery codes")
				}
				assertRecoveryDirectoryRestricted(t, f, link.PrincipalID, a.ID, 2)
				return
			}
			if mode == "proof_expires_after_journal_retry" {
				if e == nil || len(result.RecoveryCodes) != 0 {
					t.Fatal("stale LDAP proof published factor")
				}
				assertRecoveryDirectoryRestricted(t, f, link.PrincipalID, a.ID, 3)
				// A fresh request must obtain new TLS/LDAP evidence and a seed whose
				// version exceeds the restrictive floors retained by the aborted attempt.
				f.s.Coordinator.Register("mfa_enrollment", f.s.materializeEnrollment)
				f.clock(f.now.Add(30 * time.Second))
				en, e = f.s.StartEnrollment(f.ctx, a)
				if e != nil {
					t.Fatal("fresh typed retry", e)
				}
				u, _ = url.Parse(en.ProvisioningURI)
				seed, e = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
				if e != nil {
					t.Fatal(e)
				}
				result, e = f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30))
			}
			if e != nil || len(result.RecoveryCodes) != 10 || result.Flow.State != "ready" || result.Flow.MFASatisfied {
				t.Fatal("AD MFA publication", e)
			}
			done, e := f.s.Complete(f.ctx, a, "192.0.2.93", "actual TLS LDAP recovery fixture")
			if e != nil || done.View.State != "completed" || done.SessionToken != "" || done.CSRFToken != "" || done.View.MFASatisfied {
				t.Fatal("AD recovery issued a normal session", e)
			}
			if f.wire.serviceBinds.Load() <= before {
				t.Fatal("no actual LDAP account reads")
			}
			e = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
				var password, kind string
				var sv, pv uint64
				if e := securitystate.One(f.ctx, tx, `SELECT password_hash,identity_kind,security_version,password_version FROM users WHERE id=?`, []any{link.PrincipalID}, func(row storage.IdentityRows) error { return row.Scan(&password, &kind, &sv, &pv) }); e != nil {
					return e
				}
				if password != "" || kind != "directory" || sv != 2 || pv != 1 {
					t.Fatal("AD MFA recovery changed directory password authority")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}
func assertRecoveryDirectoryRestricted(t *testing.T, f *directoryAuthFixture, principal, flowID string, minimumFactor uint64) {
	t.Helper()
	e := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var verified, revoked bool
		var version uint64
		if e := securitystate.One(f.ctx, tx, `SELECT verified,revoked,version FROM mfa_factors WHERE principal_id=?`, []any{principal}, func(row storage.IdentityRows) error { return row.Scan(&verified, &revoked, &version) }); e != nil {
			return e
		}
		if verified && !revoked {
			t.Fatal("denial published active factor")
		}
		floor, e := securitystate.Floor(f.ctx, tx, principal, FactorID(principal))
		if e != nil {
			return e
		}
		if floor < minimumFactor || version >= floor {
			t.Fatal("restrictive factor floor lost")
		}
		cap, e := readRecoveryCapability(f.ctx, tx, flowID)
		if e != nil {
			return e
		}
		if cap.state != "pending" || cap.action != "replace_mfa" {
			t.Fatal("ongoing typed cap was not retained")
		}
		flow, e := loadFlow(f.ctx, tx, flowID)
		if e != nil {
			return e
		}
		if flow.State != "pending_mfa" {
			t.Fatal("denial left ready flow")
		}
		return nil
	})
	if e != nil {
		t.Fatal("global barrier retained", e)
	}
}
