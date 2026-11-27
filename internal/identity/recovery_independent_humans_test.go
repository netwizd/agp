package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestRecoveryIndependentHumansSQLite(t *testing.T)   { recoveryIndependentHumans(t, false) }
func TestRecoveryIndependentHumansPostgres(t *testing.T) { recoveryIndependentHumans(t, true) }

// These are separately pinned providers with actual verified TLS LDAP peers.
// The account/session bootstrap is trusted SQL; it is not corporate AD DS
// acceptance. All peers return the same object GUID, so a different forest is
// the legitimate independent-human control, while a different provider is not.
func recoveryIndependentHumans(t *testing.T, pg bool) {
	for _, alias := range []string{"independent", "creator", "target"} {
		stages := []string{"approve"}
		if alias != "independent" {
			stages = append(stages, "stored_approval", "stored_ticket")
		}
		for _, stage := range stages {
			t.Run(alias+"/"+stage, func(t *testing.T) {
				f, ids, actors, wires := newRecoveryHumansFixture(t, pg, alias)
				r := f.s.recovery.(*RecoveryService)
				op, e := r.Plan(f.ctx, actors[0], ids[2], securitystate.ID("request"), RecoveryPlanRequest{TargetPrincipalID: ids[2], ExpectedSecurityVersion: 1, AllowedAction: "replace_mfa", ExpiresAt: f.now.Add(4 * time.Minute), Reason: "independent directory recovery quorum"})
				if e != nil {
					t.Fatal("plan", e)
				}
				if stage == "approve" {
					_, e = r.ApproveOperationRequest(f.ctx, actors[1], op.ID, securitystate.ID("request"), op.RequestDigest, "review exact independent human quorum")
					if alias != "independent" {
						if !errors.Is(e, storage.ErrPermissionDenied) {
							t.Fatal("same AD human approved through another provider", e)
						}
						if _, e = r.ExecuteOperationRequest(f.ctx, actors[0], op.ID, securitystate.ID("request"), op.RequestDigest, "no independent approval exists"); !errors.Is(e, storage.ErrApprovalRequired) {
							t.Fatal("denied review left usable approval", e)
						}
					} else {
						if e != nil {
							t.Fatal("different forest must remain independent", e)
						}
						out, e := r.ExecuteOperationRequest(f.ctx, actors[0], op.ID, securitystate.ID("request"), op.RequestDigest, "creator may execute independent approved recovery")
						if e != nil || out.State != "applied" {
							t.Fatal("independent execution", out, e)
						}
						if _, e = r.IssueTicket(f.ctx, actors[0], op.ID); e != nil {
							t.Fatal("independent recovery ticket", e)
						}
					}
				} else {
					// Restore the exact approval shape produced by the vulnerable
					// binary. No production trigger or identity immutability is disabled.
					seedRecoveryAliasApproval(t, f, r, actors[1], op)
					if stage == "stored_approval" {
						if _, e = r.ExecuteOperationRequest(f.ctx, actors[0], op.ID, securitystate.ID("request"), op.RequestDigest, "recheck restored independent quorum"); !errors.Is(e, storage.ErrPermissionDenied) {
							t.Fatal("restored alias approval executed", e)
						}
					} else {
						token, raw := seedRecoveryAliasTicket(t, f, op)
						tr, e := f.s.StartWithSource(f.ctx, "recover", "setup", f.s.Profile.LoginOrigin, "alias_recovery_csrf", "", "192.0.2.123")
						if e != nil {
							t.Fatal(e)
						}
						a := FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: "alias_recovery_csrf", Origin: f.s.Profile.LoginOrigin}
						if _, e = r.ConsumeSupervisedTicket(f.ctx, a, raw, "192.0.2.123"); !errors.Is(e, storage.ErrPermissionDenied) {
							t.Fatal("restored alias ticket bound recovery capability", e)
						}
						e = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
							target, e := lifecycleRawUser(f.ctx, tx, h, ids[2])
							if e != nil {
								return e
							}
							return r.historical(f.ctx, tx, h, token, target, false)
						})
						if !errors.Is(e, storage.ErrPermissionDenied) {
							t.Fatal("metadata-only capability check accepted same human", e)
						}
					}
				}
				for i, wire := range wires {
					if wire.serviceBinds.Load() == 0 {
						t.Fatal("missing live LDAP participant", i)
					}
				}
				if e = f.s.Coordinator.Ready(f.ctx); e != nil {
					t.Fatal("quorum denial left pending barrier", e)
				}
			})
		}
	}
}

func newRecoveryHumansFixture(t *testing.T, pg bool, alias string) (*directoryAuthFixture, []string, []LifecycleActor, []*adWireFixture) {
	t.Helper()
	f := newDirectoryAuthFixture(t, pg, false)
	wires := []*adWireFixture{f.wire, newADWireFixture(t, "ldaps"), newADWireFixture(t, "ldaps")}
	forests := []string{"00000000-0000-0000-0000-000000000301", "00000000-0000-0000-0000-000000000302", "00000000-0000-0000-0000-000000000303"}
	if alias == "executor_target" {
		wires = append(wires, newADWireFixture(t, "ldaps"))
		forests = append(forests, forests[2])
	}
	if alias == "creator" {
		forests[1] = forests[0]
	}
	if alias == "target" {
		forests[1] = forests[2]
	}
	var ca []byte
	var ids []string
	for i, wire := range wires {
		wire.config.Spec.ForestGUID = forests[i]
		ca = append(ca, wire.connector.secrets.(adFixtureSecrets).ca...)
		doc := f.document
		doc.Spec.Endpoints, doc.Spec.ForestGUID = wire.config.Spec.Endpoints, forests[i]
		ids = append(ids, historicalFixturePrincipalDocument(t, f, 80+i, doc))
	}
	f.wire.connector.secrets = adFixtureSecrets{ca: ca}
	var actors []LifecycleActor
	actorIDs := append([]string{}, ids[:2]...)
	if alias == "executor_target" {
		actorIDs = append(actorIDs, ids[3])
	}
	for i, id := range actorIDs {
		_, hash, e := auth.NewToken()
		if e != nil {
			t.Fatal(e)
		}
		sessionID := securitystate.ID("session")
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `UPDATE users SET is_admin=TRUE WHERE id=?`, id); e != nil {
				return e
			}
			if _, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, id, f.group.ID); e != nil {
				return e
			}
			if e := InsertSession(f.ctx, tx, domain.Session{ID: sessionID, UserID: id, TokenHash: hash, CSRFHash: auth.TokenHash("recovery quorum fixture"), Audience: "management", AudienceOrigin: f.s.Profile.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), PrimaryAt: &f.now, MFAAt: &f.now, LastSeenAt: &f.now}); e != nil {
				return e
			}
			head, e := f.s.Coordinator.Authority.Head(f.ctx)
			if e != nil {
				return e
			}
			pin, e := directoryAuthPin(f.ctx, tx, head, id)
			if e != nil {
				return e
			}
			return writeDirectoryContext(f.ctx, tx, "sessions", sessionID, pin.context)
		})
		if e != nil {
			t.Fatal(i, e)
		}
		actors = append(actors, LifecycleActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin})
	}
	return f, ids, actors, wires
}

func seedRecoveryAliasApproval(t *testing.T, f *directoryAuthFixture, r *RecoveryService, reviewer LifecycleActor, op *RecoverySecurityOperation) {
	t.Helper()
	ctx, e := r.people(f.ctx, reviewer, op.ID)
	if e != nil {
		t.Fatal(e)
	}
	e = r.current(ctx, reviewer, true, true, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
		if _, e := tx.Exec(c, `INSERT INTO identity_recovery_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,mfa_at,primary_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?)`, securitystate.ID("approval"), op.ID, op.RequestDigest, p.ID, p.Fingerprint, p.MFAAt, p.PrimaryAt, h.RecordedAt, "trusted pre-fix restore fixture"); e != nil {
			return e
		}
		_, e := tx.Exec(c, `UPDATE identity_recovery_operations SET approval_status='approved' WHERE id=?`, op.ID)
		return e
	})
	if e != nil {
		t.Fatal("restore approval fixture", e)
	}
}

func seedRecoveryAliasTicket(t *testing.T, f *directoryAuthFixture, op *RecoverySecurityOperation) (*lifecycleToken, string) {
	t.Helper()
	raw, hash, e := auth.NewToken()
	if e != nil {
		t.Fatal(e)
	}
	var token *lifecycleToken
	e = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		record, e := readRecoveryOperation(f.ctx, tx, op.ID)
		if e != nil {
			return e
		}
		// A restored pre-fix applied operation/ticket is authority metadata, not
		// evidence that this test performed a valid independent recovery.
		if _, e = tx.Exec(f.ctx, `UPDATE identity_recovery_operations SET state='applied',post_security_version=1,post_password_version=1 WHERE id=?`, op.ID); e != nil {
			return e
		}
		token = &lifecycleToken{ID: securitystate.ID("ticket"), PrincipalID: op.SubjectID, Purpose: "recover_mfa", ProofKind: "supervised", TokenHash: hash, GuardID: securitystate.ID("guard_setup"), GuardVersion: 1, Epoch: uint64(h.Epoch), SecurityVersion: 1, PasswordVersion: 1, PolicyDigest: lifecyclePolicyDigest(), IssuerID: op.CreatedBy, IssuerFingerprint: record.creatorFingerprint, Generation: 1, AuthorizationOperationID: op.ID, AllowedAction: "replace_mfa", CreatedAt: h.RecordedAt, ExpiresAt: op.RecoveryRequest.ExpiresAt}
		return insertLifecycleToken(f.ctx, tx, token)
	})
	if e != nil {
		t.Fatal(fmt.Errorf("restore ticket fixture: %w", e))
	}
	return token, raw
}
