package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestRecoveryFinalIndependentPeopleSQLite(t *testing.T) { recoveryFinalIndependentPeople(t, false) }
func TestRecoveryFinalIndependentPeoplePostgres(t *testing.T) {
	recoveryFinalIndependentPeople(t, true)
}

func recoveryFinalIndependentPeople(t *testing.T, pg bool) {
	f, ids, actors, _ := newRecoveryHumansFixture(t, pg, "executor_target")
	r := f.s.recovery.(*RecoveryService)
	op, err := r.Plan(f.ctx, actors[0], ids[2], securitystate.ID("request"), RecoveryPlanRequest{TargetPrincipalID: ids[2], ExpectedSecurityVersion: 1, AllowedAction: "replace_mfa", ExpiresAt: f.now.Add(4 * time.Minute), Reason: "independent people final publication check"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ApproveOperationRequest(f.ctx, actors[1], op.ID, securitystate.ID("request"), op.RequestDigest, "independent reviewed recovery intent"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ExecuteOperationRequest(f.ctx, actors[2], op.ID, securitystate.ID("request"), op.RequestDigest, "current executor must be independent of target"); !errors.Is(err, storage.ErrPermissionDenied) {
		t.Fatalf("target alias accepted at admission: %v", err)
	}

	// Trusted pre-upgrade intent fixture: only the final materializer is under
	// test here. Public admission above has already rejected this executor. The
	// normal coordinator still applies its real deny-floor and barrier logic.
	ctx, err := r.people(f.ctx, actors[2], op.ID)
	if err != nil {
		t.Fatal(err)
	}
	var prepared json.RawMessage
	var executionContext context.Context
	err = r.current(ctx, actors[2], true, false, func(c context.Context, _ storage.IdentityTx, h securityjournal.Head, actor *lifecyclePrincipal) error {
		executionContext = c
		var err error
		prepared, err = recoveryJSON(recoveryExecution{OperationID: op.ID, RequestDigest: op.RequestDigest, ActorID: actor.ID, ReviewerID: ids[1], Epoch: uint64(h.Epoch), ActorFingerprint: actor.Fingerprint, ActorTokenHash: actors[2].TokenHash, ActorOrigin: actors[2].Origin, PrimaryAt: actor.PrimaryAt, MFAAt: actor.MFAAt})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.s.Coordinator.ExecuteDynamic(executionContext, "identity_recovery", func(storage.IdentityTx, securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		return prepared, recoveryRequests(ids[3], op.RecoveryRequest.RestrictiveSteps), nil
	})
	if err != nil {
		t.Fatal("final denial must retire its own barrier", err)
	}
	err = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		record, err := readRecoveryOperation(f.ctx, tx, op.ID)
		if err != nil {
			return err
		}
		if record.operation.State != "recovery_required" {
			t.Fatalf("old intent published success: %s", record.operation.State)
		}
		var version uint64
		if err = securitystate.One(f.ctx, tx, `SELECT security_version FROM users WHERE id=?`, []any{ids[2]}, func(row storage.IdentityRows) error { return row.Scan(&version) }); err != nil {
			return err
		}
		floor, err := securitystate.Floor(f.ctx, tx, ids[2], "principal_"+ids[2])
		if err != nil {
			return err
		}
		// Restrictive abort rebases SV to this operation's exact deny floor so
		// the account can be recovered again; this creates no credential grant.
		if floor != uint64(op.RecoveryRequest.RestrictiveSteps[0].MinimumVersion) || version != floor {
			t.Fatalf("denial lost its exact restrictive rebase: version=%d floor=%d", version, floor)
		}
		for _, query := range []string{
			`SELECT COUNT(*) FROM identity_one_time_tokens WHERE authorization_operation_id=?`,
			`SELECT COUNT(*) FROM mfa_factors WHERE principal_id=? AND verified=TRUE AND revoked=FALSE`,
			`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL`,
		} {
			arg := ids[2]
			if strings.Contains(query, "authorization_operation_id") {
				arg = op.ID
			}
			var count int64
			if err := securitystate.One(f.ctx, tx, query, []any{arg}, func(row storage.IdentityRows) error { return row.Scan(&count) }); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("denied final intent created ticket, factor or session")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Coordinator.Ready(f.ctx); err != nil {
		t.Fatal("final denial retained global barrier", err)
	}
}
