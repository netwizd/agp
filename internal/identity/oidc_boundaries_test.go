package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestOIDCBoundariesSQLite(t *testing.T)   { testOIDCBoundaries(t, false) }
func TestOIDCBoundariesPostgres(t *testing.T) { testOIDCBoundaries(t, true) }
func (f *oidcFixture) completedOIDC(t *testing.T, audience string) (FlowAuth, Completion) {
	t.Helper()
	a := f.primaryOIDC(t, f.startDirectory(t, audience))
	f.enroll(t, a)
	completed, e := f.s.Complete(f.ctx, a, "127.0.0.1", "OIDC full composition")
	if e != nil {
		t.Fatal(e)
	}
	return a, completed
}
func (f *oidcFixture) bumpOIDCGuard(t *testing.T, guard string, next uint64) {
	t.Helper()
	e := f.s.Coordinator.Execute(f.ctx, securitystate.Intent{Kind: "logout", Data: []byte(`{}`)}, func(storage.IdentityTx, securityjournal.Head) ([]securityjournal.AppendRequest, error) {
		return []securityjournal.AppendRequest{securitystate.FloorRequest(f.user.ID, guard, guard, next)}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func (f *oidcFixture) authorizationState(t *testing.T, state string) (string, string, string) {
	t.Helper()
	var status, key, cipher string
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(f.ctx, tx, `SELECT state,key_id,ciphertext FROM oidc_authorizations WHERE state_hash=?`, []any{auth.TokenHash(state)}, func(r storage.IdentityRows) error { return r.Scan(&status, &key, &cipher) })
	}); e != nil {
		t.Fatal(e)
	}
	return status, key, cipher
}
func testOIDCBoundaries(t *testing.T, pg bool) {
	t.Run("actual_step_up_source_fences_and_auth_time", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		a, session := f.completedOIDC(t, "login")
		_ = a
		oldHash := auth.TokenHash(session.SessionToken)
		f.clock(f.now.Add(30 * time.Second))
		step := f.startDirectoryFlow(t, "step_up", "login", oldHash)
		step = f.primaryOIDC(t, step)
		var seed []byte
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var sealed Sealed
			var version uint64
			e := securitystate.One(f.ctx, tx, `SELECT ciphertext,key_id,nonce,version FROM mfa_factors WHERE principal_id=?`, []any{f.directoryIdentity.PrincipalID}, func(r storage.IdentityRows) error {
				return r.Scan(&sealed.Ciphertext, &sealed.KeyID, &sealed.Nonce, &version)
			})
			if e != nil {
				return e
			}
			seed, e = f.s.Keys.Open(sealed, factorAAD(f.directoryIdentity.PrincipalID, version))
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.TOTPProof(f.ctx, step, TOTP(seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		renewed, e := f.s.Complete(f.ctx, step, "127.0.0.1", "OIDC step-up")
		if e != nil {
			t.Fatal(e)
		}
		if renewed.Session.PrimaryAt == nil || renewed.Session.PrimaryAt.Unix() != f.authTime.Load() {
			t.Fatal("step-up manufactured primary time")
		}
		if _, e = f.s.Session(f.ctx, oldHash, "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("old source remained active")
		}
		newHash := auth.TokenHash(renewed.SessionToken)
		revokedStep := f.startDirectoryFlow(t, "step_up", "login", newHash)
		state, code := f.beginOIDC(t, revokedStep)
		if e = f.s.Logout(f.ctx, newHash); e != nil {
			t.Fatal(e)
		}
		if _, e = f.oidc.Callback(f.ctx, revokedStep, f.p.ID, state, code, "", ""); !errors.Is(e, ErrProof) {
			t.Fatal("revoked source step-up", e)
		}
		// A local source session cannot be rebound to the external AD identity.
		foreign := f.startDirectoryFlow(t, "step_up", "management", f.author.TokenHash)
		state, code = f.beginOIDC(t, foreign)
		if _, e = f.oidc.Callback(f.ctx, foreign, f.p.ID, state, code, "", ""); !errors.Is(e, ErrProof) {
			t.Fatal("foreign source target", e)
		}
	})
	t.Run("callback_provider_pins_and_server_derived_flow", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		a := f.startDirectory(t, "login")
		state, code := f.beginOIDC(t, a)
		wire := a
		wire.ID = ""
		if _, e := f.oidc.Callback(f.ctx, wire, f.p.ID, state, code, "", f.p.Issuer+"/"); !errors.Is(e, ErrProof) {
			t.Fatal("issuer response alias", e)
		}
		if f.tokenCalls.Load() != 0 {
			t.Fatal("issuer mismatch leaked code")
		}
		result, e := f.oidc.Callback(f.ctx, wire, f.p.ID, state, code, "", f.p.Issuer)
		if e != nil || result.Terminal || result.Transition.View.ID == a.ID {
			t.Fatal("trusted derived flow rejected", e)
		}
		status, key, cipher := f.authorizationState(t, state)
		if status != "completed" || key != "" || cipher != "" {
			t.Fatal("terminal nonce/verifier retained", status)
		}
		b := f.startDirectory(t, "login")
		state, code = f.beginOIDC(t, b)
		before := f.tokenCalls.Load()
		f.bumpOIDCGuard(t, f.p.SecurityGuardID, 2)
		if _, e = f.oidc.Callback(f.ctx, b, f.p.ID, state, code, "", ""); !errors.Is(e, ErrProof) {
			t.Fatal("provider floor callback", e)
		}
		if f.tokenCalls.Load() != before {
			t.Fatal("revoked provider sent code")
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE oidc_providers SET enabled=TRUE,guard_version=1 WHERE id=?`, f.p.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Get(f.ctx, FlowAuth{ID: result.Transition.View.ID, Binding: result.Transition.Binding, CSRF: a.CSRF, Origin: a.Origin}); e == nil {
			t.Fatal("restored provider context bypassed floor")
		}
	})
	t.Run("replacement_while_exchanging_and_max_three", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		a := f.startDirectory(t, "login")
		oldState, oldCode := f.beginOIDC(t, a)
		entered := make(chan struct{})
		release := make(chan struct{})
		f.mu.Lock()
		f.tokenHook = func() error { close(entered); <-release; return nil }
		f.mu.Unlock()
		finished := make(chan error, 1)
		go func() { _, e := f.oidc.Callback(f.ctx, a, f.p.ID, oldState, oldCode, "", ""); finished <- e }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("token endpoint never entered")
		}
		f.mu.Lock()
		f.tokenHook = nil
		f.mu.Unlock()
		newState, newCode := f.beginOIDC(t, a)
		status, key, cipher := f.authorizationState(t, oldState)
		if status != "cancelled" || key != "" || cipher != "" {
			t.Fatal("predecessor retained proof")
		}
		close(release)
		if e := <-finished; !errors.Is(e, ErrProof) {
			t.Fatal("old callback completed", e)
		}
		view, e := f.s.Get(f.ctx, a)
		if e != nil || view.State != "pending_primary" {
			t.Fatal("old callback cancelled replacement", e)
		}
		result, e := f.oidc.Callback(f.ctx, a, f.p.ID, newState, newCode, "", "")
		if e != nil || result.Terminal {
			t.Fatal("replacement failed", e)
		}
		b := f.startDirectory(t, "login")
		var previous string
		for range 3 {
			state, _ := f.beginOIDC(t, b)
			if previous != "" {
				status, key, cipher := f.authorizationState(t, previous)
				if status != "cancelled" || key != "" || cipher != "" {
					t.Fatal("explicit replacement not erased")
				}
			}
			previous = state
		}
		if _, e = f.oidc.BeginAuthorization(f.ctx, b, f.p.ID, "127.0.0.1"); !errors.Is(e, ErrLimited) {
			t.Fatal("fourth authorization accepted", e)
		}
	})
	t.Run("restart_expiry_cancellation_and_irreversible_erasure", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		a := f.startDirectory(t, "login")
		state, code := f.beginOIDC(t, a)
		_ = code
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE oidc_authorizations SET ciphertext='rewritten' WHERE state_hash=?`, auth.TokenHash(state))
			return e
		}); e == nil {
			t.Fatal("active proof rewritten")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE oidc_authorizations SET state='exchanging',exchange_started_at=? WHERE state_hash=?`, f.now, auth.TokenHash(state))
			return e
		}); e != nil {
			t.Fatal(e)
		}
		restarted, e := NewOIDCService(f.s, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = restarted.RecoverAuthorizations(f.ctx); e != nil {
			t.Fatal(e)
		}
		status, key, cipher := f.authorizationState(t, state)
		if status != "failed" || key != "" || cipher != "" {
			t.Fatal("restart retained uncertain proof")
		}
		if _, e = f.s.Get(f.ctx, a); !errors.Is(e, ErrExpired) {
			t.Fatal("cancelled flow remained usable", e)
		}
		var flowState string
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			return securitystate.One(f.ctx, tx, `SELECT state FROM identity_flows WHERE id=?`, []any{a.ID}, func(r storage.IdentityRows) error { return r.Scan(&flowState) })
		}); e != nil || flowState != "cancelled" {
			t.Fatal("restart flow state", flowState, e)
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE oidc_authorizations SET state='pending',key_id='again',nonce='again',ciphertext='again' WHERE state_hash=?`, auth.TokenHash(state))
			return e
		}); e == nil {
			t.Fatal("terminal proof refilled")
		}
		b := f.startDirectory(t, "login")
		state, _ = f.beginOIDC(t, b)
		f.clock(f.now.Add(6 * time.Minute))
		if e = f.oidc.Cleanup(f.ctx); e != nil {
			t.Fatal(e)
		}
		status, key, cipher = f.authorizationState(t, state)
		if status != "failed" || key != "" || cipher != "" {
			t.Fatal("expiry retained proof")
		}
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		if e = f.oidc.RunCleanup(ctx); !errors.Is(e, context.Canceled) {
			t.Fatal("cleanup worker did not stop", e)
		}
	})
	t.Run("management_private_proof_marker_context_and_typed_stepup", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, f.directoryIdentity.PrincipalID, f.group.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		_, completed := f.completedOIDC(t, "management")
		hash := auth.TokenHash(completed.SessionToken)
		actor := DirectoryActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin}
		if _, e := f.oidc.GetProvider(f.ctx, actor, f.p.ID); !errors.Is(e, ErrDirectoryUnavailable) {
			t.Fatal("direct service omitted private AD proof", e)
		}
		if e := f.s.WithCurrentSession(f.ctx, hash, "management", actor.Origin, func(ctx context.Context, _ *domain.SessionContext) error {
			_, e := f.oidc.GetProvider(ctx, actor, f.p.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET oidc_authentication=FALSE WHERE token_hash=?`, hash)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.Session(f.ctx, hash, "management", actor.Origin); e == nil {
			t.Fatal("OIDC context without marker became direct AD")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET oidc_authentication=TRUE WHERE token_hash=?`, hash)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		// A valid directory projection plus the OIDC marker cannot manufacture the
		// missing immutable OIDC context after partial restore.
		fake := completed.Session
		fake.ID = securitystate.ID("session")
		_, fake.TokenHash, _ = auth.NewToken()
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if e := InsertSession(f.ctx, tx, fake); e != nil {
				return e
			}
			c, e := directoryStoredContext(f.ctx, tx, "sessions", completed.Session.ID)
			if e != nil {
				return e
			}
			if e = writeDirectoryContext(f.ctx, tx, "sessions", fake.ID, c); e != nil {
				return e
			}
			_, e = tx.Exec(f.ctx, `UPDATE sessions SET oidc_authentication=TRUE WHERE id=?`, fake.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.Session(f.ctx, fake.TokenHash, "management", actor.Origin); e == nil {
			t.Fatal("missing OIDC context allowed")
		}
		for _, column := range []string{"primary_at", "mfa_at"} {
			if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				_, e := tx.Exec(f.ctx, `UPDATE sessions SET `+column+`=? WHERE token_hash=?`, f.now.Add(-6*time.Minute), f.author.TokenHash)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if _, e := f.oidc.GetProvider(f.ctx, f.author, f.p.ID); e != nil {
				t.Fatal("stale freshness blocked ordinary read", e)
			}
			if _, e := f.oidc.CreateProvider(f.ctx, f.author, OIDCProviderCreate{Name: "other", Issuer: "https://other.example.test"}); !errors.Is(e, ErrOIDCReauthRequired) {
				t.Fatal("typed step-up", column, e)
			}
			if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				_, e := tx.Exec(f.ctx, `UPDATE sessions SET `+column+`=? WHERE token_hash=?`, f.now, f.author.TokenHash)
				return e
			}); e != nil {
				t.Fatal(e)
			}
		}
	})
	t.Run("pairwise_subject_limit_two_and_disable_frees_slot", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		create := func(subject string) *OIDCSecurityOperation {
			op, e := f.oidc.PlanLink(f.ctx, f.author, f.p.ID, securitystate.ID("req"), OIDCLinkCreate{Subject: subject, DirectoryIdentityID: f.directoryIdentity.ID, ExpiresAt: f.now.Add(4 * time.Minute), Reason: "approved distinct pairwise subject"})
			if e != nil {
				t.Fatal(e)
			}
			return op
		}
		second := create("distinct-management-pairwise-subject")
		f.approveOIDC(t, second)
		if _, e := f.oidc.ExecuteOperationRequest(f.ctx, f.author, second.ID, securitystate.ID("req"), second.RequestDigest, "enable second pairwise subject"); e != nil {
			t.Fatal(e)
		}
		third := create("next-client-migration-subject")
		if _, e := f.oidc.ApproveOperationRequest(f.ctx, f.reviewer, third.ID, securitystate.ID("req"), third.RequestDigest, "third enabled link denied"); !errors.Is(e, storage.ErrConflict) {
			t.Fatal("third link exceeded bound", e)
		}
		disable, e := f.oidc.PlanLinkChange(f.ctx, f.author, f.p.ID, f.link.ID, securitystate.ID("req"), f.link.Revision, OIDCLinkSuccessor{DirectoryIdentityID: f.directoryIdentity.ID, Enabled: false, ExpiresAt: f.now.Add(4 * time.Minute), Reason: "retire first client link"})
		if e != nil {
			t.Fatal(e)
		}
		f.approveOIDC(t, disable)
		if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, disable.ID, securitystate.ID("req"), disable.RequestDigest, "free old subject slot"); e != nil {
			t.Fatal(e)
		}
		f.approveOIDC(t, third)
		if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, third.ID, securitystate.ID("req"), third.RequestDigest, "enable new client link after retirement"); e != nil {
			t.Fatal(e)
		}
	})
}
func TestOIDCStateKeySeparationAndProtectedFile(t *testing.T) {
	f := newOIDCFixture(t, false)
	raw, _ := base64.RawURLEncoding.DecodeString(f.s.Keys.Keys[f.s.Keys.Active])
	duplicate, e := NewOIDCStateKeyring("state", map[string][]byte{"state": raw})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.oidc.WithStateKeys(duplicate); !errors.Is(e, ErrDirectoryUnavailable) {
		t.Fatal("MFA key reused for OIDC")
	}
	dir, e := os.MkdirTemp("/tmp", "agp-oidc-state-key-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "state.json")
	doc := []byte(`{"apiVersion":"agp.oidc-state-keyring/v1alpha1","activeKeyId":"state","keys":{"state":"` + base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + `"}}`)
	if e = os.WriteFile(file, doc, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadOIDCStateKeyring(file); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadOIDCStateKeyring(file); !errors.Is(e, ErrDirectoryUnavailable) {
		t.Fatal("public state key accepted", e)
	}
}
