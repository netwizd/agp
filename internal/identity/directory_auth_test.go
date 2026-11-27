package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type directoryAuthFixture struct {
	*directoryFixture
	wire *adWireFixture
}

func newDirectoryAuthFixture(t *testing.T, pg, jit bool) *directoryAuthFixture {
	t.Helper()
	f := newDirectoryFixture(t, pg)
	wire := newADWireFixture(t, "ldaps")
	wire.config.Spec.ForestGUID = f.provider.ForestGUID
	f.document.Spec = wire.config.Spec
	f.document.Spec.GroupMappings = []DirectoryGroupMapping{{GroupObjectGUID: "10112233-4455-6677-8899-aabbccddeeff", AccessGroupID: f.group.ID}}
	if jit {
		f.document.Spec.Provisioning = "jit_unprivileged"
	}
	f.directory.validator = wire.connector
	f.s.WithDirectory(f.directory, wire.connector)
	f.propose(t)
	f.test(t)
	op := f.plan(t, true)
	f.approve(t, op)
	if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e != nil {
		t.Fatal(e)
	}
	return &directoryAuthFixture{f, wire}
}
func (f *directoryAuthFixture) startDirectory(t *testing.T, audience string) FlowAuth {
	t.Helper()
	return f.startDirectoryFlow(t, "login", audience, "")
}
func (f *directoryAuthFixture) startDirectoryFlow(t *testing.T, purpose, audience, sourceHash string) FlowAuth {
	t.Helper()
	origin := f.s.Profile.LoginOrigin
	if audience == "management" {
		origin = f.s.Profile.ManagementOrigin
	}
	csrf, _, _ := auth.NewToken()
	tr, e := f.s.Start(f.ctx, purpose, audience, origin, csrf, sourceHash)
	if e != nil {
		t.Fatal(e)
	}
	return FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: csrf, Origin: origin}
}
func (f *directoryAuthFixture) primaryDirectory(t *testing.T, a FlowAuth) FlowAuth {
	t.Helper()
	tr, e := f.s.PrimaryDirectory(f.ctx, a, f.provider.ID, "alice@corp.example.net", "synthetic-user-password", "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	a.ID = tr.View.ID
	a.Binding = tr.Binding
	return a
}
func (f *directoryAuthFixture) provision(t *testing.T) *DirectoryIdentityView {
	t.Helper()
	link, e := f.directory.ProvisionIdentity(f.ctx, f.author, f.provider.ID, "20112233-4455-6677-8899-aabbccddeeff")
	if e != nil {
		t.Fatal(e)
	}
	return link
}
func (f *directoryAuthFixture) login(t *testing.T, audience string) Completion {
	t.Helper()
	a := f.primaryDirectory(t, f.startDirectory(t, audience))
	f.enroll(t, a)
	completion, e := f.s.Complete(f.ctx, a, "127.0.0.1", "directory TLS fixture")
	if e != nil {
		t.Fatal(e)
	}
	return completion
}
func (f *directoryAuthFixture) managementDirectory(t *testing.T) (*DirectoryIdentityView, DirectoryActor) {
	t.Helper()
	link := f.provision(t)
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, link.PrincipalID, f.group.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	login := f.login(t, "management")
	return link, DirectoryActor{TokenHash: auth.TokenHash(login.SessionToken), Origin: f.s.Profile.ManagementOrigin}
}
func (f *directoryAuthFixture) directoryRequest(t *testing.T, actor DirectoryActor, fn func(context.Context) error) {
	t.Helper()
	if e := f.s.WithCurrentSession(f.ctx, actor.TokenHash, "management", actor.Origin, func(ctx context.Context, _ *domain.SessionContext) error { return fn(ctx) }); e != nil {
		t.Fatal(e)
	}
}
func (f *directoryAuthFixture) successor(t *testing.T, enabled bool) *ProviderSecurityOperation {
	t.Helper()
	f.provider.Revision++
	f.document.Metadata.VersionID = securitystate.ID("dirver")
	f.document.Metadata.SecurityGuardVersion = 2
	f.propose(t)
	if enabled {
		f.test(t)
	}
	return f.plan(t, enabled)
}
func TestDirectoryAuthenticationSQLite(t *testing.T)   { testDirectoryAuthentication(t, false) }
func TestDirectoryAuthenticationPostgres(t *testing.T) { testDirectoryAuthentication(t, true) }
func testDirectoryAuthentication(t *testing.T, pg bool) {
	t.Run("explicit_stable_link_requires_MFA_no_local_merge_or_role_mapping", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		a := f.startDirectory(t, "login")
		if _, e := f.s.PrimaryDirectory(f.ctx, a, f.provider.ID, "alice@corp.example.net", "synthetic-user-password", "127.0.0.1"); !errors.Is(e, ErrProof) {
			t.Fatalf("unprovisioned account: %v", e)
		}
		link := f.provision(t)
		if link.PrincipalID == f.user.ID {
			t.Fatal("directory account merged with local admin")
		}
		a = f.primaryDirectory(t, f.startDirectory(t, "login"))
		if _, e := f.s.Complete(f.ctx, a, "", "test"); !errors.Is(e, ErrProof) {
			t.Fatal("password-only directory session", e)
		}
		f.enroll(t, a)
		login, e := f.s.Complete(f.ctx, a, "127.0.0.1", "test")
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "login", f.s.Profile.LoginOrigin)
		if e != nil || session.User.ID != link.PrincipalID || session.User.IsAdmin || len(session.Permissions) != 0 || len(session.Groups) != 1 || session.Groups[0] != f.group.ID {
			t.Fatalf("unexpected identity/management roles %#v %v", session, e)
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var password, kind string
			e := securitystate.One(f.ctx, tx, `SELECT password_hash,identity_kind FROM users WHERE id=?`, []any{link.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&password, &kind) })
			if e != nil {
				return e
			}
			if password != "" || kind != "directory" {
				t.Fatal("directory local fallback credential")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		f.wire.disabled.Store(true)
		if _, e = f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("disabled AD account kept session allow")
		}
		f.wire.disabled.Store(false)
		f.wire.missingGroups.Store(true)
		if _, e = f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("incomplete AD groups used cached session allow")
		}
	})
	t.Run("live_groups_handoff_redeem_and_edge_without_stored_membership", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		login := f.login(t, "login")
		resource, e := f.base.CreateResource(f.ctx, domain.ResourceInput{Name: "Directory app", PublicHost: "directory-app.agp.test", InternalURL: "http://127.0.0.1:9999", Enabled: true, GroupIDs: []string{f.group.ID}})
		if e != nil {
			t.Fatal(e)
		}
		gateway := domain.GatewayRegistration{ID: "directory_gateway", NodeID: "directory_node", Origin: "https://directory-app.agp.test", Callback: "https://directory-app.agp.test/_agp/callback", ResourceID: resource.ID, Generation: "directory_generation"}
		if e = f.s.RegisterGateway(f.ctx, gateway); e != nil {
			t.Fatal(e)
		}
		verifier, _, _ := auth.NewToken()
		hashed := sha256.Sum256([]byte(verifier))
		redirect, e := f.s.Authorize(f.ctx, auth.TokenHash(login.SessionToken), AuthorizeRequest{GatewayID: gateway.ID, RedirectURI: gateway.Callback, State: "bound_state", Challenge: base64.RawURLEncoding.EncodeToString(hashed[:]), Method: "S256"})
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(redirect)
		request := domain.HandoffRedeemRequest{Code: u.Query().Get("code"), GatewayID: gateway.ID, RedirectURI: gateway.Callback, CodeVerifier: verifier}
		f.wire.disabled.Store(true)
		if _, e = f.s.Redeem(f.ctx, gateway.NodeID, gateway.ID, request); e == nil {
			t.Fatal("disabled AD account redeemed handoff")
		}
		f.wire.disabled.Store(false)
		app, e := f.s.Redeem(f.ctx, gateway.NodeID, gateway.ID, request)
		if e != nil {
			t.Fatal(e)
		}
		decision := domain.EdgeDecisionRequest{GatewayID: gateway.ID, RouteID: resource.ID, DeploymentGeneration: gateway.Generation, SessionToken: app.SessionToken, ClientIP: "127.0.0.1", Method: "GET", Path: "/"}
		allow, e := f.s.Decision(f.ctx, gateway.NodeID, gateway.ID, decision)
		if e != nil || allow.Decision != "allow" || allow.UserID != link.PrincipalID {
			t.Fatalf("directory edge allow %#v %v", allow, e)
		}
		f.wire.unmappedMembership.Store(true)
		denied, e := f.s.Decision(f.ctx, gateway.NodeID, gateway.ID, decision)
		if e != nil || denied.Decision != "deny" {
			t.Fatalf("removed live membership %#v %v", denied, e)
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			groups, e := securitystate.Strings(f.ctx, tx, `SELECT group_id FROM user_groups WHERE user_id=?`, link.PrincipalID)
			if e != nil {
				return e
			}
			if len(groups) != 0 {
				t.Fatal("AD groups materialized into local roles/memberships")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("directory_stepup_rotation_and_recovery_require_live_account", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, link.PrincipalID, f.group.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		a := f.primaryDirectory(t, f.startDirectory(t, "management"))
		seed, codes := f.enroll(t, a)
		login, e := f.s.Complete(f.ctx, a, "127.0.0.1", "test")
		if e != nil {
			t.Fatal(e)
		}
		f.clock(f.now.Add(30 * time.Second))
		step := f.primaryDirectory(t, f.startDirectoryFlow(t, "step_up", "management", auth.TokenHash(login.SessionToken)))
		if _, e = f.s.TOTPProof(f.ctx, step, TOTP(seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		rotated, e := f.s.Complete(f.ctx, step, "127.0.0.1", "test")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "management", f.s.Profile.ManagementOrigin); e == nil {
			t.Fatal("old AD session survived step-up rotation")
		}
		if _, e = f.s.Session(f.ctx, auth.TokenHash(rotated.SessionToken), "management", f.s.Profile.ManagementOrigin); e != nil {
			t.Fatal("rotated AD context missing", e)
		}
		recover := f.primaryDirectory(t, f.startDirectoryFlow(t, "recover", "setup", ""))
		f.wire.disabled.Store(true)
		if _, e = f.s.RecoveryProof(f.ctx, recover, codes[0]); e == nil {
			t.Fatal("disabled directory principal used recovery code")
		}
		f.wire.disabled.Store(false)
		view, e := f.s.RecoveryProof(f.ctx, recover, codes[0])
		if e != nil || view.MFASatisfied {
			t.Fatalf("AD recovery prematurely grants MFA %#v %v", view, e)
		}
		if _, e = f.s.Session(f.ctx, auth.TokenHash(rotated.SessionToken), "management", f.s.Profile.ManagementOrigin); e == nil {
			t.Fatal("AD recovery did not revoke old sessions")
		}
		f.clock(f.now.Add(30 * time.Second))
		f.enroll(t, recover)
		finished, e := f.s.Complete(f.ctx, recover, "127.0.0.1", "test")
		if e != nil || finished.SessionToken != "" || finished.View.MFASatisfied {
			t.Fatalf("AD factor recovery issued login %#v %v", finished, e)
		}
	})

	t.Run("JIT_login_is_unprivileged_and_does_not_link_same_UPN", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, true)
		local, e := f.base.CreateUser(f.ctx, domain.UserInput{Username: "alice@corp.example.net", PasswordHash: f.s.dummy, IsAdmin: true, GroupIDs: []string{f.group.ID}})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.PrimaryDirectory(f.ctx, f.startDirectory(t, "management"), f.provider.ID, "alice@corp.example.net", "synthetic-user-password", "127.0.0.1"); !errors.Is(e, ErrProof) {
			t.Fatal("JIT created management principal", e)
		}
		a := f.primaryDirectory(t, f.startDirectory(t, "login"))
		var principal string
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			flow, e := loadFlow(f.ctx, tx, a.ID)
			if e == nil {
				principal = flow.PrincipalID
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if principal == local.ID {
			t.Fatal("UPN auto-linked existing local principal")
		}
		f.enroll(t, a)
		login, e := f.s.Complete(f.ctx, a, "", "test")
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "login", f.s.Profile.LoginOrigin)
		if e != nil || session.User.IsAdmin || len(session.Permissions) != 0 {
			t.Fatalf("JIT permissions %#v %v", session, e)
		}
	})
	t.Run("revocation_floor_survives_mutable_link_session_restore", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		login := f.login(t, "login")
		if e := f.directory.RevokeIdentity(f.ctx, f.author, f.provider.ID, link.ID, "Revoke the stable directory identity"); e != nil {
			t.Fatal(e)
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `UPDATE directory_identities SET revoked=FALSE WHERE id=?`, link.ID); e != nil {
				return e
			}
			_, e := tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=NULL WHERE id=?`, login.Session.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("restored link/session bypassed independent authenticator floor")
		}
	})
	t.Run("management_requires_private_live_proof_and_current_provider_pin", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		// Explicit trusted fixture provisioning of a manual management group. AD
		// membership alone never creates this row or these management permissions.
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, link.PrincipalID, f.group.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		login := f.login(t, "management")
		hash := auth.TokenHash(login.SessionToken)
		actor := DirectoryActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin}
		if _, e := f.directory.GetProvider(f.ctx, actor, f.provider.ID); !errors.Is(e, ErrDirectoryUnavailable) {
			t.Fatal("direct AD token bypassed live context proof", e)
		}
		e := f.s.WithCurrentSession(f.ctx, hash, "management", f.s.Profile.ManagementOrigin, func(ctx context.Context, _ *domain.SessionContext) error {
			_, e := f.directory.GetProvider(ctx, actor, f.provider.ID)
			return e
		})
		if e != nil {
			t.Fatal("current live proof", e)
		}
		e = f.s.WithCurrentSession(f.ctx, hash, "management", f.s.Profile.ManagementOrigin, func(ctx context.Context, _ *domain.SessionContext) error {
			f.clock(f.now.Add(11 * time.Second))
			_, e := f.directory.GetProvider(ctx, actor, f.provider.ID)
			return e
		})
		if !errors.Is(e, ErrDirectoryUnavailable) {
			t.Fatal("old request live proof reused", e)
		}
	})

	t.Run("typed_kind_link_consistency_and_no_local_password_fallback", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		hash, e := auth.HashPassword("synthetic-local-fallback", auth.Argon2idParams{Memory: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
		if e != nil {
			t.Fatal(e)
		}
		var username string
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `UPDATE users SET password_hash=? WHERE id=?`, hash, link.PrincipalID); e != nil {
				return e
			}
			return securitystate.One(f.ctx, tx, `SELECT username FROM users WHERE id=?`, []any{link.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&username) })
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Primary(f.ctx, f.startDirectory(t, "login"), username, "synthetic-local-fallback", "127.0.0.1"); !errors.Is(e, ErrProof) {
			t.Fatal("directory principal used local password fallback", e)
		}
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET identity_kind='local' WHERE id=?`, link.PrincipalID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.PrimaryDirectory(f.ctx, f.startDirectory(t, "login"), f.provider.ID, "alice@corp.example.net", "synthetic-user-password", "127.0.0.1"); !errors.Is(e, ErrProof) {
			t.Fatal("local kind accepted directory link", e)
		}
		token, tokenHash, _ := auth.NewToken()
		if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `INSERT INTO users(id,username,password_hash,identity_kind,security_version,password_version) VALUES('orphan_directory','orphan-directory','','directory',1,1)`); e != nil {
				return e
			}
			return InsertSession(f.ctx, tx, domain.Session{ID: "orphan_directory_session", UserID: "orphan_directory", TokenHash: tokenHash, CSRFHash: auth.TokenHash(token), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), Audience: "management", AudienceOrigin: f.s.Profile.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, MFAAt: &f.now, LastSeenAt: &f.now})
		}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Session(f.ctx, tokenHash, "management", f.s.Profile.ManagementOrigin); !errors.Is(e, ErrProof) {
			t.Fatal("directory kind without link became local allow", e)
		}
	})
	for _, enabled := range []bool{true, false} {
		name := "AD_reviewer_same_provider_disable"
		if enabled {
			name = "AD_reviewer_same_provider_rotation"
		}
		t.Run(name, func(t *testing.T) {
			f := newDirectoryAuthFixture(t, pg, false)
			_, actor := f.managementDirectory(t)
			op := f.successor(t, enabled)
			f.directoryRequest(t, actor, func(ctx context.Context) error {
				_, e := f.directory.ApproveOperationRequest(ctx, actor, op.ID, securitystate.ID("request"), op.RequestDigest, "Independent AD reviewer verified immutable successor")
				return e
			})
			applied, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest)
			if e != nil || applied.State != "applied" {
				t.Fatalf("same-provider change %#v %v", applied, e)
			}
			if _, e = f.s.Session(f.ctx, actor.TokenHash, "management", actor.Origin); e == nil {
				t.Fatal("same-provider transition failed to invalidate old reviewer session")
			}
		})
	}
	t.Run("historical_AD_reviewer_disabled_or_link_revoked_cannot_activate", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link, actor := f.managementDirectory(t)
		op := f.successor(t, true)
		f.directoryRequest(t, actor, func(ctx context.Context) error {
			_, e := f.directory.ApproveOperation(ctx, actor, op.ID, op.RequestDigest, "Independent AD reviewer verified immutable successor")
			return e
		})
		f.wire.disabled.Store(true)
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e == nil {
			t.Fatal("disabled historical AD reviewer authorized activation")
		}
		f.wire.disabled.Store(false)
		if e := f.directory.RevokeIdentity(f.ctx, f.author, f.provider.ID, link.ID, "Revoke directory reviewer before execution"); e != nil {
			t.Fatal(e)
		}
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e == nil {
			t.Fatal("locally revoked historical AD reviewer authorized activation")
		}
		if view, e := f.directory.GetOperation(f.ctx, f.author, op.ID); e != nil || view.ApprovalStatus != "expired" {
			t.Fatalf("revoked reviewer status %#v %v", view, e)
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE directory_identities SET revoked=FALSE WHERE id=?`, link.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e == nil {
			t.Fatal("restored revoked historical AD reviewer bypassed independent link floor")
		}
		current, e := f.directory.CurrentProvider(f.ctx, f.provider.ID)
		if e != nil || current.Metadata.SecurityGuardVersion != 1 {
			t.Fatalf("denied execution changed provider %#v %v", current, e)
		}
	})
	t.Run("recovery_does_not_reuse_persisted_AD_approval_as_live_proof", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		_, actor := f.managementDirectory(t)
		op := f.successor(t, true)
		f.directoryRequest(t, actor, func(ctx context.Context) error {
			_, e := f.directory.ApproveOperation(ctx, actor, op.ID, op.RequestDigest, "Independent AD reviewer verified immutable successor")
			return e
		})
		f.j.failAppend = true
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e == nil {
			t.Fatal("expected interrupted independent append")
		}
		f.j.failAppend = false
		RegisterDirectoryRecovery(f.s.Coordinator)
		if e := f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal(e)
		}
		view, e := f.directory.GetOperation(f.ctx, f.author, op.ID)
		if e != nil || view.State != "recovery_required" {
			t.Fatalf("recovery reused persisted AD proof %#v %v", view, e)
		}
		if _, e = f.directory.CurrentProvider(f.ctx, f.provider.ID); e == nil {
			t.Fatal("recovery allowed provider beneath its restrictive floor")
		}
	})

	t.Run("AD_operation_author_executor_can_disable_own_provider", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		_, actor := f.managementDirectory(t)
		f.provider.Revision++
		f.document.Metadata.VersionID = securitystate.ID("dirver")
		f.document.Metadata.SecurityGuardVersion = 2
		f.propose(t)
		var op *ProviderSecurityOperation
		f.directoryRequest(t, actor, func(ctx context.Context) error {
			var e error
			op, e = f.directory.PlanActivation(ctx, actor, f.provider.ID, securitystate.ID("request"), DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: false, Reason: "Disable provider with independent review"})
			return e
		})
		f.approve(t, op)
		f.directoryRequest(t, actor, func(ctx context.Context) error {
			applied, e := f.directory.ExecuteOperationRequest(ctx, actor, op.ID, securitystate.ID("request"), op.RequestDigest, "Execute self-provider disable")
			if e == nil && applied.State != "applied" {
				t.Fatalf("AD executor own transition %#v", applied)
			}
			return e
		})
		if _, e := f.s.Session(f.ctx, actor.TokenHash, "management", actor.Origin); e == nil {
			t.Fatal("AD executor session survived own disable")
		}
	})

	t.Run("historical_AD_version_author_live_check_and_same_provider_execution", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		_, actor := f.managementDirectory(t)
		f.provider.Revision++
		f.document.Metadata.VersionID = securitystate.ID("dirver")
		f.document.Metadata.SecurityGuardVersion = 2
		f.directoryRequest(t, actor, func(ctx context.Context) error {
			_, e := f.directory.ProposeVersion(ctx, actor, f.provider.ID, f.provider.Revision, f.document)
			return e
		})
		f.provider.Revision++
		f.test(t)
		op := f.plan(t, true)
		f.approve(t, op)
		f.wire.disabled.Store(true)
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e == nil {
			t.Fatal("disabled historical AD version author authorized activation")
		}
		f.wire.disabled.Store(false)
		applied, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest)
		if e != nil || applied.State != "applied" {
			t.Fatalf("same-provider AD author change %#v %v", applied, e)
		}
	})

	t.Run("provider_successor_invalidates_old_session_context", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		f.provision(t)
		login := f.login(t, "login")
		f.provider.Revision++
		f.document.Metadata.VersionID = securitystate.ID("dirver")
		f.document.Metadata.SecurityGuardVersion = 2
		f.propose(t)
		f.test(t)
		op := f.plan(t, true)
		f.approve(t, op)
		if _, e := f.directory.ExecuteOperation(f.ctx, f.author, op.ID, op.RequestDigest); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.Session(f.ctx, auth.TokenHash(login.SessionToken), "login", f.s.Profile.LoginOrigin); e == nil {
			t.Fatal("old provider version session remained valid")
		}
	})
}
