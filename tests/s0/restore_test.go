// Package s0 contains destructive tests only against the disposable clusters
// provisioned by scripts/test-s0-full.sh. Never point these tests at a live DB.
package s0

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
)

func TestNativeControlPlaneRestore(t *testing.T) {
	if os.Getenv("AGP_TEST_S0_DISPOSABLE") != "1" {
		t.Skip("requires the disposable two-cluster S0 harness")
	}
	cpDSN := os.Getenv("AGP_TEST_S0_CP_DSN")
	journalDSN := os.Getenv("AGP_TEST_JOURNAL_DSN")
	if !strings.Contains(cpDSN, "host=/tmp/agp-s0-full.") || !strings.Contains(cpDSN, "dbname=agp_cp") || !strings.Contains(journalDSN, "host=/tmp/agp-s0-full.") || cpDSN == journalDSN {
		t.Fatal("restore test requires distinct disposable CP/journal clusters")
	}
	ctx := context.Background()
	openCP := func() *postgres.Store {
		s, e := postgres.Open(ctx, cpDSN)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	cp := openCP()
	defer func() {
		if cp != nil {
			cp.Close()
		}
	}()
	if e := cp.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	approvalPub, approvalKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityID := securitystate.ID("restore")
	journal, e := securityjournal.Open(ctx, securityjournal.StoreConfig{DSN: journalDSN, AuthorityID: authorityID, KeyID: "s0_signer", SigningKey: key, ApprovalKeys: map[string]securityjournal.ApprovalKey{"s0_approver": {PrincipalID: "independent_approver", PublicKey: approvalPub, AllowedKinds: []string{"advance_authority_epoch"}}}})
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	if e = journal.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	group, e := cp.CreateGroup(ctx, domain.GroupInput{Name: securitystate.ID("group")})
	if e != nil {
		t.Fatal(e)
	}
	oldPassword := "synthetic-old-" + securitystate.ID("pw")
	oldHash, e := auth.HashPassword(oldPassword, auth.DefaultArgon2idParams)
	if e != nil {
		t.Fatal(e)
	}
	user, e := cp.CreateUser(ctx, domain.UserInput{Username: strings.ToLower(securitystate.ID("restoreuser")), PasswordHash: oldHash, GroupIDs: []string{group.ID}})
	if e != nil {
		t.Fatal(e)
	}
	coordinator := securitystate.New(cp, journal)
	if e = coordinator.Activate(ctx); e != nil {
		t.Fatal(e)
	}
	var grantID string
	if e = cp.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(ctx, tx, `SELECT id FROM security_grants WHERE kind='membership' AND subject_id=? AND object_id=? AND active=?`, []any{user.ID, group.ID, true}, func(rows storage.IdentityRows) error { return rows.Scan(&grantID) })
	}); e != nil {
		t.Fatal(e)
	}
	appendEvent := func(r securityjournal.AppendRequest) securityjournal.Event {
		t.Helper()
		h, e := journal.Head(ctx)
		if e != nil {
			t.Fatal(e)
		}
		r.OperationID = securitystate.ID("op")
		r.ExpectedEpoch = h.Epoch
		r.ExpectedSequence = h.Sequence
		r.ExpectedDigest = h.Digest
		r.RecordedAt = time.Now().UTC()
		r.AuthorizationDigest = securitystate.Digest(r)
		if r.ActorID == "" {
			r.ActorID = "restore_operator"
		}
		ev, e := journal.Append(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		if e = coordinator.Replay(ctx); e != nil {
			t.Fatal(e)
		}
		return ev
	}

	// Enroll through the real identity engine before the backup, retaining the
	// original factor/codes to prove their rejection after a genuine restore.
	appendEvent(securitystate.FloorRequest("restore_operator", user.ID, identity.PasswordID(user.ID), 1))
	profile := domain.SessionProfile{SecureProfile: true, PortalHost: "portal.agp.test", ManagementOrigin: "https://management.agp.test", LoginOrigin: "https://login.agp.test"}
	keys := &identity.Keyring{Active: "s0", Keys: map[string]string{"s0": randomKey(t)}}
	service, e := identity.New(cp, coordinator, keys, profile)
	if e != nil {
		t.Fatal(e)
	}
	primary := func(purpose, password string) (identity.FlowAuth, error) {
		audience := "login"
		if purpose == "recover" {
			audience = "setup"
		}
		csrf := securitystate.ID("csrf")
		flow, e := service.Start(ctx, purpose, audience, profile.LoginOrigin, csrf, "")
		if e != nil {
			return identity.FlowAuth{}, e
		}
		a := identity.FlowAuth{ID: flow.View.ID, Binding: flow.Binding, CSRF: csrf, Origin: profile.LoginOrigin}
		proof, e := service.Primary(ctx, a, user.Username, password, "127.0.0.1")
		if e != nil {
			return a, e
		}
		a.Binding = proof.Binding
		a.ID = proof.View.ID
		return a, nil
	}
	setup, e := primary("login", oldPassword)
	if e != nil {
		t.Fatal(e)
	}
	enrollment, e := service.StartEnrollment(ctx, setup)
	if e != nil {
		t.Fatal(e)
	}
	provisioning, e := url.Parse(enrollment.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	oldSeed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(provisioning.Query().Get("secret"))
	if e != nil {
		t.Fatal(e)
	}
	enrolled, e := service.ConfirmEnrollment(ctx, setup, enrollment.EnrollmentID, identity.TOTP(oldSeed, time.Now().Unix()/30))
	if e != nil {
		t.Fatal(e)
	}
	if len(enrolled.RecoveryCodes) == 0 {
		t.Fatal("enrollment did not issue recovery codes")
	}
	oldRecovery := enrolled.RecoveryCodes[0]
	codeHash := auth.TokenHash(oldRecovery)
	completed, e := service.Complete(ctx, setup, "127.0.0.1", "restore-test")
	if e != nil {
		t.Fatal(e)
	}
	if completed.SessionToken == "" {
		t.Fatal("completed MFA did not issue a session")
	}
	oldSessionID := completed.Session.ID
	unfinished, e := primary("login", oldPassword)
	if e != nil {
		t.Fatal(e)
	}
	oldFlowID := unfinished.ID

	backup := filepath.Join(t.TempDir(), "cp-before-revocations.dump")
	pgbin := os.Getenv("AGP_TEST_PG_BINDIR")
	pgCommand(t, filepath.Join(pgbin, "pg_dump"), "--format=custom", "--file="+backup, "--dbname="+cpDSN)
	// Actor did not exist in the backup. Its historical journal identity must not
	// cause it or any grants to be recreated during replay.
	later, e := cp.CreateUser(ctx, domain.UserInput{Username: securitystate.ID("lateractor"), PasswordHash: oldHash})
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{identity.PasswordID(user.ID), identity.FactorID(user.ID), identity.RecoveryID(user.ID)} {
		appendEvent(securitystate.FloorRequest(later.ID, user.ID, id, 2))
	}
	appendEvent(securityjournal.AppendRequest{Kind: "remove_membership", TargetType: "grant", TargetID: grantID, ActorID: later.ID, Payload: securityjournal.Payload{GrantID: grantID}})
	appendEvent(securityjournal.AppendRequest{Kind: "revoke_session", TargetType: "session", TargetID: oldSessionID, ActorID: later.ID, Payload: securityjournal.Payload{SessionID: oldSessionID}})
	newPassword := "synthetic-new-" + securitystate.ID("pw")
	newerHash, e := auth.HashPassword(newPassword, auth.DefaultArgon2idParams)
	if e != nil {
		t.Fatal(e)
	}
	if e = cp.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `UPDATE users SET password_hash=?,password_version=2 WHERE id=?`, newerHash, user.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// Fencing ends the old writer lifetime BEFORE the independent restore epoch.
	cp.Close()
	cp = nil
	head, e := journal.Head(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cutoff := time.Now().UTC().Truncate(time.Microsecond)
	restore := securityjournal.AppendRequest{OperationID: securitystate.ID("restore"), ExpectedEpoch: head.Epoch, ExpectedSequence: head.Sequence, ExpectedDigest: head.Digest, Kind: "advance_authority_epoch", TargetType: "authority", TargetID: authorityID, ActorID: "restore_operator", ApproverID: "independent_approver", ApprovalKeyID: "s0_approver", RecordedAt: cutoff, Payload: securityjournal.Payload{NewEpoch: head.Epoch + 1, RestoreCutoff: cutoff, ReleaseAfter: cutoff.Add(92 * time.Second)}}
	restore.AuthorizationDigest = securitystate.Digest(restore)
	if e = securityjournal.SignApproval(&restore, approvalKey); e != nil {
		t.Fatal(e)
	}
	if _, e = journal.Append(ctx, restore); e != nil {
		t.Fatal(e)
	}
	pgCommand(t, filepath.Join(pgbin, "pg_restore"), "--clean", "--if-exists", "--no-owner", "--no-acl", "--dbname="+cpDSN, backup)
	cp = openCP()
	coordinator = securitystate.New(cp, journal)
	if e = coordinator.Ready(ctx); e == nil {
		t.Fatal("restored stale CP was ready before replay")
	}
	if e = coordinator.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if e = coordinator.Ready(ctx); !errors.Is(e, securitystate.ErrBarrier) {
		t.Fatalf("TOTP restore quarantine not enforced: %v", e)
	}
	if e = cp.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		for _, id := range []string{identity.PasswordID(user.ID), identity.FactorID(user.ID), identity.RecoveryID(user.ID)} {
			floor, e := securitystate.Floor(ctx, tx, user.ID, id)
			if e != nil || floor != 2 {
				t.Fatalf("floor %s: %d %v", id, floor, e)
			}
		}
		var hash string
		var version int64
		if e := securitystate.One(ctx, tx, `SELECT password_hash,password_version FROM users WHERE id=?`, []any{user.ID}, func(r storage.IdentityRows) error { return r.Scan(&hash, &version) }); e != nil {
			return e
		}
		if hash != oldHash || version != 1 {
			t.Fatal("test did not actually restore old password material")
		}
		floor, e := securitystate.Floor(ctx, tx, user.ID, identity.PasswordID(user.ID))
		if e != nil || uint64(version) >= floor {
			t.Fatal("old password material was relabelled above independent floor")
		}
		members, e := securitystate.Strings(ctx, tx, `SELECT user_id FROM user_groups WHERE user_id=? AND group_id=?`, user.ID, group.ID)
		if e != nil || len(members) != 0 {
			t.Fatal("removed grant revived")
		}
		actors, e := securitystate.Strings(ctx, tx, `SELECT id FROM users WHERE id=?`, later.ID)
		if e != nil || len(actors) != 0 {
			t.Fatal("historical actor recreated")
		}
		live, e := securitystate.Strings(ctx, tx, `SELECT id FROM sessions WHERE id=? AND revoked_at IS NULL`, oldSessionID)
		if e != nil || len(live) != 0 {
			t.Fatal("revoked session revived")
		}
		flows, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_flows WHERE id=? AND state<>'cancelled'`, oldFlowID)
		if e != nil || len(flows) != 0 {
			t.Fatal("pre-restore flow revived")
		}
		var epoch int64
		if e := securitystate.One(ctx, tx, `SELECT epoch FROM recovery_codes WHERE code_hash=?`, []any{codeHash}, func(r storage.IdentityRows) error { return r.Scan(&epoch) }); e != nil {
			return e
		}
		if epoch != 1 {
			t.Fatal("recovery material must not receive a new epoch")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	t.Log("real pg_dump/pg_restore: revokes, stable grants, old-secret floors and epoch replay verified; waiting out real TOTP quarantine")
	for time.Now().Before(restore.Payload.ReleaseAfter.Add(time.Millisecond)) {
		time.Sleep(250 * time.Millisecond)
	}
	if e = coordinator.Ready(ctx); e != nil {
		t.Fatalf("did not become ready after real quarantine: %v", e)
	}
	service, e = identity.New(cp, coordinator, keys, profile)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = primary("login", oldPassword); !errors.Is(e, identity.ErrProof) {
		t.Fatalf("restored old password was accepted: %v", e)
	}
	if _, e = service.Session(ctx, auth.TokenHash(completed.SessionToken), "login", profile.LoginOrigin); e == nil {
		t.Fatal("restored pre-epoch session accepted")
	}
	if _, e = service.Get(ctx, unfinished); e == nil {
		t.Fatal("restored pre-epoch flow accepted")
	}
	// Publish genuinely new material after its independent floor. This permits
	// isolating the restored TOTP/recovery tests from the old password denial.
	if e = cp.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `UPDATE users SET password_hash=?,password_version=2 WHERE id=?`, newerHash, user.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	factorFlow, e := primary("login", newPassword)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.TOTPProof(ctx, factorFlow, identity.TOTP(oldSeed, time.Now().Unix()/30)); e == nil {
		t.Fatal("restored old TOTP seed accepted")
	}
	recoveryFlow, e := primary("recover", newPassword)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.RecoveryProof(ctx, recoveryFlow, oldRecovery); e == nil {
		t.Fatal("restored old recovery code accepted")
	}

	if e = journal.ValidateChain(ctx); e != nil {
		t.Fatal(e)
	}
	// Password hash comparison alone would succeed after restoring. The actual
	// identity service must still enforce the independent floor (separate API test).
	if valid, err := auth.VerifyPassword(oldPassword, oldHash); err != nil || !valid {
		t.Fatal("synthetic old credential was not usable before the floor gate")
	}
}
func pgCommand(t *testing.T, path string, args ...string) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("native PostgreSQL bindir required")
	}
	command := exec.Command(path, args...)
	out, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("%s failed: %v\n%s", filepath.Base(path), e, out)
	}
}
func randomKey(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
