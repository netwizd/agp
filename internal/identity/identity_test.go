package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

// memoryJournal is a deterministic fault-injection double. Native signed mTLS
// journal and real restore acceptance live in securityjournal and tests/s0.
type memoryJournal struct {
	mu                                               sync.Mutex
	head                                             securityjournal.Head
	events                                           []securityjournal.Event
	unavailable, failAppend, lostResponse, badLookup bool
}

func newMemoryJournal() *memoryJournal {
	return &memoryJournal{head: securityjournal.Head{AuthorityID: "test_authority", Epoch: 1, Digest: securitystate.Digest("genesis")}}
}
func (j *memoryJournal) Head(context.Context) (securityjournal.Head, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.unavailable {
		return securityjournal.Head{}, securityjournal.ErrUnavailable
	}
	return j.head, nil
}
func (j *memoryJournal) Append(_ context.Context, r securityjournal.AppendRequest) (securityjournal.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failAppend {
		return securityjournal.Event{}, securityjournal.ErrUnavailable
	}
	for _, e := range j.events {
		if e.Request.OperationID == r.OperationID {
			return e, nil
		}
	}
	if r.ExpectedEpoch != j.head.Epoch || r.ExpectedSequence != j.head.Sequence || r.ExpectedDigest != j.head.Digest {
		return securityjournal.Event{}, securityjournal.ErrConflict
	}
	digest, _ := securityjournal.RequestDigest(r)
	e := securityjournal.Event{AuthorityID: j.head.AuthorityID, ID: securitystate.ID("event"), Epoch: j.head.Epoch, Sequence: j.head.Sequence + 1, Request: r, RequestDigest: digest, PreviousDigest: j.head.Digest, RecordedAt: r.RecordedAt}
	if r.Kind == "advance_authority_epoch" {
		e.Epoch = r.Payload.NewEpoch
		j.head.RestoreCutoff = r.Payload.RestoreCutoff
		j.head.ReleaseAfter = r.Payload.ReleaseAfter
	}
	e.Digest = securitystate.Digest(e)
	j.head.Epoch = e.Epoch
	j.head.Sequence = e.Sequence
	j.head.Digest = e.Digest
	j.events = append(j.events, e)
	if j.lostResponse {
		j.lostResponse = false
		return securityjournal.Event{}, securityjournal.ErrUnavailable
	}
	return e, nil
}
func (j *memoryJournal) Operation(_ context.Context, id string) (securityjournal.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.events {
		if e.Request.OperationID == id {
			if j.badLookup {
				e.RequestDigest = securitystate.Digest("wrong-request")
			}
			return e, nil
		}
	}
	return securityjournal.Event{}, securityjournal.ErrNotFound
}
func (j *memoryJournal) Events(_ context.Context, after securityjournal.UInt63, limit int) ([]securityjournal.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []securityjournal.Event
	for _, e := range j.events {
		if e.Sequence > after {
			out = append(out, e)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

type fixture struct {
	s           *Service
	base        storage.Store
	j           *memoryJournal
	user, other domain.User
	group       domain.Group
	ctx         context.Context
	now         time.Time
}

func identityStore(t *testing.T, pg bool) storage.Store {
	t.Helper()
	ctx := context.Background()
	if !pg {
		s, e := sqlite.Open(filepath.Join(t.TempDir(), "identity.sqlite"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { s.Close() })
		if e = s.Migrate(ctx); e != nil {
			t.Fatal(e)
		}
		return s
	}
	dsn := os.Getenv("AGP_TEST_IDENTITY_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGP_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("AGP_TEST_IDENTITY_DSN / AGP_TEST_POSTGRES_DSN not set")
	}
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "identity_" + strings.ReplaceAll(securitystate.ID("t"), "-", "_")
	schema = strings.ToLower(schema)
	if _, e = pool.Exec(ctx, `CREATE SCHEMA `+schema); e != nil {
		pool.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); pool.Close() })
	u, e := url.Parse(dsn)
	if e != nil || u.Scheme == "" {
		dsn += " search_path=" + schema
	} else {
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	s, e := postgres.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return s
}
func newFixture(t *testing.T, pg bool) *fixture { return newFixtureSetup(t, pg, nil) }
func newFixtureSetup(t *testing.T, pg bool, setup func(context.Context, storage.Store, string) error) *fixture {
	t.Helper()
	ctx := context.Background()
	base := identityStore(t, pg)
	group, e := base.CreateGroup(ctx, domain.GroupInput{Name: "Administrators", PermissionIDs: authz.AllPermissions()})
	if e != nil {
		t.Fatal(e)
	}
	hash, e := auth.HashPassword("test-initial-password", auth.Argon2idParams{Memory: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if e != nil {
		t.Fatal(e)
	}
	user, e := base.CreateUser(ctx, domain.UserInput{Username: "admin", PasswordHash: hash, IsAdmin: true, GroupIDs: []string{group.ID}})
	if e != nil {
		t.Fatal(e)
	}
	other, e := base.CreateUser(ctx, domain.UserInput{Username: "other", PasswordHash: hash, IsAdmin: true, GroupIDs: []string{group.ID}})
	if e != nil {
		t.Fatal(e)
	}
	profile := domain.SessionProfile{SecureProfile: true, PortalHost: "portal.agp.test", ManagementOrigin: "https://management.agp.test", LoginOrigin: "https://login.agp.test", SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf"}
	if setup != nil {
		if e = setup(ctx, base, user.ID); e != nil {
			t.Fatal(e)
		}
	}
	j := newMemoryJournal()
	c := securitystate.New(base, j)
	if e = c.ActivateProfile(ctx, &profile); e != nil {
		t.Fatal(e)
	}
	protected := securitystate.ProtectStore(base, c, profile)
	key := make([]byte, 32)
	rand.Read(key)
	keys := &Keyring{Active: "test", Keys: map[string]string{"test": base64.RawURLEncoding.EncodeToString(key)}}
	s, e := New(protected, c, keys, profile)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	j.mu.Lock()
	j.head.RecordedAt = now
	j.mu.Unlock()
	s.Now = func() time.Time { return now }
	return &fixture{s: s, base: base, j: j, user: *user, other: *other, group: *group, ctx: ctx, now: now}
}
func (f *fixture) clock(now time.Time) {
	f.now = now
	f.s.Now = func() time.Time { return now }
	f.j.mu.Lock()
	f.j.head.RecordedAt = now
	f.j.mu.Unlock()
}
func (f *fixture) start(t *testing.T, purpose string, source string) FlowAuth {
	t.Helper()
	csrf, _, _ := auth.NewToken()
	audience := "management"
	if purpose == "recover" {
		audience = "setup"
	}
	tr, e := f.s.Start(f.ctx, purpose, audience, f.s.Profile.ManagementOrigin, csrf, source)
	if e != nil {
		t.Fatal(e)
	}
	return FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: csrf, Origin: f.s.Profile.ManagementOrigin}
}
func (f *fixture) primary(t *testing.T, a FlowAuth, password string) FlowAuth {
	t.Helper()
	tr, e := f.s.Primary(f.ctx, a, "admin", password, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	a.ID = tr.View.ID
	a.Binding = tr.Binding
	return a
}
func (f *fixture) enroll(t *testing.T, a FlowAuth) ([]byte, []string) {
	t.Helper()
	en, e := f.s.StartEnrollment(f.ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(en.ProvisioningURI)
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if e != nil {
		t.Fatal(e)
	}
	confirmed, e := f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30))
	if e != nil {
		t.Fatal(e)
	}
	if len(confirmed.RecoveryCodes) != 10 {
		t.Fatal("missing recovery codes")
	}
	return seed, confirmed.RecoveryCodes
}
func (f *fixture) issue(t *testing.T) (Completion, []byte, []string) {
	t.Helper()
	a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
	seed, codes := f.enroll(t, a)
	complete, e := f.s.Complete(f.ctx, a, "127.0.0.1", "test")
	if e != nil {
		t.Fatal(e)
	}
	return complete, seed, codes
}

func TestLocalIdentity(t *testing.T)         { runLocalIdentity(t, false) }
func TestLocalIdentityPostgres(t *testing.T) { runLocalIdentity(t, true) }
func runLocalIdentity(t *testing.T, pg bool) {
	t.Run("binding_no_session_before_mfa", func(t *testing.T) {
		f := newFixture(t, pg)
		a := f.start(t, "login", "")
		old := a
		a = f.primary(t, a, "test-initial-password")
		if _, e := f.s.Get(f.ctx, old); !errors.Is(e, ErrProof) {
			t.Fatalf("old binding accepted: %v", e)
		}
		if _, e := f.s.Complete(f.ctx, a, "", ""); !errors.Is(e, ErrProof) {
			t.Fatalf("password-only completion: %v", e)
		}
		a.Origin = f.s.Profile.LoginOrigin
		if _, e := f.s.Get(f.ctx, a); !errors.Is(e, ErrProof) {
			t.Fatalf("origin swap: %v", e)
		}
	})
	t.Run("totp_replay_recovery_and_stepup", func(t *testing.T) {
		f := newFixture(t, pg)
		complete, seed, codes := f.issue(t)
		if complete.Session.MFAAt == nil || !complete.Session.MFAAt.Equal(f.now) {
			t.Fatal("incorrect actual proof timestamp")
		}
		if _, e := f.s.Session(f.ctx, auth.TokenHash(complete.SessionToken), "login", f.s.Profile.LoginOrigin); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("management token changed audience: %v", e)
		}
		a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
		if _, e := f.s.TOTPProof(f.ctx, a, TOTP(seed, f.now.Unix()/30)); !errors.Is(e, ErrProof) {
			t.Fatalf("replayed enrollment code: %v", e)
		}
		f.clock(f.now.Add(30 * time.Second))
		if _, e := f.s.TOTPProof(f.ctx, a, TOTP(seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.Session(f.ctx, auth.TokenHash(complete.SessionToken), "management", f.s.Profile.ManagementOrigin); e != nil {
			t.Fatalf("proof revoked unrelated session: %v", e)
		}
		// A durable replay floor survives rollback of the mutable last_step.
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE mfa_factors SET last_step=-1 WHERE principal_id=?`, f.user.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		replay := f.primary(t, f.start(t, "login", ""), "test-initial-password")
		if _, e := f.s.TOTPProof(f.ctx, replay, TOTP(seed, f.now.Unix()/30)); !errors.Is(e, ErrProof) {
			t.Fatalf("rollback replay accepted: %v", e)
		}
		f.clock(f.now.Add(30 * time.Second))
		step := f.primary(t, f.start(t, "step_up", auth.TokenHash(complete.SessionToken)), "test-initial-password")
		if _, e := f.s.TOTPProof(f.ctx, step, TOTP(seed, f.now.Unix()/30)); e != nil {
			t.Fatal(e)
		}
		rotated, e := f.s.Complete(f.ctx, step, "", "")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.s.Session(f.ctx, auth.TokenHash(complete.SessionToken), "management", f.s.Profile.ManagementOrigin); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("old session survived stepup: %v", e)
		}
		recovery := f.primary(t, f.start(t, "recover", ""), "test-initial-password")
		view, e := f.s.RecoveryProof(f.ctx, recovery, codes[0])
		if e != nil {
			t.Fatal(e)
		}
		if view.MFASatisfied {
			t.Fatal("recovery grants MFA")
		}
		if _, e = f.s.Complete(f.ctx, recovery, "", ""); !errors.Is(e, ErrProof) {
			t.Fatalf("recovery session before replacement: %v", e)
		}
		if _, e = f.s.Session(f.ctx, auth.TokenHash(rotated.SessionToken), "management", f.s.Profile.ManagementOrigin); !errors.Is(e, storage.ErrNotFound) {
			t.Fatalf("factor recovery did not revoke sessions: %v", e)
		}
		f.clock(f.now.Add(30 * time.Second))
		_, replacementCodes := f.enroll(t, recovery)
		if len(replacementCodes) != 10 {
			t.Fatal("replacement batch missing")
		}
		finished, e := f.s.Complete(f.ctx, recovery, "", "")
		if e != nil {
			t.Fatal(e)
		}
		if finished.SessionToken != "" || finished.View.MFASatisfied {
			t.Fatal("recovery issued session")
		}
		again := f.primary(t, f.start(t, "recover", ""), "test-initial-password")
		if _, e = f.s.RecoveryProof(f.ctx, again, codes[0]); !errors.Is(e, ErrProof) {
			t.Fatalf("recovery code reused: %v", e)
		}
	})
	t.Run("pending_and_lost_response", func(t *testing.T) {
		f := newFixture(t, pg)
		a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
		en, e := f.s.StartEnrollment(f.ctx, a)
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(en.ProvisioningURI)
		seed, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		f.j.failAppend = true
		if _, e = f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); e == nil {
			t.Fatal("missing journal accepted enrollment")
		}
		if e = f.s.Coordinator.Ready(f.ctx); !errors.Is(e, securitystate.ErrBarrier) {
			t.Fatalf("missing pending barrier: %v", e)
		}
		f.j.failAppend = false
		f.j.lostResponse = true
		if e = f.s.Coordinator.Recover(f.ctx); e != nil {
			t.Fatal(e)
		}
		if e = f.s.Coordinator.Ready(f.ctx); e != nil {
			t.Fatal(e)
		}
		view, e := f.s.Get(f.ctx, a)
		if e != nil || view.State != "ready" {
			t.Fatalf("recovery state: %+v %v", view, e)
		}
	})
	t.Run("v1_lifecycle_failclosed_and_metadata", func(t *testing.T) {
		f := newFixture(t, pg)
		complete, _, _ := f.issue(t)
		hash := "administrator-selected-password-hash"
		_, err := f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: f.user.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, UserUpdate: domain.UserUpdate{PasswordHash: &hash}})
		if !errors.Is(err, storage.ErrInviteRequired) {
			t.Fatalf("legacy final password allowed: %v", err)
		}
		_, err = f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityCreateUser, ManagementOrigin: f.s.Profile.ManagementOrigin, UserInput: domain.UserInput{Username: "uninvited", PasswordHash: hash}})
		if !errors.Is(err, storage.ErrInviteRequired) {
			t.Fatalf("legacy create allowed: %v", err)
		}
		_, err = f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityCreateGroup, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: "escalate", PermissionIDs: []string{authz.PermUsersManage}}})
		if !errors.Is(err, storage.ErrApprovalRequired) {
			t.Fatalf("unapproved privilege grant: %v", err)
		}
		ordinary, err := f.base.CreateUser(f.ctx, domain.UserInput{Username: "ordinary", PasswordHash: "fixture", IsAdmin: false})
		if err != nil {
			t.Fatal(err)
		}
		promotion := true
		_, err = f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: ordinary.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, UserUpdate: domain.UserUpdate{IsAdmin: &promotion}})
		if !errors.Is(err, storage.ErrApprovalRequired) {
			t.Fatalf("is_admin promotion accepted: %v", err)
		}
		_, err = f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: ordinary.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, UserUpdate: domain.UserUpdate{UpdateGroups: true, GroupIDs: []string{f.group.ID}}})
		if !errors.Is(err, storage.ErrApprovalRequired) {
			t.Fatalf("privileged membership accepted: %v", err)
		}
		empty, err := f.base.CreateGroup(f.ctx, domain.GroupInput{Name: "empty"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: empty.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: "empty", PermissionIDs: []string{authz.PermUsersRead}}})
		if !errors.Is(err, storage.ErrApprovalRequired) {
			t.Fatalf("group permission extension accepted: %v", err)
		}
		_, err = f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: f.group.ID, ManagementOrigin: f.s.Profile.ManagementOrigin, GroupInput: domain.GroupInput{Name: f.group.Name, Description: "metadata update", PermissionIDs: authz.AllPermissions()}})
		if err != nil {
			t.Fatalf("self group metadata mutation stuck after own revocation: %v", err)
		}
		if err = f.s.Coordinator.Ready(f.ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = f.s.Store.CreateUser(f.ctx, domain.UserInput{Username: "bypass"}); !errors.Is(err, storage.ErrPermissionDenied) {
			t.Fatalf("raw user bypass: %v", err)
		}
	})
	t.Run("v1_revoke_session_is_idempotent", func(t *testing.T) {
		f := newFixture(t, pg)
		complete, _, _ := f.issue(t)
		if _, err := f.s.Store.ApplyIdentityMutation(f.ctx, auth.TokenHash(complete.SessionToken), storage.IdentityMutation{Kind: storage.IdentityRevokeSession, ID: complete.Session.ID, ManagementOrigin: f.s.Profile.ManagementOrigin}); err != nil {
			t.Fatal(err)
		}
		if err := f.s.Coordinator.Ready(f.ctx); err != nil {
			t.Fatalf("revoke left pending barrier: %v", err)
		}
	})
	t.Run("enrollment_proof_time_survives_delay", func(t *testing.T) {
		f := newFixture(t, pg)
		a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
		en, err := f.s.StartEnrollment(f.ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(en.ProvisioningURI)
		seed, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		proofAt := f.now
		f.j.failAppend = true
		if _, err = f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); err == nil {
			t.Fatal("journal failure ignored")
		}
		f.clock(f.now.Add(2 * time.Minute))
		f.j.failAppend = false
		if err = f.s.Coordinator.Recover(f.ctx); err != nil {
			t.Fatal(err)
		}
		complete, err := f.s.Complete(f.ctx, a, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if complete.Session.MFAAt == nil || !complete.Session.MFAAt.Equal(proofAt) {
			t.Fatal("materialization refreshed MFA proof")
		}
	})
	t.Run("authority_failure", func(t *testing.T) {
		f := newFixture(t, pg)
		complete, _, _ := f.issue(t)
		f.j.unavailable = true
		if _, e := f.s.Session(f.ctx, auth.TokenHash(complete.SessionToken), "management", f.s.Profile.ManagementOrigin); e == nil {
			t.Fatal("authority outage accepted")
		}
	})
}

func TestTOTPAndEncryption(t *testing.T) {
	seed := []byte("12345678901234567890")
	now := time.Unix(59, 0)
	if got := TOTP(seed, 1); got != "287082" {
		t.Fatalf("RFC6238 truncation got %s", got)
	}
	step, ok := VerifyTOTP(seed, "287082", now, -1)
	if !ok || step != 1 {
		t.Fatal("valid code rejected")
	}
	if _, ok = VerifyTOTP(seed, "287082", now, 1); ok {
		t.Fatal("replay accepted")
	}
	if _, ok = VerifyTOTP(seed, "287082", now.Add(90*time.Second), -1); ok {
		t.Fatal("expired code accepted")
	}
	key := make([]byte, 32)
	rand.Read(key)
	k := &Keyring{Active: "k", Keys: map[string]string{"k": base64.RawURLEncoding.EncodeToString(key)}}
	sealed, e := k.Seal(seed, factorAAD("u", 1))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = k.Open(sealed, factorAAD("other", 1)); e == nil {
		t.Fatal("cross-principal decrypt accepted")
	}
	if _, e = k.Open(sealed, factorAAD("u", 2)); e == nil {
		t.Fatal("wrong version decrypt accepted")
	}
	raw, _ := json.Marshal(sealed)
	if strings.Contains(string(raw), string(seed)) {
		t.Fatal("plaintext seed persisted")
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	raw, _ = json.Marshal(k)
	if e = os.WriteFile(path, raw, 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadKeyring(path); e == nil {
		t.Fatal("public keyring accepted")
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadKeyring(path); e != nil {
		t.Fatal(e)
	}
}

func TestPrimaryRejectsBeforeKDF(t *testing.T) {
	f := newFixture(t, false)
	calls := 0
	f.s.verifyPassword = func(string, string) (bool, error) { calls++; return false, nil }
	if _, err := f.s.Primary(f.ctx, FlowAuth{ID: "missing", Binding: "invalid", Origin: f.s.Profile.ManagementOrigin}, "admin", "password", "ip"); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("invalid flow invoked KDF")
	}
	a := f.start(t, "login", "")
	if err := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO identity_limits(bucket,window_start,attempts) VALUES(?,?,?)`, "primary_account_"+auth.TokenHash("admin"), f.now, 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Primary(f.ctx, a, "admin", "password", "ip"); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("limited flow invoked KDF")
	}
}

func TestCentralEdgePostgres(t *testing.T) {
	f := newFixture(t, true)
	management, seed, _ := f.issue(t)
	ctx := securitystate.WithActor(f.ctx, auth.TokenHash(management.SessionToken))
	resource, err := f.s.Store.CreateResource(ctx, domain.ResourceInput{Name: "App", PublicHost: "app.agp.test", InternalURL: "http://127.0.0.1:9999", Enabled: true, GroupIDs: []string{f.group.ID}, PublicPath: "/dashboard"})
	if err != nil {
		t.Fatal(err)
	}
	registration := domain.GatewayRegistration{ID: "gateway_one", NodeID: "node_one", Origin: "https://app.agp.test:8443", Callback: "https://app.agp.test:8443/_agp/callback", ResourceID: resource.ID, Generation: "generation_one"}
	if err = f.s.RegisterGateway(f.ctx, registration); err != nil {
		t.Fatal(err)
	}
	collision := registration
	collision.ID = "gateway_two"
	collision.Origin = "https://app.agp.test:9443"
	collision.Callback = collision.Origin + "/_agp/callback"
	if err = f.s.RegisterGateway(f.ctx, collision); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("same hostname other port accepted: %v", err)
	}
	reserved := registration
	reserved.ID = "gateway_reserved"
	reserved.Origin = f.s.Profile.LoginOrigin
	reserved.Callback = reserved.Origin + "/_agp/callback"
	if err = f.s.RegisterGateway(f.ctx, reserved); err == nil {
		t.Fatal("login host registered as gateway")
	}
	csrf, _, _ := auth.NewToken()
	tr, err := f.s.Start(f.ctx, "login", "login", f.s.Profile.LoginOrigin, csrf, "")
	if err != nil {
		t.Fatal(err)
	}
	a := FlowAuth{ID: tr.View.ID, Binding: tr.Binding, CSRF: csrf, Origin: f.s.Profile.LoginOrigin}
	tr, err = f.s.Primary(f.ctx, a, "admin", "test-initial-password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	a.ID = tr.View.ID
	a.Binding = tr.Binding
	f.clock(f.now.Add(30 * time.Second))
	if _, err = f.s.TOTPProof(f.ctx, a, TOTP(seed, f.now.Unix()/30)); err != nil {
		t.Fatal(err)
	}
	login, err := f.s.Complete(f.ctx, a, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	verifier, _, _ := auth.NewToken()
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	request := AuthorizeRequest{GatewayID: registration.ID, RedirectURI: registration.Callback, State: "state_nonce", Challenge: challenge, Method: "S256"}
	if _, err = f.s.Authorize(f.ctx, auth.TokenHash(management.SessionToken), request); err == nil {
		t.Fatal("management token authorized app handoff")
	}
	callback, err := f.s.Authorize(f.ctx, auth.TokenHash(login.SessionToken), request)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(callback)
	code := u.Query().Get("code")
	if u.Query().Get("state") != "state_nonce" || code == "" {
		t.Fatal("wrong callback")
	}
	redeem := domain.HandoffRedeemRequest{Code: code, GatewayID: registration.ID, RedirectURI: registration.Callback, CodeVerifier: verifier}
	if _, err = f.s.Redeem(f.ctx, "wrong_node", registration.ID, redeem); err == nil {
		t.Fatal("wrong mTLS node redeemed code")
	}
	wrong := redeem
	wrong.CodeVerifier = strings.Repeat("a", 43)
	if _, err = f.s.Redeem(f.ctx, registration.NodeID, registration.ID, wrong); err == nil {
		t.Fatal("wrong PKCE accepted")
	}
	app, err := f.s.Redeem(f.ctx, registration.NodeID, registration.ID, redeem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Redeem(f.ctx, registration.NodeID, registration.ID, redeem); err == nil {
		t.Fatal("handoff reused")
	}
	decision := domain.EdgeDecisionRequest{GatewayID: registration.ID, RouteID: resource.ID, DeploymentGeneration: registration.Generation, SessionToken: app.SessionToken, ClientIP: "127.0.0.1", Method: "GET", Path: "/dashboard?one=two"}
	allow, err := f.s.Decision(f.ctx, registration.NodeID, registration.ID, decision)
	if err != nil || allow.Decision != "allow" || allow.UserID != f.user.ID || allow.GroupIDs == nil {
		t.Fatalf("allow: %+v %v", allow, err)
	}
	wrongGeneration := decision
	wrongGeneration.DeploymentGeneration = "stale"
	if _, err = f.s.Decision(f.ctx, registration.NodeID, registration.ID, wrongGeneration); err == nil {
		t.Fatal("wrong generation allowed")
	}
	traversal := decision
	traversal.Path = "/dashboard/%2e%2e/private"
	if _, err = f.s.Decision(f.ctx, registration.NodeID, registration.ID, traversal); err == nil {
		t.Fatal("path traversal allowed")
	}
	if _, err = f.s.Session(f.ctx, auth.TokenHash(app.SessionToken), "management", f.s.Profile.ManagementOrigin); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("app token gained management: %v", err)
	}
	f.j.unavailable = true
	if _, err = f.s.Decision(f.ctx, registration.NodeID, registration.ID, decision); err == nil {
		t.Fatal("dependency outage allowed")
	}
	f.j.unavailable = false
	if err = f.s.Logout(f.ctx, auth.TokenHash(login.SessionToken)); err != nil {
		t.Fatal(err)
	}
	deny, err := f.s.Decision(f.ctx, registration.NodeID, registration.ID, decision)
	if err != nil || deny.Decision != "deny" {
		t.Fatalf("source logout: %+v %v", deny, err)
	}
}

func TestCoordinatorFailureRecovery(t *testing.T) {
	for _, scenario := range []string{"old_epoch", "foreign_restriction", "foreign_higher_floor", "wrong_receipt"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			a := f.primary(t, f.start(t, "login", ""), "test-initial-password")
			en, err := f.s.StartEnrollment(f.ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(en.ProvisioningURI)
			seed, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
			f.j.failAppend = true
			if _, err = f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); err == nil {
				t.Fatal("append failure ignored")
			}
			f.j.failAppend = false
			switch scenario {
			case "old_epoch", "foreign_restriction", "foreign_higher_floor":
				head, _ := f.j.Head(f.ctx)
				r := securityjournal.AppendRequest{OperationID: "external", ExpectedEpoch: head.Epoch, ExpectedSequence: head.Sequence, ExpectedDigest: head.Digest, Kind: "block_principal", TargetType: "principal", TargetID: f.user.ID, ActorID: "external_admin", Payload: securityjournal.Payload{PrincipalID: f.user.ID}, RecordedAt: f.now}
				if scenario == "foreign_higher_floor" {
					r.Kind = "bump_authenticator_floor"
					r.TargetType = "authenticator"
					r.TargetID = FactorID(f.user.ID)
					r.Payload = securityjournal.Payload{PrincipalID: f.user.ID, AuthenticatorID: FactorID(f.user.ID), MinimumVersion: 2}
				}
				if scenario == "old_epoch" {
					r.Kind = "advance_authority_epoch"
					r.TargetType = "authority"
					r.TargetID = head.AuthorityID
					r.Payload = securityjournal.Payload{NewEpoch: head.Epoch + 1}
				}
				if _, err = f.j.Append(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				if err = f.s.Coordinator.Recover(f.ctx); err != nil {
					t.Fatal(err)
				}
				if err = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					ids, e := securitystate.Strings(f.ctx, tx, `SELECT principal_id FROM mfa_factors WHERE principal_id=?`, f.user.ID)
					if e != nil {
						return e
					}
					if len(ids) > 0 {
						t.Fatal("old positive factor intent was resurrected")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err = f.s.Coordinator.Ready(f.ctx); err != nil {
					t.Fatalf("aborted operation retained barrier: %v", err)
				}
			case "wrong_receipt":
				f.j.lostResponse = true
				f.j.badLookup = true
				if err = f.s.Coordinator.Recover(f.ctx); err == nil {
					t.Fatal("mismatched persisted operation receipt accepted")
				}
				f.j.badLookup = false
				if err = f.s.Coordinator.Recover(f.ctx); err != nil {
					t.Fatal(err)
				}
				if err = f.s.Coordinator.Ready(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestStaleEnrollmentDoesNotCreateBarrier(t *testing.T) {
	f := newFixture(t, false)
	first := f.primary(t, f.start(t, "login", ""), "test-initial-password")
	second := f.primary(t, f.start(t, "login", ""), "test-initial-password")
	firstEnrollment, err := f.s.StartEnrollment(f.ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	secondEnrollment, err := f.s.StartEnrollment(f.ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	seedFor := func(uri string) []byte {
		u, _ := url.Parse(uri)
		seed, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		return seed
	}
	if _, err = f.s.ConfirmEnrollment(f.ctx, first, firstEnrollment.EnrollmentID, TOTP(seedFor(firstEnrollment.ProvisioningURI), f.now.Unix()/30)); err != nil {
		t.Fatal(err)
	}
	f.clock(f.now.Add(30 * time.Second))
	if _, err = f.s.ConfirmEnrollment(f.ctx, second, secondEnrollment.EnrollmentID, TOTP(seedFor(secondEnrollment.ProvisioningURI), f.now.Unix()/30)); !errors.Is(err, ErrProof) {
		t.Fatalf("stale enrollment accepted: %v", err)
	}
	if err = f.s.Coordinator.Ready(f.ctx); err != nil {
		t.Fatalf("stale enrollment left barrier: %v", err)
	}
}

func TestEphemeralAdmissionAndCleanup(t *testing.T) {
	f := newFixture(t, false)
	csrf, _, _ := auth.NewToken()
	for i := 0; i < 60; i++ {
		if _, err := f.s.StartWithSource(f.ctx, "login", "management", f.s.Profile.ManagementOrigin, csrf, "", "source"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.StartWithSource(f.ctx, "login", "management", f.s.Profile.ManagementOrigin, csrf, "", "source"); !errors.Is(err, ErrLimited) {
		t.Fatalf("unbounded source flow admission: %v", err)
	}
	f.clock(f.now.Add(6 * time.Minute))
	if _, err := f.s.StartWithSource(f.ctx, "login", "management", f.s.Profile.ManagementOrigin, csrf, "", "source"); err != nil {
		t.Fatal(err)
	}
	if err := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		ids, err := securitystate.Strings(f.ctx, tx, `SELECT id FROM identity_flows`)
		if err != nil {
			return err
		}
		if len(ids) != 1 {
			t.Fatalf("expired flows retained: %d", len(ids))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f.s.verifyPassword = func(string, string) (bool, error) { calls++; return false, nil }
	if err := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO identity_limits(bucket,window_start,attempts) VALUES(?,?,?)`, "primary_source_"+auth.TokenHash("blocked"), f.now, 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a := f.start(t, "login", "")
	if _, err := f.s.Primary(f.ctx, a, "new-random-username", "pass", "blocked"); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	if err := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		ids, err := securitystate.Strings(f.ctx, tx, `SELECT bucket FROM identity_limits WHERE bucket=?`, "primary_account_"+auth.TokenHash("new-random-username"))
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			t.Fatal("exhausted source created new arbitrary account bucket")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("exhausted source invoked KDF")
	}
}

func TestScopedManagementSQLite(t *testing.T)   { testScopedManagement(t, false) }
func TestScopedManagementPostgres(t *testing.T) { testScopedManagement(t, true) }
func testScopedManagement(t *testing.T, pg bool) {
	f := newFixtureSetup(t, pg, func(ctx context.Context, store storage.Store, user string) error {
		return store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			for _, q := range []string{`UPDATE users SET is_admin=FALSE WHERE id=?`, `DELETE FROM user_groups WHERE user_id=?`} {
				if _, e := tx.Exec(ctx, q, user); e != nil {
					return e
				}
			}
			_, e := tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES('cgrant_login',?,'config.edit','site','site_msk',1,?)`, user, time.Now().UTC())
			return e
		})
	})
	a := f.start(t, "login", "")
	if _, e := f.s.Primary(f.ctx, a, "admin", "test-initial-password", "127.0.0.1"); e != nil {
		t.Fatalf("scoped operator cannot start management MFA: %v", e)
	}
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(f.ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id='cgrant_login'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	a = f.start(t, "login", "")
	if _, e := f.s.Primary(f.ctx, a, "admin", "test-initial-password", "127.0.0.1"); e == nil {
		t.Fatal("revoked scope still admits a new management primary proof")
	}
}
