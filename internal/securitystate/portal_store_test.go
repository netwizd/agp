package securitystate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

// This authority double isolates final-head drift. Native signed journal and AD
// qualification are covered separately; portal metadata must append no events.
type portalAuthority struct {
	mu                 sync.Mutex
	head               securityjournal.Head
	calls              int
	drift, unavailable bool
}

func (a *portalAuthority) Head(context.Context) (securityjournal.Head, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.unavailable {
		return securityjournal.Head{}, securityjournal.ErrUnavailable
	}
	h := a.head
	if a.drift && a.calls == 2 {
		h.Sequence++
		h.Digest = securitystate.Digest("foreign restrictive change")
	}
	return h, nil
}
func (*portalAuthority) Append(context.Context, securityjournal.AppendRequest) (securityjournal.Event, error) {
	return securityjournal.Event{}, errors.New("portal metadata must not append journal events")
}
func (*portalAuthority) Operation(context.Context, string) (securityjournal.Event, error) {
	return securityjournal.Event{}, securityjournal.ErrNotFound
}
func (*portalAuthority) Events(context.Context, securityjournal.UInt63, int) ([]securityjournal.Event, error) {
	return nil, nil
}
func (a *portalAuthority) arm(drift, unavailable bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = 0
	a.drift = drift
	a.unavailable = unavailable
}

func portalTestStore(t *testing.T, pg bool) storage.Store {
	t.Helper()
	ctx := context.Background()
	if !pg {
		s, e := sqlite.Open(filepath.Join(t.TempDir(), "portal.db"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = s.Close() })
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
	schema := strings.ToLower(strings.ReplaceAll(securitystate.ID("portal"), "-", "_"))
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
	t.Cleanup(func() { _ = s.Close() })
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return s
}

type portalFixture struct {
	ctx               context.Context
	base, protected   storage.Store
	c                 *securitystate.Coordinator
	authority         *portalAuthority
	user              domain.User
	group             domain.Group
	now               time.Time
	token, downloadID string
	profile           domain.SessionProfile
}

func newPortalFixture(t *testing.T, pg bool) *portalFixture {
	t.Helper()
	base := portalTestStore(t, pg)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	group, e := base.CreateGroup(ctx, domain.GroupInput{Name: "Portal operators", PermissionIDs: []string{authz.PermDownloadsManage, authz.PermPortalSettingsManage}})
	if e != nil {
		t.Fatal(e)
	}
	user, e := base.CreateUser(ctx, domain.UserInput{Username: "portal-operator", PasswordHash: "synthetic-unused-hash", GroupIDs: []string{group.ID}})
	if e != nil {
		t.Fatal(e)
	}
	a := &portalAuthority{head: securityjournal.Head{AuthorityID: "portal_test", Epoch: 1, Digest: securitystate.Digest("genesis"), RecordedAt: now}}
	c := securitystate.New(base, a)
	profile := domain.SessionProfile{SecureProfile: true, PortalHost: "portal.agp.test", ManagementOrigin: "https://management.agp.test", LoginOrigin: "https://login.agp.test", SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf"}
	if e = c.ActivateProfile(ctx, &profile); e != nil {
		t.Fatal(e)
	}
	token := "synthetic-portal-token-hash"
	if e = base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "portal_session", UserID: user.ID, TokenHash: token, CSRFHash: "synthetic-csrf-hash", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: "management", AudienceOrigin: profile.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, MFAAt: &now, LastSeenAt: &now})
	}); e != nil {
		t.Fatal(e)
	}
	protected := securitystate.ProtectStore(base, c, profile)
	seed := portalDownload()
	seed.StoredName = "seed-download-content"
	d, e := base.CreatePublicDownload(ctx, seed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = base.UpdatePortalSettings(ctx, portalSettings("Initial")); e != nil {
		t.Fatal(e)
	}
	return &portalFixture{ctx: securitystate.WithActor(ctx, token), base: base, protected: protected, c: c, authority: a, user: *user, group: *group, now: now, token: token, downloadID: d.ID, profile: profile}
}
func portalDownload() domain.PublicDownloadInput {
	return domain.PublicDownloadInput{Title: "Client installer", Description: "Signed desktop client", FileName: "nlgate-client.pkg", StoredName: "sha256-immutable-client", ContentType: "application/octet-stream", SHA256: strings.Repeat("a", 64), SizeBytes: 12345, Enabled: true}
}
func portalSettings(brand string) domain.PortalSettings {
	return domain.PortalSettings{BrandName: brand, LogoText: "NL", PortalTitle: "Corporate access", PortalSubtitle: "Internal services", WelcomeTitle: "Welcome", WelcomeBody: "Use corporate credentials", FooterText: "NLGate", SupportText: "Support", SupportURL: "https://support.example.test"}
}
func (f *portalFixture) snapshot(t *testing.T) string {
	t.Helper()
	downloads, e := f.base.ListPublicDownloads(f.ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	settings, e := f.base.GetPortalSettings(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	audit, e := f.base.ListAuditEvents(f.ctx, domain.AuditFilter{Limit: 200})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(struct {
		Downloads []domain.PublicDownload
		Settings  *domain.PortalSettings
		Audit     []domain.AuditEvent
	}{downloads, settings, audit})
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func (f *portalFixture) write(t *testing.T, fn func(storage.IdentityTx) error) {
	t.Helper()
	if e := f.base.WriteIdentity(f.ctx, fn); e != nil {
		t.Fatal(e)
	}
}
func (f *portalFixture) mutation(name string) func() error {
	switch name {
	case "create":
		return func() error { _, e := f.protected.CreatePublicDownload(f.ctx, portalDownload()); return e }
	case "update":
		return func() error {
			title := "Changed title"
			_, e := f.protected.UpdatePublicDownload(f.ctx, f.downloadID, domain.PublicDownloadUpdate{Title: &title})
			return e
		}
	case "delete":
		return func() error { return f.protected.DeletePublicDownload(f.ctx, f.downloadID) }
	case "settings":
		return func() error { _, e := f.protected.UpdatePortalSettings(f.ctx, portalSettings("Changed")); return e }
	default:
		panic("unknown portal mutation")
	}
}
func (f *portalFixture) denyAll(t *testing.T, want error) {
	t.Helper()
	before := f.snapshot(t)
	for _, name := range []string{"create", "update", "delete", "settings"} {
		if e := f.mutation(name)(); e == nil || (want != nil && !errors.Is(e, want)) {
			t.Errorf("%s: got %v, want %v", name, e, want)
		}
	}
	if after := f.snapshot(t); after != before {
		t.Error("denied portal mutation changed metadata or audit")
	}
}
func TestProtectedPortalSQLite(t *testing.T)   { testProtectedPortal(t, false) }
func TestProtectedPortalPostgres(t *testing.T) { testProtectedPortal(t, true) }
func testProtectedPortal(t *testing.T, pg bool) {
	t.Run("CRUD_preserves_complete_metadata_and_audit", func(t *testing.T) {
		f := newPortalFixture(t, pg)
		in := portalDownload()
		got, e := f.protected.CreatePublicDownload(f.ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		want := domain.PublicDownload{ID: got.ID, Title: in.Title, Description: in.Description, FileName: in.FileName, StoredName: in.StoredName, ContentType: in.ContentType, SHA256: in.SHA256, SizeBytes: in.SizeBytes, Enabled: in.Enabled, CreatedAt: f.now, UpdatedAt: f.now}
		if !portalDownloadEqual(*got, want) {
			t.Fatalf("created metadata %#v", got)
		}
		stored, e := f.base.FindPublicDownloadByID(f.ctx, got.ID)
		if e != nil || !portalDownloadEqual(*stored, want) {
			t.Fatalf("stored metadata %#v %v", stored, e)
		}
		title, description, enabled := "Updated title", "Updated description", false
		got, e = f.protected.UpdatePublicDownload(f.ctx, got.ID, domain.PublicDownloadUpdate{Title: &title, Description: &description, Enabled: &enabled})
		if e != nil {
			t.Fatal(e)
		}
		want.Title = title
		want.Description = description
		want.Enabled = enabled
		if !portalDownloadEqual(*got, want) {
			t.Fatalf("update changed immutable file metadata %#v", got)
		}
		stored, e = f.base.FindPublicDownloadByID(f.ctx, got.ID)
		if e != nil || !portalDownloadEqual(*stored, want) {
			t.Fatalf("stored update %#v %v", stored, e)
		}
		settings := portalSettings("NLGate updated")
		changed, e := f.protected.UpdatePortalSettings(f.ctx, settings)
		if e != nil {
			t.Fatal(e)
		}
		settings.UpdatedAt = f.now
		if !portalSettingsEqual(*changed, settings) {
			t.Fatal("settings response lost fields", changed)
		}
		persisted, e := f.base.GetPortalSettings(f.ctx)
		if e != nil || !portalSettingsEqual(*persisted, settings) {
			t.Fatal("settings persistence lost fields", persisted, e)
		}
		if e = f.protected.DeletePublicDownload(f.ctx, got.ID); e != nil {
			t.Fatal(e)
		}
		if _, e = f.base.FindPublicDownloadByID(f.ctx, got.ID); !errors.Is(e, storage.ErrNotFound) {
			t.Fatal("deleted download remains", e)
		}
		for _, kind := range []string{"portal.download.created", "portal.download.updated", "portal.download.deleted", "portal.settings.updated"} {
			events, e := f.base.ListAuditEvents(f.ctx, domain.AuditFilter{EventType: kind, Limit: 10})
			if e != nil || len(events) != 1 || events[0].SubjectUserID != f.user.ID {
				t.Fatalf("audit %s %#v %v", kind, events, e)
			}
		}
	})
	t.Run("denied_guard_checks_all_four_writes", func(t *testing.T) {
		f := newPortalFixture(t, pg)
		denied := errors.New("stale private directory proof")
		calls := 0
		f.c.RegisterSessionGuard(func(_ context.Context, _ storage.IdentityTx, h securityjournal.Head, hash string) error {
			calls++
			if hash != f.token || h.Epoch != 1 {
				t.Fatal("guard binding changed")
			}
			return denied
		})
		f.denyAll(t, denied)
		if calls != 4 {
			t.Fatal("guard bypass", calls)
		}
	})
	t.Run("current_management_permissions_and_MFA_required", func(t *testing.T) {
		f := newPortalFixture(t, pg)
		cases := []struct {
			name, query string
			args        []any
		}{
			{"missing_permission", `DELETE FROM user_groups WHERE user_id=?`, []any{f.user.ID}},
			{"revoked_session", `UPDATE sessions SET revoked_at=? WHERE id='portal_session'`, []any{f.now}},
			{"expired_session", `UPDATE sessions SET expires_at=? WHERE id='portal_session'`, []any{f.now.Add(-time.Hour)}},
			{"missing_MFA", `UPDATE sessions SET mfa_at=NULL WHERE id='portal_session'`, nil},
			{"stale_MFA", `UPDATE sessions SET mfa_at=? WHERE id='portal_session'`, []any{f.now.Add(-10 * time.Minute)}},
			{"idle_session", `UPDATE sessions SET last_seen_at=? WHERE id='portal_session'`, []any{f.now.Add(-time.Hour)}},
			{"stale_session_version", `UPDATE sessions SET security_version=0 WHERE id='portal_session'`, nil},
			{"wrong_audience", `UPDATE sessions SET audience='login' WHERE id='portal_session'`, nil},
			{"wrong_origin", `UPDATE sessions SET audience_origin='https://other.example.test' WHERE id='portal_session'`, nil},
			{"old_epoch", `UPDATE sessions SET authority_epoch=2 WHERE id='portal_session'`, nil},
			{"blocked_principal", `UPDATE users SET blocked_at=? WHERE id=?`, []any{f.now, f.user.ID}},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				f.write(t, func(tx storage.IdentityTx) error {
					if _, e := tx.Exec(f.ctx, `UPDATE users SET blocked_at=NULL WHERE id=?`, f.user.ID); e != nil {
						return e
					}
					if _, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?) ON CONFLICT(user_id,group_id) DO NOTHING`, f.user.ID, f.group.ID); e != nil {
						return e
					}
					if _, e := tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=NULL,expires_at=?,mfa_at=?,last_seen_at=?,security_version=1,audience='management',audience_origin=?,authority_epoch=1 WHERE id='portal_session'`, f.now.Add(time.Hour), f.now, f.now, f.profile.ManagementOrigin); e != nil {
						return e
					}
					_, e := tx.Exec(f.ctx, test.query, test.args...)
					return e
				})
				f.denyAll(t, storage.ErrPermissionDenied)
			})
		}
	})

	t.Run("typed_AD_direct_without_configured_or_private_proof_denied", func(t *testing.T) {
		f := newPortalFixture(t, pg)
		f.write(t, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE users SET identity_kind='directory' WHERE id=?`, f.user.ID)
			return e
		})
		f.denyAll(t, securitystate.ErrUnavailable)
		f.c.RegisterSessionGuard(identity.CheckDirectorySessionProjection)
		f.denyAll(t, identity.ErrProof) // missing immutable link also remains closed
		installPortalDirectoryLink(t, f)
		f.denyAll(t, identity.ErrDirectoryUnavailable) // valid projection cannot replace private live evidence
	})
	t.Run("final_independent_head_drift_rolls_back_metadata_and_audit", func(t *testing.T) {
		f := newPortalFixture(t, pg)
		for _, name := range []string{"create", "update", "delete", "settings"} {
			before := f.snapshot(t)
			f.authority.arm(true, false)
			if e := f.mutation(name)(); !errors.Is(e, securitystate.ErrUnavailable) {
				t.Fatalf("%s final drift: %v", name, e)
			}
			f.authority.mu.Lock()
			calls := f.authority.calls
			f.authority.mu.Unlock()
			f.authority.arm(false, false)
			if calls != 2 {
				t.Fatalf("%s did not reach final fence: %d", name, calls)
			}
			if after := f.snapshot(t); after != before {
				t.Fatalf("%s final drift committed metadata/audit", name)
			}
		}
	})
	t.Run("restored_principal_or_password_below_floor_denied", func(t *testing.T) {
		f := newPortalFixture(t, pg)
		for _, authenticator := range []string{"principal_" + f.user.ID, "password_" + f.user.ID} {
			f.write(t, func(tx storage.IdentityTx) error {
				// Exact projection of a replayed restriction followed by a restored old
				// user/session. A restrictive floor must defeat that stale positive row.
				event := securityjournal.Event{RecordedAt: f.now, Request: securityjournal.AppendRequest{Kind: "bump_authenticator_floor", Payload: securityjournal.Payload{PrincipalID: f.user.ID, AuthenticatorID: authenticator, MinimumVersion: 2}}}
				if e := securitystate.MaterializeEvent(f.ctx, tx, event); e != nil {
					return e
				}
				_, e := tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=NULL WHERE id='portal_session'`)
				return e
			})
			f.denyAll(t, storage.ErrPermissionDenied)
			f.write(t, func(tx storage.IdentityTx) error {
				_, e := tx.Exec(f.ctx, `DELETE FROM authenticator_floors WHERE principal_id=? AND authenticator_id=?`, f.user.ID, authenticator)
				return e
			})
		}
	})
}

func portalDownloadEqual(a, b domain.PublicDownload) bool {
	a.CreatedAt = a.CreatedAt.UTC()
	a.UpdatedAt = a.UpdatedAt.UTC()
	b.CreatedAt = b.CreatedAt.UTC()
	b.UpdatedAt = b.UpdatedAt.UTC()
	return reflect.DeepEqual(a, b)
}
func portalSettingsEqual(a, b domain.PortalSettings) bool {
	a.UpdatedAt = a.UpdatedAt.UTC()
	b.UpdatedAt = b.UpdatedAt.UTC()
	return reflect.DeepEqual(a, b)
}
