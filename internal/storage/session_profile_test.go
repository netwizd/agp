package storage_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

func TestSessionProfileStorage(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			profile := domain.SessionProfile{PortalHost: "portal.example", ManagementOrigin: "https://management.example:8443", SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf"}
			legacy := profile
			legacy.ManagementOrigin = ""
			t.Run("explicit_activation_and_audience", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				if err := f.store.CheckSessionProfile(f.ctx, legacy); err != nil {
					t.Fatalf("untouched legacy must work: %v", err)
				}
				if err := f.store.CheckSessionProfile(f.ctx, profile); !errors.Is(err, storage.ErrSessionProfile) {
					t.Fatalf("enabled profile started without activation: %v", err)
				}
				current, err := f.store.GetSessionProfile(f.ctx)
				if err != nil || current != nil {
					t.Fatalf("preview changed profile: %v %v", current, err)
				}
				f.active(t, f.rootToken, true)
				revoked, err := f.store.ApplySessionProfile(f.ctx, profile)
				if err != nil || revoked != 4 {
					t.Fatalf("activate: revoked=%d err=%v", revoked, err)
				}
				f.active(t, f.rootToken, false)
				f.active(t, f.managerToken, false)
				issue := func(id string, user *domain.User, audience, audienceOrigin string, p domain.SessionProfile) error {
					latest, err := f.store.FindUserByUsername(f.ctx, user.Username)
					if err != nil {
						t.Fatal(err)
					}
					now := time.Now().UTC()
					return f.store.CreateAuthenticatedSession(f.ctx, domain.Session{ID: id, UserID: user.ID, TokenHash: id, CSRFHash: "csrf", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: audience, AudienceOrigin: audienceOrigin}, latest.PasswordHash, latest.UpdatedAt, p)
				}
				if err := issue("old-process", f.root, domain.SessionAudienceLegacy, "", legacy); !errors.Is(err, storage.ErrSessionProfile) {
					t.Fatalf("stale process issued legacy admin-capable session: %v", err)
				}
				if err := issue("portal-root", f.root, domain.SessionAudienceLegacy, "", profile); err != nil {
					t.Fatal(err)
				}
				if err := issue("management-root", f.root, domain.SessionAudienceManagement, profile.ManagementOrigin, profile); err != nil {
					t.Fatal(err)
				}
				if err := issue("management-user", f.ordinary, domain.SessionAudienceManagement, profile.ManagementOrigin, profile); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("ordinary user obtained management session: %v", err)
				}
				if err := issue("wrong-origin", f.root, domain.SessionAudienceManagement, "https://other.example", profile); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("management session bound to wrong origin: %v", err)
				}
				portalSession, err := f.store.FindSessionByTokenHash(f.ctx, "portal-root")
				if err != nil || portalSession.Audience != domain.SessionAudienceLegacy || portalSession.AudienceOrigin != "" {
					t.Fatalf("portal audience: %#v %v", portalSession, err)
				}
				managementSession, err := f.store.FindSessionByTokenHash(f.ctx, "management-root")
				if err != nil || managementSession.Audience != domain.SessionAudienceManagement || managementSession.AudienceOrigin != profile.ManagementOrigin {
					t.Fatalf("management audience: %#v %v", managementSession, err)
				}
				display := "updated"
				mutation := storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: f.ordinary.ID, UserUpdate: domain.UserUpdate{DisplayName: &display}, ManagementOrigin: profile.ManagementOrigin}
				for _, token := range []string{"portal-root", f.rootToken} {
					if _, err := f.store.ApplyIdentityMutation(f.ctx, token, mutation); !errors.Is(err, storage.ErrPermissionDenied) {
						t.Fatalf("legacy/revoked session performed management mutation: %v", err)
					}
				}
				mutation.ManagementOrigin = ""
				if _, err := f.store.ApplyIdentityMutation(f.ctx, "management-root", mutation); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("stale process audience bypass: %v", err)
				}
				mutation.ManagementOrigin = profile.ManagementOrigin
				f.apply(t, "management-root", mutation)
				revoked, err = f.store.ApplySessionProfile(f.ctx, profile)
				if err != nil || revoked != 0 {
					t.Fatalf("same profile reset: %d %v", revoked, err)
				}
				f.active(t, "portal-root", true)
				f.active(t, "management-root", true)
				events, err := f.store.ListAuditEvents(f.ctx, domain.AuditFilter{EventType: "session.profile.changed", Limit: 100})
				if err != nil || len(events) != 1 {
					t.Fatalf("activation audit: %d %v", len(events), err)
				}
				if err := f.store.CheckSessionProfile(f.ctx, profile); err != nil {
					t.Fatal(err)
				}
				for _, change := range []string{"management", "portal", "cookies"} {
					next := profile
					switch change {
					case "management":
						next.ManagementOrigin = "https://second.example"
					case "portal":
						next.PortalHost = "second.example"
					case "cookies":
						next.SessionCookieName = "other_session"
					}
					if err := f.store.CheckSessionProfile(f.ctx, next); !errors.Is(err, storage.ErrSessionProfile) {
						t.Fatalf("%s configuration change silently accepted: %v", change, err)
					}
				}
				if err := f.store.CheckSessionProfile(f.ctx, legacy); !errors.Is(err, storage.ErrSessionProfile) {
					t.Fatalf("rollback silently accepted: %v", err)
				}
				revoked, err = f.store.ApplySessionProfile(f.ctx, legacy)
				if err != nil || revoked != 2 {
					t.Fatalf("explicit rollback reset: %d %v", revoked, err)
				}
				f.active(t, "portal-root", false)
				f.active(t, "management-root", false)
				if err := issue("legacy-after-reset", f.root, domain.SessionAudienceLegacy, "", legacy); err != nil {
					t.Fatal(err)
				}
				mutation.ManagementOrigin = ""
				f.apply(t, "legacy-after-reset", mutation)
			})
			t.Run("management_hostname_cannot_host_resources", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				resource, err := f.store.CreateResource(f.ctx, domain.ResourceInput{Name: "existing", PublicHost: "MANAGEMENT.example:9443", InternalURL: "http://upstream.example", Enabled: true})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.ApplySessionProfile(f.ctx, profile); !errors.Is(err, storage.ErrConflict) {
					t.Fatalf("profile enabled over resource: %v", err)
				}
				f.active(t, f.rootToken, true)
				current, err := f.store.GetSessionProfile(f.ctx)
				if err != nil || current != nil {
					t.Fatalf("failed activation persisted profile: %v %v", current, err)
				}
				host := "app.example"
				if _, err := f.store.UpdateResource(f.ctx, resource.ID, domain.ResourceUpdate{PublicHost: &host}); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.ApplySessionProfile(f.ctx, profile); err != nil {
					t.Fatal(err)
				}
				for i, host := range []string{"management.example", "management.example:9443", "MANAGEMENT.example"} {
					if _, err := f.store.CreateResource(f.ctx, domain.ResourceInput{Name: fmt.Sprintf("collision%d", i), PublicHost: host, InternalURL: "http://upstream.example"}); !errors.Is(err, storage.ErrConflict) {
						t.Fatalf("created management-host resource %s: %v", host, err)
					}
					if _, err := f.store.UpdateResource(f.ctx, resource.ID, domain.ResourceUpdate{PublicHost: &host}); !errors.Is(err, storage.ErrConflict) {
						t.Fatalf("moved resource onto management hostname %s: %v", host, err)
					}
				}
				got, err := f.store.FindResourceByID(f.ctx, resource.ID)
				if err != nil || got.PublicHost != "app.example" {
					t.Fatalf("denied collision changed resource: %#v %v", got, err)
				}
			})
		})
	}
}
