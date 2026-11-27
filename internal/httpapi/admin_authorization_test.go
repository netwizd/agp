package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

func TestAdminIdentityTargetGuard(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(t.TempDir() + "/identity.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	makeGroup := func(name string, permissions []string) *domain.Group {
		group, err := store.CreateGroup(ctx, domain.GroupInput{Name: name, PermissionIDs: permissions})
		if err != nil {
			t.Fatal(err)
		}
		return group
	}
	makeUser := func(name string, admin bool, group string) *domain.User {
		user, err := store.CreateUser(ctx, domain.UserInput{Username: name, PasswordHash: "unchanged-hash", IsAdmin: admin, GroupIDs: []string{group}})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if err := store.CreateSession(ctx, domain.Session{ID: name + "-session", UserID: user.ID, TokenHash: auth.TokenHash(name + "-token"), CSRFHash: auth.TokenHash("csrf"), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		return user
	}
	rootGroup := makeGroup("root", nil)
	managerGroup := makeGroup("manager", []string{authz.PermUsersManage, authz.PermGroupsManage, authz.PermSessionsRevoke, authz.PermResourcesManage})
	privilegedGroup := makeGroup("privileged", []string{authz.PermResourcesManage})
	ordinaryGroup := makeGroup("ordinary", nil)
	root := makeUser("root", true, rootGroup.ID)
	makeUser("manager", false, managerGroup.ID)
	privileged := makeUser("privileged", false, privilegedGroup.ID)
	ordinary := makeUser("ordinary", false, ordinaryGroup.ID)
	api := NewServer(config.Config{SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := api.Handler()
	request := func(method, path string, payload any, actor string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "http://portal.example"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", "csrf")
		r.AddCookie(&http.Cookie{Name: "agp_session", Value: actor + "-token"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, target := range []*domain.User{root, privileged} {
		for _, payload := range []any{map[string]any{"password": "new-long-password"}, map[string]any{"blocked": true}, map[string]any{"group_ids": []string{}}, map[string]any{"display_name": "takeover"}} {
			w := request(http.MethodPatch, "/api/v1/admin/users/"+target.ID, payload, "manager")
			if w.Code != http.StatusForbidden {
				t.Fatalf("PATCH privileged %s: status=%d body=%s", target.Username, w.Code, w.Body.String())
			}
		}
		w := request(http.MethodDelete, "/api/v1/admin/users/"+target.ID, nil, "manager")
		if w.Code != http.StatusForbidden {
			t.Fatalf("DELETE privileged %s: status=%d body=%s", target.Username, w.Code, w.Body.String())
		}
		w = request(http.MethodDelete, "/api/v1/admin/sessions/"+target.Username+"-session", nil, "manager")
		if w.Code != http.StatusForbidden {
			t.Fatalf("revoke privileged %s session: status=%d body=%s", target.Username, w.Code, w.Body.String())
		}
	}
	for _, group := range []*domain.Group{rootGroup, privilegedGroup} {
		w := request(http.MethodPatch, "/api/v1/admin/groups/"+group.ID, map[string]any{"name": group.Name, "permission_ids": []string{}}, "manager")
		if w.Code != http.StatusForbidden {
			t.Fatalf("PATCH protected group: status=%d body=%s", w.Code, w.Body.String())
		}
		w = request(http.MethodDelete, "/api/v1/admin/groups/"+group.ID, nil, "manager")
		if w.Code != http.StatusForbidden {
			t.Fatalf("DELETE protected group: status=%d body=%s", w.Code, w.Body.String())
		}
	}
	for _, test := range []struct {
		method, path string
		payload      any
	}{
		{http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "super", "password": "new-long-password", "is_admin": true}},
		{http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "privileged-copy", "password": "new-long-password", "group_ids": []string{privilegedGroup.ID}}},
		{http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "supergroup", "permission_ids": []string{authz.PermUsersSuperAdminManage}}},
		{http.MethodPatch, "/api/v1/admin/groups/" + ordinaryGroup.ID, map[string]any{"name": "ordinary", "permission_ids": []string{authz.PermResourcesManage}}},
		{http.MethodPatch, "/api/v1/admin/groups/" + managerGroup.ID, map[string]any{"name": "manager", "permission_ids": append([]string{authz.PermUsersSuperAdminManage}, managerGroup.PermissionIDs...)}},
	} {
		w := request(test.method, test.path, test.payload, "manager")
		if w.Code != http.StatusForbidden {
			t.Fatalf("delegation route %s %s: status=%d body=%s", test.method, test.path, w.Code, w.Body.String())
		}
	}
	for _, name := range []string{"root", "privileged"} {
		user, err := store.FindUserByUsername(ctx, name)
		if err != nil || user.PasswordHash != "unchanged-hash" || user.BlockedAt != nil {
			t.Fatalf("denied HTTP action changed %s: %#v %v", name, user, err)
		}
		if _, err := store.FindSessionByTokenHash(ctx, auth.TokenHash(name+"-token")); err != nil {
			t.Fatalf("denied HTTP action revoked %s: %v", name, err)
		}
	}
	// The same route remains available for ordinary targets within the ceiling.
	w := request(http.MethodPatch, "/api/v1/admin/users/"+ordinary.ID, map[string]any{"password": "new-long-password"}, "manager")
	if w.Code != http.StatusOK {
		t.Fatalf("ordinary password reset: status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(http.MethodGet, "/api/v1/me", nil, "ordinary")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("reset session still authorizes HTTP: status=%d body=%s", w.Code, w.Body.String())
	}
	events, err := store.ListAuditEvents(ctx, domain.AuditFilter{EventType: "admin.identity.denied", Limit: 100})
	if err != nil || len(events) == 0 {
		t.Fatalf("identity denials were not audited: %v %v", events, err)
	}
}
