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
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

func TestManagementOriginIsolation(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(t.TempDir() + "/origin.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	password := "management-test-password"
	hash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	var ordinaryID string
	for _, username := range []string{"root", "ordinary"} {
		user, err := store.CreateUser(ctx, domain.UserInput{Username: username, PasswordHash: hash, IsAdmin: username == "root", GroupIDs: []string{group.ID}})
		if err != nil {
			t.Fatal(err)
		}
		if username == "ordinary" {
			ordinaryID = user.ID
		}
	}
	if _, err := store.CreateResource(ctx, domain.ResourceInput{Name: "app", PublicHost: "portal.example", PublicPath: "/apps/app", InternalURL: "http://upstream.example", Enabled: true, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{PortalHost: "portal.example:8443", ManagementOrigin: "https://management.example:8443", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour, LoginRateLimitMax: 30, LoginRateLimitWind: time.Minute}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewServer(cfg, store, logger).Handler()
	request := func(method, host, path string, payload any, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "https://"+host+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	managementHost := "management.example:8443"
	portalHost := "portal.example:8443"
	if w := request(http.MethodGet, managementHost, "/api/v1/public/runtime", nil, nil, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unactivated management served: %d %s", w.Code, w.Body.String())
	}
	if _, err := store.ApplySessionProfile(ctx, cfg.SessionProfile()); err != nil {
		t.Fatal(err)
	}
	for host, wantMode := range map[string]string{managementHost: "management", portalHost: "portal"} {
		w := request(http.MethodGet, host, "/api/v1/public/runtime", nil, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("runtime: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		wantCSRF := cfg.CSRFCookieName
		if wantMode == "management" {
			wantCSRF = domain.ManagementCSRFCookieName
		}
		if body["mode"] != wantMode || body["management_url"] != cfg.ManagementOrigin || body["csrf_cookie_name"] != wantCSRF {
			t.Fatalf("runtime contract: %v", body)
		}
	}
	for _, badOrigin := range []string{"", "null", "https://portal.example:8443", "https://management.example", "https://management.example:8443/"} {
		w := request(http.MethodPost, managementHost, "/api/v1/auth/login", map[string]string{"username": "root", "password": password}, nil, map[string]string{"Origin": badOrigin})
		if w.Code != http.StatusForbidden {
			t.Fatalf("login accepted Origin %q: %d %s", badOrigin, w.Code, w.Body.String())
		}
	}
	login := func(host, username string) ([]*http.Cookie, string) {
		t.Helper()
		headers := map[string]string{}
		if host == managementHost {
			headers["Origin"] = cfg.ManagementOrigin
		}
		w := request(http.MethodPost, host, "/api/v1/auth/login", map[string]string{"username": username, "password": password}, nil, headers)
		if w.Code != http.StatusOK {
			t.Fatalf("login %s: %d %s", username, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies(), body["csrf_token"].(string)
	}
	managementCookies, csrf := login(managementHost, "root")
	portalCookies, _ := login(portalHost, "root")
	for _, cookie := range managementCookies {
		if !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" {
			t.Fatalf("management cookie scope: %#v", cookie)
		}
		if cookie.Name == domain.ManagementSessionCookieName && !cookie.HttpOnly {
			t.Fatal("management session is readable by JS")
		}
	}
	var managementToken, portalToken string
	for _, cookie := range managementCookies {
		if cookie.Name == domain.ManagementSessionCookieName {
			managementToken = cookie.Value
		}
	}
	for _, cookie := range portalCookies {
		if cookie.Name == cfg.SessionCookieName {
			portalToken = cookie.Value
		}
	}
	if managementToken == "" || portalToken == "" || managementToken == portalToken {
		t.Fatal("audiences did not receive independent sessions")
	}
	for _, host := range []string{portalHost, "application.example:8443"} {
		for _, path := range []string{"/admin", "/admin/users", "/api/v1/admin/dashboard"} {
			w := request(http.MethodGet, host, path, nil, append(managementCookies, portalCookies...), map[string]string{"X-Forwarded-Host": managementHost})
			if w.Code != http.StatusForbidden {
				t.Fatalf("forwarded management host bypass %s%s: %d", host, path, w.Code)
			}
		}
	}
	for _, path := range []string{"/api/v1/resources", "/api/v1/public/downloads", "/downloads/file.txt", "/help", "/help/manual.pdf", "/auth/request"} {
		w := request(http.MethodGet, managementHost, path, nil, managementCookies, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("management exposed %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/", "/admin", "/styles.css", "/app.js", "/nlgate-logo.png", "/api/v1/public/settings", "/api/v1/admin/users"} {
		w := request(http.MethodGet, managementHost, path, nil, managementCookies, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("management UI %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, test := range []struct{ host, name, token string }{{managementHost, domain.ManagementSessionCookieName, portalToken}, {portalHost, cfg.SessionCookieName, managementToken}} {
		w := request(http.MethodGet, test.host, "/api/v1/me", nil, []*http.Cookie{{Name: test.name, Value: test.token}}, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token audience swap accepted: %d %s", w.Code, w.Body.String())
		}
	}
	w := request(http.MethodGet, portalHost, "/auth/request", nil, portalCookies, map[string]string{"X-Original-URI": "/apps/app"})
	if w.Code != http.StatusNoContent {
		t.Fatalf("portal auth_request compatibility: %d %s", w.Code, w.Body.String())
	}
	w = request(http.MethodGet, portalHost, "/auth/request", nil, []*http.Cookie{{Name: cfg.SessionCookieName, Value: managementToken}}, map[string]string{"X-Original-URI": "/apps/app"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("management token authorized app traffic: %d", w.Code)
	}
	w = request(http.MethodPost, managementHost, "/api/v1/auth/login", map[string]string{"username": "ordinary", "password": password}, nil, map[string]string{"Origin": cfg.ManagementOrigin})
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("ordinary user received management login: %d %s", w.Code, w.Body.String())
	}
	mutationPath := "/api/v1/admin/users/" + ordinaryID
	w = request(http.MethodPatch, managementHost, mutationPath, map[string]string{"display_name": "changed"}, managementCookies, map[string]string{"Origin": cfg.ManagementOrigin})
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing synchronizer CSRF accepted: %d", w.Code)
	}
	w = request(http.MethodPatch, managementHost, mutationPath, map[string]string{"display_name": "changed"}, managementCookies, map[string]string{"Origin": "null", "X-CSRF-Token": csrf})
	if w.Code != http.StatusForbidden {
		t.Fatalf("Origin bypass using CSRF: %d", w.Code)
	}
	w = request(http.MethodPatch, managementHost, mutationPath, map[string]string{"display_name": "changed"}, managementCookies, map[string]string{"Origin": cfg.ManagementOrigin, "X-CSRF-Token": csrf})
	if w.Code != http.StatusOK {
		t.Fatalf("valid management mutation denied: %d %s", w.Code, w.Body.String())
	}
	w = request(http.MethodPost, managementHost, "/api/v1/auth/logout", nil, managementCookies, map[string]string{"Origin": cfg.ManagementOrigin, "X-CSRF-Token": csrf})
	if w.Code != http.StatusOK {
		t.Fatalf("management logout: %d %s", w.Code, w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if !cookie.Secure || cookie.MaxAge >= 0 || cookie.Domain != "" || cookie.Path != "/" {
			t.Fatalf("management logout cookie: %#v", cookie)
		}
	}
	w = request(http.MethodGet, managementHost, "/api/v1/me", nil, managementCookies, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("management logout left session active: %d", w.Code)
	}
	w = request(http.MethodGet, portalHost, "/api/v1/me", nil, portalCookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("management logout revoked portal session: %d", w.Code)
	}
	legacyProfile := cfg.SessionProfile()
	legacyProfile.ManagementOrigin = ""
	if _, err := store.ApplySessionProfile(ctx, legacyProfile); err != nil {
		t.Fatal(err)
	}
	w = request(http.MethodGet, managementHost, "/api/v1/me", nil, managementCookies, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("old running config accepted reset profile: %d", w.Code)
	}
	cfg.ManagementOrigin = ""
	handler = NewServer(cfg, store, logger).Handler()
	legacyCookies, _ := login(portalHost, "root")
	w = request(http.MethodGet, portalHost, "/api/v1/admin/dashboard", nil, legacyCookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("explicit rollback lost legacy compatibility: %d %s", w.Code, w.Body.String())
	}
}
