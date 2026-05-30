package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

func TestAdminAPIResourceAndNginxFlow(t *testing.T) {
	ctx := context.Background()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	store, err := sqlite.Open(t.TempDir() + "/agp.db")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	password := "enterprise-admin-password"
	passwordHash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Administrators"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{
		Username:     "admin",
		PasswordHash: passwordHash,
		DisplayName:  "Administrator",
		IsAdmin:      true,
		GroupIDs:     []string{group.ID},
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	api := NewServer(config.Config{
		HTTPAddr:           "127.0.0.1:0",
		PortalHost:         "portal.company.ru",
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		CookieSecure:       false,
		TrustProxyHeaders:  false,
		SessionTTL:         time.Hour,
		ShutdownTimeout:    time.Second,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)

	client := clientWithJar(t, server.Client())
	loginBody := postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": password,
	}, nil)
	csrfToken, ok := loginBody["csrf_token"].(string)
	if !ok || csrfToken == "" {
		t.Fatalf("login response does not contain csrf_token: %#v", loginBody)
	}

	createResourceBody := postJSON(t, client, server.URL+"/api/v1/admin/resources", map[string]any{
		"name":         "1C Enterprise",
		"description":  "Internal 1C service",
		"internal_url": upstream.URL,
		"public_host":  "e1c.company.ru",
		"enabled":      true,
		"group_ids":    []string{group.ID},
		"allow_cidrs":  []string{"10.50.0.0/16"},
	}, map[string]string{"X-CSRF-Token": csrfToken})

	resourcePayload, ok := createResourceBody["resource"].(map[string]any)
	if !ok {
		t.Fatalf("create resource response does not contain resource: %#v", createResourceBody)
	}
	resourceID, ok := resourcePayload["ID"].(string)
	if !ok || resourceID == "" {
		t.Fatalf("create resource response does not contain resource ID: %#v", resourcePayload)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/admin/resources/"+resourceID+"/nginx", nil)
	if err != nil {
		t.Fatalf("build nginx request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("nginx request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected nginx status: %d", resp.StatusCode)
	}
	var nginxBody map[string]map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&nginxBody); err != nil {
		t.Fatalf("decode nginx response: %v", err)
	}
	snippet, ok := nginxBody["nginx"]["snippet"].(string)
	if !ok || !bytes.Contains([]byte(snippet), []byte("server_name e1c.company.ru;")) {
		t.Fatalf("unexpected nginx snippet: %#v", nginxBody)
	}

	diagBody := postJSON(t, client, server.URL+"/api/v1/admin/resources/"+resourceID+"/diagnostics", nil, map[string]string{"X-CSRF-Token": csrfToken})
	diagnosticsPayload, ok := diagBody["diagnostics"].(map[string]any)
	if !ok {
		t.Fatalf("diagnostics response does not contain diagnostics: %#v", diagBody)
	}
	httpPayload, ok := diagnosticsPayload["http"].(map[string]any)
	if !ok || httpPayload["ok"] != true {
		t.Fatalf("diagnostics response does not contain successful http check: %#v", diagnosticsPayload)
	}
}

func TestAdminAPIPermissions(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(t.TempDir() + "/agp.db")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	password := "enterprise-user-password"
	passwordHash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	noPermGroup, err := store.CreateGroup(ctx, domain.GroupInput{Name: "No Permissions"})
	if err != nil {
		t.Fatalf("create no-perm group: %v", err)
	}
	readGroup, err := store.CreateGroup(ctx, domain.GroupInput{
		Name:          "Dashboard Readers",
		PermissionIDs: []string{authz.PermDashboardRead},
	})
	if err != nil {
		t.Fatalf("create read group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{
		Username:     "noperm",
		PasswordHash: passwordHash,
		GroupIDs:     []string{noPermGroup.ID},
	}); err != nil {
		t.Fatalf("create no-perm user: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{
		Username:     "reader",
		PasswordHash: passwordHash,
		GroupIDs:     []string{readGroup.ID},
	}); err != nil {
		t.Fatalf("create reader user: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		CookieSecure:       false,
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	noPermClient := clientWithJar(t, server.Client())
	postJSON(t, noPermClient, server.URL+"/api/v1/auth/login", map[string]string{
		"username": "noperm",
		"password": password,
	}, nil)
	resp, err := noPermClient.Get(server.URL + "/api/v1/admin/dashboard")
	if err != nil {
		t.Fatalf("get dashboard without permission: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden for no-perm user, got %d", resp.StatusCode)
	}

	readerClient := clientWithJar(t, server.Client())
	postJSON(t, readerClient, server.URL+"/api/v1/auth/login", map[string]string{
		"username": "reader",
		"password": password,
	}, nil)
	resp, err = readerClient.Get(server.URL + "/api/v1/admin/dashboard")
	if err != nil {
		t.Fatalf("get dashboard with permission: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected ok for dashboard reader, got %d", resp.StatusCode)
	}
}

func TestPublicDownloadsAndPortalSettings(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(t.TempDir() + "/agp.db")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	password := "enterprise-admin-password"
	passwordHash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{
		Username:     "admin",
		PasswordHash: passwordHash,
		IsAdmin:      true,
	}); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		DownloadsDir:       t.TempDir(),
		DownloadMaxBytes:   1024 * 1024,
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		CookieSecure:       false,
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	publicSettings := getJSON(t, server.Client(), server.URL+"/api/v1/public/settings")
	if publicSettings["settings"] == nil {
		t.Fatalf("public settings response is empty: %#v", publicSettings)
	}

	client := clientWithJar(t, server.Client())
	loginBody := postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": password,
	}, nil)
	csrfToken, _ := loginBody["csrf_token"].(string)
	if csrfToken == "" {
		t.Fatalf("missing csrf token: %#v", loginBody)
	}

	settingsBody := doJSON(t, client, http.MethodPut, server.URL+"/api/v1/admin/portal-settings", map[string]string{
		"brand_name":      "NLGate",
		"logo_text":       "NL",
		"portal_title":    "NLGate Portal",
		"portal_subtitle": "Internal services",
		"welcome_title":   "Welcome",
		"welcome_body":    "Use approved resources only.",
		"support_text":    "Support",
		"support_url":     "mailto:helpdesk@example.com",
		"footer_text":     "NLGate corporate portal",
	}, map[string]string{"X-CSRF-Token": csrfToken})
	if settingsBody["settings"] == nil {
		t.Fatalf("settings update response is empty: %#v", settingsBody)
	}

	uploadBody := postMultipart(t, client, server.URL+"/api/v1/admin/downloads", map[string]string{
		"title":       "VPN Client",
		"description": "Approved VPN client package",
		"enabled":     "true",
	}, "file", "vpn-client.txt", []byte("vpn client payload"), map[string]string{"X-CSRF-Token": csrfToken})
	downloadPayload, ok := uploadBody["download"].(map[string]any)
	if !ok {
		t.Fatalf("upload response does not contain download: %#v", uploadBody)
	}
	downloadID, _ := downloadPayload["ID"].(string)
	if downloadID == "" {
		t.Fatalf("upload response does not contain ID: %#v", downloadPayload)
	}

	publicDownloads := getJSON(t, server.Client(), server.URL+"/api/v1/public/downloads")
	downloads, ok := publicDownloads["downloads"].([]any)
	if !ok || len(downloads) != 1 {
		t.Fatalf("unexpected public downloads: %#v", publicDownloads)
	}

	resp, err := server.Client().Get(server.URL + "/downloads/" + downloadID)
	if err != nil {
		t.Fatalf("download public file: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "vpn client payload" {
		t.Fatalf("unexpected download response %d: %q", resp.StatusCode, body)
	}

	doJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/downloads/"+downloadID, map[string]bool{"enabled": false}, map[string]string{"X-CSRF-Token": csrfToken})
	publicDownloads = getJSON(t, server.Client(), server.URL+"/api/v1/public/downloads")
	downloads, _ = publicDownloads["downloads"].([]any)
	if len(downloads) != 0 {
		t.Fatalf("disabled download leaked into public list: %#v", publicDownloads)
	}
}

func TestFrontendFallbackServesSPA(t *testing.T) {
	api := NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)

	resp, err := server.Client().Get(server.URL + "/admin")
	if err != nil {
		t.Fatalf("get frontend: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected frontend status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read frontend body: %v", err)
	}
	if !bytes.Contains(body, []byte("Auth Gateway Portal")) {
		t.Fatalf("frontend body does not look like AGP index: %s", body)
	}
	for _, label := range [][]byte{[]byte("Группы"), []byte("Пользователи"), []byte("Сессии"), []byte("Аудит"), []byte("Файлы")} {
		if !bytes.Contains(body, label) {
			t.Fatalf("frontend body does not contain %q: %s", label, body)
		}
	}
}

func TestReadinessAndMetrics(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(t.TempDir() + "/agp.db")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	resp, err := server.Client().Get(server.URL + "/readyz")
	if err != nil {
		t.Fatalf("get readiness: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected readiness status: %d", resp.StatusCode)
	}

	resp, err = server.Client().Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected metrics status: %d", resp.StatusCode)
	}
	for _, marker := range [][]byte{
		[]byte("agp_up 1"),
		[]byte("agp_db_up 1"),
		[]byte("agp_users_total"),
		[]byte("agp_resources_total"),
		[]byte("agp_audit_events_total"),
	} {
		if !bytes.Contains(body, marker) {
			t.Fatalf("metrics body does not contain %q: %s", marker, body)
		}
	}
}

func postJSON(t *testing.T, client *http.Client, url string, payload any, headers map[string]string) map[string]any {
	t.Helper()
	return doJSON(t, client, http.MethodPost, url, payload, headers)
}

func doJSON(t *testing.T, client *http.Client, method string, url string, payload any, headers map[string]string) map[string]any {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, data)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

func getJSON(t *testing.T, client *http.Client, url string) map[string]any {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("get json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, data)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

func postMultipart(t *testing.T, client *http.Client, url string, fields map[string]string, fileField string, fileName string, fileBody []byte, headers map[string]string) map[string]any {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
	}
	part, err := writer.CreateFormFile(fileField, fileName)
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := part.Write(fileBody); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatalf("build multipart request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post multipart: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, data)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

func clientWithJar(t *testing.T, client *http.Client) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client.Jar = jar
	return client
}
