package httpapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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
		HTTPAddr:              "127.0.0.1:0",
		PortalHost:            "portal.company.ru",
		SessionCookieName:     "agp_session",
		CSRFCookieName:        "agp_csrf",
		CookieSecure:          false,
		TrustProxyHeaders:     false,
		DiagnosticsAllowCIDRs: []string{"127.0.0.0/8", "::1/128"},
		SessionTTL:            time.Hour,
		ShutdownTimeout:       time.Second,
		LoginRateLimitMax:     5,
		LoginRateLimitWind:    time.Minute,
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
		"name":         "Example App",
		"description":  "Internal example service",
		"internal_url": upstream.URL,
		"public_host":  "app.company.ru",
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
	if !ok || !bytes.Contains([]byte(snippet), []byte("server_name app.company.ru;")) {
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
	historyPayload, ok := diagBody["history"].([]any)
	if !ok || len(historyPayload) == 0 {
		t.Fatalf("diagnostics response does not contain history: %#v", diagBody)
	}
	diagnosticsHistory := getJSON(t, client, server.URL+"/api/v1/admin/resources/"+resourceID+"/diagnostics")
	historyPayload, ok = diagnosticsHistory["history"].([]any)
	if !ok || len(historyPayload) == 0 {
		t.Fatalf("diagnostics history response is empty: %#v", diagnosticsHistory)
	}
	auditCSVReq, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/admin/audit/export?format=csv&type=admin.resource.diagnostics", nil)
	if err != nil {
		t.Fatalf("build audit export request: %v", err)
	}
	auditCSVResp, err := client.Do(auditCSVReq)
	if err != nil {
		t.Fatalf("export audit csv: %v", err)
	}
	auditCSVBody, _ := io.ReadAll(auditCSVResp.Body)
	_ = auditCSVResp.Body.Close()
	if auditCSVResp.StatusCode != http.StatusOK || !bytes.Contains(auditCSVBody, []byte("admin.resource.diagnostics")) {
		t.Fatalf("unexpected audit csv export: status=%d body=%s", auditCSVResp.StatusCode, auditCSVBody)
	}

	if err := store.AppendAudit(ctx, domain.AuditEvent{
		Type:         "manual",
		Username:     "=cmd|' /C calc'!A0",
		Outcome:      "success",
		Reason:       "+formula",
		MetadataJSON: "{\"value\":\"@formula\"}",
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("append malicious audit event: %v", err)
	}
	auditFormulaReq, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/admin/audit/export?format=csv&type=manual", nil)
	if err != nil {
		t.Fatalf("build audit formula export request: %v", err)
	}
	auditFormulaResp, err := client.Do(auditFormulaReq)
	if err != nil {
		t.Fatalf("export audit formula csv: %v", err)
	}
	auditFormulaBody, _ := io.ReadAll(auditFormulaResp.Body)
	_ = auditFormulaResp.Body.Close()
	rows, err := csv.NewReader(bytes.NewReader(auditFormulaBody)).ReadAll()
	if err != nil {
		t.Fatalf("parse audit formula csv: %v body=%s", err, auditFormulaBody)
	}
	if len(rows) < 2 {
		t.Fatalf("expected audit formula row, got %d rows: %s", len(rows), auditFormulaBody)
	}
	if got := rows[1][2]; !strings.HasPrefix(got, "'=") {
		t.Fatalf("expected formula username to be escaped, got %q in csv %s", got, auditFormulaBody)
	}
	if got := rows[1][7]; !strings.HasPrefix(got, "'+") {
		t.Fatalf("expected formula reason to be escaped, got %q in csv %s", got, auditFormulaBody)
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

	userManagerGroup, err := store.CreateGroup(ctx, domain.GroupInput{
		Name:          "User Managers",
		PermissionIDs: []string{authz.PermUsersManage},
	})
	if err != nil {
		t.Fatalf("create user-manager group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{
		Username:     "manager",
		PasswordHash: passwordHash,
		GroupIDs:     []string{userManagerGroup.ID},
	}); err != nil {
		t.Fatalf("create manager user: %v", err)
	}
	managerClient := clientWithJar(t, server.Client())
	loginBody := postJSON(t, managerClient, server.URL+"/api/v1/auth/login", map[string]string{
		"username": "manager",
		"password": password,
	}, nil)
	csrfToken, ok := loginBody["csrf_token"].(string)
	if !ok || csrfToken == "" {
		t.Fatalf("login response does not contain csrf token: %#v", loginBody)
	}
	payload, err := json.Marshal(map[string]any{
		"username": "escalated",
		"password": password,
		"is_admin": true,
	})
	if err != nil {
		t.Fatalf("marshal escalation payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/users", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build escalation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	resp, err = managerClient.Do(req)
	if err != nil {
		t.Fatalf("create escalated user: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden for user-manager superadmin escalation, got %d", resp.StatusCode)
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
	if contentType, _ := downloadPayload["ContentType"].(string); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("expected server-detected text/plain content type, got %#v", downloadPayload["ContentType"])
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
	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("expected server-detected text/plain download content type, got %q", contentType)
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
	} {
		if !bytes.Contains(body, marker) {
			t.Fatalf("metrics body does not contain %q: %s", marker, body)
		}
	}
}

func TestAuthRequestIgnoresUntrustedForwardedHost(t *testing.T) {
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
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Users"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "user", PasswordHash: passwordHash, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := store.CreateResource(ctx, domain.ResourceInput{Name: "Allowed", InternalURL: "http://allowed.internal", PublicHost: "allowed.company.test", Enabled: true, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create allowed resource: %v", err)
	}
	if _, err := store.CreateResource(ctx, domain.ResourceInput{Name: "Spoofed", InternalURL: "http://spoofed.internal", PublicHost: "spoofed.company.test", Enabled: true}); err != nil {
		t.Fatalf("create spoofed resource: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
		TrustProxyHeaders:  false,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	client := clientWithJar(t, server.Client())
	postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{"username": "user", "password": password}, nil)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/auth/request", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Host = "allowed.company.test"
	req.Header.Set("X-Forwarded-Host", "spoofed.company.test")
	attachJarCookies(t, client, server.URL, req)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auth request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected auth request to use Host when proxy is untrusted, got %d", resp.StatusCode)
	}
}

func TestAuthRequestRoutesByPublicHostAndPath(t *testing.T) {
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
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Users"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "user", PasswordHash: passwordHash, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := store.CreateResource(ctx, domain.ResourceInput{Name: "Allowed", InternalURL: "http://app.internal.local/anything-needed", PublicHost: "enter.company.test", PublicPath: "/anything-needed", Enabled: true, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create allowed resource: %v", err)
	}
	if _, err := store.CreateResource(ctx, domain.ResourceInput{Name: "Denied", InternalURL: "http://app.internal.local/secret", PublicHost: "enter.company.test", PublicPath: "/secret", Enabled: true}); err != nil {
		t.Fatalf("create denied resource: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	client := clientWithJar(t, server.Client())
	postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{"username": "user", "password": password}, nil)

	for _, tc := range []struct {
		name       string
		path       string
		statusCode int
	}{
		{name: "allowed prefix", path: "/anything-needed", statusCode: http.StatusNoContent},
		{name: "allowed subpath", path: "/anything-needed/report", statusCode: http.StatusNoContent},
		{name: "denied resource", path: "/secret", statusCode: http.StatusForbidden},
		{name: "unknown resource", path: "/not-found", statusCode: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL+"/auth/request", nil)
			if err != nil {
				t.Fatalf("build auth request: %v", err)
			}
			req.Host = "enter.company.test"
			req.Header.Set("X-Original-URI", tc.path)
			attachJarCookies(t, client, server.URL, req)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("auth request: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.statusCode {
				t.Fatalf("expected status %d, got %d", tc.statusCode, resp.StatusCode)
			}
		})
	}
}

func TestAuthRequestRequiresTrustedProxyWhenProxyHeadersEnabled(t *testing.T) {
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
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Users"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "user", PasswordHash: passwordHash, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := store.CreateResource(ctx, domain.ResourceInput{Name: "Allowed", InternalURL: "http://allowed.internal", PublicHost: "allowed.company.test", Enabled: true, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create resource: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
		TrustProxyHeaders:  true,
		TrustedProxyCIDRs:  []string{"10.0.0.0/8"},
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	client := clientWithJar(t, server.Client())
	postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{"username": "user", "password": password}, nil)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/auth/request", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Host = "allowed.company.test"
	attachJarCookies(t, client, server.URL, req)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auth request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected untrusted proxy request to be denied, got %d", resp.StatusCode)
	}
}

func TestAuditExportRequiresExportPermission(t *testing.T) {
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
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Auditors", PermissionIDs: []string{authz.PermAuditRead}})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "auditor", PasswordHash: passwordHash, GroupIDs: []string{group.ID}}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.AppendAudit(ctx, domain.AuditEvent{Type: "manual", Username: "auditor", Outcome: "success", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("append audit: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:  "agp_session",
		CSRFCookieName:     "agp_csrf",
		SessionTTL:         time.Hour,
		LoginRateLimitMax:  5,
		LoginRateLimitWind: time.Minute,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	client := clientWithJar(t, server.Client())
	postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{"username": "auditor", "password": password}, nil)
	getJSON(t, client, server.URL+"/api/v1/admin/audit")

	resp, err := client.Get(server.URL + "/api/v1/admin/audit/export?format=csv")
	if err != nil {
		t.Fatalf("export audit: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected audit export to require audit.export, got %d", resp.StatusCode)
	}
}

func TestDiagnosticsBlocksDeniedCIDRs(t *testing.T) {
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
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "admin", PasswordHash: passwordHash, IsAdmin: true}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	resource, err := store.CreateResource(ctx, domain.ResourceInput{Name: "Loopback", InternalURL: "http://127.0.0.1:1", PublicHost: "loopback.company.test", Enabled: true})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}

	server := httptest.NewServer(NewServer(config.Config{
		SessionCookieName:    "agp_session",
		CSRFCookieName:       "agp_csrf",
		SessionTTL:           time.Hour,
		LoginRateLimitMax:    5,
		LoginRateLimitWind:   time.Minute,
		DiagnosticsDenyCIDRs: []string{"127.0.0.0/8"},
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)

	client := clientWithJar(t, server.Client())
	loginBody := postJSON(t, client, server.URL+"/api/v1/auth/login", map[string]string{"username": "admin", "password": password}, nil)
	csrfToken, _ := loginBody["csrf_token"].(string)
	body := postJSON(t, client, server.URL+"/api/v1/admin/resources/"+resource.ID+"/diagnostics", nil, map[string]string{"X-CSRF-Token": csrfToken})
	diagnosticsPayload, ok := body["diagnostics"].(map[string]any)
	if !ok {
		t.Fatalf("diagnostics response does not contain diagnostics: %#v", body)
	}
	tcpPayload, ok := diagnosticsPayload["tcp"].(map[string]any)
	if !ok {
		t.Fatalf("diagnostics response does not contain tcp check: %#v", diagnosticsPayload)
	}
	if tcpPayload["ok"] != false || !strings.Contains(tcpPayload["detail"].(string), "AGP_DIAGNOSTICS_DENY_CIDRS") {
		t.Fatalf("expected diagnostics to block denied CIDR, got %#v", tcpPayload)
	}
}

func TestDownloadScannerQuotesPlaceholderPath(t *testing.T) {
	path := t.TempDir() + "/scan target 'quoted'.txt"
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write scan target: %v", err)
	}
	server := NewServer(config.Config{
		DownloadScanCmd:     "test -f {path}",
		DownloadScanTimeout: time.Second,
		LoginRateLimitMax:   5,
		LoginRateLimitWind:  time.Minute,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := server.scanDownloadFile(context.Background(), path); err != nil {
		t.Fatalf("scanner command should quote placeholder path: %v", err)
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

func attachJarCookies(t *testing.T, client *http.Client, rawURL string, req *http.Request) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	for _, cookie := range client.Jar.Cookies(parsed) {
		req.AddCookie(cookie)
	}
}
