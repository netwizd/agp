package nginx_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/httpapi"
	nginx "github.com/netwizd/agp/internal/reverseproxy/nginx"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

// This checks generated Nginx Host routing over HTTP, including its default
// virtual host. TLS and actual browser cookie rules are covered separately.
func TestNativeManagementHostIsolation(t *testing.T) {
	binary := os.Getenv("AGP_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("AGP_TEST_NGINX_BIN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := sqlite.Open(t.TempDir() + "/native.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser(ctx, domain.UserInput{Username: "root", PasswordHash: "hash", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{PortalHost: "portal.example:8443", ManagementOrigin: "https://management.example:8443", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf", SessionTTL: time.Hour}
	if _, err := store.ApplySessionProfile(ctx, cfg.SessionProfile()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.CreateSession(ctx, domain.Session{ID: "management", UserID: user.ID, TokenHash: auth.TokenHash("management-token"), CSRFHash: "csrf", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: domain.SessionAudienceManagement, AudienceOrigin: cfg.ManagementOrigin}); err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(httpapi.NewServer(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer backend.Close()
	bundle, err := nginx.GenerateBundleForProfile(nil, cfg.PortalHost, cfg.ManagementOrigin)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.LastIndex(bundle.Snippet, "\nserver {")
	if start < 0 {
		t.Fatal("management server absent")
	}
	snippet := "upstream agp_backend { server " + strings.TrimPrefix(backend.URL, "http://") + "; }\n" + bundle.Snippet[start:]
	resourceSnippet, err := nginx.GenerateResourceServerForProfile(domain.ResourceDetail{Resource: domain.Resource{PublicHost: "app.example", InternalURL: backend.URL}}, cfg.PortalHost, cfg.ManagementOrigin)
	if err != nil {
		t.Fatal(err)
	}
	snippet += "\n" + resourceSnippet.Snippet
	if err := store.CreateSession(ctx, domain.Session{ID: "portal", UserID: user.ID, TokenHash: auth.TokenHash("portal-token"), CSRFHash: "csrf", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	var lines []string
	for _, line := range strings.Split(snippet, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ssl_certificate") || strings.HasPrefix(trimmed, "http2 ") || strings.HasPrefix(trimmed, "access_log ") || strings.HasPrefix(trimmed, "error_log ") {
			continue
		}
		line = strings.ReplaceAll(line, "listen 443 ssl;", "listen "+address+";")
		lines = append(lines, strings.ReplaceAll(line, "listen 8443 ssl;", "listen "+address+";"))
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0700); err != nil {
		t.Fatal(err)
	}
	configText := "pid nginx.pid;\nerror_log stderr;\nevents {}\nhttp {\naccess_log off;\nclient_body_temp_path body;\nproxy_temp_path proxy;\nfastcgi_temp_path fastcgi;\nuwsgi_temp_path uwsgi;\nscgi_temp_path scgi;\n" + strings.Join(lines, "\n") + "\n}\n"
	configPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "-p", dir+"/", "-c", configPath, "-e", "stderr", "-g", "daemon off;")
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(log.String())
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(host, path string, cookie bool) (int, string, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			return 0, "", err
		}
		req.Host = host
		req.Header.Set("X-Forwarded-Host", "management.example:8443")
		if cookie {
			req.AddCookie(&http.Cookie{Name: domain.ManagementSessionCookieName, Value: "management-token"})
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw), err
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, body, err := request("management.example:8443", "/api/v1/public/runtime", false)
		if err == nil {
			if status != http.StatusOK || !strings.Contains(body, `"mode":"management"`) {
				t.Fatalf("valid management runtime: %d %s", status, body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, test := range []struct {
		path   string
		cookie bool
	}{{"/api/v1/public/runtime", false}, {"/api/v1/admin/dashboard", true}} {
		status, body, err := request("attacker.example:8443", test.path, test.cookie)
		if err != nil || status != http.StatusForbidden || strings.Contains(body, `"mode":"management"`) {
			t.Fatalf("default listener promoted attacker Host: status=%d body=%s err=%v", status, body, err)
		}
	}
	if status, body, err := request("management.example:8443", "/api/v1/admin/dashboard", true); err != nil || status != http.StatusOK {
		t.Fatalf("valid management cookie: %d %s %v", status, body, err)
	}
	for _, test := range []struct {
		cookie   bool
		location string
	}{{false, "https://portal.example:8443/login"}, {true, "https://portal.example:8443/access-denied"}} {
		req, err := http.NewRequest(http.MethodGet, "http://"+address+"/protected", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "app.example"
		if test.cookie {
			req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: "portal-token"})
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != test.location {
			t.Fatalf("resource denial lost portal authority: %d %q want %q", resp.StatusCode, resp.Header.Get("Location"), test.location)
		}
	}

}
