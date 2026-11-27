package nginx

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

// Run with an explicitly selected native binary. This verifies the generated
// proxy locations over HTTP; it does not qualify TLS, cookies or browser SSO.
func TestNativeIdentityHeaderSpoofing(t *testing.T) {
	binary := os.Getenv("AGP_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("AGP_TEST_NGINX_BIN is not set; native Nginx spoofing test was not run")
	}
	for _, tc := range []struct {
		name          string
		path          string
		emptyIdentity bool
	}{
		{"server_verified", "", false},
		{"server_empty_identity", "", true},
		{"path_verified", "/app", false},
		{"path_empty_identity", "/app", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if !tc.emptyIdentity {
					w.Header().Set("X-AGP-User", "verified-user")
					w.Header().Set("X-AGP-User-ID", "usr_verified")
					w.Header().Set("X-AGP-Groups", "verified-group")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer backend.Close()
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(r.Header)
			}))
			defer app.Close()
			resource := domain.ResourceDetail{Resource: domain.Resource{
				ID: "res_native", InternalURL: app.URL, PublicHost: "app.example", PublicPath: path,
			}}
			var snippet string
			if path == "" {
				recommendation, err := GenerateResourceServer(resource, "portal.example")
				if err != nil {
					t.Fatal(err)
				}
				snippet = "upstream agp_backend { server " + strings.TrimPrefix(backend.URL, "http://") + "; }\n" + recommendation.Snippet
			} else {
				bundle, err := GenerateBundle([]domain.ResourceDetail{resource}, "portal.example")
				if err != nil {
					t.Fatal(err)
				}
				snippet = strings.ReplaceAll(bundle.Snippet, "127.0.0.1:8080", strings.TrimPrefix(backend.URL, "http://"))
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
				lines = append(lines, strings.ReplaceAll(line, "listen 443 ssl;", "listen "+address+";"))
			}
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "logs"), 0700); err != nil {
				t.Fatal(err)
			}
			config := "pid nginx.pid;\nerror_log stderr;\nevents {}\nhttp {\naccess_log off;\n" +
				"client_body_temp_path body;\nproxy_temp_path proxy;\nfastcgi_temp_path fastcgi;\nuwsgi_temp_path uwsgi;\nscgi_temp_path scgi;\n" +
				strings.Join(lines, "\n") + "\n}\n"
			configPath := filepath.Join(dir, "nginx.conf")
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-p", dir+"/", "-c", configPath, "-g", "daemon off;")
			var log bytes.Buffer
			cmd.Stdout, cmd.Stderr = &log, &log
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
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
			defer client.CloseIdleConnections()
			deadline := time.Now().Add(3 * time.Second)
			for {
				req, err := http.NewRequest(http.MethodGet, "http://"+address+path+"/health", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "app.example"
				req.Header.Set("X-AGP-User", "spoofed-user")
				req.Header.Set("X-AGP-User-ID", "usr_spoofed")
				req.Header.Set("X-AGP-Groups", "spoofed-group")
				resp, err := client.Do(req)
				if err == nil {
					body, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr != nil || resp.StatusCode != http.StatusOK {
						t.Fatalf("native upstream failed: status=%d body=%s error=%v", resp.StatusCode, body, readErr)
					}
					var headers http.Header
					if err := json.Unmarshal(body, &headers); err != nil {
						t.Fatal(err)
					}
					for key, expected := range map[string]string{
						"X-AGP-User": "verified-user", "X-AGP-User-ID": "usr_verified", "X-AGP-Groups": "verified-group",
					} {
						actual := headers.Values(key)
						if tc.emptyIdentity {
							if len(actual) != 0 {
								t.Errorf("upstream retained spoofed %s without trusted identity: %v", key, actual)
							}
						} else if len(actual) != 1 || actual[0] != expected {
							t.Errorf("upstream trusted spoofed %s: %v", key, actual)
						}
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("native Nginx did not start: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
