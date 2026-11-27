package frontend

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthEntryAndAssets(t *testing.T) {
	handler := Handler()
	for _, path := range []string{"/auth-ui", "/auth-ui/", "/auth-ui/login", "/auth-ui/recover", "/auth-ui/step-up"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<agp-auth-shell>") {
				t.Fatalf("auth route not served: status %d", response.Code)
			}
			if strings.Contains(response.Body.String(), "<base") || strings.Contains(response.Body.String(), "<style") {
				t.Fatal("strict CSP auth entry must not require inline styles or base URI")
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("auth entry must not be cached")
			}
		})
	}
	bundles, err := fs.Glob(staticFS, "static/auth/main-*.js")
	if err != nil || len(bundles) != 1 {
		t.Fatalf("expected one production auth bundle: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth-ui/"+strings.TrimPrefix(bundles[0], "static/auth/"), nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("auth bundle: %d %s", response.Code, response.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/auth-ui/missing.js", "/auth-ui/missing.css", "/auth-ui/missing.json"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("missing auth asset %s returned %d", path, response.Code)
		}
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `id="adminView"`) {
		t.Fatal("legacy management entry changed")
	}
}

func TestConfigEntryAndAssets(t *testing.T) {
	handler := Handler()
	for _, requestPath := range []string{"/config-ui", "/config-ui/", "/config-ui/revisions/example"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<agp-config-shell>") {
			t.Fatalf("config route %s: status %d", requestPath, response.Code)
		}
		if strings.Contains(response.Body.String(), "<base") || strings.Contains(response.Body.String(), "<style") {
			t.Fatal("config entry requires forbidden inline style or base")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("config entry must not be cached")
		}
	}
	bundles, err := fs.Glob(staticFS, "static/config/main-*.js")
	if err != nil || len(bundles) != 1 {
		t.Fatalf("expected one production config bundle: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config-ui/"+strings.TrimPrefix(bundles[0], "static/config/"), nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("config bundle: %d", response.Code)
	}
	for _, requestPath := range []string{"/config-ui/missing.js", "/config-ui/missing.css", "/config-ui/missing.json"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("missing asset %s returned %d", requestPath, response.Code)
		}
	}
}

func TestDirectoryEntryAndAssets(t *testing.T) {
	handler := Handler()
	for _, requestPath := range []string{"/directory-ui", "/directory-ui/", "/directory-ui/providers/example"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<agp-directory-shell>") {
			t.Fatalf("directory route %s: status %d", requestPath, response.Code)
		}
		if strings.Contains(response.Body.String(), "<base") || strings.Contains(response.Body.String(), "<style") {
			t.Fatal("directory entry requires forbidden inline style or base")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("directory entry must not be cached")
		}
	}
	bundles, err := fs.Glob(staticFS, "static/directory/main-*.js")
	if err != nil || len(bundles) != 1 {
		t.Fatalf("expected one production directory bundle: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/directory-ui/"+strings.TrimPrefix(bundles[0], "static/directory/"), nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("directory bundle: %d", response.Code)
	}
	for _, requestPath := range []string{"/directory-ui/missing.js", "/directory-ui/missing.css", "/directory-ui/missing.json"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("missing directory asset %s returned %d", requestPath, response.Code)
		}
	}
}
