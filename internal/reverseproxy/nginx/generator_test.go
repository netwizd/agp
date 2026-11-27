package nginx

import (
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

func TestGenerateResourceServer(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_app",
			Name:        "Example App",
			InternalURL: "http://app.internal.local",
			PublicHost:  "app.company.ru",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		GroupIDs:   []string{"grp_admins"},
		AllowCIDRs: []string{"10.50.0.0/16"},
	}

	recommendation, err := GenerateResourceServer(resource, "portal.company.ru")
	if err != nil {
		t.Fatalf("GenerateResourceServer returned error: %v", err)
	}
	if recommendation.PublicHost != "app.company.ru" {
		t.Fatalf("unexpected public host: %s", recommendation.PublicHost)
	}
	if !strings.Contains(recommendation.Snippet, "server_name app.company.ru;") {
		t.Fatalf("snippet does not contain server_name: %s", recommendation.Snippet)
	}
	if !strings.Contains(recommendation.Snippet, "proxy_pass http://app.internal.local;") {
		t.Fatalf("snippet does not contain proxy_pass: %s", recommendation.Snippet)
	}
	if !strings.Contains(recommendation.Snippet, "error_page 403 =302 https://portal.company.ru/access-denied;") {
		t.Fatalf("snippet does not contain access denied redirect: %s", recommendation.Snippet)
	}
	if len(recommendation.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", recommendation.Warnings)
	}
}

func TestGeneratePathResourceLocation(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_osrp_do",
			Name:        "Example Service",
			InternalURL: "http://app.internal.local/anything-needed",
			PublicHost:  "enter.company.ru",
			PublicPath:  "/anything-needed",
			Enabled:     true,
		},
		GroupIDs: []string{"grp_users"},
	}

	recommendation, err := GenerateResourceServer(resource, "enter.company.ru")
	if err != nil {
		t.Fatalf("GenerateResourceServer returned error: %v", err)
	}
	for _, expected := range []string{
		"location ^~ /anything-needed {",
		"auth_request /_agp_auth;",
		"proxy_pass http://app.internal.local/anything-needed;",
		"proxy_redirect http://app.internal.local/anything-needed $scheme://$host/anything-needed;",
		"proxy_redirect http://app.internal.local/ $scheme://$host/anything-needed/;",
		"proxy_cookie_path /anything-needed /anything-needed;",
		"proxy_cookie_domain app.internal.local $host;",
		"error_page 403 =302 https://enter.company.ru/access-denied;",
	} {
		if !strings.Contains(recommendation.Snippet, expected) {
			t.Fatalf("snippet does not contain %q: %s", expected, recommendation.Snippet)
		}
	}
	if strings.Contains(recommendation.Snippet, "server_name") {
		t.Fatalf("path resource recommendation must be a location snippet, got: %s", recommendation.Snippet)
	}
}

func TestGenerateBundleContainsProtectedPathLocation(t *testing.T) {
	bundle, err := GenerateBundle([]domain.ResourceDetail{
		{
			Resource: domain.Resource{
				ID:          "res_osrp_do",
				InternalURL: "http://app.internal.local/anything-needed",
				PublicHost:  "enter.company.ru",
				PublicPath:  "/anything-needed",
				Enabled:     true,
			},
			GroupIDs: []string{"grp_users"},
		},
	}, "enter.company.ru")
	if err != nil {
		t.Fatalf("GenerateBundle returned error: %v", err)
	}
	for _, expected := range []string{
		"server_name enter.company.ru;",
		"client_max_body_size 256m;",
		"location = /_agp_auth {",
		"location ^~ /anything-needed {",
		"auth_request /_agp_auth;",
		"proxy_pass http://app.internal.local/anything-needed;",
		"proxy_redirect http://app.internal.local/anything-needed $scheme://$host/anything-needed;",
		"location / {",
	} {
		if !strings.Contains(bundle.Snippet, expected) {
			t.Fatalf("bundle does not contain %q: %s", expected, bundle.Snippet)
		}
	}
}

func TestGenerateBundleUsesNeutralTLSPlaceholders(t *testing.T) {
	bundle, err := GenerateBundle(nil, "enter.company.ru")
	if err != nil {
		t.Fatalf("GenerateBundle returned error: %v", err)
	}
	if strings.Contains(bundle.Snippet, "/etc/letsencrypt/live/") {
		t.Fatalf("bundle must not assume Let's Encrypt paths: %s", bundle.Snippet)
	}
	for _, expected := range []string{
		"ssl_certificate /etc/nginx/ssl/portal/cert.pem;",
		"ssl_certificate_key /etc/nginx/ssl/portal/private.key;",
		"Replace these paths with your real TLS certificate files.",
	} {
		if !strings.Contains(bundle.Snippet, expected) {
			t.Fatalf("bundle does not contain %q: %s", expected, bundle.Snippet)
		}
	}
}

func TestGenerateBundleDoesNotApplyCSPToProxiedResources(t *testing.T) {
	bundle, err := GenerateBundle([]domain.ResourceDetail{
		{
			Resource: domain.Resource{
				ID:          "res_legacy",
				InternalURL: "http://app.internal.local/anything-needed",
				PublicHost:  "enter.company.ru",
				PublicPath:  "/anything-needed",
				Enabled:     true,
			},
			GroupIDs: []string{"grp_users"},
		},
	}, "enter.company.ru")
	if err != nil {
		t.Fatalf("GenerateBundle returned error: %v", err)
	}
	if strings.Contains(bundle.Snippet, "Content-Security-Policy") {
		t.Fatalf("bundle must not add CSP at nginx server level because proxied apps may rely on inline assets: %s", bundle.Snippet)
	}
}

func TestGenerateResourceServerRejectsUnsafeHost(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_bad",
			InternalURL: "http://internal.local",
			PublicHost:  "safe.local; include /etc/passwd;",
		},
	}

	if _, err := GenerateResourceServer(resource, "portal.company.ru"); err == nil {
		t.Fatal("expected unsafe host to be rejected")
	}
}

func TestGenerateResourceServerRejectsInvalidCIDR(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_bad",
			InternalURL: "http://internal.local",
			PublicHost:  "safe.local",
		},
		AllowCIDRs: []string{"10.50.0.0/99"},
	}

	if _, err := GenerateResourceServer(resource, "portal.company.ru"); err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}

func TestTrustedIdentityHeadersAreSetInEachProxyLocation(t *testing.T) {
	for _, path := range []string{"", "/app"} {
		t.Run("path="+path, func(t *testing.T) {
			recommendation, err := GenerateResourceServer(domain.ResourceDetail{
				Resource: domain.Resource{ID: "res_app", InternalURL: "http://app.internal", PublicHost: "app.example", PublicPath: path},
			}, "portal.example")
			if err != nil {
				t.Fatal(err)
			}
			marker := "location / {"
			if path != "" {
				marker = "location ^~ " + path + " {"
			}
			_, location, found := strings.Cut(recommendation.Snippet, marker)
			if !found {
				t.Fatal("missing application proxy location")
			}
			location, _, _ = strings.Cut(location, "}")
			for _, header := range []string{
				"Host $host", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for",
				"X-Forwarded-Proto $scheme", "X-Forwarded-Host $host",
				"X-AGP-User $agp_user", "X-AGP-User-ID $agp_user_id", "X-AGP-Groups $agp_groups",
			} {
				if !strings.Contains(location, "proxy_set_header "+header+";") {
					t.Errorf("application location does not override %s", header)
				}
			}
		})
	}
}

func TestManagementBundleIsolation(t *testing.T) {
	resource := domain.ResourceDetail{Resource: domain.Resource{ID: "app", Name: "App", PublicHost: "portal.example", PublicPath: "/apps/app", InternalURL: "http://upstream.example", Enabled: true}}
	bundle, err := GenerateBundleForProfile([]domain.ResourceDetail{resource}, "portal.example:8443", "https://management.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server_name management.example;", "listen 9443 ssl;", "listen 8443 ssl;", "proxy_set_header Host $http_host;", "location = /admin { return 403; }", "/etc/nginx/ssl/management/cert.pem", "https://portal.example:8443/login", "https://portal.example:8443/access-denied"} {
		if !strings.Contains(bundle.Snippet, want) {
			t.Fatalf("management bundle lacks %q:\n%s", want, bundle.Snippet)
		}
	}
	for _, publicPath := range []string{"", "/apps/app"} {
		resource.PublicPath = publicPath
		snippet, err := GenerateResourceServerForProfile(resource, "portal.example:8443", "https://management.example:9443")
		if err != nil {
			t.Fatal(err)
		}
		for _, redirect := range []string{"https://portal.example:8443/login", "https://portal.example:8443/access-denied"} {
			if !strings.Contains(snippet.Snippet, redirect) {
				t.Fatalf("standalone resource stripped portal port: %s", snippet.Snippet)
			}
		}
	}
	for _, host := range []string{"management.example", "MANAGEMENT.example:8443"} {
		resource.PublicHost = host
		if _, err := GenerateBundleForProfile([]domain.ResourceDetail{resource}, "portal.example", "https://management.example"); err == nil {
			t.Fatalf("generated application on management host %s", host)
		}
		if _, err := GenerateResourceServerForProfile(resource, "portal.example", "https://management.example"); err == nil {
			t.Fatalf("standalone snippet accepted management host %s", host)
		}
	}
	if _, err := GenerateBundleForProfile(nil, "management.example:8443", "https://management.example:9443"); err == nil {
		t.Fatal("port-only origin separation accepted")
	}
}
