package config

import "testing"

func TestManagementOriginValidation(t *testing.T) {
	base := Config{PortalHost: "portal.example:8443", ManagementOrigin: "https://management.example:8443", CookieSecure: true, SessionCookieName: "agp_session", CSRFCookieName: "agp_csrf"}
	if err := base.ValidateManagement(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://management.example", "https://Management.example", "https://management.example/", "https://management.example:443", "https://user:secret@management.example", "https://management.example?x=1", "https://management.example#fragment", "https://management.example.", "https://management.example:00080", "https://portal.example:9443", "https://management.example;include"} {
		cfg := base
		cfg.ManagementOrigin = raw
		if err := cfg.ValidateManagement(); err == nil {
			t.Fatalf("accepted unsafe/noncanonical origin %q", raw)
		}
	}
	cfg := base
	cfg.CookieSecure = false
	if err := cfg.ValidateManagement(); err == nil {
		t.Fatal("management accepted insecure cookies")
	}
	cfg = base
	cfg.SessionCookieName = "__Host-agp_management"
	if err := cfg.ValidateManagement(); err == nil {
		t.Fatal("legacy cookie can shadow management cookie")
	}
	if err := base.ValidateResourceHost("Management.example:9443"); err == nil {
		t.Fatal("port bypassed management hostname reservation")
	}
	if err := base.ValidateResourceHost("application.example"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadManagementOrigin(t *testing.T) {
	t.Setenv("AGP_MANAGEMENT_ORIGIN", "https://management.example:8443")
	t.Setenv("AGP_PORTAL_HOST", "portal.example:8443")
	t.Setenv("AGP_COOKIE_SECURE", "true")
	t.Setenv("AGP_SESSION_COOKIE_NAME", "agp_session")
	t.Setenv("AGP_CSRF_COOKIE_NAME", "agp_csrf")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManagementOrigin != "https://management.example:8443" || cfg.SessionProfile().PortalHost != "portal.example:8443" {
		t.Fatalf("unexpected origin profile: %#v", cfg.SessionProfile())
	}
}
