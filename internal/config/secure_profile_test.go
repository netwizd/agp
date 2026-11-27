package config

import "testing"

func TestValidateSecureProfile(t *testing.T) {
	base := Config{SecureProfile: true, DatabaseDriver: "postgres", PortalHost: "portal.agp.test:8443", ManagementOrigin: "https://management.agp.test:8443", LoginOrigin: "https://login.agp.test:8443", CookieSecure: true, MFAKeyFile: "/private/keyring", AuthMTLSAddr: "127.0.0.1:8444", AuthMTLSCertFile: "/private/cert", AuthMTLSKeyFile: "/private/key", AuthMTLSClientCAFile: "/private/ca"}
	if err := base.ValidateSecure(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"sqlite", func(c *Config) { c.DatabaseDriver = "sqlite" }},
		{"http_login", func(c *Config) { c.LoginOrigin = "http://login.agp.test" }},
		{"portal_hostname_other_port", func(c *Config) { c.LoginOrigin = "https://portal.agp.test:9443" }},
		{"management_hostname_other_port", func(c *Config) { c.LoginOrigin = "https://management.agp.test:9443" }},
		{"insecure_cookie", func(c *Config) { c.CookieSecure = false }},
		{"missing_external_key", func(c *Config) { c.MFAKeyFile = "" }},
		{"missing_mtls_ca", func(c *Config) { c.AuthMTLSClientCAFile = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			if err := cfg.ValidateSecure(); err == nil {
				t.Fatal("invalid secure profile accepted")
			}
		})
	}
	if err := base.ValidateResourceHost("login.agp.test:9443"); err == nil {
		t.Fatal("resource collided with login hostname")
	}
	if err := base.ValidateResourceHost("app.agp.test"); err != nil {
		t.Fatal(err)
	}
}
