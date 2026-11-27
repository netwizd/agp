package config

import "testing"

func TestPlanReviewSignerRequiresSecureConfiguration(t *testing.T) {
	base := Config{SecureProfile: true, ConfigurationEnabled: true, DatabaseDriver: "postgres", PortalHost: "portal.test", ManagementOrigin: "https://management.test", LoginOrigin: "https://login.test", CookieSecure: true, MFAKeyFile: "/private/mfa", AuthMTLSAddr: "127.0.0.1:8444", AuthMTLSCertFile: "/private/cert", AuthMTLSKeyFile: "/private/key", AuthMTLSClientCAFile: "/private/ca", PlanReviewKeyID: "planning-review", PlanReviewKeyFile: "/private/review-key"}
	if err := base.ValidateSecure(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.PlanReviewKeyID = "" },
		func(c *Config) { c.PlanReviewKeyFile = "" },
		func(c *Config) { c.ConfigurationEnabled = false },
		func(c *Config) { c.SecureProfile = false },
	} {
		c := base
		edit(&c)
		if err := c.ValidateSecure(); err == nil {
			t.Fatal("unsafe/incomplete review signer configuration accepted")
		}
	}
}
