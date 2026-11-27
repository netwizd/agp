package config

import "testing"

func TestAgentConfigurationIsCompleteAndSeparate(t *testing.T) {
	base := Config{SecureProfile: true, ConfigurationEnabled: true, HTTPAddr: "127.0.0.1:8080", AuthMTLSAddr: "127.0.0.1:8444", AuthMTLSCertFile: "/etc/agp/auth.pem", AuthMTLSKeyFile: "/etc/agp/auth.key", AgentMTLSAddr: "127.0.0.1:8445", AgentMTLSCertFile: "/etc/agp/agent.pem", AgentMTLSKeyFile: "/etc/agp/agent.key", AgentMTLSClientCAFile: "/etc/agp/agent-ca.pem", AgentRegistryFile: "/etc/agp/agent-registry.json"}
	if err := base.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{}).ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"partial", func(c *Config) { c.AgentRegistryFile = "" }},
		{"insecure", func(c *Config) { c.SecureProfile = false }},
		{"configuration disabled", func(c *Config) { c.ConfigurationEnabled = false }},
		{"same port different host", func(c *Config) { c.AgentMTLSAddr = "0.0.0.0:8444" }},
		{"same public port", func(c *Config) { c.AgentMTLSAddr = "[::]:8080" }},
		{"ephemeral port", func(c *Config) { c.AgentMTLSAddr = "127.0.0.1:0" }},
		{"service port", func(c *Config) { c.AgentMTLSAddr = "127.0.0.1:https" }},
		{"port alias", func(c *Config) { c.AgentMTLSAddr = "127.0.0.1:08444" }},
		{"relative registry", func(c *Config) { c.AgentRegistryFile = "registry.json" }},
		{"shared key", func(c *Config) { c.AgentMTLSKeyFile = c.AuthMTLSKeyFile }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			if c.ValidateAgent() == nil {
				t.Fatal("accepted unsafe partial/shared listener")
			}
		})
	}
}

func TestManagedEnrollmentListenerSeparation(t *testing.T) {
	base := Config{SecureProfile: true, ConfigurationEnabled: true, HTTPAddr: "127.0.0.1:8080", AuthMTLSAddr: "127.0.0.1:8444", AuthMTLSCertFile: "/etc/agp/auth.pem", AuthMTLSKeyFile: "/etc/agp/auth.key", AgentMTLSAddr: "127.0.0.1:8445", AgentMTLSCertFile: "/etc/agp/agent.pem", AgentMTLSKeyFile: "/etc/agp/agent.key", AgentMTLSClientCAFile: "/etc/agp/agent-ca.pem", NodeIdentityConfig: "/etc/agp/node-identity.json", EnrollmentTLSAddr: "127.0.0.1:8446", EnrollmentTLSCertFile: "/etc/agp/enrollment.pem", EnrollmentTLSKeyFile: "/etc/agp/enrollment.key"}
	if err := base.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"mixed authority", func(c *Config) { c.AgentRegistryFile = "/etc/agp/registry.json" }},
		{"partial enrollment", func(c *Config) { c.EnrollmentTLSKeyFile = "" }},
		{"no enrollment", func(c *Config) { c.EnrollmentTLSAddr, c.EnrollmentTLSKeyFile, c.EnrollmentTLSCertFile = "", "", "" }},
		{"no role listener", func(c *Config) { c.AgentMTLSAddr = "" }},
		{"shared agent port", func(c *Config) { c.EnrollmentTLSAddr = "0.0.0.0:8445" }},
		{"shared browser port", func(c *Config) { c.EnrollmentTLSAddr = "0.0.0.0:8080" }},
		{"shared auth key", func(c *Config) { c.EnrollmentTLSKeyFile = c.AuthMTLSKeyFile }},
		{"shared agent certificate", func(c *Config) { c.EnrollmentTLSCertFile = c.AgentMTLSCertFile }},
		{"relative managed config", func(c *Config) { c.NodeIdentityConfig = "identity.json" }},
		{"relative enrollment key", func(c *Config) { c.EnrollmentTLSKeyFile = "enrollment.key" }},
		{"no managed source", func(c *Config) { c.NodeIdentityConfig = ""; c.AgentRegistryFile = "/etc/agp/registry.json" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if cfg.ValidateAgent() == nil {
				t.Fatal("accepted unsafe managed enrollment configuration")
			}
		})
	}
}
