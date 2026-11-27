package config

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
)

// Agent ingress is optional, but a partial or shared listener is never enabled.
func (cfg Config) ValidateAgent() error {
	values := []string{cfg.AgentMTLSAddr, cfg.AgentMTLSCertFile, cfg.AgentMTLSKeyFile, cfg.AgentMTLSClientCAFile}
	set := 0
	for _, value := range values {
		if value != "" {
			set++
		}
	}
	managed := cfg.NodeIdentityConfig != ""
	enrollment := []string{cfg.EnrollmentTLSAddr, cfg.EnrollmentTLSCertFile, cfg.EnrollmentTLSKeyFile}
	enrollmentSet := 0
	for _, v := range enrollment {
		if v != "" {
			enrollmentSet++
		}
	}
	if set == 0 && cfg.AgentRegistryFile == "" && !managed && enrollmentSet == 0 {
		return nil
	}
	if set != len(values) || !cfg.SecureProfile || !cfg.ConfigurationEnabled || managed == (cfg.AgentRegistryFile != "") {
		return fmt.Errorf("agent inventory requires the secure configuration profile, a dedicated mTLS listener and exactly one identity source")
	}
	port, err := agentListenerPort(cfg.AgentMTLSAddr)
	if err != nil {
		return err
	}
	for _, other := range []string{cfg.HTTPAddr, cfg.AuthMTLSAddr} {
		_, otherPort, e := net.SplitHostPort(other)
		if e != nil || port == otherPort {
			return fmt.Errorf("agent inventory must use a separate listener port")
		}
	}
	paths := append([]string{}, values[1:]...)
	if managed {
		if enrollmentSet != len(enrollment) {
			return fmt.Errorf("managed identity requires a separate enrollment TLS listener")
		}
		enrollmentPort, e := agentListenerPort(cfg.EnrollmentTLSAddr)
		if e != nil {
			return e
		}
		for _, other := range []string{cfg.HTTPAddr, cfg.AuthMTLSAddr, cfg.AgentMTLSAddr} {
			_, otherPort, e := net.SplitHostPort(other)
			if e != nil || enrollmentPort == otherPort {
				return fmt.Errorf("enrollment requires a separate listener port")
			}
		}
		if cfg.EnrollmentTLSKeyFile == cfg.AuthMTLSKeyFile || cfg.EnrollmentTLSKeyFile == cfg.AgentMTLSKeyFile || cfg.EnrollmentTLSCertFile == cfg.AuthMTLSCertFile || cfg.EnrollmentTLSCertFile == cfg.AgentMTLSCertFile {
			return fmt.Errorf("enrollment and role listeners require separate credentials")
		}
		paths = append(paths, cfg.NodeIdentityConfig, cfg.EnrollmentTLSCertFile, cfg.EnrollmentTLSKeyFile)
	} else {
		if enrollmentSet != 0 {
			return fmt.Errorf("enrollment listener requires the managed identity source")
		}
		paths = append(paths, cfg.AgentRegistryFile)
	}
	for _, value := range paths {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("agent mTLS and registry paths must be absolute and clean")
		}
	}
	if cfg.AgentMTLSKeyFile == cfg.AuthMTLSKeyFile || cfg.AgentMTLSCertFile == cfg.AuthMTLSCertFile {
		return fmt.Errorf("agent and EdgeAuth listener credentials must be separate")
	}
	return nil
}

func agentListenerPort(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", fmt.Errorf("agent and enrollment listeners require a numeric nonzero port")
	}
	return port, nil
}
