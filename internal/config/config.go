package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr                 string
	PortalHost               string
	DatabaseDriver           string
	DatabasePath             string
	DatabaseDSN              string
	DownloadsDir             string
	DownloadMaxBytes         int64
	SessionCookieName        string
	CSRFCookieName           string
	CookieSecure             bool
	TrustProxyHeaders        bool
	TrustedProxyCIDRs        []string
	SessionTTL               time.Duration
	SessionRetention         time.Duration
	AuditRetention           time.Duration
	ShutdownTimeout          time.Duration
	LoginRateLimitMax        int
	LoginRateLimitWind       time.Duration
	DownloadAllowedExt       []string
	DownloadScanCmd          string
	DownloadScanTimeout      time.Duration
	DiagnosticsAllowCIDRs    []string
	DiagnosticsDenyCIDRs     []string
	DiagnosticsRateLimitMax  int
	DiagnosticsRateLimitWind time.Duration
}

var DefaultDiagnosticsDenyCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"169.254.0.0/16",
	"fe80::/10",
	"0.0.0.0/8",
	"::/128",
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:                 envString("AGP_HTTP_ADDR", "127.0.0.1:8080"),
		PortalHost:               envString("AGP_PORTAL_HOST", "portal.company.ru"),
		DatabaseDriver:           envString("AGP_DATABASE_DRIVER", "postgres"),
		DatabasePath:             envString("AGP_DATABASE_PATH", "./agp.db"),
		DatabaseDSN:              envString("AGP_DATABASE_DSN", "postgres://agp:agp@127.0.0.1:5432/agp?sslmode=disable"),
		DownloadsDir:             envString("AGP_DOWNLOADS_DIR", "./data/downloads"),
		DownloadMaxBytes:         int64(envInt("AGP_DOWNLOAD_MAX_BYTES", 268435456)),
		SessionCookieName:        envString("AGP_SESSION_COOKIE_NAME", "agp_session"),
		CSRFCookieName:           envString("AGP_CSRF_COOKIE_NAME", "agp_csrf"),
		CookieSecure:             envBool("AGP_COOKIE_SECURE", true),
		TrustProxyHeaders:        envBool("AGP_TRUST_PROXY_HEADERS", false),
		TrustedProxyCIDRs:        envCSV("AGP_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128"),
		SessionTTL:               envDuration("AGP_SESSION_TTL", 8*time.Hour),
		SessionRetention:         envDuration("AGP_SESSION_RETENTION", 720*time.Hour),
		AuditRetention:           envDuration("AGP_AUDIT_RETENTION", 8760*time.Hour),
		ShutdownTimeout:          envDuration("AGP_SHUTDOWN_TIMEOUT", 10*time.Second),
		LoginRateLimitMax:        envInt("AGP_LOGIN_RATE_LIMIT_MAX", 5),
		LoginRateLimitWind:       envDuration("AGP_LOGIN_RATE_LIMIT_WINDOW", time.Minute),
		DownloadAllowedExt:       envCSV("AGP_DOWNLOAD_ALLOWED_EXTENSIONS", ".zip,.rar,.7z,.msi,.exe,.pkg,.dmg,.pdf,.txt,.rdp,.ovpn,.conf"),
		DownloadScanCmd:          envString("AGP_DOWNLOAD_SCAN_COMMAND", ""),
		DownloadScanTimeout:      envDuration("AGP_DOWNLOAD_SCAN_TIMEOUT", 30*time.Second),
		DiagnosticsAllowCIDRs:    envCSV("AGP_DIAGNOSTICS_ALLOW_CIDRS", ""),
		DiagnosticsDenyCIDRs:     defaultedCSV("AGP_DIAGNOSTICS_DENY_CIDRS", DefaultDiagnosticsDenyCIDRs),
		DiagnosticsRateLimitMax:  envInt("AGP_DIAGNOSTICS_RATE_LIMIT_MAX", 30),
		DiagnosticsRateLimitWind: envDuration("AGP_DIAGNOSTICS_RATE_LIMIT_WINDOW", time.Minute),
	}

	if cfg.SessionTTL <= 0 {
		return Config{}, errors.New("AGP_SESSION_TTL must be positive")
	}
	if cfg.SessionRetention <= 0 {
		return Config{}, errors.New("AGP_SESSION_RETENTION must be positive")
	}
	if cfg.AuditRetention <= 0 {
		return Config{}, errors.New("AGP_AUDIT_RETENTION must be positive")
	}
	if cfg.DownloadScanTimeout <= 0 {
		return Config{}, errors.New("AGP_DOWNLOAD_SCAN_TIMEOUT must be positive")
	}
	if cfg.LoginRateLimitMax <= 0 {
		return Config{}, errors.New("AGP_LOGIN_RATE_LIMIT_MAX must be positive")
	}
	if cfg.DiagnosticsRateLimitMax <= 0 {
		return Config{}, errors.New("AGP_DIAGNOSTICS_RATE_LIMIT_MAX must be positive")
	}
	if cfg.DiagnosticsRateLimitWind <= 0 {
		return Config{}, errors.New("AGP_DIAGNOSTICS_RATE_LIMIT_WINDOW must be positive")
	}
	for _, cidr := range cfg.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return Config{}, fmt.Errorf("AGP_TRUSTED_PROXY_CIDRS contains invalid CIDR %q", cidr)
		}
	}
	for i, ext := range cfg.DownloadAllowedExt {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext != "" && !strings.HasPrefix(ext, ".") {
			return Config{}, fmt.Errorf("AGP_DOWNLOAD_ALLOWED_EXTENSIONS contains invalid extension %q", ext)
		}
		cfg.DownloadAllowedExt[i] = ext
	}
	if err := validateCIDRs("AGP_DIAGNOSTICS_ALLOW_CIDRS", cfg.DiagnosticsAllowCIDRs); err != nil {
		return Config{}, err
	}
	if err := validateCIDRs("AGP_DIAGNOSTICS_DENY_CIDRS", cfg.DiagnosticsDenyCIDRs); err != nil {
		return Config{}, err
	}
	if cfg.DatabaseDriver != "postgres" && cfg.DatabaseDriver != "sqlite" {
		return Config{}, errors.New("AGP_DATABASE_DRIVER must be postgres or sqlite")
	}
	if cfg.DatabaseDriver == "postgres" && cfg.DatabaseDSN == "" {
		return Config{}, errors.New("AGP_DATABASE_DSN must be set for postgres")
	}
	if cfg.DatabaseDriver == "sqlite" && cfg.DatabasePath == "" {
		return Config{}, errors.New("AGP_DATABASE_PATH must be set for sqlite")
	}
	if cfg.DownloadsDir == "" {
		return Config{}, errors.New("AGP_DOWNLOADS_DIR must be set")
	}
	if cfg.DownloadMaxBytes <= 0 {
		return Config{}, errors.New("AGP_DOWNLOAD_MAX_BYTES must be positive")
	}
	return cfg, nil
}

func validateCIDRs(key string, cidrs []string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%s contains invalid CIDR %q", key, cidr)
		}
	}
	return nil
}

func envString(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envCSV(key, fallback string) []string {
	value := envString(key, fallback)
	return splitCSV(value)
}

func defaultedCSV(key string, fallback []string) []string {
	value := os.Getenv(key)
	if strings.TrimSpace(value) == "" {
		return append([]string(nil), fallback...)
	}
	return splitCSV(value)
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid duration %s=%q, fallback is used\n", key, value)
		return fallback
	}
	return parsed
}
