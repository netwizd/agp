package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr           string
	PortalHost         string
	DatabaseDriver     string
	DatabasePath       string
	DatabaseDSN        string
	SessionCookieName  string
	CSRFCookieName     string
	CookieSecure       bool
	TrustProxyHeaders  bool
	SessionTTL         time.Duration
	ShutdownTimeout    time.Duration
	LoginRateLimitMax  int
	LoginRateLimitWind time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:           envString("AGP_HTTP_ADDR", "127.0.0.1:8080"),
		PortalHost:         envString("AGP_PORTAL_HOST", "portal.company.ru"),
		DatabaseDriver:     envString("AGP_DATABASE_DRIVER", "postgres"),
		DatabasePath:       envString("AGP_DATABASE_PATH", "./agp.db"),
		DatabaseDSN:        envString("AGP_DATABASE_DSN", "postgres://agp:agp@127.0.0.1:5432/agp?sslmode=disable"),
		SessionCookieName:  envString("AGP_SESSION_COOKIE_NAME", "agp_session"),
		CSRFCookieName:     envString("AGP_CSRF_COOKIE_NAME", "agp_csrf"),
		CookieSecure:       envBool("AGP_COOKIE_SECURE", true),
		TrustProxyHeaders:  envBool("AGP_TRUST_PROXY_HEADERS", true),
		SessionTTL:         envDuration("AGP_SESSION_TTL", 8*time.Hour),
		ShutdownTimeout:    envDuration("AGP_SHUTDOWN_TIMEOUT", 10*time.Second),
		LoginRateLimitMax:  envInt("AGP_LOGIN_RATE_LIMIT_MAX", 5),
		LoginRateLimitWind: envDuration("AGP_LOGIN_RATE_LIMIT_WINDOW", time.Minute),
	}

	if cfg.SessionTTL <= 0 {
		return Config{}, errors.New("AGP_SESSION_TTL must be positive")
	}
	if cfg.LoginRateLimitMax <= 0 {
		return Config{}, errors.New("AGP_LOGIN_RATE_LIMIT_MAX must be positive")
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
	return cfg, nil
}

func envString(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
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
