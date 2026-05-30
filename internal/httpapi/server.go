package httpapi

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/storage"
)

type Server struct {
	cfg          config.Config
	store        storage.Store
	logger       *slog.Logger
	loginLimiter *rateLimiter
}

func NewServer(cfg config.Config, store storage.Store, logger *slog.Logger) *Server {
	return &Server{
		cfg:          cfg,
		store:        store,
		logger:       logger,
		loginLimiter: newRateLimiter(cfg.LoginRateLimitMax, cfg.LoginRateLimitWind),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.withSession(s.requireCSRF(s.logout)))
	mux.HandleFunc("GET /api/v1/me", s.withSession(s.me))
	mux.HandleFunc("GET /api/v1/resources", s.withSession(s.resources))
	mux.HandleFunc("GET /auth/request", s.authRequest)
	return s.securityHeaders(s.recoverPanic(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
			return value
		}
		if value := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); value != "" {
			return strings.TrimSpace(strings.Split(value, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func sessionCookie(name, value string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func csrfCookie(name, value string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
