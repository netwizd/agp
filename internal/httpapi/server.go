package httpapi

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/frontend"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/version"
)

type Server struct {
	cfg                config.Config
	store              storage.Store
	logger             *slog.Logger
	loginLimiter       *rateLimiter
	diagnosticsLimiter *rateLimiter
}

func NewServer(cfg config.Config, store storage.Store, logger *slog.Logger) *Server {
	if cfg.DiagnosticsRateLimitMax <= 0 {
		cfg.DiagnosticsRateLimitMax = 30
	}
	if cfg.DiagnosticsRateLimitWind <= 0 {
		cfg.DiagnosticsRateLimitWind = time.Minute
	}
	if len(cfg.DiagnosticsAllowCIDRs) == 0 && len(cfg.DiagnosticsDenyCIDRs) == 0 {
		cfg.DiagnosticsDenyCIDRs = append([]string(nil), config.DefaultDiagnosticsDenyCIDRs...)
	}
	return &Server{
		cfg:                cfg,
		store:              store,
		logger:             logger,
		loginLimiter:       newRateLimiter(cfg.LoginRateLimitMax, cfg.LoginRateLimitWind),
		diagnosticsLimiter: newRateLimiter(cfg.DiagnosticsRateLimitMax, cfg.DiagnosticsRateLimitWind),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /api/v1/version", s.version)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.withSession(s.requireCSRF(s.logout)))
	mux.HandleFunc("GET /api/v1/me", s.withSession(s.me))
	mux.HandleFunc("GET /api/v1/resources", s.withSession(s.resources))
	mux.HandleFunc("GET /api/v1/public/settings", s.publicPortalSettings)
	mux.HandleFunc("GET /api/v1/public/downloads", s.publicDownloads)
	mux.HandleFunc("GET /downloads/{id}", s.downloadPublicFile)
	mux.HandleFunc("GET /api/v1/admin/dashboard", s.withPermission(authz.PermDashboardRead, s.adminDashboard))
	mux.HandleFunc("GET /api/v1/admin/users", s.withPermission(authz.PermUsersRead, s.adminListUsers))
	mux.HandleFunc("POST /api/v1/admin/users", s.withPermission(authz.PermUsersManage, s.requireCSRF(s.adminCreateUser)))
	mux.HandleFunc("PATCH /api/v1/admin/users/{id}", s.withPermission(authz.PermUsersManage, s.requireCSRF(s.adminUpdateUser)))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}", s.withPermission(authz.PermUsersManage, s.requireCSRF(s.adminDeleteUser)))
	mux.HandleFunc("GET /api/v1/admin/groups", s.withPermission(authz.PermGroupsRead, s.adminListGroups))
	mux.HandleFunc("POST /api/v1/admin/groups", s.withPermission(authz.PermGroupsManage, s.requireCSRF(s.adminCreateGroup)))
	mux.HandleFunc("PATCH /api/v1/admin/groups/{id}", s.withPermission(authz.PermGroupsManage, s.requireCSRF(s.adminUpdateGroup)))
	mux.HandleFunc("DELETE /api/v1/admin/groups/{id}", s.withPermission(authz.PermGroupsManage, s.requireCSRF(s.adminDeleteGroup)))
	mux.HandleFunc("GET /api/v1/admin/resources", s.withPermission(authz.PermResourcesRead, s.adminListResources))
	mux.HandleFunc("POST /api/v1/admin/resources", s.withPermission(authz.PermResourcesManage, s.requireCSRF(s.adminCreateResource)))
	mux.HandleFunc("GET /api/v1/admin/resources/{id}", s.withPermission(authz.PermResourcesRead, s.adminGetResource))
	mux.HandleFunc("PATCH /api/v1/admin/resources/{id}", s.withPermission(authz.PermResourcesManage, s.requireCSRF(s.adminUpdateResource)))
	mux.HandleFunc("DELETE /api/v1/admin/resources/{id}", s.withPermission(authz.PermResourcesManage, s.requireCSRF(s.adminDeleteResource)))
	mux.HandleFunc("GET /api/v1/admin/nginx/bundle", s.withPermission(authz.PermNginxRecommendationsRead, s.adminNginxBundle))
	mux.HandleFunc("GET /api/v1/admin/resources/{id}/nginx", s.withPermission(authz.PermNginxRecommendationsRead, s.adminResourceNginx))
	mux.HandleFunc("POST /api/v1/admin/resources/{id}/diagnostics", s.withPermission(authz.PermResourcesDiagnostics, s.requireCSRF(s.adminResourceDiagnostics)))
	mux.HandleFunc("GET /api/v1/admin/resources/{id}/diagnostics", s.withPermission(authz.PermResourcesDiagnostics, s.adminResourceDiagnosticsHistory))
	mux.HandleFunc("GET /api/v1/admin/downloads", s.withPermission(authz.PermDownloadsRead, s.adminListDownloads))
	mux.HandleFunc("POST /api/v1/admin/downloads", s.withPermission(authz.PermDownloadsManage, s.requireCSRF(s.adminCreateDownload)))
	mux.HandleFunc("PATCH /api/v1/admin/downloads/{id}", s.withPermission(authz.PermDownloadsManage, s.requireCSRF(s.adminUpdateDownload)))
	mux.HandleFunc("DELETE /api/v1/admin/downloads/{id}", s.withPermission(authz.PermDownloadsManage, s.requireCSRF(s.adminDeleteDownload)))
	mux.HandleFunc("GET /api/v1/admin/portal-settings", s.withPermission(authz.PermPortalSettingsRead, s.adminGetPortalSettings))
	mux.HandleFunc("PUT /api/v1/admin/portal-settings", s.withPermission(authz.PermPortalSettingsManage, s.requireCSRF(s.adminUpdatePortalSettings)))
	mux.HandleFunc("GET /api/v1/admin/sessions", s.withPermission(authz.PermSessionsRead, s.adminListSessions))
	mux.HandleFunc("DELETE /api/v1/admin/sessions/{id}", s.withPermission(authz.PermSessionsRevoke, s.requireCSRF(s.adminRevokeSession)))
	mux.HandleFunc("GET /api/v1/admin/audit", s.withPermission(authz.PermAuditRead, s.adminListAudit))
	mux.HandleFunc("GET /api/v1/admin/audit/export", s.withPermission(authz.PermAuditExport, s.adminExportAudit))
	mux.HandleFunc("GET /auth/request", s.authRequest)
	mux.Handle("GET /", frontend.Handler())
	return s.securityHeaders(s.recoverPanic(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, version.Info())
}

func (s *Server) clientIP(r *http.Request) string {
	remoteIP := s.remoteIP(r)
	if s.trustedProxyRequest(r) {
		if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
			return value
		}
		if value := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); value != "" {
			return strings.TrimSpace(strings.Split(value, ",")[0])
		}
	}
	if remoteIP != "" {
		return remoteIP
	}
	return r.RemoteAddr
}

func (s *Server) forwardedHost(r *http.Request) string {
	if s.trustedProxyRequest(r) {
		if host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); host != "" {
			return host
		}
	}
	return r.Host
}

func (s *Server) trustedProxyRequest(r *http.Request) bool {
	if !s.cfg.TrustProxyHeaders {
		return false
	}
	return s.remoteAddrTrusted(s.remoteIP(r))
}

func (s *Server) remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func (s *Server) remoteAddrTrusted(remoteIP string) bool {
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	for _, rawCIDR := range s.cfg.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			s.logger.Error("invalid trusted proxy cidr in config", "cidr", rawCIDR)
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
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
