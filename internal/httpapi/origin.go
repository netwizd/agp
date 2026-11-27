package httpapi

import (
	"net/http"
	"path"
	"strings"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/origin"
)

func (s *Server) managementRequest(r *http.Request) bool {
	if s.cfg.ManagementOrigin == "" {
		return false
	}
	authority, err := origin.Authority(r.Host)
	return err == nil && "https://"+authority == s.cfg.ManagementOrigin
}

func (s *Server) portalRequest(r *http.Request) bool {
	actual, err := origin.Authority(r.Host)
	if err != nil {
		return false
	}
	expected, err := origin.Authority(s.cfg.PortalHost)
	return err == nil && actual == expected
}

func (s *Server) loginOriginRequest(r *http.Request) bool {
	if !s.cfg.SecureProfile || s.cfg.LoginOrigin == "" {
		return false
	}
	a, err := origin.Authority(r.Host)
	return err == nil && "https://"+a == s.cfg.LoginOrigin
}
func (s *Server) cookieProfile(r *http.Request) (string, string, bool) {
	if s.loginOriginRequest(r) {
		return domain.LoginSessionCookieName, domain.LoginCSRFCookieName, true
	}
	if s.managementRequest(r) {
		return domain.ManagementSessionCookieName, domain.ManagementCSRFCookieName, true
	}
	return s.cfg.SessionCookieName, s.cfg.CSRFCookieName, s.cfg.CookieSecure
}

func pathWithin(value, root string) bool { return value == root || strings.HasPrefix(value, root+"/") }

func managementUIPath(value string) bool {
	if value == "/" || pathWithin(value, "/admin") {
		return true
	}
	if strings.Count(value, "/") != 1 {
		return false
	}
	switch path.Ext(value) {
	case ".js", ".css", ".png", ".svg", ".ico", ".jpg", ".jpeg", ".webp":
		return true
	}
	return false
}

func (s *Server) originBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		if s.store != nil {
			if err := s.store.CheckSessionProfile(r.Context(), s.cfg.SessionProfile()); err != nil {
				writeError(w, http.StatusServiceUnavailable, "session_profile_mismatch")
				return
			}
		}
		if s.cfg.SecureProfile {
			if s.identityDispatch(w, r) {
				return
			}
			if s.identity == nil {
				writeError(w, http.StatusServiceUnavailable, "security_state_unavailable")
				return
			}
			if s.loginOriginRequest(r) {
				if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
					values := r.Header.Values("Origin")
					if len(values) != 1 || values[0] != s.cfg.LoginOrigin {
						writeError(w, http.StatusForbidden, "origin_required")
						return
					}
				}
				allowed := managementUIPath(r.URL.Path) || pathWithin(r.URL.Path, "/auth-ui") || pathWithin(r.URL.Path, "/api/v2/me/contacts")
				switch r.URL.Path {
				case "/resources", "/api/v1/me", "/api/v1/resources", "/api/v1/auth/logout", "/api/v1/public/runtime", "/api/v1/public/settings", "/api/v1/version", "/readyz":
					allowed = true
				}
				if pathWithin(r.URL.Path, "/admin") {
					allowed = false
				}
				if !allowed {
					writeError(w, http.StatusForbidden, "login_path_forbidden")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
		}
		if s.cfg.ManagementOrigin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if err := s.cfg.ValidateManagement(); err != nil {
			writeError(w, http.StatusServiceUnavailable, "management_configuration_invalid")
			return
		}
		management := s.managementRequest(r)
		if !management {
			if pathWithin(r.URL.Path, "/api/v1/admin") || pathWithin(r.URL.Path, "/api/v2") || pathWithin(r.URL.Path, "/config-ui") || pathWithin(r.URL.Path, "/directory-ui") || pathWithin(r.URL.Path, "/admin") {
				writeError(w, http.StatusForbidden, "management_origin_required")
				return
			}
			// Auth subrequests retain application Host; forwarded headers can select a
			// resource, but never management authority. Readiness also supports loopback.
			if r.URL.Path != "/auth/request" && r.URL.Path != "/readyz" && !s.portalRequest(r) {
				writeError(w, http.StatusForbidden, "unknown_browser_origin")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 || origins[0] != s.cfg.ManagementOrigin {
				writeError(w, http.StatusForbidden, "origin_required")
				return
			}
		}
		allowed := managementUIPath(r.URL.Path) || pathWithin(r.URL.Path, "/api/v1/admin") || (s.cfg.SecureProfile && pathWithin(r.URL.Path, "/auth-ui")) || (s.cfg.ConfigurationEnabled && (pathWithin(r.URL.Path, "/config-ui") || pathWithin(r.URL.Path, "/api/v2/config") || pathWithin(r.URL.Path, "/api/v2/waf") || pathWithin(r.URL.Path, "/api/v2/operations")))
		if s.cfg.SecureProfile && s.cfg.ConfigurationEnabled && (pathWithin(r.URL.Path, "/api/v2/nodes") || pathWithin(r.URL.Path, "/api/v2/node-identity-operations")) {
			allowed = true
		}
		if s.cfg.SecureProfile && (pathWithin(r.URL.Path, "/api/v2/directory-providers") || pathWithin(r.URL.Path, "/api/v2/identity-providers") || r.URL.Path == "/api/v2/directory-access" || r.URL.Path == "/api/v2/identity-access" || pathWithin(r.URL.Path, "/api/v2/users") || pathWithin(r.URL.Path, "/api/v2/role-bindings") || r.URL.Path == "/api/v2/roles" || r.URL.Path == "/api/v2/permissions" || pathWithin(r.URL.Path, "/api/v2/identity-deliveries") || pathWithin(r.URL.Path, "/api/v2/security/operations") || pathWithin(r.URL.Path, "/directory-ui") || pathWithin(r.URL.Path, "/api/v2/me/contacts")) {
			allowed = true
		}
		switch r.URL.Path {
		case "/api/v2/gateways":
			allowed = s.cfg.SecureProfile && s.cfg.ConfigurationEnabled && (r.Method == http.MethodGet || r.Method == http.MethodHead)
		case "/api/v2/agent-inventory", "/api/v2/node-identity-profile":
			allowed = s.cfg.SecureProfile && s.cfg.ConfigurationEnabled
		case "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/me", "/api/v1/public/runtime", "/api/v1/public/settings", "/api/v1/version", "/readyz":
			allowed = true
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "management_path_forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) publicRuntime(w http.ResponseWriter, r *http.Request) {
	mode := "legacy"
	if s.cfg.ManagementOrigin != "" {
		mode = "portal"
		if s.managementRequest(r) {
			mode = "management"
		}
	}
	if s.loginOriginRequest(r) {
		mode = "login"
	}
	_, csrfName, _ := s.cookieProfile(r)
	authUI := "/auth-ui/login"
	if s.cfg.SecureProfile && !s.managementRequest(r) && !s.loginOriginRequest(r) {
		authUI = s.cfg.LoginOrigin + authUI
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "management_url": s.cfg.ManagementOrigin, "login_url": s.cfg.LoginOrigin, "secure_profile": s.cfg.SecureProfile, "configuration_enabled": s.cfg.ConfigurationEnabled, "auth_ui_url": authUI, "csrf_cookie_name": csrfName})
}
