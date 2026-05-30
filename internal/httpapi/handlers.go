package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	username := strings.TrimSpace(strings.ToLower(req.Username))
	ip := s.clientIP(r)
	ua := r.UserAgent()
	if username == "" || req.Password == "" {
		s.audit(r, "auth.login", "", username, "", ip, ua, "failure", "empty_credentials")
		writeError(w, http.StatusBadRequest, "invalid_credentials")
		return
	}
	if !s.loginLimiter.Allow(ip+"|"+username, time.Now()) {
		s.audit(r, "auth.login", "", username, "", ip, ua, "failure", "rate_limited")
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	user, err := s.store.FindUserByUsername(r.Context(), username)
	if err != nil {
		s.audit(r, "auth.login", "", username, "", ip, ua, "failure", "not_found")
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if user.BlockedAt != nil {
		s.audit(r, "auth.login", user.ID, username, "", ip, ua, "failure", "user_blocked")
		writeError(w, http.StatusForbidden, "user_blocked")
		return
	}

	ok, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !ok {
		s.audit(r, "auth.login", user.ID, username, "", ip, ua, "failure", "password_mismatch")
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	sessionToken, sessionHash, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_generation_failed")
		return
	}
	csrfToken, csrfHash, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_generation_failed")
		return
	}

	now := time.Now().UTC()
	expires := now.Add(s.cfg.SessionTTL)
	session := domain.Session{
		ID:        newID("sess"),
		UserID:    user.ID,
		TokenHash: sessionHash,
		CSRFHash:  csrfHash,
		IP:        ip,
		UserAgent: ua,
		ExpiresAt: expires,
		CreatedAt: now,
	}
	if err := s.store.CreateSession(r.Context(), session); err != nil {
		s.logger.Error("session create failed", "error", err, "username", username)
		writeError(w, http.StatusInternalServerError, "session_create_failed")
		return
	}

	http.SetCookie(w, sessionCookie(s.cfg.SessionCookieName, sessionToken, expires, s.cfg.CookieSecure))
	http.SetCookie(w, csrfCookie(s.cfg.CSRFCookieName, csrfToken, expires, s.cfg.CookieSecure))
	s.audit(r, "auth.login", user.ID, username, "", ip, ua, "success", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       publicUser(user.User),
		"expires_at": expires,
		"csrf_token": csrfToken,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	if err := s.store.DeleteSession(r.Context(), session.TokenHash); err != nil {
		s.logger.Error("session delete failed", "error", err, "user_id", session.User.ID)
	}
	expired := time.Unix(0, 0)
	http.SetCookie(w, sessionCookie(s.cfg.SessionCookieName, "", expired, s.cfg.CookieSecure))
	http.SetCookie(w, csrfCookie(s.cfg.CSRFCookieName, "", expired, s.cfg.CookieSecure))
	s.audit(r, "auth.logout", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, session *domain.SessionContext) {
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        publicUser(session.User),
		"groups":      session.Groups,
		"permissions": session.Permissions,
	})
}

func (s *Server) resources(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	resources, err := s.store.ListResourcesForUser(r.Context(), session.User.ID)
	if err != nil {
		s.logger.Error("list resources failed", "error", err, "user_id", session.User.ID)
		writeError(w, http.StatusInternalServerError, "resource_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": resources})
}

func (s *Server) authRequest(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	ua := r.UserAgent()
	session, err := s.lookupSession(r)
	if err != nil {
		s.audit(r, "proxy.auth_request", "", "", "", ip, ua, "failure", "unauthorized")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	host = normalizeHost(host)
	resource, err := s.store.FindResourceByPublicHost(r.Context(), host)
	if err != nil {
		reason := "resource_not_found"
		if !errors.Is(err, storage.ErrNotFound) {
			s.logger.Error("find resource failed", "error", err, "host", host)
			reason = "storage_error"
		}
		s.audit(r, "proxy.auth_request", session.User.ID, session.User.Username, "", ip, ua, "failure", reason)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !resource.Enabled {
		s.audit(r, "proxy.auth_request", session.User.ID, session.User.Username, resource.ID, ip, ua, "failure", "resource_disabled")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.ipAllowed(r, resource.ID, ip) {
		s.audit(r, "proxy.auth_request", session.User.ID, session.User.Username, resource.ID, ip, ua, "failure", "ip_denied")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	allowed, err := s.store.UserHasResourceAccess(r.Context(), session.User.ID, resource.ID)
	if err != nil {
		s.logger.Error("resource access check failed", "error", err, "user_id", session.User.ID, "resource_id", resource.ID)
		s.audit(r, "proxy.auth_request", session.User.ID, session.User.Username, resource.ID, ip, ua, "failure", "storage_error")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !allowed {
		s.audit(r, "proxy.auth_request", session.User.ID, session.User.Username, resource.ID, ip, ua, "failure", "access_denied")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	s.audit(r, "proxy.auth_request", session.User.ID, session.User.Username, resource.ID, ip, ua, "success", "")
	w.Header().Set("X-AGP-User", session.User.Username)
	w.Header().Set("X-AGP-User-ID", session.User.ID)
	w.Header().Set("X-AGP-Groups", strings.Join(session.Groups, ","))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ipAllowed(r *http.Request, resourceID string, ipText string) bool {
	cidrs, err := s.store.ListResourceAllowCIDRs(r.Context(), resourceID)
	if err != nil {
		s.logger.Error("list resource cidrs failed", "error", err, "resource_id", resourceID)
		return false
	}
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(ipText)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			s.logger.Error("invalid cidr in database", "cidr", cidr, "resource_id", resourceID)
			return false
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) audit(r *http.Request, eventType string, userID string, username string, resourceID string, ip string, ua string, outcome string, reason string) {
	event := domain.AuditEvent{
		Type:          eventType,
		SubjectUserID: userID,
		Username:      username,
		ResourceID:    resourceID,
		IP:            ip,
		UserAgent:     ua,
		Outcome:       outcome,
		Reason:        reason,
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.store.AppendAudit(r.Context(), event); err != nil {
		s.logger.Error("audit append failed", "error", err, "event_type", eventType, "outcome", outcome)
	}
}

func publicUser(user domain.User) map[string]any {
	return map[string]any{
		"id":           user.ID,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"is_admin":     user.IsAdmin,
	}
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			return parsedHost
		}
	}
	return host
}

func newID(prefix string) string {
	token, _, err := auth.NewToken()
	if err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + token[:22]
}
