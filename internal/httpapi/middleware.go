package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type sessionContextKey struct{}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic recovered", "error", recovered, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withSession(next func(http.ResponseWriter, *http.Request, *domain.SessionContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.SecureProfile {
			hash, audience, expected, err := s.secureSessionInput(r)
			if err == nil {
				err = s.identity.WithCurrentSession(r.Context(), hash, audience, expected, func(ctx context.Context, session *domain.SessionContext) error {
					ctx = context.WithValue(securitystate.WithActor(ctx, session.TokenHash), sessionContextKey{}, session)
					next(w, r.WithContext(ctx), session)
					return nil
				})
			}
			if err != nil {
				if errors.Is(err, identity.ErrDirectoryUnavailable) {
					writeError(w, 503, "identity_provider_unavailable")
				} else if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, identity.ErrProof) || errors.Is(err, identity.ErrExpired) {
					writeError(w, 401, "unauthorized")
				} else {
					writeError(w, 503, "security_state_unavailable")
				}
			}
			return
		}
		session, err := s.lookupSession(r)
		if err != nil {
			if s.cfg.SecureProfile && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrPermissionDenied) {
				writeError(w, http.StatusServiceUnavailable, "security_state_unavailable")
				return
			}
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(securitystate.WithActor(r.Context(), session.TokenHash), sessionContextKey{}, session)
		next(w, r.WithContext(ctx), session)
	}
}

// Refresh a management proof after a slow upload, before publishing metadata.
// The storage transaction independently checks permissions and pins again.
func (s *Server) currentManagementWrite(ctx context.Context, previous *domain.SessionContext, fn func(context.Context) error) error {
	if !s.cfg.SecureProfile {
		return fn(ctx)
	}
	if s.identity == nil || previous == nil || previous.TokenHash == "" {
		return storage.ErrPermissionDenied
	}
	return s.identity.WithCurrentSession(ctx, previous.TokenHash, domain.SessionAudienceManagement, s.cfg.ManagementOrigin, func(current context.Context, session *domain.SessionContext) error {
		if session.User.ID != previous.User.ID || session.TokenHash != previous.TokenHash {
			return storage.ErrPermissionDenied
		}
		return fn(securitystate.WithActor(current, session.TokenHash))
	})
}

func (s *Server) secureSessionInput(r *http.Request) (hash, audience, expected string, err error) {
	_, audience, ok := s.secureOrigin(r)
	if !ok || s.identity == nil {
		return "", "", "", storage.ErrPermissionDenied
	}
	name, _, _ := s.cookieProfile(r)
	value, ok := uniqueIdentityCookie(r, name)
	if !ok {
		return "", "", "", storage.ErrNotFound
	}
	expected = s.cfg.LoginOrigin
	if audience == domain.SessionAudienceManagement {
		expected = s.cfg.ManagementOrigin
	}
	return auth.TokenHash(value), audience, expected, nil
}

func (s *Server) withPermission(permission string, next func(http.ResponseWriter, *http.Request, *domain.SessionContext)) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !authz.HasPermission(session.Permissions, permission) {
			s.audit(r, "admin.access", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "failure", "permission_required:"+permission)
			writeError(w, http.StatusForbidden, "permission_required")
			return
		}
		if s.cfg.SecureProfile && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if session.MFAAt == nil || time.Since(*session.MFAAt) > 5*time.Minute {
				writeError(w, http.StatusForbidden, "step_up_required")
				return
			}
		}
		next(w, r, session)
	})
}

func (s *Server) lookupSession(r *http.Request) (*domain.SessionContext, error) {
	sessionCookieName, _, _ := s.cookieProfile(r)
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, storage.ErrNotFound
	}
	if s.cfg.SecureProfile {
		_, audience, ok := s.secureOrigin(r)
		if !ok || s.identity == nil {
			return nil, storage.ErrPermissionDenied
		}
		value, ok := uniqueIdentityCookie(r, sessionCookieName)
		if !ok {
			return nil, storage.ErrNotFound
		}
		expected := s.cfg.LoginOrigin
		if audience == domain.SessionAudienceManagement {
			expected = s.cfg.ManagementOrigin
		}
		return s.identity.Session(r.Context(), auth.TokenHash(value), audience, expected)
	}
	session, err := s.store.FindSessionByTokenHash(r.Context(), auth.TokenHash(cookie.Value))
	if err != nil {
		return nil, err
	}
	expectedAudience, expectedOrigin := domain.SessionAudienceLegacy, ""
	if s.managementRequest(r) {
		expectedAudience = domain.SessionAudienceManagement
		expectedOrigin = s.cfg.ManagementOrigin
	}
	if session.Audience != expectedAudience || session.AudienceOrigin != expectedOrigin {
		return nil, storage.ErrPermissionDenied
	}
	if session.User.BlockedAt != nil {
		return nil, errors.New("user is blocked")
	}
	return session, nil
}

func (s *Server) requireCSRF(next func(http.ResponseWriter, *http.Request, *domain.SessionContext)) func(http.ResponseWriter, *http.Request, *domain.SessionContext) {
	return func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		token := r.Header.Get("X-CSRF-Token")
		if token == "" || !auth.ConstantTimeEqualHash(token, session.CSRFHash) {
			writeError(w, http.StatusForbidden, "csrf_required")
			return
		}
		next(w, r, session)
	}
}
